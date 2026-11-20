// Applies the public edge's host-namespace firewall (docs/design/front-door.md §3.11).
// The domain worker requests ark_front and the 5432 limits before publishing HAProxy.
// The database worker can also refresh the 5432 limits through its own policy file.
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  DB_INGRESS_LIMITS_CHAIN,
  DB_INGRESS_TABLE,
  FRONT_DEDICATED_CHAIN,
  FRONT_RAW_RANGE,
  FRONT_SHARED_CHAIN,
  FRONT_TABLE,
  HOST_FIREWALL_TABLE,
  POSTGRES_ROUTER_PORT,
  SHARED_SNI_PORTS,
  assertHostFirewall,
  frontSharedPorts,
  hostRoutesFromFront,
  mailEnabled,
  parseNftCounters,
  parseSniPorts,
  preserveDbIngressGenerations,
  hostPublicIpv6Addresses,
  readHostSshAccess,
  updateHostFirewallPorts,
  sha256Hex,
  type IngressCounterSnapshot,
  type HostPortConfig,
} from "@ark-stack/shared";

const dir = process.env.ARK_PGBOUNCER_DIR ?? join(process.cwd(), "tmp", "pgbouncer");
const nftFile = join(dir, "allowlist.nft");
const frontDir = process.env.ARK_FRONT_INGRESS_DIR;
const hostConfig =
  process.env.ARK_HOST_HARDENING === "1"
    ? {
        mailEnabled: mailEnabled(process.env.ARK_MAIL_ENABLED),
        sniPorts: parseSniPorts(process.env.ARK_EDGE_SNI_PORTS),
      }
    : undefined;
// The API mounts only the metrics directory, without policies or PgBouncer credentials.
const metricsDir = process.env.ARK_DB_INGRESS_METRICS_DIR ?? join(process.cwd(), "tmp", "db-ingress");
const countersFile = join(metricsDir, "counters.json");
const counterIntervalMs = Number(process.env.ARK_DB_INGRESS_COUNTER_INTERVAL_MS ?? "15000");

const dbGuard = { table: "ark_db_ingress_guard", ports: String(POSTGRES_ROUTER_PORT) };
const frontGuard = {
  table: "ark_front_guard",
  ports: `{ ${guardSharedPorts().join(", ")}, ${POSTGRES_ROUTER_PORT}, ${FRONT_RAW_RANGE} }`,
};

function guardSharedPorts() {
  try {
    return frontSharedPorts(parseSniPorts(process.env.ARK_EDGE_SNI_PORTS));
  } catch (error) {
    console.error(`Invalid shared SNI port configuration: ${String(error)}`);
    return frontSharedPorts([...SHARED_SNI_PORTS]);
  }
}

async function nft(args: string[], input?: string) {
  const child = Bun.spawn(["nft", ...args], {
    stdin: input === undefined ? "ignore" : new TextEncoder().encode(input),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, output, error] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0) throw new Error(`nft ${args.join(" ")} exited ${status}: ${error.trim().slice(0, 1000)}`);
  return output;
}

async function readOptional(file: string) {
  return readFile(file, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
}

async function publish(file: string, content: string) {
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  await writeFile(temporary, content, { mode: 0o644 });
  await rename(temporary, file);
}

function declaresTable(rules: string, table: string) {
  return `\n${rules}`.includes(`\ntable inet ${table} {`);
}

const legacyDbReset = /^delete table inet ark_db_ingress$/m;
const legacyDbFlush = `flush table inet ${DB_INGRESS_TABLE}`;

function chainRules(rules: string) {
  return new Map(
    [...rules.matchAll(/^[\t ]+chain (\w+) \{\n([\s\S]*?)^[\t ]+}\s*$/gm)].map(([, name, body]) => [
      name!,
      body!
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#")),
    ]),
  );
}

function listPolicyTable(table: string) {
  return nft(["-s", "-t", "-y", "list", "table", "inet", table]);
}

async function installedPolicyTable(table: string) {
  const tables = await nft(["list", "tables", "inet"]);
  return tables.split("\n").includes(`table inet ${table}`) ? listPolicyTable(table) : "";
}

// nft canonicalizes addresses, operators and port lists. Check the installed chain
// structure, dispatch and verdicts in order, without comparing a textual ruleset dump.
function ruleActions(rule: string) {
  return rule
    .replaceAll('"', "")
    .match(
      /(?:(?:\d+\s*:\s*)?\b(?:jump|goto) \w+|@\w+|\b(?:counter name \w+|drop|accept|return)\b|ct count over \d+|limit rate over \d+\/\w+)/g,
    )
    ?.join(" ");
}

async function verifyPolicyTable(table: string, rules: string, priority: number) {
  const installed = chainRules(await listPolicyTable(table));
  const desired = chainRules(rules);
  for (const hook of ["input", "forward"]) {
    if (installed.get(hook)?.[0] !== `type filter hook ${hook} priority ${priority}; policy accept;`) {
      throw new Error(`nft readback did not show the ${hook} hook in ${table}`);
    }
  }
  const required = ["input", "forward"];
  // Pre-FD-18 files have no meter chain. Startup applies their existing policy until
  // the database worker publishes the configured limits.
  if (table === DB_INGRESS_TABLE && !rules.split("\n").includes(legacyDbFlush)) {
    required.push(DB_INGRESS_LIMITS_CHAIN);
  }
  if (table === FRONT_TABLE) required.push(FRONT_SHARED_CHAIN, FRONT_DEDICATED_CHAIN);
  for (const chain of new Set([...required, ...desired.keys()])) {
    const expected = desired.get(chain);
    const actual = installed.get(chain);
    const minimum = chain === "input" || chain === "forward" ? 2 : 1;
    if (
      !expected ||
      !actual ||
      expected.length < minimum ||
      expected.length !== actual.length ||
      expected.some((rule, index) => ruleActions(rule) !== ruleActions(actual[index]!))
    ) {
      throw new Error(`nft readback did not show the requested ${table}/${chain} policy`);
    }
  }
}

type Guard = typeof dbGuard;

function clearGuard(guard: Guard) {
  return `table inet ${guard.table}\ndelete table inet ${guard.table}\n`;
}

// A rejected nft transaction normally leaves the previous policy in the kernel.
// Keep an independent drop guard until a replacement has passed readback.
async function guardFailure(guard: Guard, error: unknown) {
  try {
    const rules = `table inet ${guard.table} {
  chain input {
    type filter hook input priority -2; policy accept;
    tcp dport ${guard.ports} drop
  }
  chain forward {
    type filter hook forward priority -2; policy accept;
    ct direction original ct status dnat tcp dport ${guard.ports} drop
  }
}
`;
    await nft(["-f", "-"], clearGuard(guard) + rules);
    await verifyPolicyTable(guard.table, rules, -2);
    return String(error);
  } catch (guardError) {
    return `${String(error)}. Failed to install the drop guard: ${String(guardError)}`;
  }
}

async function applyPolicies(policies: [string, string][], guards: Guard[], host?: HostPortConfig) {
  for (const [table, rules] of policies) {
    if (!declaresTable(rules, table)) throw new Error(`Policy does not declare ${table}`);
  }
  const transaction = policies.map(([, rules]) => rules);
  if (host) transaction.push(updateHostFirewallPorts(host));
  await nft(["-f", "-"], transaction.join("\n"));
  for (const [table, rules] of policies) await verifyPolicyTable(table, rules, -1);
  if (host) {
    const rules = await nft(["-s", "-y", "list", "table", "inet", HOST_FIREWALL_TABLE]);
    const ssh = /\bchain ssh_access \{/.test(rules) ? readHostSshAccess(rules) : undefined;
    assertHostFirewall(rules, host, ssh);
  }
  await nft(["-f", "-"], guards.map(clearGuard).join(""));
}

async function databasePolicy(rules: string) {
  return preserveDbIngressGenerations(
    rules.replace(legacyDbReset, legacyDbFlush),
    await installedPolicyTable(DB_INGRESS_TABLE),
  );
}

async function frontPolicy(rules: string) {
  // Existing FD-15 requests used a table reset. Upgrade the transaction in place as well.
  const policy = rules.replace(/^delete table inet ark_front$/m, `flush table inet ${FRONT_TABLE}`);
  // After the rule flush, obsolete dedicated chains and meter sets are unreferenced.
  const installed = await installedPolicyTable(FRONT_TABLE);
  const obsolete = [
    ...installed.matchAll(
      /^[\t ]+(chain|set) (port_\d+(?:_limits)?|(?:conn|rate)[46]_(?:shared|\d+)(?:_\d+)*) \{/gm,
    ),
  ]
    .filter(([, kind, name]) => !policy.includes(`  ${kind} ${name} {`))
    .map(([, kind, name]) => `delete ${kind} inet ${FRONT_TABLE} ${name}\n`);
  return policy + "\n" + obsolete.join("");
}

function statusError(error: string) {
  return error.replace(/\s+/g, " ").trim();
}

let dbApplied: string | null = null;
let dbHash = "";
let dbError = "";
let frontAcknowledged: string | null = null;
let frontGuardError = "";
let lastDbStatus: string | null = null;

async function publishDatabaseStatus() {
  const error = dbError || frontGuardError;
  const status = `applied=${!error}\nenforced=false\npolicy_hash=${dbHash}\nerror=${statusError(error)}\n`;
  if (status !== lastDbStatus) {
    await publish(join(dir, "allowlist.status"), status);
    lastDbStatus = status;
  }
}

async function reconcileDatabase() {
  try {
    const rules = await readOptional(nftFile);
    if (rules === null) {
      dbApplied = null;
      // Keep a prior failure visible until a verified fallback supersedes it.
      return { rules, error: "", changed: false };
    }
    dbHash = sha256Hex(rules);
    if (rules === dbApplied) return { rules, error: "", changed: false };
    await applyPolicies([[DB_INGRESS_TABLE, await databasePolicy(rules)]], [dbGuard]);
    dbApplied = rules;
    dbError = "";
    return { rules, error: "", changed: true };
  } catch (error) {
    dbApplied = null;
    dbError = await guardFailure(dbGuard, error);
    return { rules: null, error: dbError, changed: false };
  }
}

async function reconcileFront(database: Awaited<ReturnType<typeof reconcileDatabase>>) {
  if (!frontDir) return false;
  const requestText = await readOptional(join(frontDir, "policy.request"));
  if (!requestText) return false;
  const request = JSON.parse(requestText) as { id: string; hash: string };
  const rules = await readOptional(join(frontDir, "policy.nft"));
  if (rules === null || !/^[a-f0-9-]{36}$/.test(request.id) || request.hash !== sha256Hex(rules))
    return false;
  if (request.id === frontAcknowledged) return false;

  const statusFile = join(frontDir, "policy.status");
  const requestStatus = `policy_hash=${request.hash}\nrequest_id=${request.id}\n`;
  const legacy = !declaresTable(rules, FRONT_TABLE) && declaresTable(rules, "ark_front_raw");
  let error = database.error;
  if (legacy) {
    // The installer preserves these files and starts us before the new domain worker.
    error = "Awaiting a front policy from the upgraded domain worker.";
  } else if (!error) {
    try {
      const boundary = rules.indexOf("\n#!", 1);
      if (boundary === -1) throw new Error("Front request is missing its combined policy sections");
      const desiredDb = database.rules ?? rules.slice(0, boundary);
      const front = await frontPolicy(rules.slice(boundary + 1));
      // Reapply every fresh request, including identical bytes, to repair external drift.
      // A present database file owns 5432 and cannot be overwritten by a front replay.
      await applyPolicies(
        [
          [DB_INGRESS_TABLE, await databasePolicy(desiredDb)],
          [FRONT_TABLE, front],
        ],
        [frontGuard, dbGuard],
        hostConfig ? { ...hostConfig, routes: hostRoutesFromFront(rules) } : undefined,
      );
      frontGuardError = "";
      dbError = "";
      dbHash = sha256Hex(desiredDb);
    } catch (failure) {
      frontAcknowledged = null;
      frontGuardError = await guardFailure(frontGuard, failure);
      error = frontGuardError;
    }
  }
  await publish(statusFile, `applied=${!error}\n${requestStatus}error=${statusError(error)}\n`);
  if (legacy || !error) frontAcknowledged = request.id;
  return !error;
}

let dbCounters: IngressCounterSnapshot | undefined;
let frontCounters: IngressCounterSnapshot | undefined;
let exporting = false;

async function scrapeCounters(table: IngressCounterSnapshot["table"]) {
  try {
    const json = await nft(["-j", "list", "counters", "table", "inet", table]);
    return parseNftCounters(json, new Date(), table);
  } catch (error) {
    console.error(`nft counter export for ${table} failed: ${String(error)}`);
    return undefined;
  }
}

async function exportCounters() {
  if (exporting) return;
  exporting = true;
  try {
    const addresses = hostPublicIpv6Addresses();
    await publish(join(metricsDir, "ipv6-host.json"), JSON.stringify({ at: Date.now(), addresses }));
    const [dbSample, frontSample] = await Promise.all([
      scrapeCounters(DB_INGRESS_TABLE),
      frontDir ? scrapeCounters(FRONT_TABLE) : undefined,
    ]);
    dbCounters = dbSample ?? dbCounters;
    frontCounters = frontSample ?? frontCounters;
    if (dbSample || frontSample) {
      await publish(countersFile, `${JSON.stringify({ ...dbCounters, front: frontCounters })}\n`);
    }
  } catch (error) {
    console.error(`nft counter snapshot publication failed: ${String(error)}`);
  } finally {
    exporting = false;
  }
}

function reportRefreshError(scope: string) {
  return (error: unknown) => {
    console.error(`${scope} refresh failed: ${String(error)}`);
    return false;
  };
}

let reconciling = false;
async function reconcile() {
  if (reconciling) return;
  reconciling = true;
  try {
    const database = await reconcileDatabase();
    const frontChanged = await reconcileFront(database).catch(reportRefreshError("Front ingress"));
    await publishDatabaseStatus().catch(reportRefreshError("Database ingress status"));
    if (database.changed || frontChanged) await exportCounters();
  } finally {
    reconciling = false;
  }
}

await mkdir(dir, { recursive: true, mode: 0o700 });
await mkdir(metricsDir, { recursive: true, mode: 0o755 });
if (frontDir && (await installedPolicyTable(frontGuard.table))) {
  frontGuardError = "The public front policy is still guarded pending successful readback.";
}
if (await installedPolicyTable(dbGuard.table)) {
  dbError = "The database policy is still guarded pending successful readback.";
}
// Keep each last-good sample even when the process restarts during a one-table scrape failure.
try {
  const previous = await readOptional(countersFile);
  if (previous) {
    const snapshot = JSON.parse(previous) as IngressCounterSnapshot & { front?: IngressCounterSnapshot };
    if (snapshot.table === DB_INGRESS_TABLE) dbCounters = snapshot;
    if (snapshot.front?.table === FRONT_TABLE) frontCounters = snapshot.front;
  }
} catch (error) {
  console.error(`Could not load the previous nft counter snapshot: ${String(error)}`);
}
await reconcile();
await exportCounters();
// Poll for atomically published files. Bind mount notifications can be lost during an upgrade.
setInterval(() => void reconcile(), 250);
setInterval(() => void exportCounters(), counterIntervalMs);
