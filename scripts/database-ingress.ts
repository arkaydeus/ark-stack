// Applies the public edge's host-namespace firewall (docs/design/front-door.md §3.11).
// The domain worker requests ark_front and the 5432 limits before publishing HAProxy.
// The database worker can also refresh the 5432 limits through its own policy file.
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  DB_INGRESS_TABLE,
  FRONT_RAW_RANGE,
  FRONT_TABLE,
  POSTGRES_ROUTER_PORT,
  SHARED_SNI_PORTS,
  frontSharedPorts,
  parseNftCounters,
  parseSniPorts,
  sha256Hex,
  type IngressCounterSnapshot,
} from "@ark-stack/shared";

const dir = process.env.ARK_PGBOUNCER_DIR ?? join(process.cwd(), "tmp", "pgbouncer");
const nftFile = join(dir, "allowlist.nft");
const frontDir = process.env.ARK_FRONT_INGRESS_DIR;
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

async function readPolicyTable(table: string) {
  const listed = await nft(["list", "table", "inet", table]);
  for (const hook of ["input", "forward"]) {
    if (!listed.includes(`hook ${hook} `))
      throw new Error(`nft readback did not show the ${hook} hook in ${table}`);
  }
}

// A failed nft transaction normally leaves the previous table in the kernel. Install a drop
// guard independently of the failed bytes, and keep it through retries until readback succeeds.
async function applyPolicy(rules: string | null, tables: string[], guard: { table: string; ports: string }) {
  const clearGuard = `table inet ${guard.table}\ndelete table inet ${guard.table}\n`;
  try {
    if (rules !== null) {
      for (const table of tables) {
        if (!`\n${rules}`.includes(`\ntable inet ${table} {`)) {
          throw new Error(`Policy does not declare ${table}`);
        }
      }
      await nft(["-f", "-"], rules);
    }
    for (const table of tables) await readPolicyTable(table);
    await nft(["-f", "-"], clearGuard);
    return "";
  } catch (error) {
    try {
      await nft(
        ["-f", "-"],
        `${clearGuard}table inet ${guard.table} {
  chain input {
    type filter hook input priority -2; policy accept;
    tcp dport ${guard.ports} drop
  }
  chain forward {
    type filter hook forward priority -2; policy accept;
    ct direction original ct status dnat tcp dport ${guard.ports} drop
  }
}
`,
      );
      await readPolicyTable(guard.table);
      return String(error);
    } catch (guardError) {
      return `${String(error)}. Failed to install the drop guard: ${String(guardError)}`;
    }
  }
}

function statusError(error: string) {
  return error.replace(/\s+/g, " ").trim();
}

let dbApplied: string | null = null;
let frontApplied: string | null = null;
let frontAcknowledged: string | null = null;
let lastDbStatus: string | null = null;

async function reconcileDatabase() {
  const rules = await readOptional(nftFile);
  if (rules === dbApplied && lastDbStatus !== null) return false;
  const error = rules === null ? "" : await applyPolicy(rules, [DB_INGRESS_TABLE], dbGuard);
  const status = `applied=${!error}\nenforced=false\npolicy_hash=${rules === null ? "" : sha256Hex(rules)}\nerror=${statusError(error)}\n`;
  if (status !== lastDbStatus) {
    await publish(join(dir, "allowlist.status"), status);
    lastDbStatus = status;
  }
  dbApplied = error ? null : rules;
  // On a fresh front request, install the combined policy again if the database worker has
  // changed 5432 in the meantime. An already acknowledged front request must not roll that back.
  if (rules !== null) frontApplied = null;
  return rules !== null && !error;
}

async function reconcileFront() {
  if (!frontDir) return false;
  const requestText = await readOptional(join(frontDir, "policy.request"));
  if (!requestText) return false;
  const request = JSON.parse(requestText) as { id: string; hash: string };
  const rules = await readOptional(join(frontDir, "policy.nft"));
  if (rules === null || !/^[a-f0-9-]{36}$/.test(request.id) || request.hash !== sha256Hex(rules))
    return false;
  if (request.id === frontAcknowledged) return false;

  const error = await applyPolicy(
    rules === frontApplied ? null : rules,
    [DB_INGRESS_TABLE, FRONT_TABLE],
    frontGuard,
  );
  frontApplied = error ? null : rules;
  await publish(
    join(frontDir, "policy.status"),
    `applied=${!error}\npolicy_hash=${request.hash}\nrequest_id=${request.id}\nerror=${statusError(error)}\n`,
  );
  if (!error) frontAcknowledged = request.id;
  return !error;
}

let frontCounters: IngressCounterSnapshot | undefined;
async function exportCounters() {
  if (dbApplied === null && frontAcknowledged === null) return;
  try {
    const json = await nft(["-j", "list", "counters", "table", "inet", DB_INGRESS_TABLE]);
    const dbCounters = parseNftCounters(json);
    if (frontAcknowledged !== null) {
      try {
        const front = await nft(["-j", "list", "counters", "table", "inet", FRONT_TABLE]);
        frontCounters = parseNftCounters(front, new Date(), FRONT_TABLE);
      } catch (error) {
        console.error(`Front ingress counter export failed: ${String(error)}`);
      }
    }
    await publish(countersFile, `${JSON.stringify({ ...dbCounters, front: frontCounters })}\n`);
  } catch (error) {
    // Leave the last snapshot, whose age the metrics endpoint reports.
    console.error(`nft counter export failed: ${String(error)}`);
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
    const dbChanged = await reconcileDatabase().catch(reportRefreshError("Database ingress"));
    const frontChanged = await reconcileFront().catch(reportRefreshError("Front ingress"));
    if (dbChanged || frontChanged) await exportCounters();
  } finally {
    reconciling = false;
  }
}

await mkdir(dir, { recursive: true, mode: 0o700 });
await mkdir(metricsDir, { recursive: true, mode: 0o755 });
await reconcile();
// Poll for atomically published files. Bind mount notifications can be lost during an upgrade.
setInterval(() => void reconcile(), 250);
setInterval(() => void exportCounters(), counterIntervalMs);
