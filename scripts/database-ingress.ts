// Host-namespace reconciler for the public database port's nftables policy (docs/design/front-door.md
// §3.8.3, §3.11). It applies `inet ark_db_ingress` (FD-18 per-source limits on tcp/5432, matched on
// both the input and forward hooks) from the database-worker policy, and `inet ark_front_raw` plus
// the same 5432 limits from the domain-worker publication policy. It acknowledges the
// exact bytes in `allowlist.status`, and exports the drop counters for /api/metrics/prometheus.
//
// Since FD-26 it no longer listens on 5432: HAProxy's `fe_pg5432` in edge-ts owns the public port and
// reaches PgBouncer over the internal `pgbouncer-ingress` network, and whether PgBouncer is reachable is
// decided there (`be_pgbouncer` is rendered only while a database is published). The Bun relay to
// `127.0.0.1:15432` and its `expose` toggle are gone.
import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { watch } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";

import {
  FRONT_RAW_TABLE,
  DB_INGRESS_TABLE,
  dbIngressAllowlistEnforced,
  parseNftCounters,
  sha256Hex,
} from "@ark-stack/shared";

const dir = process.env.ARK_PGBOUNCER_DIR ?? join(process.cwd(), "tmp", "pgbouncer");
const nftFile = join(dir, "allowlist.nft");
const statusFile = join(dir, "allowlist.status");
// Drop counters for /api/metrics/prometheus (front door §3.11, FD-18). A separate directory, so
// the API can mount it read-only without seeing the PgBouncer userlist or TLS key, and so the
// periodic write does not wake the watcher below.
const metricsDir = process.env.ARK_DB_INGRESS_METRICS_DIR ?? join(process.cwd(), "tmp", "db-ingress");
const countersFile = join(metricsDir, "counters.json");
const counterIntervalMs = Number(process.env.ARK_DB_INGRESS_COUNTER_INTERVAL_MS ?? "15000");

let reconciling = false;
let dirty = false;
let appliedRules: string | null = null;
let attemptedRules: string | null = null;
let frontApplied: string | null = null;

function run(command: string, args: string[], input?: string) {
  return new Promise<string>((resolve, reject) => {
    const child = spawn(command, args, { stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    child.on("error", reject);
    if (input !== undefined) child.stdin?.end(input);
    let output = "";
    child.stdout!.on("data", (chunk) => {
      output += String(chunk);
    });
    child.stderr!.on("data", (chunk) => {
      output += String(chunk);
    });
    child.on("exit", (code) => {
      if (code === 0) resolve(output);
      else reject(new Error(`${command} ${args.join(" ")} exited ${code}: ${output.slice(0, 1000)}`));
    });
  });
}

async function applyNft() {
  if (!existsSync(nftFile)) throw new Error(`Allowlist file not found: ${nftFile}`);
  const rules = await readFile(nftFile, "utf8");
  attemptedRules = rules;
  if (rules === appliedRules) return;
  // Apply the same bytes we hash, even if a newer policy is atomically published mid-pass.
  await run("nft", ["-f", "-"], rules);
  const listed = await run("nft", ["list", "table", "inet", DB_INGRESS_TABLE]);
  if (!listed.includes("ark_db")) throw new Error("nft readback did not show ark_db_ingress");
  appliedRules = rules;
  // A legacy database-worker update must not leave the domain worker's acknowledged 5432 policy stale.
  frontApplied = null;
}

async function exportCounters() {
  // Nothing has been applied yet, so there is no table to read.
  if (!existsSync(nftFile)) return;
  try {
    const json = await run("nft", ["-j", "list", "counters", "table", "inet", DB_INGRESS_TABLE]);
    const snapshot = parseNftCounters(json);
    // Counters are not secret, and the API reads them as a different uid.
    const temporary = `${countersFile}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(snapshot)}\n`, { mode: 0o644 });
    await rename(temporary, countersFile);
  } catch (error) {
    // No table yet (nothing applied) or nft failed: leave the last snapshot, whose age the
    // metrics endpoint reports, rather than inventing zeros.
    console.error(`nft counter export failed: ${error instanceof Error ? error.message : error}`);
  }
}

async function writeStatus(input: { applied: boolean; enforced: boolean; error?: string }) {
  // Status contains no credentials. Publish a complete, worker-readable acknowledgement
  // even when upgrading an older root-owned 0600 status file.
  const temporary = `${statusFile}.${crypto.randomUUID()}.tmp`;
  await writeFile(
    temporary,
    `applied=${input.applied}\nenforced=${input.enforced}\npolicy_hash=${attemptedRules === null ? "" : sha256Hex(attemptedRules)}\nerror=${input.error ?? ""}\n`,
    { mode: 0o644 },
  );
  await rename(temporary, statusFile);
}

async function reconcile() {
  // A policy write landing mid-pass must not be dropped: re-run once instead.
  if (reconciling) {
    dirty = true;
    return;
  }
  reconciling = true;
  try {
    if (!existsSync(nftFile)) {
      attemptedRules = null;
      appliedRules = null;
      await writeStatus({ applied: true, enforced: false });
    } else {
      await applyNft();
      // An empty allowlist installs only the per-source limits, which is the normal case since FD-26
      // (source allowlists are HAProxy's). Report that honestly rather than claiming enforcement.
      const enforced = dbIngressAllowlistEnforced(appliedRules ?? "");
      await writeStatus({ applied: true, enforced });
      await exportCounters();
    }
  } catch (error) {
    await writeStatus({
      applied: false,
      enforced: false,
      error: error instanceof Error ? error.message : "allowlist apply failed",
    });
  } finally {
    reconciling = false;
  }
  if (dirty) {
    dirty = false;
    await reconcile();
  }
}

await mkdir(dir, { recursive: true, mode: 0o700 });
await mkdir(metricsDir, { recursive: true, mode: 0o755 });
watch(dir, (_event, filename) => {
  // Config, credentials and our own status writes do not change firewall policy. A null
  // filename is an unspecified event, so reconcile conservatively (the content check is cheap).
  if (filename && filename.toString() !== "allowlist.nft") return;
  void reconcile();
});

await reconcile();
setInterval(() => void exportCounters(), counterIntervalMs);

// Bind-mount notifications can be coalesced or lost during an upgrade. Poll only the desired policy
// as a fallback; an unchanged file does not run nft or rewrite status/snapshots.
setInterval(() => {
  void (async () => {
    const desired = existsSync(nftFile) ? await readFile(nftFile, "utf8") : null;
    if (desired !== appliedRules) await reconcile();
  })().catch((error) => console.error(`database ingress refresh failed: ${String(error)}`));
}, 1500);

// Domain-worker policies live outside PgBouncer's credentials mount. Apply both the 5432 limits
// and all raw ports in one nft transaction before acknowledging publication. Polling also retries
// a failed apply; failed and stale hashes cannot release the worker's publication barrier.
const frontDir = process.env.ARK_FRONT_INGRESS_DIR;
let frontBusy = false;
let frontAcknowledged: string | null = null;
async function reconcileFront() {
  if (!frontDir || frontBusy) return;
  frontBusy = true;
  try {
    const rules = await readFile(join(frontDir, "policy.nft"), "utf8");
    const hash = sha256Hex(rules);
    const request = JSON.parse(await readFile(join(frontDir, "policy.request"), "utf8")) as {
      id: string;
      hash: string;
    };
    if (request.hash !== hash || !/^[a-f0-9-]{36}$/.test(request.id)) return;
    if (rules === frontApplied && request.id === frontAcknowledged) return;
    let error = "";
    try {
      if (rules !== frontApplied) await run("nft", ["-f", "-"], rules);
      await run("nft", ["list", "table", "inet", DB_INGRESS_TABLE]);
      await run("nft", ["list", "table", "inet", FRONT_RAW_TABLE]);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    }
    const status = join(frontDir, "policy.status");
    const temporary = `${status}.${crypto.randomUUID()}.tmp`;
    await writeFile(
      temporary,
      `applied=${!error}\npolicy_hash=${hash}\nrequest_id=${request.id}\nerror=${error}\n`,
      { mode: 0o644 },
    );
    await rename(temporary, status);
    if (!error) {
      frontApplied = rules;
      frontAcknowledged = request.id;
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT")
      console.error(`Front ingress refresh failed: ${String(error)}`);
  } finally {
    frontBusy = false;
  }
}
await reconcileFront();
setInterval(() => void reconcileFront(), 250);
