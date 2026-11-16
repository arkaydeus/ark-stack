import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { watch } from "node:fs";
import { createServer, connect } from "node:net";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { DB_INGRESS_TABLE, dbIngressAllowlistEnforced, parseNftCounters, sha256Hex } from "@ark-stack/shared";

const dir = process.env.ARK_PGBOUNCER_DIR ?? join(process.cwd(), "tmp", "pgbouncer");
const nftFile = join(dir, "allowlist.nft");
const exposeFile = join(dir, "expose");
const statusFile = join(dir, "allowlist.status");
const backendPort = Number(process.env.ARK_PGBOUNCER_LOOPBACK_PORT ?? "15432");
const listenPort = Number(process.env.ARK_PUBLIC_DB_PORT ?? "5432");
// Drop counters for /api/metrics/prometheus (front door §3.11, FD-18). A separate directory, so
// the API can mount it read-only without seeing the PgBouncer userlist or TLS key, and so the
// periodic write does not wake the watcher below.
const metricsDir = process.env.ARK_DB_INGRESS_METRICS_DIR ?? join(process.cwd(), "tmp", "db-ingress");
const countersFile = join(metricsDir, "counters.json");
const counterIntervalMs = Number(process.env.ARK_DB_INGRESS_COUNTER_INTERVAL_MS ?? "15000");

let server: ReturnType<typeof createServer> | null = null;
let reconciling = false;
let dirty = false;
let appliedRules: string | null = null;
let attemptedRules: string | null = null;

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

async function shouldExpose() {
  if (!existsSync(exposeFile)) return false;
  return (await readFile(exposeFile, "utf8")).trim() === "1";
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

function stopListener() {
  if (!server) return;
  server.close();
  server = null;
}

function startListener() {
  if (server) return;
  server = createServer((client) => {
    const upstream = connect({ host: "127.0.0.1", port: backendPort });
    client.pipe(upstream);
    upstream.pipe(client);
    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
  });
  // Without a handler an EADDRINUSE would surface as an uncaught exception and take the
  // reconciler down instead of being reported as a failed apply.
  server.on("error", (error) => {
    console.error(`public database listener failed: ${error.message}`);
    stopListener();
    void writeStatus({
      applied: true,
      enforced: true,
      exposed: false,
      error: `listener failed: ${error.message}`,
    });
  });
  server.listen(listenPort, "0.0.0.0");
}

async function writeStatus(input: { applied: boolean; enforced: boolean; exposed: boolean; error?: string }) {
  // Status contains no credentials. Publish a complete, worker-readable acknowledgement
  // even when upgrading an older root-owned 0600 status file.
  const temporary = `${statusFile}.${crypto.randomUUID()}.tmp`;
  await writeFile(
    temporary,
    `applied=${input.applied}\nenforced=${input.enforced}\nexposed=${input.exposed}\npolicy_hash=${attemptedRules === null ? "" : sha256Hex(attemptedRules)}\nerror=${input.error ?? ""}\n`,
    { mode: 0o644 },
  );
  await rename(temporary, statusFile);
}

async function reconcile() {
  // The control plane writes `allowlist.nft` and `expose` back to back. Dropping an event that
  // lands mid-pass would leave the listener out of step with the newest files until some
  // unrelated change happened to trigger another pass, so re-run once instead.
  if (reconciling) {
    dirty = true;
    return;
  }
  reconciling = true;
  try {
    const expose = await shouldExpose();
    // Revocation must not wait for nft or the pooler's admin socket to recover.
    if (!expose) {
      stopListener();
      await writeStatus({ applied: false, enforced: false, exposed: false });
    }
    if (!existsSync(nftFile)) {
      stopListener();
      attemptedRules = null;
      appliedRules = null;
      await writeStatus({ applied: true, enforced: false, exposed: false });
    } else {
      await applyNft();
      // Re-read after nft: a revocation arriving during apply must not reopen admission.
      const exposeNow = expose && (await shouldExpose());
      if (exposeNow) startListener();
      else stopListener();
      // An empty allowlist installs only the per-source limits, so the table exists but no CIDR
      // allowlist is enforced. Report that honestly rather than claiming enforcement.
      const enforced = dbIngressAllowlistEnforced(appliedRules ?? "");
      await writeStatus({ applied: true, enforced, exposed: exposeNow && Boolean(server) });
      await exportCounters();
    }
  } catch (error) {
    stopListener();
    await writeStatus({
      applied: false,
      enforced: false,
      exposed: false,
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
  if (filename && !["allowlist.nft", "expose"].includes(filename.toString())) return;
  void reconcile();
});

await reconcile();
setInterval(() => void exportCounters(), counterIntervalMs);

// Bind-mount notifications can be coalesced or lost during an upgrade. Poll only the two
// desired inputs as a fallback; unchanged files do not run nft or rewrite status/snapshots.
setInterval(() => {
  void (async () => {
    const desired = existsSync(nftFile) ? await readFile(nftFile, "utf8") : null;
    if (desired !== appliedRules || (await shouldExpose()) !== Boolean(server)) await reconcile();
  })().catch((error) => console.error(`database ingress refresh failed: ${String(error)}`));
}, 1500);

// File notifications may be coalesced or delayed across host filesystems. Poll only closure
// requests (never reopen from polling) so revocation cannot retain an old public listener.
setInterval(() => {
  void shouldExpose()
    .then((expose) => {
      if (!expose && (server || !existsSync(statusFile))) void reconcile();
    })
    .catch((error) => console.error("public database closure poll failed", error));
}, 250);
