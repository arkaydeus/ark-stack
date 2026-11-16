import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { watch } from "node:fs";
import { createServer, connect } from "node:net";
import { join } from "node:path";
import { spawn } from "node:child_process";

const dir = process.env.ARK_PGBOUNCER_DIR ?? join(process.cwd(), "tmp", "pgbouncer");
const nftFile = join(dir, "allowlist.nft");
const exposeFile = join(dir, "expose");
const statusFile = join(dir, "allowlist.status");
const backendPort = Number(process.env.ARK_PGBOUNCER_LOOPBACK_PORT ?? "15432");
const listenPort = Number(process.env.ARK_PUBLIC_DB_PORT ?? "5432");

let server: ReturnType<typeof createServer> | null = null;
let reconciling = false;
let dirty = false;

function run(command: string, args: string[]) {
  return new Promise<string>((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
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
  return (await Bun.file(exposeFile).text()).trim() === "1";
}

async function applyNft() {
  if (!existsSync(nftFile)) throw new Error(`Allowlist file not found: ${nftFile}`);
  await run("nft", ["-f", nftFile]);
  const listed = await run("nft", ["list", "table", "inet", "ark_db_ingress"]);
  if (!listed.includes("ark_db")) throw new Error("nft readback did not show ark_db_ingress");
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
  await writeFile(
    statusFile,
    `applied=${input.applied}\nenforced=${input.enforced}\nexposed=${input.exposed}\nerror=${input.error ?? ""}\n`,
    { mode: 0o600 },
  );
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
  const expose = await shouldExpose();
  try {
    // Revocation must not wait for nft or the pooler's admin socket to recover.
    if (!expose) {
      stopListener();
      await writeStatus({ applied: false, enforced: false, exposed: false });
    }
    if (!existsSync(nftFile)) {
      stopListener();
      await writeStatus({ applied: true, enforced: false, exposed: false });
      return;
    }
    await applyNft();
    if (expose) startListener();
    else stopListener();
    // An empty allowlist installs an accept-only chain, so the table exists but nothing is
    // enforced. Report that honestly rather than claiming enforcement.
    const enforced = (await Bun.file(nftFile).text()).includes("drop");
    await writeStatus({ applied: true, enforced, exposed: expose && Boolean(server) });
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
watch(dir, (_event, filename) => {
  // `writeStatus` writes into the directory being watched; reacting to it would make every
  // reconcile trigger another one.
  if (filename && filename.toString() === "allowlist.status") return;
  void reconcile();
});

// Watch before the initial pass so a revocation during startup cannot be lost.
await reconcile();

// File notifications may be coalesced or delayed across host filesystems. Poll only closure
// requests (never reopen from polling) so revocation cannot retain an old public listener.
setInterval(() => {
  void shouldExpose()
    .then((expose) => {
      if (!expose && (server || !existsSync(statusFile))) void reconcile();
    })
    .catch((error) => console.error("public database closure poll failed", error));
}, 250);
