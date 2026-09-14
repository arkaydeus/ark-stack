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
  if (reconciling) return;
  reconciling = true;
  const expose = await shouldExpose();
  try {
    if (!existsSync(nftFile)) {
      stopListener();
      await writeStatus({ applied: true, enforced: false, exposed: false });
      return;
    }
    await applyNft();
    if (expose) startListener();
    else stopListener();
    await writeStatus({ applied: true, enforced: true, exposed: expose && Boolean(server) });
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
}

await mkdir(dir, { recursive: true, mode: 0o700 });
await reconcile();
watch(dir, () => {
  void reconcile();
});
