import { existsSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";

const file = process.argv[2] ?? join(process.cwd(), "tmp", "pgbouncer", "allowlist.nft");
const dir = join(file, "..");
const composeFile =
  process.env.ARK_PLATFORM_COMPOSE ?? join(process.cwd(), "infra/platform/docker-compose.yml");
const exposeFile = join(dir, "expose");
const statusFile = join(dir, "allowlist.status");

if (!existsSync(file)) {
  console.error(`Allowlist file not found: ${file}`);
  process.exit(1);
}

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
      else reject(new Error(`${command} exited ${code}: ${output.slice(0, 1000)}`));
    });
  });
}

const expose = existsSync(exposeFile) ? (await Bun.file(exposeFile).text()).trim() === "1" : false;

try {
  await run("nft", ["-f", file]);
  const listed = await run("nft", ["list", "table", "inet", "ark_db_ingress"]);
  if (!listed.includes("ark_db")) throw new Error("nft readback did not show ark_db_ingress");
  if (expose && process.env.ARK_PUBLIC_DB_CONTROL === "1") {
    await run("docker", ["compose", "-f", composeFile, "up", "-d", "database-ingress", "pgbouncer-public"]);
  }
  // An empty allowlist installs an accept-only chain, so the table exists but nothing is
  // enforced. Report that honestly rather than claiming enforcement.
  const enforced = (await Bun.file(file).text()).includes("drop");
  await writeFile(statusFile, `applied=true\nenforced=${enforced}\nexposed=${expose}\nerror=\n`, {
    mode: 0o600,
  });
} catch (error) {
  if (process.env.ARK_PUBLIC_DB_CONTROL === "1") {
    await run("docker", ["compose", "-f", composeFile, "restart", "database-ingress"]).catch(() => undefined);
  }
  await writeFile(
    statusFile,
    `applied=false\nenforced=false\nexposed=false\nerror=${error instanceof Error ? error.message : "failed"}\n`,
    { mode: 0o600 },
  );
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}
