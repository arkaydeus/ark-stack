import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { generateInstallSecrets, mergeInstallEnv } from "@ark-stack/shared";

const root = join(import.meta.dir, "..");

function run(command: string, args: string[]) {
  return new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, stdio: "inherit" });
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} ${args.join(" ")} exited ${code}`));
    });
  });
}

const envPath = join(root, ".env");
const examplePath = join(root, ".env.example");
const hasEnv = existsSync(envPath);
const existing = hasEnv ? await Bun.file(envPath).text() : "";
const template = !hasEnv && existsSync(examplePath) ? await Bun.file(examplePath).text() : "";
const generated = generateInstallSecrets();
await Bun.write(envPath, mergeInstallEnv(hasEnv ? existing : template, generated, { template: !hasEnv }));
await mkdir(join(root, "tmp", "certs"), { recursive: true });
await mkdir(join(root, "tmp", "pgbouncer"), { recursive: true });
await mkdir(join(root, "tmp", "edge"), { recursive: true });
await mkdir(join(root, "tmp", "mail-state"), { recursive: true });

if (process.env.ARK_INSTALL_SKIP_DOCKER !== "1") {
  await run("docker", [
    "compose",
    "-f",
    "infra/platform/docker-compose.yml",
    "up",
    "-d",
    "postgres",
    "app-postgres",
  ]);
  await run("bun", ["run", "--cwd", "server", "db:migrate"]);
}

const parsed = Object.fromEntries(
  (await Bun.file(envPath).text())
    .split("\n")
    .filter((line) => line.includes("=") && !line.startsWith("#"))
    .map((line) => {
      const eq = line.indexOf("=");
      return [line.slice(0, eq), line.slice(eq + 1)];
    }),
);

console.log(`Ark Stack host install ready.
Setup URL: http://127.0.0.1:3000
Setup token: ${parsed.ARK_SETUP_TOKEN}
Use an SSH tunnel if this host is remote. Create the owner, enroll MFA, then run the domain wizard.
Do not reuse this token after bootstrap closes.
`);
