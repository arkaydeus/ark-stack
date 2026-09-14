import { existsSync } from "node:fs";
import { chmod, mkdir } from "node:fs/promises";
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
await mkdir(join(root, "tmp", "acme"), { recursive: true });
await mkdir(join(root, "tmp", "backups"), { recursive: true });
await mkdir(join(root, "tmp", "restore-runs"), { recursive: true });
await mkdir(join(root, "tmp", "pgbouncer"), { recursive: true });
await mkdir(join(root, "tmp", "edge"), { recursive: true });
if (!existsSync(join(root, "tmp", "edge", "Caddyfile"))) {
  await Bun.write(
    join(root, "tmp", "edge", "Caddyfile"),
    await Bun.file(join(root, "infra", "platform", "Caddyfile")).text(),
  );
}
if (!existsSync(join(root, "tmp", "edge", "serve.json"))) {
  await Bun.write(
    join(root, "tmp", "edge", "serve.json"),
    await Bun.file(join(root, "infra", "platform", "serve.json")).text(),
  );
}
await mkdir(join(root, "tmp", "mail-state"), { recursive: true });

const parsed = Object.fromEntries(
  (await Bun.file(envPath).text())
    .split("\n")
    .filter((line) => line.includes("=") && !line.startsWith("#"))
    .map((line) => {
      const eq = line.indexOf("=");
      return [line.slice(0, eq), line.slice(eq + 1)];
    }),
);
await Bun.write(join(root, "tmp", "metrics.token"), `${parsed.ARK_METRICS_TOKEN}\n`);
await chmod(join(root, "tmp", "metrics.token"), 0o600);

if (process.env.ARK_INSTALL_SKIP_DOCKER !== "1") {
  for (const network of ["ark_mail_management", "ark_monitoring"]) {
    await run("docker", ["network", "inspect", "--format", "{{.Name}}", network]).catch(() =>
      run("docker", ["network", "create", network]),
    );
  }
  const compose = ["compose", "-f", "infra/platform/docker-compose.yml"];
  await run("docker", [
    ...compose,
    "build",
    "api",
    "migrate",
    "database-worker",
    "mail-worker",
    "domain-worker",
    "backup-worker",
    "agent",
  ]);
  await run("docker", [...compose, "up", "-d", "postgres", "app-postgres"]);
  await run("docker", [
    "compose",
    "-f",
    "infra/mail/docker-compose.yml",
    "up",
    "-d",
    "--wait",
    "--wait-timeout",
    "120",
  ]);
  await run("docker", [
    ...compose,
    "exec",
    "-T",
    "postgres",
    "sh",
    "/docker-entrypoint-initdb.d/10-runtime.sh",
  ]);
  await run("docker", [...compose, "run", "--rm", "migrate"]);
  await run("docker", [
    ...compose,
    "up",
    "-d",
    "--wait",
    "--wait-timeout",
    "120",
    "api",
    "database-worker",
    "mail-worker",
    "domain-worker",
    "backup-worker",
    "agent",
    "edge",
  ]);
  await run("docker", [
    "compose",
    "-f",
    "infra/monitoring/docker-compose.yml",
    "up",
    "-d",
    "--wait",
    "--wait-timeout",
    "120",
  ]);
}

console.log(`Ark Stack host install ready.
Setup URL: http://127.0.0.1:3000
Setup token: ${parsed.ARK_SETUP_TOKEN}
Use an SSH tunnel if this host is remote. Create the owner, enroll MFA, then run the domain wizard.
Do not reuse this token after bootstrap closes.
`);
