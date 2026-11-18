import { existsSync } from "node:fs";
import { chmod, chown, mkdir, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { applyEdgeSniPorts, generateInstallSecrets, mergeInstallEnv } from "@ark-stack/shared";

import { rejoinNamespaceDependents } from "./edge-namespace.ts";
import { configureEdgeAuthKey } from "./install-edge-auth.ts";
import { chownEdgeL4, composeImages, seedEdgeL4, verifyImageIds } from "./install-edge-l4.ts";
import { seedPgbouncerBootstrap } from "./pgbouncer-bootstrap.ts";

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
// `.env` holds every platform secret and `Bun.write` creates it 0644.
await chmod(envPath, 0o600);
const edgeAuthKey = await configureEdgeAuthKey(envPath);
// Shared SNI ports for tls routes (FD-14): ARK_EDGE_SNI_PORTS from the environment, else from .env.
// Each enabled port is published on edge-ts; the API and domain worker accept tls routes only there.
const sni = applyEdgeSniPorts(await Bun.file(envPath).text(), process.env.ARK_EDGE_SNI_PORTS);
await Bun.write(envPath, sni.env);
await chmod(envPath, 0o600);
console.log(`Shared SNI ports: ${sni.ports.length ? sni.ports.join(", ") : "none (443 only)"}`);
for (const path of [
  "certs",
  "acme",
  "backups",
  "restore-runs",
  "pgbouncer",
  "db-ingress",
  "edge",
  "edge-l4",
  "mail-state",
]) {
  await mkdir(join(root, "tmp", path), { recursive: true });
}
// edge-l4 (HAProxy SNI router on 443) starts from an initial generation that sends every hostname to
// Caddy; the domain worker's edge.l4_apply replaces it (docs/design/front-door.md §3.8.6).
await seedEdgeL4(join(root, "tmp", "edge-l4"));
await mkdir(join(root, "tmp", "certs", "database"), { recursive: true });
const databaseCert = join(root, "tmp", "certs", "database");
if (!existsSync(join(databaseCert, "fullchain.pem")) || !existsSync(join(databaseCert, "privkey.pem"))) {
  await run("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-keyout",
    join(databaseCert, "privkey.pem"),
    "-out",
    join(databaseCert, "fullchain.pem"),
    "-days",
    "3650",
    "-nodes",
    "-subj",
    "/CN=database",
  ]);
  await chmod(join(databaseCert, "privkey.pem"), 0o600);
}
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
const parsed = Object.fromEntries(
  (await Bun.file(envPath).text())
    .split("\n")
    .filter((line) => line.includes("=") && !line.startsWith("#"))
    .map((line) => {
      const eq = line.indexOf("=");
      return [line.slice(0, eq), line.slice(eq + 1)];
    }),
);
// The closed PgBouncer configuration admits nobody; the console administrator's SCRAM verifier
// lets the database worker RELOAD over the shared admin socket once clients exist.
await seedPgbouncerBootstrap(join(root, "tmp", "pgbouncer"), {
  adminPassword: parsed.ARK_PGBOUNCER_ADMIN_PASSWORD,
});
await Bun.write(join(root, "tmp", "pgbouncer", "expose"), "0\n");
await Bun.write(join(root, "tmp", "metrics.token"), `${parsed.ARK_METRICS_TOKEN}\n`);
await chmod(join(root, "tmp", "metrics.token"), 0o600);

// Containers run as uid 1000 with CAP_DAC_OVERRIDE dropped, so a host directory created by
// root (or by any other uid) leaves the workers unable to write to their bind mounts.
const containerUid = Number(process.env.ARK_CONTAINER_UID ?? "1000");
const containerGid = Number(process.env.ARK_CONTAINER_GID ?? "1000");
if (process.platform === "linux" && process.getuid?.() === 0) {
  for (const path of [
    "certs",
    "acme",
    "backups",
    "restore-runs",
    "pgbouncer",
    "db-ingress",
    "edge",
    "mail-state",
  ]) {
    await chownRecursive(join(root, "tmp", path), containerUid, containerGid);
  }
  // Generations are readable by the shared group 4400 (edge-l4, the validator and the watchdog).
  await chownEdgeL4(join(root, "tmp", "edge-l4"), containerUid);
}

if (process.env.ARK_INSTALL_SKIP_DOCKER !== "1") {
  // Numeric IDs, not names: HAProxy must be uid 99 and GID 4400 must be free in the pinned images.
  await verifyImageIds(
    composeImages(
      await Bun.file(join(root, "infra/platform/docker-compose.yml")).text(),
      await Bun.file(join(root, "Dockerfile")).text(),
    ),
  );
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
    "edge-watchdog",
    "haproxy-validator",
    "backup-worker",
    "agent",
    "database-ingress",
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
    "edge-ts",
    "edge-watchdog",
    "haproxy-validator",
    "edge",
    "edge-l4",
    "pgbouncer-public",
    "database-ingress",
  ]);
  // A re-run that restarted edge-ts in place would otherwise leave edge and edge-l4 in its old namespace.
  await rejoinNamespaceDependents({
    project: "ark-platform",
    composeArgs: ["-f", join(root, "infra/platform/docker-compose.yml"), "-p", "ark-platform"],
  });
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
if (edgeAuthKey === "missing") {
  console.log(`TS_EDGE_AUTHKEY is empty. That is expected once the edge node (edge-ts) has joined. If it has
not, the edge still serves but cannot reach tailnet services: create a one-off, pre-approved key for tag:ark-edge, put it in .env as
TS_EDGE_AUTHKEY (or re-run this installer with it in the environment), then run
\`docker compose --env-file .env -f infra/platform/docker-compose.yml up -d edge-ts edge edge-l4\` and \`mise run edge:rejoin\`.
See docs/operating.md, "Edge Tailscale node".
`);
}

async function chownRecursive(path: string, uid: number, gid: number) {
  await chown(path, uid, gid).catch(() => undefined);
  const info = await stat(path).catch(() => null);
  if (!info?.isDirectory()) return;
  for (const entry of await readdir(path)) {
    await chownRecursive(join(path, entry), uid, gid);
  }
}
