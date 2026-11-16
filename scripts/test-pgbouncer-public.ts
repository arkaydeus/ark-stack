// Starts the real `app-postgres` and `pgbouncer-public` Compose services in a disposable
// project, feeds PgBouncer a config produced by Ark's generator, and connects over TLS with
// SCRAM as a runtime role. The Compose file's relative bind mounts (`../../tmp/...`) are
// redirected into a temporary directory with `--project-directory`, so the repository's own
// `tmp/` state is never touched.
import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { pgbouncerConfig, pgbouncerUserlist } from "@ark-stack/shared";

const root = resolve(import.meta.dir, "..");
const composeFile = join(root, "infra", "platform", "docker-compose.yml");
const template = join(root, "infra", "database", "pgbouncer.ini");
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const project = `ark-pgbouncer-smoke-${suffix}`;
const work = await mkdtemp(join(tmpdir(), `ark-pgbouncer-${suffix}-`));
// `../../tmp/pgbouncer` in the Compose file resolves against this directory.
const projectDir = join(work, "infra", "platform");
const pgbouncerDir = join(work, "tmp", "pgbouncer");
const certDir = join(work, "tmp", "certs", "database");
const caFile = join(work, "client-ca.pem");
// Ark's containers and the installer's chown use uid/gid 1000 (scripts/install.ts).
const arkUid = "1000:1000";
const database = "ark_smoke";
const runtimeRole = "ark_smoke_runtime";
const ownerRole = "ark_smoke_owner";
const secret = () => randomBytes(18).toString("base64url");
const runtimePassword = secret();
const ownerPassword = secret();
const adminPassword = secret();

const env: Record<string, string> = { ...(process.env as Record<string, string>) };
// The Compose file interpolates every service, so each installer-generated value needs a
// placeholder even though only two services start.
for (const name of [
  "ARK_AGENT_TOKEN",
  "ARK_API_DB_PASSWORD",
  "ARK_BACKUP_WORKER_TOKEN",
  "ARK_CONTROL_DB_PASSWORD",
  "ARK_DATABASE_WORKER_TOKEN",
  "ARK_DOMAIN_WORKER_TOKEN",
  "ARK_INTERNAL_TOKEN",
  "ARK_MAIL_WORKER_TOKEN",
  "ARK_MAINTENANCE_TOKEN",
  "ARK_METRICS_TOKEN",
  "ARK_MFA_RECOVERY_TOKEN",
  "ARK_OFFHOST_HEARTBEAT_TOKEN",
  "ARK_ROOT_KEY",
  "ARK_SETUP_TOKEN",
  "BETTER_AUTH_SECRET",
  "BETTER_AUTH_TRUSTED_ORIGINS",
  "BETTER_AUTH_URL",
  "STALWART_ADMIN_PASSWORD",
]) {
  env[name] = `smoke-${secret()}`;
}
env.ARK_APP_DB_PASSWORD = adminPassword;
delete env.COMPOSE_FILE;
delete env.COMPOSE_PROJECT_NAME;

let pgbouncerImage = "";
let clientImage = "";
const compose = ["docker", "compose", "-f", composeFile, "--project-directory", projectDir, "-p", project];

async function run(command: string[], options: { allowFailure?: boolean } = {}) {
  const child = Bun.spawn(command, { env, stdout: "pipe", stderr: "pipe" });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0 && !options.allowFailure) {
    throw new Error(`${command.slice(0, 4).join(" ")} … failed (${status}):\n${stderr || stdout}`);
  }
  return { status, stdout: stdout.trim(), stderr: stderr.trim() };
}

function log(line: string) {
  console.log(line);
}

async function service(name: string) {
  const { stdout } = await run([...compose, "ps", "-q", name]);
  if (!stdout) throw new Error(`${name} has no container`);
  return stdout.split("\n")[0]!;
}

async function inspect(container: string, format: string) {
  return (await run(["docker", "inspect", "--format", format, container])).stdout;
}

function settings(text: string) {
  return new Map(
    text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith(";") && !line.startsWith("#") && !line.startsWith("["))
      .map((line) => {
        const eq = line.indexOf("=");
        return [line.slice(0, eq).trim(), line.slice(eq + 1).trim()] as const;
      }),
  );
}

// Every setting in the checked-in template must survive into the generated config, so the
// smoke test exercises the same listener, auth, TLS and pooling settings production uses.
function assertTemplateCoverage(generated: string, source: string) {
  const expected = settings(source);
  const actual = settings(generated);
  for (const [key, value] of expected) {
    if (actual.get(key) !== value) {
      throw new Error(`Generated pgbouncer.ini drifts from the template: ${key} = ${actual.get(key)}`);
    }
  }
}

async function psql(
  network: string,
  role: string,
  password: string,
  sslmode: string,
  sql: string,
  allowFailure = false,
) {
  return run(
    [
      "docker",
      "run",
      "--rm",
      "--network",
      network,
      "--volume",
      `${caFile}:/smoke/ca.pem:ro`,
      "--env",
      `PGPASSWORD=${password}`,
      "--env",
      "PGCONNECT_TIMEOUT=10",
      clientImage,
      "psql",
      `host=pgbouncer-public port=5432 dbname=${database} user=${role} sslmode=${sslmode} sslrootcert=/smoke/ca.pem`,
      "--no-psqlrc",
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      sql,
    ],
    { allowFailure },
  );
}

try {
  await mkdir(projectDir, { recursive: true });
  await mkdir(pgbouncerDir, { recursive: true });
  await mkdir(certDir, { recursive: true });

  // Self-signed server certificate whose SAN matches the Compose service name, so the client
  // can use sslmode=verify-full.
  await run([
    "openssl",
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-sha256",
    "-nodes",
    "-days",
    "2",
    "-subj",
    "/CN=pgbouncer-public",
    "-addext",
    "subjectAltName=DNS:pgbouncer-public,DNS:localhost,IP:127.0.0.1",
    "-keyout",
    join(certDir, "privkey.pem"),
    "-out",
    join(certDir, "fullchain.pem"),
  ]);
  await Bun.write(caFile, await Bun.file(join(certDir, "fullchain.pem")).text());

  const config = pgbouncerConfig({ mappings: [{ database, host: "app-postgres" }] });
  assertTemplateCoverage(config, await Bun.file(template).text());
  const userlist = pgbouncerUserlist([
    { name: runtimeRole, password: runtimePassword },
    { name: ownerRole, password: ownerPassword },
  ]);
  if (userlist.includes(ownerRole)) throw new Error("Userlist admitted a privileged _owner role.");
  await Bun.write(join(pgbouncerDir, "pgbouncer.ini"), config);
  await Bun.write(join(pgbouncerDir, "userlist.txt"), userlist);
  for (const file of [
    join(pgbouncerDir, "pgbouncer.ini"),
    join(pgbouncerDir, "userlist.txt"),
    join(certDir, "privkey.pem"),
  ]) {
    await chmod(file, 0o600);
  }

  const resolved = JSON.parse((await run([...compose, "config", "--format", "json"])).stdout) as {
    services: Record<string, { image: string }>;
  };
  const appImage = resolved.services["app-postgres"]!.image;
  pgbouncerImage = resolved.services["pgbouncer-public"]!.image;
  // psql from the app-postgres image acts as the client.
  clientImage = appImage;
  log(`pgbouncer-public image: ${pgbouncerImage}`);
  // Match production ownership: the installer chowns these trees to uid 1000 and Ark writes
  // the files with mode 0600. PgBouncer runs with every capability dropped, so this proves
  // the service user can read them without CAP_DAC_OVERRIDE.
  await run([
    "docker",
    "run",
    "--rm",
    "--user",
    "0:0",
    "--entrypoint",
    "chown",
    "--volume",
    `${join(work, "tmp")}:/smoke`,
    pgbouncerImage,
    "-R",
    arkUid,
    "/smoke",
  ]);

  log("Starting app-postgres…");
  await run([...compose, "up", "--detach", "--wait", "--wait-timeout", "120", "app-postgres"]);
  const appContainer = await service("app-postgres");
  await run([
    "docker",
    "exec",
    appContainer,
    "psql",
    "--username",
    "ark_cluster_admin",
    "--dbname",
    "postgres",
    "--set",
    "ON_ERROR_STOP=1",
    "--command",
    `CREATE ROLE ${runtimeRole} LOGIN PASSWORD '${runtimePassword}'`,
    "--command",
    `CREATE ROLE ${ownerRole} LOGIN PASSWORD '${ownerPassword}'`,
    "--command",
    `CREATE DATABASE ${database} OWNER ${ownerRole}`,
    "--command",
    `REVOKE ALL ON DATABASE ${database} FROM PUBLIC`,
    "--command",
    `GRANT CONNECT ON DATABASE ${database} TO ${runtimeRole}`,
  ]);
  const verifier = await run([
    "docker",
    "exec",
    appContainer,
    "psql",
    "--username",
    "ark_cluster_admin",
    "--dbname",
    "postgres",
    "--tuples-only",
    "--no-align",
    "--command",
    `SELECT left(rolpassword, 14) FROM pg_authid WHERE rolname = '${runtimeRole}'`,
  ]);
  if (verifier.stdout !== "SCRAM-SHA-256$") throw new Error(`Runtime role is not SCRAM: ${verifier.stdout}`);
  log(`app-postgres (${appImage}) ready; ${runtimeRole} stores a SCRAM-SHA-256 verifier.`);

  log("Starting pgbouncer-public…");
  await run([...compose, "up", "--detach", "--wait", "--wait-timeout", "120", "pgbouncer-public"]);
  const bouncer = await service("pgbouncer-public");
  log(
    `pgbouncer-public: ${await inspect(bouncer, "status={{.State.Status}} health={{.State.Health.Status}} user={{.Config.User}} entrypoint={{json .Config.Entrypoint}} cmd={{json .Config.Cmd}} capdrop={{json .HostConfig.CapDrop}} secopt={{json .HostConfig.SecurityOpt}}")}`,
  );
  const startup = await run(["docker", "logs", bouncer]);
  const banner = `${startup.stdout}\n${startup.stderr}`
    .split("\n")
    .find((line) => line.includes("process up"));
  if (!banner?.includes("PgBouncer 1.26.1")) throw new Error(`Unexpected PgBouncer banner: ${banner}`);
  log(`log: ${banner.trim()}`);

  const network = `${project}_database-management`;
  const connected = await psql(
    network,
    runtimeRole,
    runtimePassword,
    "verify-full",
    "SELECT current_user, current_database(), split_part(version(), ' ', 2) AS server_version",
  );
  log(`runtime role over TLS (verify-full) + SCRAM:\n${connected.stdout}`);
  const tls = await psql(network, runtimeRole, runtimePassword, "verify-full", "\\conninfo");
  if (!/SSL connection \(protocol: TLSv1\.[23]/.test(tls.stdout)) {
    throw new Error(`Client connection was not TLS: ${tls.stdout}`);
  }
  log(tls.stdout);

  const plaintext = await psql(network, runtimeRole, runtimePassword, "disable", "SELECT 1", true);
  if (plaintext.status === 0) throw new Error("PgBouncer accepted a plaintext client.");
  log(`plaintext client rejected: ${plaintext.stderr.split("\n").at(-1)}`);
  const wrong = await psql(network, runtimeRole, `${runtimePassword}x`, "verify-full", "SELECT 1", true);
  if (wrong.status === 0) throw new Error("PgBouncer accepted a wrong password.");
  log(`wrong password rejected: ${wrong.stderr.split("\n").at(-1)}`);
  const owner = await psql(network, ownerRole, ownerPassword, "verify-full", "SELECT 1", true);
  if (owner.status === 0) throw new Error("PgBouncer admitted an _owner role.");
  log(`_owner role rejected: ${owner.stderr.split("\n").at(-1)}`);

  const health = await inspect(bouncer, "{{.State.Health.Status}} restarts={{.RestartCount}}");
  if (!health.startsWith("healthy restarts=0")) throw new Error(`pgbouncer-public degraded: ${health}`);
  log(`pgbouncer-public after checks: ${health}`);

  // The Compose file binds 127.0.0.1:15432 for database-ingress. Report whether Docker
  // actually published it; a container attached only to an `internal: true` network gets no
  // published ports.
  const published = await run(["docker", "port", bouncer, "5432/tcp"], { allowFailure: true });
  log(
    published.status === 0 && published.stdout
      ? `loopback publish: ${published.stdout}`
      : "loopback publish: NOT bound (pgbouncer-public is only on the internal database-management network)",
  );
  log("pgbouncer-public smoke test passed.");
} catch (error) {
  const bouncer = await run([...compose, "logs", "--no-color", "pgbouncer-public"], {
    allowFailure: true,
  });
  console.error(bouncer.stdout || bouncer.stderr);
  throw error;
} finally {
  await run([...compose, "down", "--volumes", "--remove-orphans", "--timeout", "5"], {
    allowFailure: true,
  });
  // Files are owned by uid 1000 now; hand them back so the runner can delete them.
  if (pgbouncerImage) {
    const owner = `${process.getuid?.() ?? 0}:${process.getgid?.() ?? 0}`;
    await run(
      [
        "docker",
        "run",
        "--rm",
        "--user",
        "0:0",
        "--entrypoint",
        "chown",
        "--volume",
        `${join(work, "tmp")}:/smoke`,
        pgbouncerImage,
        "-R",
        owner,
        "/smoke",
      ],
      { allowFailure: true },
    );
  }
  await rm(work, { recursive: true, force: true });
}
