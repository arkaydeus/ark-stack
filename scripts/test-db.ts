// Throwaway PostgreSQL for the DB-backed tests (`mise run test:db`).
//
//   bun scripts/test-db.ts [bun test args…]  start, migrate, run tests (default: `server`), remove
//   bun scripts/test-db.ts up                start and migrate, print DATABASE_URL, leave running
//   bun scripts/test-db.ts down <container>  remove a container that `up` started
//
// Each run gets its own uniquely named postgres:17.6 container on a loopback port that Docker
// picks, with its data on tmpfs (no volume). Two runs never share a name, port or data. Only
// containers carrying this script's label are ever removed, and the shared `ark-platform`
// Compose project (`mise run db:up`) is never touched.
//
// Migrations and tests use the owner role `ark_migration`, as in production migrations: test
// cleanup deletes `audit_events` rows, which the runtime role may not do.
import { spawn } from "node:child_process";

import postgres from "postgres";

const IMAGE = "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929";
const LABEL = "ark-stack.test-db";
const OWNER = "ark_migration";
const DATABASE = "ark_platform";
const NAME_PATTERN = /^ark-test-db-[a-f0-9]{12}$/;
const root = new URL("..", import.meta.url).pathname;

// Fixed, test-only secrets (the same shape as the CI job's environment). A developer's `.env`
// is deliberately not read: tests must never see real installation secrets.
const TEST_ENV: Record<string, string> = {
  BETTER_AUTH_SECRET: "test-db-better-auth-secret-0123456789abcdef",
  BETTER_AUTH_URL: "http://127.0.0.1:3000",
  BETTER_AUTH_TRUSTED_ORIGINS: "http://127.0.0.1:3000",
  ARK_ROOT_KEY: "test-db-root-key-0123456789abcdef0123456789abcdef",
  ARK_SETUP_TOKEN: "test-db-setup-token-0123456789",
  ARK_INTERNAL_TOKEN: "test-db-internal-token-0123456789",
  ARK_DATABASE_WORKER_TOKEN: "test-db-database-worker-token-0123456789",
  ARK_DOMAIN_WORKER_TOKEN: "test-db-domain-worker-token-0123456789",
  ARK_MAIL_WORKER_TOKEN: "test-db-mail-worker-token-0123456789",
  ARK_BACKUP_WORKER_TOKEN: "test-db-backup-worker-token-0123456789",
  ARK_AGENT_TOKEN: "test-db-agent-token-0123456789",
  ARK_MAINTENANCE_TOKEN: "test-db-maintenance-token-0123456789",
  ARK_MFA_RECOVERY_TOKEN: "test-db-mfa-recovery-token-0123456789",
  ARK_METRICS_TOKEN: "test-db-metrics-token-0123456789",
  ARK_OFFHOST_HEARTBEAT_TOKEN: "test-db-offhost-heartbeat-token-0123456789",
  ARK_CONTROL_DB_PASSWORD: "test-db-control-db-password-0123456789",
  ARK_APP_DB_PASSWORD: "test-db-app-db-password-0123456789",
  ARK_API_DB_PASSWORD: "test-db-api-db-password-0123456789",
  ARK_PGBOUNCER_ADMIN_PASSWORD: "test-db-pgbouncer-admin-password-0123456789",
};

function run(command: string, args: string[], options: { env?: NodeJS.ProcessEnv; quiet?: boolean } = {}) {
  return new Promise<{ code: number; output: string }>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: root,
      env: options.env ?? process.env,
      stdio: options.quiet ? ["ignore", "pipe", "pipe"] : "inherit",
    });
    let output = "";
    child.stdout?.on("data", (chunk) => (output += String(chunk)));
    child.stderr?.on("data", (chunk) => (output += String(chunk)));
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code: code ?? (signal ? 128 : 1), output }));
  });
}

async function docker(args: string[]) {
  const result = await run("docker", args, { quiet: true });
  if (result.code !== 0) throw new Error(`docker ${args.join(" ")} failed: ${result.output.trim()}`);
  return result.output.trim();
}

async function remove(name: string) {
  if (!NAME_PATTERN.test(name)) throw new Error(`Refusing to remove ${name}: not a test-db container name.`);
  const label = await run("docker", ["inspect", "--format", `{{index .Config.Labels "${LABEL}"}}`, name], {
    quiet: true,
  });
  if (label.code !== 0) return; // Already gone.
  if (label.output.trim() !== "1")
    throw new Error(`Refusing to remove ${name}: it lacks the ${LABEL} label.`);
  // -v also removes any anonymous volume; data lives on tmpfs, so normally there is none.
  await docker(["rm", "--force", "--volumes", name]);
}

async function start() {
  const name = `ark-test-db-${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
  const password = crypto.randomUUID().replaceAll("-", "");
  await docker([
    "run",
    "--detach",
    "--name",
    name,
    "--label",
    `${LABEL}=1`,
    "--env",
    `POSTGRES_USER=${OWNER}`,
    "--env",
    `POSTGRES_PASSWORD=${password}`,
    "--env",
    `POSTGRES_DB=${DATABASE}`,
    // Data on tmpfs at the image's VOLUME path, so Docker creates no volume to leak.
    "--tmpfs",
    "/var/lib/postgresql/data:rw,size=1g",
    // Port 0 on loopback: Docker picks a free port, so concurrent runs cannot collide.
    "--publish",
    "127.0.0.1::5432",
    IMAGE,
  ]);
  try {
    const mapping = await docker(["port", name, "5432/tcp"]);
    const port = Number(/:(\d+)\s*$/m.exec(mapping)?.[1]);
    if (!Number.isInteger(port) || port <= 0) throw new Error(`Unexpected port mapping: ${mapping}`);
    const url = `postgres://${OWNER}:${password}@127.0.0.1:${port}/${DATABASE}`;
    // The image's init phase listens only on its Unix socket, so a TCP query succeeds only once the
    // final server is up.
    const deadline = Date.now() + 60_000;
    for (;;) {
      const probe = postgres(url, { max: 1, connect_timeout: 2, onnotice: () => undefined });
      const ready = await probe`SELECT 1`.then(
        () => true,
        () => false,
      );
      await probe.end({ timeout: 1 });
      if (ready) break;
      if (Date.now() > deadline) throw new Error(`${name} did not accept connections within 60 s.`);
      await Bun.sleep(250);
    }
    const env: Record<string, string | undefined> = {
      ...process.env,
      ...TEST_ENV,
      DATABASE_URL: url,
      // Database-client tests create roles in a cluster; the container's owner can do that.
      DATABASE_APP_URL: `postgres://${OWNER}:${password}@127.0.0.1:${port}/postgres`,
    };
    const migrated = await run(process.execPath, ["--no-env-file", "server/src/migrate.ts"], {
      env,
      quiet: true,
    });
    if (migrated.code !== 0) throw new Error(`Migrations failed:\n${migrated.output}`);
    return { name, env };
  } catch (error) {
    await remove(name).catch(() => undefined);
    throw error;
  }
}

const [command, ...rest] = process.argv.slice(2);

if (command === "down") {
  if (rest.length !== 1) throw new Error("Usage: bun scripts/test-db.ts down <container>");
  await remove(rest[0]!);
  console.log(`Removed ${rest[0]}.`);
} else if (command === "up") {
  const { name, env } = await start();
  const exports = ["DATABASE_URL", "DATABASE_APP_URL", ...Object.keys(TEST_ENV)];
  console.log(`# Started and migrated ${name}. Load it into your shell with:`);
  console.log(`#   eval "$(mise run test:db:up)"`);
  for (const key of exports) console.log(`export ${key}='${env[key]}'`);
  console.log(`# Run one file:  bun --no-env-file test server/src/coordinator.test.ts`);
  console.log(`# Remove it:     mise run test:db:down ${name}`);
} else {
  const args = command === undefined ? ["server"] : [command, ...rest];
  const { name, env } = await start();
  console.error(`test-db: ${name} migrated; running bun test ${args.join(" ")}`);
  let exitCode = 1;
  const cleanup = async () => {
    await remove(name).catch((error: unknown) => console.error(`test-db: cleanup failed: ${String(error)}`));
  };
  for (const [signal, code] of [
    ["SIGINT", 130],
    ["SIGTERM", 143],
    ["SIGHUP", 129],
  ] as const) {
    process.on(signal, () => void cleanup().finally(() => process.exit(code)));
  }
  try {
    exitCode = (await run(process.execPath, ["--no-env-file", "test", ...args], { env })).code;
  } finally {
    await cleanup();
    console.error(`test-db: removed ${name}`);
  }
  process.exit(exitCode);
}
