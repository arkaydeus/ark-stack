// Throwaway PostgreSQL for the DB-backed tests (`mise run test:db`).
//
//   bun --no-env-file scripts/test-db.ts [bun test args…]  start, migrate, run tests (default: `server`), remove
//   bun --no-env-file scripts/test-db.ts up                start and migrate, print DATABASE_URL, leave running
//   bun --no-env-file scripts/test-db.ts down <container>  remove a container that `up` started
//
// Each run gets its own uniquely named postgres:17.6 container on a loopback port that Docker
// picks, with its data on tmpfs (no volume). Two runs never share a name, port or data. Only
// containers carrying this script's label are ever removed, and the shared `ark-platform`
// Compose project (`mise run db:up`) is never touched.
//
// Migrations and tests use the owner role `ark_migration`, as in production migrations: test
// cleanup deletes `audit_events` rows, which the runtime role may not do.
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { resolve as resolvePath } from "node:path";

import postgres from "postgres";

const IMAGE = "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929";
const LABEL = "ark-stack.test-db";
const OWNER = "ark_migration";
const DATABASE = "ark_platform";
const NAME_PATTERN = /^ark-test-db-[a-f0-9]{12}$/;
const root = resolvePath(import.meta.dir, "..");

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

// Only host settings required to find executables and temporary files reach tests. Docker
// commands retain their host environment (including remote contexts and credential helpers).
const HOST_KEYS = ["PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SystemRoot", "LANG", "LC_ALL", "TZ"];
function testEnvironment(): NodeJS.ProcessEnv {
  return Object.fromEntries(
    HOST_KEYS.flatMap((key) => (process.env[key] === undefined ? [] : [[key, process.env[key]]])),
  );
}

let owned: string | null = null;
let starting: Promise<unknown> | null = null;
let cleanupPromise: Promise<void> | undefined;
let interruption = 0;
const children = new Set<ChildProcess>();

function checkInterrupted() {
  if (interruption) throw new Error("Interrupted.");
}

function run(command: string, args: string[], options: { env?: NodeJS.ProcessEnv; quiet?: boolean } = {}) {
  if (options.env) checkInterrupted();
  return new Promise<{ code: number; output: string }>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: root,
      env: options.env ?? process.env,
      stdio: options.quiet ? ["ignore", "pipe", "pipe"] : "inherit",
    });
    if (options.env) children.add(child);
    let output = "";
    child.stdout?.on("data", (chunk) => (output += String(chunk)));
    child.stderr?.on("data", (chunk) => (output += String(chunk)));
    child.once("error", reject);
    child.once("close", (code, signal) => {
      children.delete(child);
      resolve({ code: code ?? (signal ? 128 : 1), output });
    });
  });
}

async function docker(args: string[]) {
  const result = await run("docker", args, { quiet: true });
  if (result.code !== 0) throw new Error(`docker ${args[0]} failed: ${result.output.trim()}`);
  return result.output.trim();
}

/** Removes a container this script labelled; returns false only for confirmed absence. */
async function remove(name: string) {
  if (!NAME_PATTERN.test(name)) throw new Error(`Refusing to remove ${name}: not a test-db container name.`);
  for (let attempt = 0; ; attempt++) {
    const label = await run("docker", ["inspect", "--format", `{{index .Config.Labels "${LABEL}"}}`, name], {
      quiet: true,
    });
    if (label.code === 0 && label.output.trim() !== "1")
      throw new Error(`Refusing to remove ${name}: it lacks the ${LABEL} label.`);
    if (label.code !== 0 && /No such (?:object|container):/i.test(label.output)) return false;
    const removed =
      label.code === 0 ? await run("docker", ["rm", "--force", "--volumes", name], { quiet: true }) : label;
    if (removed.code === 0) return true;
    if (attempt === 2) throw new Error(`Unable to remove ${name}: ${removed.output.trim()}`);
    await Bun.sleep(250);
  }
}

function cleanup() {
  cleanupPromise ??= (async () => {
    // Wait for creation to settle before inspecting. launch checks interruption before every
    // next phase, and the same promise is shared with finally and all signal handlers.
    await starting?.catch(() => undefined);
    if (!owned) return;
    const name = owned;
    let removed = await remove(name);
    // A group signal can kill the Docker CLI after it submitted creation to the daemon.
    // Confirm absence again briefly, in case that creation completes after the CLI exits.
    for (let attempt = 0; !removed && attempt < 5; attempt++) {
      if (!interruption) break;
      await Bun.sleep(500);
      removed = await remove(name);
    }
    owned = null;
    console.error(removed ? `test-db: removed ${name}` : `test-db: ${name} is already absent`);
  })();
  return cleanupPromise;
}

async function interrupted(code: number) {
  if (interruption) return;
  interruption = code;
  // Stop migration/test children before deleting their database. Escalate if a child ignores
  // SIGTERM; waiting for close ensures the child has actually exited before cleanup.
  const stopped = [...children].map(
    (child) =>
      new Promise<void>((resolve) => {
        child.once("close", () => {
          clearTimeout(timer);
          resolve();
        });
        const timer = setTimeout(() => child.kill("SIGKILL"), 2000);
        child.kill("SIGTERM");
      }),
  );
  await Promise.all(stopped);
  try {
    await cleanup();
  } catch (error) {
    console.error(`test-db: cleanup failed: ${String(error)}`);
  }
  process.exit(code);
}

for (const [signal, code] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
  ["SIGHUP", 129],
] as const) {
  process.on(signal, () => void interrupted(code));
}

async function start() {
  const name = `ark-test-db-${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
  owned = name;
  starting = launch(name);
  return (await starting) as Awaited<ReturnType<typeof launch>>;
}

async function launch(name: string) {
  const password = crypto.randomUUID().replaceAll("-", "");
  checkInterrupted();
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
  checkInterrupted();
  const mapping = await docker(["port", name, "5432/tcp"]);
  const port = Number(/:(\d+)\s*$/m.exec(mapping)?.[1]);
  if (!Number.isInteger(port) || port <= 0) throw new Error(`Unexpected port mapping: ${mapping}`);
  const url = `postgres://${OWNER}:${password}@127.0.0.1:${port}/${DATABASE}`;
  // The image's init phase listens only on its Unix socket, so a TCP query succeeds only once the
  // final server is up.
  const deadline = Date.now() + 60_000;
  for (;;) {
    checkInterrupted();
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
    ...testEnvironment(),
    ...TEST_ENV,
    DATABASE_URL: url,
    // Database-client tests create roles in a cluster; the container's owner can do that.
    DATABASE_APP_URL: `postgres://${OWNER}:${password}@127.0.0.1:${port}/postgres`,
  };
  checkInterrupted();
  const migrated = await run(process.execPath, ["--no-env-file", "server/src/migrate.ts"], {
    env,
    quiet: true,
  });
  if (migrated.code !== 0) throw new Error(`Migrations failed:\n${migrated.output}`);
  checkInterrupted();
  return { name, env };
}

const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
let exitCode = 0;
try {
  const [command, ...rest] = process.argv.slice(2);
  if (command === "down") {
    if (rest.length !== 1) throw new Error("Usage: bun --no-env-file scripts/test-db.ts down <container>");
    if (!(await remove(rest[0]!))) throw new Error(`No such test-db container: ${rest[0]}`);
    console.log(`Removed ${rest[0]}.`);
  } else {
    const { name, env } = await start();
    checkInterrupted();
    if (command === "up") {
      const exports = ["DATABASE_URL", "DATABASE_APP_URL", ...Object.keys(TEST_ENV)];
      console.log(`# Started and migrated ${name}. Load it into your shell with:`);
      console.log(`#   eval "$(mise run test:db:up)"`);
      for (const key of exports) console.log(`export ${key}=${shellQuote(env[key]!)}`);
      // env -i protects follow-up tests from provider settings already present in the caller's
      // shell, while leaving that shell's environment intact. Quote every value for eval.
      const assignments = Object.entries(env).map(([key, value]) => shellQuote(`${key}=${value}`));
      console.log(
        `ark_test_db() { (cd ${shellQuote(root)} && env -i ${assignments.join(" ")} ${shellQuote(process.execPath)} --no-env-file test "$@"); }`,
      );
      console.log(`# Run one file:  ark_test_db server/src/coordinator.test.ts`);
      console.log(`# Remove it:     mise run test:db:down ${name}`);
      owned = null; // Output is complete; deliberately hand ownership to the caller.
    } else {
      const args = command === undefined ? ["server"] : [command, ...rest];
      console.error(`test-db: ${name} migrated; running bun test ${args.join(" ")}`);
      exitCode = (await run(process.execPath, ["--no-env-file", "test", ...args], { env })).code;
    }
  }
} catch (error) {
  if (!interruption) console.error(`test-db: ${String(error)}`);
  exitCode = 1;
} finally {
  try {
    await cleanup();
  } catch (error) {
    console.error(`test-db: cleanup failed: ${String(error)}`);
    exitCode ||= 1;
  }
}
process.exit(interruption || exitCode);
