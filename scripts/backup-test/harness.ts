// Shared harness for the FD-21 backup suites (scripts/test-backups.ts, scripts/test-backups-hosted.ts).
//
// - A throwaway control database (postgres:17.6, owner role ark_migration) with every migration.
// - The actual `postgres` and `app-postgres` Compose services from infra/platform/docker-compose.yml,
//   built from the Dockerfile stages, in a unique Compose project. A test-only override publishes the
//   executors and PostgreSQL on loopback ephemeral ports and shortens archive_timeout.
// Teardown removes only this project's containers, volumes and networks and the images it tagged.
import { randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { PG_CLUSTERS, type PgCluster } from "@ark-stack/shared";

import { freePort, run } from "./minio.ts";

export const POSTGRES_IMAGE =
  "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929";
export const root = resolve(import.meta.dir, "..", "..");
const composeFile = join(root, "infra", "platform", "docker-compose.yml");

const secret = () => randomBytes(24).toString("base64url");

export type ControlDb = { url: string; container: string; stop: () => Promise<void> };

/** A throwaway control database with every migration applied (owner role ark_migration). */
export async function startControlDb(label: string): Promise<ControlDb> {
  const port = await freePort();
  const password = secret();
  const container = `ark-fd21-control-${label}-${randomBytes(3).toString("hex")}`;
  await run([
    "docker",
    "run",
    "--detach",
    "--name",
    container,
    "--label",
    "ark.test=fd21-backups",
    "--publish",
    `127.0.0.1:${port}:5432`,
    "--env",
    "POSTGRES_USER=ark_migration",
    "--env",
    `POSTGRES_PASSWORD=${password}`,
    "--env",
    "POSTGRES_DB=ark_platform",
    "--tmpfs",
    "/var/lib/postgresql/data:rw,size=512m",
    POSTGRES_IMAGE,
  ]);
  const url = `postgres://ark_migration:${password}@127.0.0.1:${port}/ark_platform`;
  const deadline = Date.now() + 60_000;
  while (
    (
      await run(
        [
          "docker",
          "exec",
          container,
          "pg_isready",
          "-U",
          "ark_migration",
          "-d",
          "ark_platform",
          "-h",
          "127.0.0.1",
        ],
        { allowFailure: true },
      )
    ).status !== 0
  ) {
    if (Date.now() > deadline) throw new Error("Control database did not start.");
    await Bun.sleep(500);
  }
  await Bun.sleep(1000);
  await run(["bun", "run", "--cwd", join(root, "server"), "db:migrate"], { env: { DATABASE_URL: url } });
  return {
    url,
    container,
    stop: async () =>
      void (await run(["docker", "rm", "--force", "--volumes", container], { allowFailure: true })),
  };
}

export type Clusters = {
  project: string;
  version: string;
  executorUrls: Record<PgCluster, string>;
  tokens: Record<PgCluster, string>;
  cipherPasses: Record<PgCluster, string>;
  stageVolumes: Record<PgCluster, string>;
  images: Record<PgCluster, string>;
  container: (cluster: PgCluster) => Promise<string>;
  psql: (cluster: PgCluster, sql: string) => Promise<string>;
  /** Environment for the in-process backup worker code. */
  workerEnv: () => Record<string, string>;
  /** `docker compose down --volumes`: removes PGDATA, repo2 and staged copies (all VPS-local copies). */
  destroy: () => Promise<void>;
  /** Removes the project and the images it tagged. */
  teardown: () => Promise<void>;
};

const SUPERUSER: Record<PgCluster, [string, string]> = {
  platform: ["ark_migration", "ark_platform"],
  app: ["ark_cluster_admin", "postgres"],
};

export async function startClusters(label: string): Promise<Clusters> {
  const suffix = `${label}-${randomBytes(3).toString("hex")}`;
  const project = `ark-fd21-${suffix}`;
  const version = `fd21-test-${suffix}`;
  const work = await mkdtemp(join(tmpdir(), `ark-fd21-${suffix}-`));
  const override = join(work, "override.yml");
  await writeFile(
    override,
    `# FD-21 test override: loopback ports for the executors and PostgreSQL, a 10 s archive_timeout.
services:
  postgres:
    ports: ["127.0.0.1::8432", "127.0.0.1::5432"]
    environment: { ARK_PG_ARCHIVE_TIMEOUT: "10" }
    networks: [control, backup-management, fd21-loopback]
  app-postgres:
    ports: ["127.0.0.1::8432", "127.0.0.1::5432"]
    environment: { ARK_PG_ARCHIVE_TIMEOUT: "10" }
    networks: [database-management, backup-management, fd21-loopback]
networks:
  fd21-loopback: {}
`,
  );
  const tokens = { platform: secret(), app: secret() };
  const cipherPasses = { platform: secret(), app: secret() };
  const env: Record<string, string> = { ...(process.env as Record<string, string>) };
  for (const name of [
    "ARK_AGENT_TOKEN",
    "ARK_API_DB_PASSWORD",
    "ARK_APP_DB_PASSWORD",
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
    "ARK_PGBOUNCER_ADMIN_PASSWORD",
    "ARK_ROOT_KEY",
    "ARK_SETUP_TOKEN",
    "BETTER_AUTH_SECRET",
    "BETTER_AUTH_TRUSTED_ORIGINS",
    "BETTER_AUTH_URL",
    "STALWART_ADMIN_PASSWORD",
  ]) {
    env[name] = `fd21-${secret()}`;
  }
  env.ARK_VERSION = version;
  env.ARK_PLATFORM_PG_EXECUTOR_TOKEN = tokens.platform;
  env.ARK_APP_PG_EXECUTOR_TOKEN = tokens.app;
  env.ARK_PLATFORM_PG_REPO_CIPHER_PASS = cipherPasses.platform;
  env.ARK_APP_PG_REPO_CIPHER_PASS = cipherPasses.app;
  delete env.COMPOSE_FILE;
  delete env.COMPOSE_PROJECT_NAME;
  const compose = ["docker", "compose", "-f", composeFile, "-f", override, "-p", project];
  const images = { platform: `ark-postgres:${version}`, app: `ark-app-postgres:${version}` };

  const teardown = async () => {
    await run([...compose, "down", "--volumes", "--remove-orphans", "--timeout", "5"], {
      env,
      allowFailure: true,
    });
    await run(["docker", "image", "rm", images.platform, images.app], { allowFailure: true });
    await rm(work, { recursive: true, force: true });
  };
  try {
    await run(
      [
        ...compose,
        "up",
        "--build",
        "--detach",
        "--wait",
        "--wait-timeout",
        "300",
        "postgres",
        "app-postgres",
      ],
      { env },
    );
  } catch (error) {
    await teardown();
    throw error;
  }
  const container = async (cluster: PgCluster) => {
    const { stdout } = await run([...compose, "ps", "-q", PG_CLUSTERS[cluster].service], { env });
    if (!stdout) throw new Error(`${PG_CLUSTERS[cluster].service} has no container`);
    return stdout.split("\n")[0]!;
  };
  const executorUrls = {} as Record<PgCluster, string>;
  for (const cluster of ["platform", "app"] as const) {
    const { stdout } = await run([...compose, "port", PG_CLUSTERS[cluster].service, "8432"], { env });
    executorUrls[cluster] = `http://${stdout.split("\n")[0]!.replace("0.0.0.0", "127.0.0.1")}`;
  }
  // Wait until both executors answer and their stanzas exist.
  for (const cluster of ["platform", "app"] as const) {
    const deadline = Date.now() + 120_000;
    while (true) {
      const response = await fetch(`${executorUrls[cluster]}/v1/check`, {
        method: "POST",
        headers: { authorization: `Bearer ${tokens[cluster]}` },
      }).catch(() => null);
      if (response?.ok) break;
      if (Date.now() > deadline) {
        throw new Error(`${cluster} executor not ready: ${response ? await response.text() : "unreachable"}`);
      }
      await Bun.sleep(1000);
    }
  }
  return {
    project,
    version,
    executorUrls,
    tokens,
    cipherPasses,
    stageVolumes: { platform: `${project}_ark_platform_pg_stages`, app: `${project}_ark_app_pg_stages` },
    images,
    container,
    psql: async (cluster, sql) => {
      const [user, database] = SUPERUSER[cluster];
      return (
        await run([
          "docker",
          "exec",
          await container(cluster),
          "psql",
          "-X",
          "-A",
          "-t",
          "-v",
          "ON_ERROR_STOP=1",
          "-h",
          "/var/run/postgresql",
          "-U",
          user,
          "-d",
          database,
          "-c",
          sql,
        ])
      ).stdout;
    },
    workerEnv: () => ({
      ARK_PLATFORM_PG_EXECUTOR_URL: executorUrls.platform,
      ARK_PLATFORM_PG_EXECUTOR_TOKEN: tokens.platform,
      ARK_APP_PG_EXECUTOR_URL: executorUrls.app,
      ARK_APP_PG_EXECUTOR_TOKEN: tokens.app,
      ARK_PG_STAGE_ROOT: "/var/lib/ark/pg-stages",
      ARK_RESTIC_BIN: join(root, "scripts", "backup-test", "restic-docker.sh"),
      ARK_RESTIC_HOME: process.env.HOME ?? "/tmp",
    }),
    destroy: async () => {
      await run([...compose, "down", "--volumes", "--remove-orphans", "--timeout", "5"], { env });
    },
    teardown,
  };
}

/** docker args that give the test restic wrapper a network and the read-only staging volumes. */
export function resticDockerArgs(clusters: Clusters, network: string) {
  return [
    `--network ${network}`,
    `-v ${clusters.stageVolumes.platform}:/var/lib/ark/pg-stages/ark-platform:ro`,
    `-v ${clusters.stageVolumes.app}:/var/lib/ark/pg-stages/ark-app:ro`,
  ].join(" ");
}

export type Recorder = { record: (check: string, outcome: string) => void; summary: () => void };

export function recorder(): Recorder {
  const results: Array<[string, string]> = [];
  return {
    record: (check, outcome) => {
      results.push([check, outcome]);
      console.log(`✓ ${check}: ${outcome}`);
    },
    summary: () => {
      console.log("\nFD-21 checks:");
      for (const [check, outcome] of results) console.log(`  ✓ ${check} — ${outcome}`);
    },
  };
}

export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}
