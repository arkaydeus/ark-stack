// Shared harness for the FD-21 backup suites (scripts/test-backups.ts, scripts/test-backups-hosted.ts).
//
// - A throwaway control database (postgres:17.6, owner role ark_migration) with every migration.
// - The actual `postgres` and `app-postgres` Compose services from infra/platform/docker-compose.yml,
//   built from the Dockerfile stages, in a unique Compose project. A test-only override publishes the
//   PostgreSQL on loopback ephemeral ports and relays executor requests through docker exec,
//   preserving their private bind addresses. Small project-owned subnets and a short archive_timeout
//   keep fixtures independent of daemon address-pool pressure and external mail/monitoring networks.
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
  compose: (args: string[]) => Promise<import("./minio.ts").Run>;
  work: string;
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

const ipv4 = (value: string) => value.split(".").reduce((n, part) => (n << 8n) + BigInt(part), 0n);

/** Allocate small isolated test networks without consuming Docker's limited default /16 pools. */
export async function testNetworkBase() {
  const ids = (await run(["docker", "network", "ls", "--quiet"])).stdout.split(/\s+/).filter(Boolean);
  const existing = ids.length
    ? (JSON.parse((await run(["docker", "network", "inspect", ...ids])).stdout) as Array<{
        IPAM?: { Config?: Array<{ Subnet?: string }> };
      }>)
    : [];
  const ranges = existing
    .flatMap((network) => network.IPAM?.Config ?? [])
    .flatMap(({ Subnet }) => {
      if (!Subnet || Subnet.includes(":")) return [];
      const [address, bits] = Subnet.split("/");
      const size = 1n << BigInt(32 - Number(bits));
      const start = ipv4(address!);
      return [{ start, end: start + size - 1n }];
    });
  const offset = randomBytes(2).readUInt16BE() % 512;
  for (let i = 0; i < 512; i++) {
    const block = (offset + i) % 512;
    const base = `198.${18 + Math.floor(block / 256)}.${block % 256}`;
    const start = ipv4(`${base}.0`),
      end = start + 255n;
    if (!ranges.some((range) => start <= range.end && end >= range.start)) return base;
  }
  throw new Error("No unused benchmark-range /24 remains for isolated backup test networks.");
}

export async function startClusters(label: string): Promise<Clusters> {
  const suffix = `${label}-${randomBytes(3).toString("hex")}`;
  const project = `ark-fd21-${suffix}`;
  const version = `fd21-test-${suffix}`;
  const work = await mkdtemp(join(tmpdir(), `ark-fd21-${suffix}-`));
  const override = join(work, "override.yml");
  const networkBase = await testNetworkBase();
  const testNetworks = [
    "control",
    "admin",
    "edge-control",
    "database-management",
    "pgbouncer-ingress",
    "backup-management",
    "backup-egress",
    // FD-30: the Compose backup-worker also joins backup-tailnet (backup-ts's SOCKS5 network).
    "backup-tailnet",
    "backup-ts-egress",
    "fd21-loopback",
    "mail-management",
    "monitoring",
  ]
    .map(
      (name, index) =>
        `  ${name}:\n${name === "mail-management" || name === "monitoring" ? `    external: false\n    name: ${project}_test-${name}\n    internal: true\n` : ""}    ipam: { config: [{ subnet: ${networkBase}.${index * 16}/28 }] }`,
    )
    .join("\n");
  await writeFile(
    override,
    `# FD-21 test override: loopback ports for the executors and PostgreSQL, a 10 s archive_timeout.
services:
  postgres:
    command: [postgres, -c, track_commit_timestamp=on]
    ports: ["127.0.0.1::5432"]
    environment: { ARK_PG_ARCHIVE_TIMEOUT: "10" }
    networks:
      control: {}
      backup-management: {}
      fd21-loopback: {}
  app-postgres:
    command: [postgres, -c, track_commit_timestamp=on]
    ports: ["127.0.0.1::5432"]
    environment: { ARK_PG_ARCHIVE_TIMEOUT: "10" }
    networks:
      database-management: {}
      backup-management: {}
      fd21-loopback: {}
networks:
${testNetworks}
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

  const proxies: Array<ReturnType<typeof Bun.serve>> = [];
  const teardown = async () => {
    for (const proxy of proxies) proxy.stop(true);
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
  // Production executors bind only the backup interface. A host-only test relay uses docker
  // exec to reach that interface; no published port or wildcard bind weakens the tested images.
  const executorUrls = {} as Record<PgCluster, string>;
  for (const cluster of ["platform", "app"] as const) {
    const id = await container(cluster);
    const relay = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(request) {
        const body = await request.text();
        const url = `http://ark-${cluster === "platform" ? "platform" : "app"}-backup:8432${new URL(request.url).pathname}`;
        const script = `const r=await fetch(process.env.RELAY_URL,{method:process.env.RELAY_METHOD,headers:{authorization:process.env.RELAY_AUTH,"content-type":"application/json"},...(process.env.RELAY_METHOD==="GET"?{}:{body:process.env.RELAY_BODY||"{}"})});console.log(JSON.stringify({status:r.status,body:await r.text()}));`;
        const result = await run(
          [
            "docker",
            "exec",
            ...["RELAY_URL", "RELAY_METHOD", "RELAY_AUTH", "RELAY_BODY"].flatMap((key) => ["--env", key]),
            id,
            "bun",
            "-e",
            script,
          ],
          {
            env: {
              RELAY_URL: url,
              RELAY_METHOD: request.method,
              RELAY_AUTH: request.headers.get("authorization") ?? "",
              RELAY_BODY: body,
            },
            allowFailure: true,
          },
        );
        if (result.status !== 0) return new Response(result.stderr, { status: 502 });
        const response = JSON.parse(result.stdout);
        return new Response(response.body, {
          status: response.status,
          headers: { "content-type": "application/json" },
        });
      },
    });
    proxies.push(relay);
    executorUrls[cluster] = `http://127.0.0.1:${relay.port}`;
  }
  // Wait until both executors answer and their stanzas exist.
  for (const cluster of ["platform", "app"] as const) {
    const deadline = Date.now() + 120_000;
    while (true) {
      const response = await fetch(`${executorUrls[cluster]}/v1/check`, {
        method: "POST",
        headers: { authorization: `Bearer ${tokens[cluster]}` },
        body: "{}",
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
    compose: (args) => run([...compose, ...args], { env }),
    work,
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
      // The host-side API and deployed worker must authenticate with the same fixture token.
      ARK_BACKUP_WORKER_TOKEN: env.ARK_BACKUP_WORKER_TOKEN!,
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
