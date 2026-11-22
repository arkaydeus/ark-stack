// Off-VPS point-in-time restore of an Ark PostgreSQL cluster (docs/design/front-door.md §3.18.1,
// FD-21; runbook in docs/guides/backups.md).
//
// Runs on a separate recovery machine with Docker. It needs only the off-VPS destination and the
// independently stored recovery material: a read-only S3 credential, the restic repository password
// and the cluster's repo2 cipher pass. Neither the VPS, its root key, Ark's database nor any VPS-local
// repository is used.
//
// 1. Pick the restic snapshot of the cluster's staged pgBackRest repository whose manifest covers the
//    requested time (the newest one by default; every newer stage is a superset).
// 2. `restic restore` it (read-only, --no-lock) into a scratch volume: a posix pgBackRest repository.
// 3. `pgbackrest restore --repo=2 --type=time --target-action=promote` into an empty PGDATA, using the
//    Ark PostgreSQL image of that cluster (same PostgreSQL major, pgBackRest and extensions).
// 4. Start PostgreSQL with no network and archiving off; it replays archived WAL to the target and
//    promotes. Recovery fails loudly if the WAL does not reach the target.
//
// CLI (all inputs through the environment, so nothing secret lands in shell history):
//   ARK_RESTORE_ENDPOINT=https://s3.us-east-1.amazonaws.com ARK_RESTORE_REGION=us-east-1 \
//   ARK_RESTORE_BUCKET=ark-backups ARK_RESTORE_PREFIX=ark ARK_RESTORE_PATH_STYLE=0 \
//   ARK_RESTORE_ACCESS_KEY_ID=... ARK_RESTORE_SECRET_ACCESS_KEY=... ARK_RESTORE_RESTIC_PASSWORD=... \
//   ARK_RESTORE_CIPHER_PASS=... ARK_RESTORE_CLUSTER=platform ARK_RESTORE_TARGET_TIME=2026-11-17T10:00:00Z \
//   ARK_RESTORE_IMAGE=ghcr.io/arkaydeus/ark-stack-postgres:<version> bun scripts/offsite-restore.ts
// The restored server keeps running in container `<name>-pg` with no network; inspect it with
// `docker exec -it <name>-pg psql -U <superuser>`, then `pg_dump` what you need.
import { randomBytes } from "node:crypto";

import {
  PG_CLUSTERS,
  PG_STAGE_MOUNT_ROOT,
  resticS3Env,
  resticS3Repository,
  type PgCluster,
  type StageManifest,
} from "@ark-stack/shared";

export const RESTIC_IMAGE =
  "restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510";

const SUPERUSERS: Record<PgCluster, string> = { platform: "ark_migration", app: "ark_cluster_admin" };
const DATABASES: Record<PgCluster, string> = { platform: "ark_platform", app: "postgres" };

export type OffsiteRestoreOptions = {
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  pathStyle: boolean;
  /** Read-only recovery credential: list and get objects only. */
  accessKeyId: string;
  secretAccessKey: string;
  resticPassword: string;
  cluster: PgCluster;
  /** The cluster's repo2 cipher pass (ARK_*_PG_REPO_CIPHER_PASS), stored off-host. */
  cipherPass: string;
  /** ISO timestamp to recover to; omitted, the snapshot's last recoverable time. */
  targetTime?: string;
  /** A specific restic snapshot ID; omitted, the newest snapshot that covers the target time. */
  snapshot?: string;
  /** The Ark PostgreSQL image for this cluster (ark-postgres or ark-app-postgres). */
  image: string;
  /** Docker network for restic (default: bridge). Tests join MinIO's namespace. */
  resticNetwork?: string;
  /** Name prefix for the containers and volumes this restore creates. */
  name?: string;
  log?: (line: string) => void;
};

export type RestoredCluster = {
  name: string;
  container: string;
  volumes: string[];
  snapshotId: string;
  manifest: StageManifest;
  targetTime: string;
  query: (sql: string) => Promise<string>;
  /** Removes only the containers and volumes this restore created. */
  cleanup: () => Promise<void>;
};

type Run = { status: number; stdout: string; stderr: string };

async function executeRestoreCommand(
  argv: string[],
  options: { allowFailure?: boolean; env?: Record<string, string> } = {},
): Promise<Run> {
  const child = Bun.spawn(argv, {
    env: { ...(process.env as Record<string, string>), ...options.env },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0 && !options.allowFailure) {
    throw new Error(
      `${argv.slice(0, 6).join(" ")} … failed (${status}):\n${(stderr || stdout).slice(-2500)}`,
    );
  }
  return { status, stdout: stdout.trim(), stderr: stderr.trim() };
}

/** Preserve PostgreSQL's microsecond precision; never round a requested recovery point up. */
export function pgbackrestTime(value: string) {
  const match = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d{1,6})?(Z|[+-]\d{2}:?\d{2})$/.exec(value);
  if (
    !match ||
    Number.isNaN(Date.parse(value)) ||
    new Date(`${match[1]}T00:00:00Z`).toISOString().slice(0, 10) !== match[1]
  )
    throw new Error(`Invalid target time: ${value}`);
  const offset = match[4] === "Z" ? "+00:00" : match[4]!;
  return `${match[1]} ${match[2]}${match[3] ?? ""}${offset}`;
}

export function recoveryMicros(value: string) {
  pgbackrestTime(value);
  const fraction = /\.(\d+)/.exec(value)?.[1] ?? "";
  return BigInt(Date.parse(value)) * 1000n + BigInt(fraction.padEnd(6, "0").slice(3, 6));
}

type Snapshot = { id: string; short_id: string; time: string; tags?: string[]; paths: string[] };

export async function offsiteRestore(
  options: OffsiteRestoreOptions,
  execute: typeof executeRestoreCommand = executeRestoreCommand,
): Promise<RestoredCluster> {
  const run = execute;
  if (options.targetTime) pgbackrestTime(options.targetTime);
  const log = options.log ?? (() => undefined);
  const profile = PG_CLUSTERS[options.cluster];
  const name = options.name ?? `ark-offsite-restore-${options.cluster}-${randomBytes(3).toString("hex")}`;
  const scratch = `${name}-repo`;
  const pgdata = `${name}-pgdata`;
  const container = `${name}-pg`;
  const config = {
    endpoint: options.endpoint,
    region: options.region,
    bucket: options.bucket,
    prefix: options.prefix,
    pathStyle: options.pathStyle,
  };
  const { repository, options: resticOptions } = resticS3Repository(config);
  const env = resticS3Env(config, {
    accessKeyId: options.accessKeyId,
    secretAccessKey: options.secretAccessKey,
    repositoryPassword: options.resticPassword,
  });
  const restic = (args: string[], mounts: string[] = []) =>
    run(
      [
        "docker",
        "run",
        "--rm",
        "--network",
        options.resticNetwork ?? "bridge",
        ...Object.keys(env).flatMap((key) => ["--env", key]),
        ...mounts.flatMap((mount) => ["--volume", mount]),
        RESTIC_IMAGE,
        "--no-lock",
        "--no-cache",
        "-r",
        repository,
        ...resticOptions,
        ...args,
      ],
      { env },
    );
  const ownership = randomBytes(16).toString("hex");
  const owned: Array<{ kind: "container" | "volume"; id: string }> = [];
  const cleanup = async () => {
    for (const resource of owned.toReversed()) {
      const inspect = await run(["docker", resource.kind, "inspect", resource.id], { allowFailure: true });
      if (inspect.status !== 0) continue;
      const [info] = JSON.parse(inspect.stdout);
      const labels = resource.kind === "container" ? info.Config?.Labels : info.Labels;
      if (labels?.["ark.restore-attempt"] !== ownership) continue;
      await run([
        "docker",
        ...(resource.kind === "container" ? ["rm", "--force"] : ["volume", "rm"]),
        resource.id,
      ]);
    }
  };

  try {
    // Never adopt an existing resource, including on failures before snapshot selection.
    for (const [kind, resource] of [
      ["container", container],
      ["volume", scratch],
      ["volume", pgdata],
    ]) {
      const existing = await run(["docker", kind!, "inspect", resource!], { allowFailure: true });
      if (existing.status === 0) throw new Error(`Restore resource already exists: ${resource}`);
      // A daemon/transport error is not evidence of absence.
      if (!/No such (object|container|volume)/i.test(existing.stderr)) throw new Error(existing.stderr);
    }
    // 1. Choose the snapshot.
    const listed = JSON.parse(
      (await restic(["snapshots", "--json", "--tag", `source=pg:${profile.stanza}`])).stdout || "[]",
    ) as Snapshot[];
    const candidates = listed
      .filter(
        (item) =>
          !options.snapshot || item.id.startsWith(options.snapshot) || item.short_id === options.snapshot,
      )
      .toSorted((a, b) => (a.time < b.time ? 1 : -1));
    if (!candidates.length)
      throw new Error(
        `No restic snapshot of ${profile.stanza} found${options.snapshot ? ` matching ${options.snapshot}` : ""}.`,
      );
    let chosen: { snapshot: Snapshot; manifest: StageManifest } | null = null;
    for (const snapshot of candidates) {
      const stage = snapshot.tags?.find((tag) => tag.startsWith("stage="))?.slice("stage=".length);
      if (!stage) continue;
      const path = snapshot.tags?.includes("layout=relative-v1")
        ? ""
        : `${PG_STAGE_MOUNT_ROOT}/${profile.stanza}/${stage}`;
      const manifest = JSON.parse(
        (await restic(["dump", snapshot.id, `${path}/manifest.json`])).stdout,
      ) as StageManifest;
      if (!manifest.lastRecoverableAt) continue;
      if (
        options.targetTime &&
        recoveryMicros(manifest.lastRecoverableAt) < recoveryMicros(options.targetTime)
      )
        continue;
      chosen = { snapshot, manifest };
      break;
    }
    if (!chosen) {
      throw new Error(
        `No off-VPS snapshot of ${profile.stanza} covers ${options.targetTime ?? "a recovery point"}; the newest exported recovery point is older.`,
      );
    }
    const targetTime = options.targetTime ?? chosen.manifest.lastRecoverableAt!;
    log(
      `${profile.stanza}: snapshot ${chosen.snapshot.short_id} (stage ${chosen.manifest.stageId}, recoverable to ${chosen.manifest.lastRecoverableAt}) -> ${targetTime}`,
    );

    // 2. restic restore into a scratch posix repository.
    for (const volume of [scratch, pgdata]) {
      await run(["docker", "volume", "create", "--label", `ark.restore-attempt=${ownership}`, volume]);
      const [created] = JSON.parse((await run(["docker", "volume", "inspect", volume])).stdout);
      if (created.Labels?.["ark.restore-attempt"] !== ownership)
        throw new Error(`Volume ownership collision: ${volume}`);
      owned.push({ kind: "volume", id: volume });
    }
    await restic(["restore", chosen.snapshot.id, "--target", "/restore"], [`${scratch}:/restore`]);
    const repoPath = chosen.snapshot.tags?.includes("layout=relative-v1")
      ? "/restore/repo2"
      : `/restore${PG_STAGE_MOUNT_ROOT}/${profile.stanza}/${chosen.manifest.stageId}/repo2`;

    // 3. pgBackRest restore into an empty PGDATA, then 4. replay to the target and promote.
    const pgbackrestEnv = {
      PGBACKREST_REPO2_PATH: repoPath,
      PGBACKREST_REPO2_CIPHER_PASS: options.cipherPass,
    };
    const restoreArgs = [
      "pgbackrest",
      `--stanza=${profile.stanza}`,
      "--repo=2",
      "--type=time",
      `--target=${pgbackrestTime(targetTime)}`,
      "--target-action=promote",
      "restore",
    ];
    await run(
      [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--volume",
        `${scratch}:/restore`,
        "--volume",
        `${pgdata}:/var/lib/postgresql/data`,
        ...Object.keys(pgbackrestEnv).flatMap((key) => ["--env", key]),
        "--entrypoint",
        "/bin/sh",
        options.image,
        "-c",
        `set -e; chown -R postgres:postgres /restore /var/lib/postgresql/data; chmod 0700 /var/lib/postgresql/data; exec gosu postgres ${restoreArgs.map((arg) => `'${arg.replaceAll("'", "'\\''")}'`).join(" ")}`,
      ],
      { env: pgbackrestEnv },
    );
    const launched = await run(
      [
        "docker",
        "run",
        "--detach",
        "--name",
        container,
        "--label",
        `ark.restore-attempt=${ownership}`,
        "--network",
        "none",
        "--volume",
        `${scratch}:/restore:ro`,
        "--volume",
        `${pgdata}:/var/lib/postgresql/data`,
        ...Object.keys(pgbackrestEnv).flatMap((key) => ["--env", key]),
        // Bypass the Ark entrypoint, which would turn WAL archiving on.
        "--entrypoint",
        "docker-entrypoint.sh",
        options.image,
        "postgres",
        "-c",
        "archive_mode=off",
        "-c",
        "listen_addresses=",
      ],
      { env: pgbackrestEnv },
    );
    owned.push({ kind: "container", id: launched.stdout });
    const superuser = SUPERUSERS[options.cluster];
    const database = DATABASES[options.cluster];
    const query = async (sql: string) =>
      (
        await run([
          "docker",
          "exec",
          container,
          "psql",
          "-X",
          "-A",
          "-t",
          "-v",
          "ON_ERROR_STOP=1",
          "-h",
          "/var/run/postgresql",
          "-U",
          superuser,
          "-d",
          database,
          "-c",
          sql,
        ])
      ).stdout;
    const deadline = Date.now() + 180_000;
    while (true) {
      const state = await run(["docker", "inspect", "--format", "{{.State.Running}}", container], {
        allowFailure: true,
      });
      if (state.stdout !== "true") {
        const logs = await run(["docker", "logs", "--tail", "40", container], { allowFailure: true });
        throw new Error(`Restored PostgreSQL stopped during recovery:\n${logs.stderr || logs.stdout}`);
      }
      const recovering = await query("SELECT pg_is_in_recovery()").catch(() => "");
      if (recovering === "f") break;
      if (Date.now() > deadline) throw new Error("Recovery did not finish within 180 s.");
      await Bun.sleep(1000);
    }
    log(`${profile.stanza}: recovered and promoted in ${container}`);
    return {
      name,
      container,
      volumes: [scratch, pgdata],
      snapshotId: chosen.snapshot.id,
      manifest: chosen.manifest,
      targetTime,
      query,
      cleanup,
    };
  } catch (error) {
    await cleanup();
    throw error;
  }
}

function need(key: string) {
  const value = process.env[key];
  if (!value) throw new Error(`${key} is required (see the header of scripts/offsite-restore.ts).`);
  return value;
}

if (import.meta.main) {
  const cluster = need("ARK_RESTORE_CLUSTER") as PgCluster;
  if (!(cluster in PG_CLUSTERS)) throw new Error("ARK_RESTORE_CLUSTER is platform or app.");
  const restored = await offsiteRestore({
    endpoint: need("ARK_RESTORE_ENDPOINT"),
    region: process.env.ARK_RESTORE_REGION ?? "us-east-1",
    bucket: need("ARK_RESTORE_BUCKET"),
    prefix: process.env.ARK_RESTORE_PREFIX ?? "ark",
    pathStyle: process.env.ARK_RESTORE_PATH_STYLE === "1",
    accessKeyId: need("ARK_RESTORE_ACCESS_KEY_ID"),
    secretAccessKey: need("ARK_RESTORE_SECRET_ACCESS_KEY"),
    resticPassword: need("ARK_RESTORE_RESTIC_PASSWORD"),
    cipherPass: need("ARK_RESTORE_CIPHER_PASS"),
    cluster,
    targetTime: process.env.ARK_RESTORE_TARGET_TIME,
    snapshot: process.env.ARK_RESTORE_SNAPSHOT,
    image: need("ARK_RESTORE_IMAGE"),
    log: console.log,
  });
  console.log(
    `Restored ${PG_CLUSTERS[cluster].stanza} to ${restored.targetTime} from snapshot ${restored.snapshotId}.\n` +
      `Container: ${restored.container} (no network). Volumes: ${restored.volumes.join(", ")}.\n` +
      `Inspect: docker exec -it ${restored.container} psql -U ${SUPERUSERS[cluster]} -d ${DATABASES[cluster]}`,
  );
}
