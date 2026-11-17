// PostgreSQL physical backups (docs/design/front-door.md §3.18.1, FD-21).
//
// Each Compose cluster (`postgres` platform and `app-postgres`) runs a pgBackRest executor inside its
// own container, next to PGDATA and the local socket. It writes a persistent, encrypted, posix
// `repo2` (expire-auto=n) and, under an exclusive executor lock, stages read-only copies of the
// completed repository for the restic exporter. This module is the contract between the executor
// and the control side. It is deliberately free of imports, so the executor bundle stays tiny.
//
// Never from the VPS: `pgbackrest expire`. Old backups are expired only by an off-host admin
// against a restored copy (docs/guides/backups.md). `assertExecutorArgv` refuses it, and
// `scripts/backup-no-expire.test.ts` checks that no VPS-side source can run it.

export type PgCluster = "platform" | "app";

export type PgClusterProfile = {
  cluster: PgCluster;
  /** pgBackRest stanza, also the restic `source=pg:<stanza>` tag. */
  stanza: string;
  /** Backup kind used by `backup.create` and the backups table. */
  backupKind: "platform-postgres" | "app-postgres";
  /** Compose service that runs PostgreSQL and the executor. */
  service: string;
  /** Environment variables the backup worker reads for the executor URL and token. */
  urlEnv: string;
  tokenEnv: string;
};

export const PG_CLUSTERS: Readonly<Record<PgCluster, PgClusterProfile>> = Object.freeze({
  platform: {
    cluster: "platform",
    stanza: "ark-platform",
    backupKind: "platform-postgres",
    service: "postgres",
    urlEnv: "ARK_PLATFORM_PG_EXECUTOR_URL",
    tokenEnv: "ARK_PLATFORM_PG_EXECUTOR_TOKEN",
  },
  app: {
    cluster: "app",
    stanza: "ark-app",
    backupKind: "app-postgres",
    service: "app-postgres",
    urlEnv: "ARK_APP_PG_EXECUTOR_URL",
    tokenEnv: "ARK_APP_PG_EXECUTOR_TOKEN",
  },
});

export const PG_EXECUTOR_PORT = 8432;
/** Inside each PostgreSQL container. */
export const PG_REPO_ROOT = "/var/lib/pgbackrest";
export const PG_REPO2_PATH = `${PG_REPO_ROOT}/repo2`;
export const PG_EXECUTOR_LOCK = `${PG_REPO_ROOT}/ark-executor.lock`;
export const PG_STAGING_ROOT = "/var/lib/pgbackrest-staging";
/** Where the backup worker mounts each cluster's staging volume read-only (`<root>/<stanza>`). */
export const PG_STAGE_MOUNT_ROOT = "/var/lib/ark/pg-stages";

export const PG_BACKUP_TYPES = ["full", "diff", "incr"] as const;
export type PgBackupType = (typeof PG_BACKUP_TYPES)[number];

/** Schedules (§3.18.1): weekly full, daily differential, off-VPS snapshots at most every 5 minutes. */
export const PG_FULL_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
export const PG_DIFF_INTERVAL_MS = 24 * 60 * 60 * 1000;
export const PG_EXPORT_INTERVAL_MS = 5 * 60 * 1000;

/** The only executor actions. There is no generic "run" and no expire. */
export const PG_EXECUTOR_ACTIONS = [
  "status",
  "stanza-create",
  "check",
  "backup",
  "stage",
  "prune-stages",
] as const;
export type PgExecutorAction = (typeof PG_EXECUTOR_ACTIONS)[number];

const STANZA = /^[a-z][a-z0-9-]{0,62}$/;

export function assertStanza(stanza: string) {
  if (!STANZA.test(stanza)) throw new Error(`Invalid pgBackRest stanza: ${stanza}`);
  return stanza;
}

/**
 * Refuses any pgBackRest argv that could delete backups or WAL from the VPS. `expire` is the only
 * pgBackRest command that removes recovery points; `stanza-delete` removes the whole stanza.
 */
export function assertExecutorArgv(argv: string[]) {
  if (argv[0] !== "pgbackrest") throw new Error("The executor only runs pgBackRest.");
  for (const arg of argv.slice(1)) {
    if (arg === "expire" || arg === "stanza-delete" || arg.startsWith("--expire-auto=y")) {
      throw new Error(`pgBackRest ${arg} is never run from the VPS.`);
    }
  }
  return argv;
}

/**
 * The fixed pgBackRest command lines. `--repo=2` is explicit wherever pgBackRest accepts it
 * (backup, info, restore); `check`, `stanza-create` and `archive-push` act on every configured
 * repository, and repo2 is the only one the image configures.
 */
export function pgbackrestArgv(
  command: "stanza-create" | "check" | "backup" | "info",
  stanza: string,
  options: { type?: PgBackupType; repoPath?: string } = {},
) {
  assertStanza(stanza);
  const argv = ["pgbackrest", `--stanza=${stanza}`];
  if (command === "backup") {
    const type = options.type ?? "full";
    if (!PG_BACKUP_TYPES.includes(type)) throw new Error(`Invalid backup type: ${type}`);
    argv.push("--repo=2", `--type=${type}`, "--no-expire-auto", "backup");
  } else if (command === "info") {
    argv.push("--repo=2");
    if (options.repoPath) argv.push(`--repo2-path=${options.repoPath}`);
    argv.push("--output=json", "info");
  } else {
    argv.push(command);
  }
  return assertExecutorArgv(argv);
}

/**
 * archive_command for both clusters (infra/backup/ark-postgres-entrypoint.sh): pgBackRest archive-push
 * under the shared executor lock. pgBackRest refuses an archive_command without `pgbackrest` in it.
 */
export function archiveCommand(stanza: string) {
  return `flock -s -w 60 ${PG_EXECUTOR_LOCK} pgbackrest --stanza=${assertStanza(stanza)} archive-push %p`;
}

export type StagedBackup = {
  label: string;
  type: string;
  startedAt: string;
  stoppedAt: string;
  walStart: string | null;
  walStop: string | null;
};

/** Written as `manifest.json` next to `repo2` in every stage, and recorded per destination. */
export type StageManifest = {
  version: 1;
  stanza: string;
  stageId: string;
  createdAt: string;
  /**
   * Every transaction committed before this instant is in WAL that was archived and copied into
   * the stage, and a backup finished before it. Null when no backup could restore to it yet.
   */
  lastRecoverableAt: string | null;
  /** The newest WAL segment the stage is guaranteed to contain. */
  walSegment: string | null;
  archive: { min: string | null; max: string | null };
  backups: StagedBackup[];
  repoBytes: number;
  pgbackrestVersion: string | null;
};

export type PgbackrestInfo = {
  backups: StagedBackup[];
  archive: { min: string | null; max: string | null };
  version: string | null;
  status: { code: number; message: string };
};

type RawInfo = Array<{
  name?: string;
  status?: { code?: number; message?: string };
  archive?: Array<{ min?: string | null; max?: string | null }>;
  backup?: Array<{
    label?: string;
    type?: string;
    error?: boolean;
    timestamp?: { start?: number; stop?: number };
    archive?: { start?: string | null; stop?: string | null };
    backrest?: { version?: string };
  }>;
}>;

/** Parses `pgbackrest --output=json info` for one stanza. Errored backups are skipped. */
export function parsePgbackrestInfo(text: string, stanza: string): PgbackrestInfo {
  const raw = JSON.parse(text) as RawInfo;
  const entry = raw.find((item) => item.name === stanza);
  if (!entry)
    return {
      backups: [],
      archive: { min: null, max: null },
      version: null,
      status: { code: -1, message: "stanza missing" },
    };
  const archives = entry.archive ?? [];
  const backups = (entry.backup ?? [])
    .filter((item) => item.label && !item.error && item.timestamp?.start && item.timestamp?.stop)
    .map((item) => ({
      label: item.label!,
      type: item.type ?? "unknown",
      startedAt: new Date(item.timestamp!.start! * 1000).toISOString(),
      stoppedAt: new Date(item.timestamp!.stop! * 1000).toISOString(),
      walStart: item.archive?.start ?? null,
      walStop: item.archive?.stop ?? null,
    }));
  const version = (entry.backup ?? []).findLast((item) => item.backrest?.version)?.backrest?.version ?? null;
  return {
    backups,
    archive: {
      min: archives.map((item) => item.min).find(Boolean) ?? null,
      max: archives.map((item) => item.max).findLast(Boolean) ?? null,
    },
    version,
    status: { code: entry.status?.code ?? -1, message: entry.status?.message ?? "unknown" },
  };
}

/**
 * The recovery point a stage can honestly claim: the instant WAL was switched, provided a backup
 * finished at least one second earlier (pgBackRest compares whole-second stop times) and the
 * switched segment is inside the staged archive range.
 */
export function stageRecoverableAt(input: {
  switchedAt: Date;
  walSegment: string | null;
  info: PgbackrestInfo;
}) {
  const { switchedAt, walSegment, info } = input;
  if (!walSegment || !info.archive.max) return null;
  if (compareWal(info.archive.max, walSegment) < 0) return null;
  const restorable = info.backups.some(
    (backup) => new Date(backup.stoppedAt).getTime() + 1000 <= switchedAt.getTime(),
  );
  return restorable ? switchedAt.toISOString() : null;
}

/** Compares WAL segment names (timeline, log, segment), each 8 hex digits. */
export function compareWal(a: string, b: string) {
  if (!/^[0-9A-F]{24}$/.test(a) || !/^[0-9A-F]{24}$/.test(b)) throw new Error("Invalid WAL segment name.");
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Stage IDs sort by creation time: `20261117T103244Z-ab12cd`. */
export function stageId(now: Date, random: string) {
  if (!/^[a-z0-9]{6}$/.test(random)) throw new Error("Stage suffix must be 6 lowercase alphanumerics.");
  return `${now
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d+Z$/, "Z")}-${random}`;
}

export const STAGE_ID = /^\d{8}T\d{6}Z-[a-z0-9]{6}$/;

/** Which backup, if any, a schedule tick should take (weekly full, daily differential). */
export function dueBackupType(backups: StagedBackup[], now: Date): PgBackupType | null {
  const fulls = backups.filter((item) => item.type === "full");
  const lastFull = fulls.at(-1);
  if (!lastFull || now.getTime() - new Date(lastFull.stoppedAt).getTime() >= PG_FULL_INTERVAL_MS)
    return "full";
  const last = backups.at(-1)!;
  if (now.getTime() - new Date(last.stoppedAt).getTime() >= PG_DIFF_INTERVAL_MS) return "diff";
  return null;
}

/** The restic tags that identify a staged PostgreSQL snapshot. */
export function pgSnapshotTags(stanza: string, stage: string) {
  assertStanza(stanza);
  if (!STAGE_ID.test(stage)) throw new Error("Invalid stage ID.");
  return ["ark", `source=pg:${stanza}`, `stage=${stage}`];
}
