import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  PG_CLUSTERS,
  backupCommand,
  restoreTestCommand,
  type BackupKind,
  type PgBackupType,
} from "@ark-stack/shared";

import { clusterForBackupKind, runPgBackup } from "./pg-executor-client.ts";

function requireExecution() {
  if (process.env.ARK_BACKUP_REQUIRED === "1" && process.env.ARK_BACKUP_EXECUTE !== "1") {
    throw new Error("Backup execution is required but ARK_BACKUP_EXECUTE is not enabled.");
  }
}

function resolvedBackupLocation(kind: BackupKind, targetId: string) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(targetId)) {
    throw new Error("Backup target ID is not a managed resource identifier.");
  }
  if (kind === "platform-postgres") {
    if (targetId !== "platform") throw new Error("Platform PostgreSQL backups require the platform target.");
    return { target: PG_CLUSTERS.platform.stanza, repository: "" };
  }
  if (kind === "app-postgres") {
    return { target: PG_CLUSTERS.app.stanza, repository: "" };
  }
  // Mail and volume backups go to the restic repository of every enabled off-VPS target (FD-21).
  return { target: targetId, repository: "backup-targets" };
}

function filesPath(kind: BackupKind, targetId: string) {
  return kind === "mail" ? "/var/lib/stalwart-snapshot" : `/var/lib/ark/volumes/${targetId}`;
}

export async function runBackup(kind: BackupKind, targetId: string, options: { type?: PgBackupType } = {}) {
  const location = resolvedBackupLocation(kind, targetId);
  const type = options.type ?? "full";
  const plan = backupCommand(kind, location.target, location.repository, type);
  requireExecution();
  if (process.env.ARK_BACKUP_EXECUTE !== "1") {
    return { status: "planned" as const, executed: false, argv: plan.argv, notes: plan.notes };
  }
  const cluster = clusterForBackupKind(kind);
  if (cluster) {
    // The executor inside the PostgreSQL container runs pgBackRest; the result is a local backup
    // until backup.export ships a stage containing it.
    const result = await runPgBackup(cluster, type);
    return {
      status: "local" as const,
      executed: true,
      argv: plan.argv,
      notes: plan.notes,
      snapshotId: result.label,
      output: (result.output ?? "").slice(0, 2000),
    };
  }
  if (kind === "mail" && process.env.ARK_MAIL_SNAPSHOT_READY !== "1") {
    throw new Error("Mail backup requires a completed native snapshot or quiesce step.");
  }
  const { exportFiles } = await import("./offsite-backups.ts");
  const source = kind === "mail" ? "mail" : `volume:${targetId}`;
  const results = await exportFiles(source, filesPath(kind, targetId), []);
  const failed = results.filter((item) => item.error);
  const snapshotId = results.find((item) => item.snapshotId)?.snapshotId;
  if (failed.length || !snapshotId) {
    throw new Error(
      `Backup to ${failed.length} target(s) failed: ${failed
        .map((item) => item.error)
        .join("; ")
        .slice(0, 800)}`,
    );
  }
  return {
    status: "uploaded" as const,
    executed: true,
    argv: plan.argv,
    notes: plan.notes,
    snapshotId,
    targets: results,
  };
}

export async function runRestoreTest(kind: BackupKind, targetId: string, backupId?: string) {
  requireExecution();
  const location = resolvedBackupLocation(kind, targetId);
  if (process.env.ARK_BACKUP_EXECUTE !== "1") {
    const argv = backupId
      ? restoreTestCommand(
          kind,
          location.target,
          backupId,
          "/var/lib/ark/restore-runs/planned",
          location.repository,
        ).argv
      : [];
    return { status: "planned" as const, executed: false, argv, isolated: true, backupId };
  }
  if (clusterForBackupKind(kind)) {
    throw new Error(
      "PostgreSQL restore tests require scripts/offsite-restore.ts on the off-VPS recovery host.",
    );
  }
  if (!backupId) throw new Error("An exact native backup ID is required for restore execution.");
  if (process.env.ARK_RESTORE_RUNNER !== "1")
    throw new Error("Restore execution requires the isolated restore runner (ARK_RESTORE_RUNNER=1).");
  const restoreRoot = await mkdtemp(join(tmpdir(), "ark-restore-"));
  const { restoreFiles } = await import("./offsite-backups.ts");
  const result = await restoreFiles(kind === "mail" ? "mail" : `volume:${targetId}`, backupId, restoreRoot);
  return {
    status: "integrity_ok" as const,
    executed: true,
    argv: result.argv,
    isolated: true,
    snapshotId: backupId,
    restoreRoot,
    validation: "Restored bytes require service boot and data/access assertions before proof.",
    output: result.stdout.slice(0, 2000),
  };
}
