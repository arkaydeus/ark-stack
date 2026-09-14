import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { backupCommand, createId, restoreTestCommand, type BackupKind } from "@ark-stack/shared";

const exec = promisify(execFile);

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
    return { target: process.env.ARK_PLATFORM_PGBACKREST_STANZA ?? "ark-platform", repository: "" };
  }
  if (kind === "app-postgres") {
    return { target: process.env.ARK_APP_PGBACKREST_STANZA ?? "ark-app", repository: "" };
  }
  const repository = process.env.RESTIC_REPOSITORY;
  if (process.env.ARK_BACKUP_EXECUTE === "1" && !repository) {
    throw new Error("RESTIC_REPOSITORY is required for mail and volume backups.");
  }
  return { target: targetId, repository: repository ?? "configured-restic-repository" };
}

export async function runBackup(kind: BackupKind, targetId: string) {
  const location = resolvedBackupLocation(kind, targetId);
  const plan = backupCommand(kind, location.target, location.repository);
  requireExecution();
  if (process.env.ARK_BACKUP_EXECUTE !== "1") {
    return { status: "planned" as const, executed: false, argv: plan.argv, notes: plan.notes };
  }
  if (kind === "mail" && process.env.ARK_MAIL_SNAPSHOT_READY !== "1") {
    throw new Error("Mail backup requires a completed native snapshot or quiesce step.");
  }
  const { stdout, stderr } = await exec(plan.argv[0], plan.argv.slice(1), { timeout: 120_000 });
  const output = `${stdout}\n${stderr}`;
  return {
    status: "uploaded" as const,
    executed: true,
    argv: plan.argv,
    notes: plan.notes,
    snapshotId: nativeSnapshotId(kind, output),
    output: output.slice(0, 2000),
  };
}

export async function runRestoreTest(kind: BackupKind, targetId: string, backupId?: string) {
  requireExecution();
  if (process.env.ARK_BACKUP_EXECUTE !== "1" && !backupId) {
    return { status: "planned" as const, executed: false, argv: [], isolated: true };
  }
  if (!backupId) throw new Error("An exact native backup ID is required for restore execution.");
  const location = resolvedBackupLocation(kind, targetId);
  const restoreRoot = `/var/lib/ark/restore-runs/${createId("restore")}`;
  const plan = restoreTestCommand(kind, location.target, backupId, restoreRoot, location.repository);
  if (!plan.isolated) throw new Error("Restore tests must target an isolated environment.");
  if (process.env.ARK_BACKUP_EXECUTE !== "1") {
    return { status: "planned" as const, executed: false, argv: plan.argv, isolated: true, backupId };
  }
  if (process.env.ARK_RESTORE_RUNNER !== "1") {
    throw new Error("Restore execution requires the isolated restore runner (ARK_RESTORE_RUNNER=1). ");
  }
  const { stdout, stderr } = await exec(plan.argv[0], plan.argv.slice(1), { timeout: 180_000 });
  const output = `${stdout}\n${stderr}`;
  return {
    status: "integrity_ok" as const,
    executed: true,
    argv: plan.argv,
    isolated: true,
    snapshotId: backupId,
    restoreRoot,
    validation: "Restored bytes require service boot and data/access assertions before proof.",
    output: output.slice(0, 2000),
  };
}

function nativeSnapshotId(kind: BackupKind, output: string) {
  if (kind === "platform-postgres" || kind === "app-postgres") {
    const match = /(?:backup label|label)\s*[:=]\s*([\w-]+)/i.exec(output);
    if (match?.[1]) return match[1];
  } else {
    for (const line of output.split("\n").toReversed()) {
      try {
        const parsed = JSON.parse(line) as { snapshot_id?: string };
        if (parsed.snapshot_id) return parsed.snapshot_id;
      } catch {
        continue;
      }
    }
  }
  throw new Error("Backup tool completed without a native snapshot identifier.");
}
