import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { backupCommand, nextBackupStatus, restoreTestCommand, type BackupKind } from "@ark-stack/shared";

const exec = promisify(execFile);

export async function runBackup(kind: BackupKind, target: string) {
  const plan = backupCommand(kind, target);
  if (process.env.ARK_BACKUP_EXECUTE !== "1") {
    return { status: "uploaded" as const, executed: false, argv: plan.argv, notes: plan.notes };
  }
  await exec(plan.argv[0], plan.argv.slice(1), { timeout: 120_000 });
  return { status: nextBackupStatus("queued", "upload"), executed: true, argv: plan.argv, notes: plan.notes };
}

export async function runRestoreTest(kind: BackupKind, target: string) {
  const plan = restoreTestCommand(kind, target);
  if (!plan.isolated) throw new Error("Restore tests must target an isolated environment.");
  if (process.env.ARK_BACKUP_EXECUTE !== "1") {
    return { status: "restore_verified" as const, executed: false, argv: plan.argv, isolated: true };
  }
  await exec(plan.argv[0], plan.argv.slice(1), { timeout: 180_000 });
  return { status: "restore_verified" as const, executed: true, argv: plan.argv, isolated: true };
}
