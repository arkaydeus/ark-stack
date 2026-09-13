import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { backupCommand, restoreTestCommand, sha256Hex, type BackupKind } from "@ark-stack/shared";

const exec = promisify(execFile);

function requireExecution() {
  if (process.env.ARK_BACKUP_REQUIRED === "1" && process.env.ARK_BACKUP_EXECUTE !== "1") {
    throw new Error("Backup execution is required but ARK_BACKUP_EXECUTE is not enabled.");
  }
}

export async function runBackup(kind: BackupKind, target: string) {
  const plan = backupCommand(kind, target);
  requireExecution();
  if (process.env.ARK_BACKUP_EXECUTE !== "1") {
    return { status: "planned" as const, executed: false, argv: plan.argv, notes: plan.notes };
  }
  const { stdout, stderr } = await exec(plan.argv[0], plan.argv.slice(1), { timeout: 120_000 });
  const output = `${stdout}\n${stderr}`;
  return {
    status: "uploaded" as const,
    executed: true,
    argv: plan.argv,
    notes: plan.notes,
    snapshotId: sha256Hex(output),
    output: output.slice(0, 2000),
  };
}

export async function runRestoreTest(kind: BackupKind, target: string) {
  const plan = restoreTestCommand(kind, target);
  if (!plan.isolated) throw new Error("Restore tests must target an isolated environment.");
  requireExecution();
  if (process.env.ARK_BACKUP_EXECUTE !== "1") {
    return { status: "planned" as const, executed: false, argv: plan.argv, isolated: true };
  }
  const { stdout, stderr } = await exec(plan.argv[0], plan.argv.slice(1), { timeout: 180_000 });
  const output = `${stdout}\n${stderr}`;
  return {
    status: "restore_verified" as const,
    executed: true,
    argv: plan.argv,
    isolated: true,
    snapshotId: sha256Hex(output),
    output: output.slice(0, 2000),
  };
}
