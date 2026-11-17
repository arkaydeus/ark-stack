import { pgbackrestArgv, type PgBackupType } from "./pg-backup.ts";

export type BackupKind = "platform-postgres" | "app-postgres" | "mail" | "volume";

export function backupCommand(
  kind: BackupKind,
  target: string,
  repository = target,
  type: PgBackupType = "full",
) {
  if (kind === "platform-postgres" || kind === "app-postgres") {
    // Runs inside the cluster's PostgreSQL container through its executor (FD-21), into the local
    // encrypted repo2; backup.export then ships staged copies off the VPS.
    return {
      argv: pgbackrestArgv("backup", target, { type }),
      tool: "pgbackrest",
      notes:
        "Physical backup into the local encrypted repo2 plus WAL archival; exported off-VPS as restic snapshots. pg_dump alone is not PITR.",
    };
  }
  if (kind === "mail") {
    return {
      argv: [
        "restic",
        "-r",
        repository,
        "backup",
        "--json",
        "--one-file-system",
        "/var/lib/stalwart-snapshot",
      ],
      tool: "restic",
      notes: "Quiesce or use a supported native snapshot. Live RocksDB copy is not verified.",
    };
  }
  return {
    argv: ["restic", "-r", repository, "backup", "--one-file-system", `/var/lib/ark/volumes/${target}`],
    tool: "restic",
    notes: "Only reviewed named volumes. No user-supplied host commands.",
  };
}

export function restoreTestCommand(
  kind: BackupKind,
  target: string,
  backupId: string,
  restoreRoot: string,
  repository = target,
) {
  if (!backupId) throw new Error("An exact native backup ID is required for restore verification.");
  if (!restoreRoot.startsWith("/var/lib/ark/restore-runs/")) {
    throw new Error("Restore verification must use a dedicated runner data root.");
  }
  if (kind === "platform-postgres" || kind === "app-postgres") {
    return {
      argv: [
        "pgbackrest",
        `--stanza=${target}`,
        "--repo=2",
        `--set=${backupId}`,
        `--pg1-path=${restoreRoot}/postgres`,
        "--delta=n",
        "--type=immediate",
        "--target-action=promote",
        "restore",
      ],
      isolated: true,
      disableReconciliation: true,
      disableOutboundMail: true,
      disablePublicIngress: true,
    };
  }
  return {
    argv: ["restic", "-r", repository, "restore", backupId, "--target", restoreRoot],
    isolated: true,
    disableReconciliation: true,
    disableOutboundMail: true,
    disablePublicIngress: true,
  };
}

/** `local`: a PostgreSQL backup in the VPS-local repo2 that no off-VPS target has yet (FD-21). */
export type BackupStatus =
  | "queued"
  | "planned"
  | "local"
  | "uploaded"
  | "integrity_ok"
  | "restore_verified"
  | "failed";

export function backupProofAllowed(input: { executed?: boolean; status: string }) {
  return (
    Boolean(input.executed) &&
    (input.status === "uploaded" || input.status === "integrity_ok" || input.status === "restore_verified")
  );
}

export function nextBackupStatus(current: BackupStatus, event: "upload" | "integrity" | "restore") {
  if (current === "failed") return "failed";
  if (event === "upload") return "uploaded";
  if (event === "integrity" && current === "uploaded") return "integrity_ok";
  if (event === "restore" && current === "integrity_ok") return "restore_verified";
  throw new Error(
    `Backup cannot move from ${current} via ${event}. Upload, integrity, and restore are separate.`,
  );
}
