export type BackupKind = "platform-postgres" | "app-postgres" | "mail" | "volume";

export function backupCommand(kind: BackupKind, target: string) {
  if (kind === "platform-postgres" || kind === "app-postgres") {
    return {
      argv: ["pgbackrest", `--stanza=${target}`, "--type=full", "backup"],
      tool: "pgbackrest",
      notes: "Physical base backup plus WAL archival. pg_dump alone is not PITR.",
    };
  }
  if (kind === "mail") {
    return {
      argv: ["restic", "-r", target, "backup", "--one-file-system", "/var/lib/stalwart"],
      tool: "restic",
      notes: "Quiesce or use a supported native snapshot. Live RocksDB copy is not verified.",
    };
  }
  return {
    argv: ["restic", "-r", target, "backup", "--one-file-system", `/var/lib/ark/volumes/${target}`],
    tool: "restic",
    notes: "Only reviewed named volumes. No user-supplied host commands.",
  };
}

export function restoreTestCommand(kind: BackupKind, target: string) {
  if (kind === "platform-postgres" || kind === "app-postgres") {
    return {
      argv: ["pgbackrest", `--stanza=${target}`, "--type=immediate", "--target-action=promote", "restore"],
      isolated: true,
      disableReconciliation: true,
      disableOutboundMail: true,
      disablePublicIngress: true,
    };
  }
  return {
    argv: ["restic", "-r", target, "restore", "latest", "--target", "/tmp/ark-restore"],
    isolated: true,
    disableReconciliation: true,
    disableOutboundMail: true,
    disablePublicIngress: true,
  };
}

export type BackupStatus = "queued" | "planned" | "uploaded" | "integrity_ok" | "restore_verified" | "failed";

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
