import { runWorker } from "./runtime.ts";
import { executeClaimedJob, scheduleBackups } from "../../server/src/coordinator.ts";

// FD-21: observe the PostgreSQL executors, take due full/differential backups, export to every
// target every five minutes and re-run the weekly append-only canary (front door §3.18).
const schedule = process.env.ARK_BACKUP_SCHEDULE === "0" ? null : scheduleBackups();
try {
  // Separate bounded lanes: uploads never wait behind a full backup or a weekly canary.
  // The coordinator excludes overlapping target IDs; the executors serialize stanza mutations.
  await Promise.all([
    runWorker("backup", ["backup.create", "backup.restore_test"], executeClaimedJob, { concurrency: 2 }),
    runWorker("backup", ["backup.export"], executeClaimedJob, { concurrency: 4 }),
    runWorker("backup", ["backup.verify_target", "backup.observe"], executeClaimedJob, { concurrency: 2 }),
    runWorker("backup", ["update.detect", "import."], executeClaimedJob),
  ]);
} finally {
  if (schedule) clearInterval(schedule);
}
