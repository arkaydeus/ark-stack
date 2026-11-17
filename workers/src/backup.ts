import { runWorker } from "./runtime.ts";
import { executeClaimedJob, scheduleBackupObserve, scheduleBackups } from "../../server/src/coordinator.ts";

// FD-21: observe the PostgreSQL executors, take due full/differential backups, export to every
// target every five minutes and re-run the weekly append-only canary (front door §3.18).
// FD-30: observe backup-ts (read-only LocalAPI socket, mounted here only) every five minutes, so the
// home target's identity lease stays fresh while transfers run (§3.18.3).
const schedule = process.env.ARK_BACKUP_SCHEDULE === "0" ? null : scheduleBackups();
const observe = process.env.ARK_BACKUP_SCHEDULE === "0" ? null : scheduleBackupObserve();
try {
  // Separate bounded lanes keep local backups and canaries from occupying all export slots.
  // The coordinator excludes overlapping target IDs; the executors serialize stanza mutations.
  // Observation has reserved capacity even when every export and canary slot is occupied.
  await Promise.all([
    runWorker("backup", ["backup.create", "backup.restore_test"], executeClaimedJob, { concurrency: 2 }),
    runWorker("backup", ["backup.export"], executeClaimedJob, { concurrency: 4 }),
    runWorker("backup", ["backup.verify_target"], executeClaimedJob, { concurrency: 2 }),
    runWorker("backup", ["backup.observe"], executeClaimedJob, { concurrency: 1 }),
    runWorker("backup", ["update.detect", "import."], executeClaimedJob),
  ]);
} finally {
  if (schedule) clearInterval(schedule);
  if (observe) clearInterval(observe);
}
