import { runWorker } from "./runtime.ts";
import { executeClaimedJob, scheduleBackups } from "../../server/src/coordinator.ts";

// FD-21: observe the PostgreSQL executors, take due full/differential backups, export to every
// target every five minutes and re-run the weekly append-only canary (front door §3.18).
const schedule = scheduleBackups();
try {
  await runWorker("backup", ["backup.", "update.detect", "import."], executeClaimedJob);
} finally {
  if (schedule) clearInterval(schedule);
}
