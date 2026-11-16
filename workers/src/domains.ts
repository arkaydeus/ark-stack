import { runWorker } from "./runtime.ts";
import { executeClaimedJob, scheduleEdgeObserve } from "../../server/src/coordinator.ts";

// `edge.observe` every five minutes while the edge node's LocalAPI socket is mounted (front door §3.4).
const observeSchedule = scheduleEdgeObserve();
try {
  await runWorker("domains", ["domain.", "dns.", "certificate.", "edge.", "admin."], executeClaimedJob);
} finally {
  if (observeSchedule) clearInterval(observeSchedule);
}
