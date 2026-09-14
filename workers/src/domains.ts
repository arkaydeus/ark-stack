import { runWorker } from "./runtime.ts";
import { executeClaimedJob } from "../../server/src/coordinator.ts";

await runWorker("domains", ["domain.", "dns.", "certificate.", "edge.", "admin."], executeClaimedJob);
