import { runWorker } from "./runtime.ts";
import { executeClaimedJob } from "../../server/src/coordinator.ts";

await runWorker("backup", ["backup.", "update.detect", "import."], executeClaimedJob);
