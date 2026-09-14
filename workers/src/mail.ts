import { runWorker } from "./runtime.ts";
import { executeClaimedJob } from "../../server/src/coordinator.ts";

await runWorker("mail", ["mail.", "mailbox.", "ses."], executeClaimedJob);
