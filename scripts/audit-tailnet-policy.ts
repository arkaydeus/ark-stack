// Offline comparison of a candidate merged policy with a freshly generated GLOBAL Ark snippet.
// No credentials or network requests. See docs/operating.md for the local model's limits.
import { auditTailnetPolicy, parseHujson, type TailnetPolicy } from "../shared/src/tailnet-acl.ts";

const [expectedPath, candidatePath] = process.argv.slice(2);
if (!expectedPath || !candidatePath) {
  console.error(
    "Usage: bun scripts/audit-tailnet-policy.ts <global-snippet.hujson> <candidate-policy.hujson>",
  );
  process.exit(1);
}
const expected = parseHujson(await Bun.file(expectedPath).text()) as TailnetPolicy;
const candidate = parseHujson(await Bun.file(candidatePath).text()) as TailnetPolicy;
const failures = auditTailnetPolicy(expected, candidate);
if (failures.length) {
  console.error(JSON.stringify(failures, null, 2));
  process.exit(1);
}
console.log("TCP/UDP access matches the global snippet on known destinations (local model only).");
