// Test-only: the installer's edge-l4 step (scripts/install-edge-l4.ts) for a disposable Compose project.
// Bundled and run as root in the pinned Bun container against the project's configuration volume:
// seeds the initial generation and `current`, then gives the tree to the worker's uid and group 4400
// with directories 2750 and files 0640, exactly as `mise run host:install` does on the host.
//
//   bun seed-edge-l4.js <root> <uid>
import { chownEdgeL4, seedEdgeL4 } from "../install-edge-l4.ts";

const [root = "/usr/local/etc/haproxy", uid = "1000"] = process.argv.slice(2);
const seeded = await seedEdgeL4(root);
await chownEdgeL4(root, Number(uid));
console.log(JSON.stringify(seeded));
