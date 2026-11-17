// Test-only entry point for `mise run test:backups-tailnet` (FD-30). The harness bundles it and runs
// it in the pinned Bun image as the backup worker's non-root `bun` user (uid 1000), with backup-ts's
// socket volume mounted read-only where the backup worker mounts it, so the production LocalAPI
// client and the `source = 'backup'` parser talk to a real tailscaled.
//
//   bun observe-backup-status.js <socket>
import { parseLocalApiStatus } from "@ark-stack/shared";

import { readLocalApiStatus } from "../../server/src/modules/tailnet-localapi.ts";

const [socket = "/var/run/tailscale-backup/tailscaled.sock"] = process.argv.slice(2);
const result: Record<string, unknown> = { uid: process.getuid?.() };
try {
  const status = (await readLocalApiStatus(socket)) as { BackendState?: string };
  result.backendState = status.BackendState;
  const parsed = parseLocalApiStatus(status, { generation: "gen_probe", source: "backup" });
  result.parsed = parsed.ok
    ? { ok: true, self: { source: parsed.self.source, tags: parsed.self.tags } }
    : { ok: false, reason: parsed.reason };
} catch (error) {
  result.statusError = (error as Error).message;
}
console.log(JSON.stringify(result));
