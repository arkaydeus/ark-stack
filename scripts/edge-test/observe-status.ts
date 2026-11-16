// Test-only entry point for `mise run test:edge` (FD-06). The harness bundles it and runs it in the
// pinned Bun image as the domain worker's non-root `bun` user, with the edge-ts socket volume mounted
// read-only, so the production LocalAPI client and status parser talk to a real tailscaled.
//
//   bun observe-status.js <socket> <probe-ip> <probe-port>
import { parseLocalApiStatus } from "@ark-stack/shared";

import { probeThroughLocalApi, readLocalApiStatus } from "../../server/src/modules/tailnet-localapi.ts";

const [socket = "", ip = "100.64.0.1", port = "80"] = process.argv.slice(2);
const result: Record<string, unknown> = { uid: process.getuid?.() };
try {
  const status = (await readLocalApiStatus(socket)) as { BackendState?: string };
  result.backendState = status.BackendState;
  const parsed = parseLocalApiStatus(status, { generation: "gen_probe" });
  result.parsed = parsed.ok
    ? {
        ok: true,
        self: { tags: parsed.self.tags, dnsName: parsed.self.dnsName },
        peers: parsed.peers.map((peer) => ({ stableId: peer.stableId, ipv4: peer.ipv4 })),
      }
    : { ok: false, reason: parsed.reason };
} catch (error) {
  result.statusError = (error as Error).message;
}
result.probe = await probeThroughLocalApi(socket, ip, Number(port), 3_000);
console.log(JSON.stringify(result));
