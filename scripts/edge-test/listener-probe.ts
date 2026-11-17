// Test-only listener prober for `mise run test:edge`. Runs in the pinned Bun image inside the edge-ts
// network namespace (`--network container:<edge-ts>`), so it reaches Caddy's loopback-only HTTPS
// listener directly, without HAProxy's connect handling in between. It opens a plain TCP connection
// every `intervalMs` and prints one JSON line whenever the listener's state changes:
//
//   bun listener-probe.ts <host> <port> [intervalMs]
//   {"state":"open"} | {"state":"closed","code":"ECONNREFUSED"}
//
// The host side (`listener.ts`) timestamps each line on receipt. A connection that opens is closed at
// once, before any PROXY header; Caddy drops it without serving anything.
import { connect } from "node:net";

const [host = "127.0.0.1", portText = "8443", intervalText = "50"] = process.argv.slice(2);
const port = Number(portText);
const intervalMs = Number(intervalText);

function attempt() {
  return new Promise<{ state: "open" | "closed"; code?: string }>((resolve) => {
    const socket = connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ state: "closed", code: "ETIMEDOUT" });
    }, 500);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      resolve({ state: "open" });
    });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      resolve({ state: "closed", code: error.code ?? error.message });
    });
  });
}

let last = "";
for (;;) {
  const result = await attempt();
  if (result.state !== last) {
    last = result.state;
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }
  await Bun.sleep(intervalMs);
}
