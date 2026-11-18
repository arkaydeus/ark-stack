// Test-only TCP relay for scripts/test-e2e-gate.ts: listens on :3000 as `api` on the edge's admin
// network and forwards every connection, unchanged, to the real Ark API on the host
// (`RELAY_TARGET`, for example `host.docker.internal:32123`).
import type { Socket } from "bun";

const [host = "host.docker.internal", port = "3000"] = (process.env.RELAY_TARGET ?? "").split(":");

/** One side of a relayed connection: its peer, and bytes not yet accepted by this socket. */
type Side = { peer?: Socket<Side>; out: Uint8Array[]; closed: boolean };

function send(socket: Socket<Side>, chunk: Uint8Array) {
  if (socket.data.out.length) {
    socket.data.out.push(chunk);
    return;
  }
  const written = socket.write(chunk);
  if (written < chunk.byteLength) socket.data.out.push(chunk.subarray(Math.max(0, written)));
}

function flush(socket: Socket<Side>) {
  while (socket.data.out.length) {
    const chunk = socket.data.out[0]!;
    const written = socket.write(chunk);
    if (written < chunk.byteLength) {
      socket.data.out[0] = chunk.subarray(Math.max(0, written));
      return;
    }
    socket.data.out.shift();
  }
  if (socket.data.closed) socket.end();
}

function finish(socket?: Socket<Side>) {
  if (!socket) return;
  socket.data.closed = true;
  if (!socket.data.out.length) socket.end();
}

Bun.listen<Side>({
  hostname: "0.0.0.0",
  port: 3000,
  socket: {
    open(client) {
      client.data = { out: [], closed: false };
      const early: Uint8Array[] = [];
      (client.data as Side & { early?: Uint8Array[] }).early = early;
      void Bun.connect<Side>({
        hostname: host,
        port: Number(port),
        socket: {
          open(upstream) {
            upstream.data = { peer: client, out: [], closed: false };
            client.data.peer = upstream;
            for (const chunk of early) send(upstream, chunk);
            early.length = 0;
          },
          data(upstream, chunk) {
            if (upstream.data.peer) send(upstream.data.peer, new Uint8Array(chunk));
          },
          drain: flush,
          close(upstream) {
            finish(upstream.data.peer);
          },
          error(upstream) {
            finish(upstream.data.peer);
          },
        },
      }).catch(() => client.end());
    },
    data(client, chunk) {
      const bytes = new Uint8Array(chunk);
      if (client.data.peer) send(client.data.peer, bytes);
      else (client.data as Side & { early?: Uint8Array[] }).early?.push(bytes);
    },
    drain: flush,
    close(client) {
      finish(client.data.peer);
    },
    error(client) {
      finish(client.data.peer);
    },
  },
});

console.log(`tcp relay :3000 -> ${host}:${port}`);
