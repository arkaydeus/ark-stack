// Test-only client agent for the FD-14 runtime suite (`mise run test:edge`). It runs in the pinned Bun
// image with a fixed address on a client network attached to edge-ts, so HAProxy sees that source,
// and holds TLS or TCP sessions through the edge for the harness, which drives it over HTTP:
//
//   POST /open  {host, port, tls?: {servername, cert?, key?}, fragment?, hold?}
//               -> {id, ok, error?, peerCN?, ms}   connect, handshake, then prove the relay by echo
//   POST /echo  {id, message} -> {echoed}           is a held session still relayed?
//   GET  /state -> {sessions: {id: {closed}}}       which held sessions have been closed
//   POST /close {ids?}                               close held sessions (all without ids)
//
// `fragment` sends the ClientHello (the first 2 KiB) in pieces of that many bytes, 40 ms apart,
// through a local relay, so the edge must buffer a fragmented ClientHello before selecting SNI.
import { connect as netConnect, createServer, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";

type Held = { socket: Socket | TLSSocket; closed: boolean };
const sessions = new Map<string, Held>();
let counter = 0;

/** A one-connection local relay that fragments the first 2 KiB from the client. */
function fragmentingRelay(host: string, port: number, size: number) {
  return new Promise<number>((resolve) => {
    const server = createServer((client) => {
      server.close();
      const upstream = netConnect({ host, port });
      let sent = 0;
      let queue = Promise.resolve();
      client.on("data", (chunk: Buffer) => {
        queue = queue.then(async () => {
          for (let offset = 0; offset < chunk.length;) {
            const piece = sent < 2048 ? Math.min(size, chunk.length - offset) : chunk.length - offset;
            upstream.write(chunk.subarray(offset, offset + piece));
            offset += piece;
            sent += piece;
            if (sent < 2048) await Bun.sleep(40);
          }
        });
      });
      upstream.on("data", (chunk) => client.write(chunk));
      const end = () => {
        client.destroy();
        upstream.destroy();
      };
      upstream.on("close", end);
      client.on("close", end);
      upstream.on("error", end);
      client.on("error", end);
    });
    server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
  });
}

async function open(input: {
  host: string;
  port: number;
  tls?: { servername: string; cert?: string; key?: string };
  fragment?: number;
  hold?: boolean;
}) {
  const started = Date.now();
  const id = `s${++counter}`;
  const host = input.fragment ? "127.0.0.1" : input.host;
  const port = input.fragment ? await fragmentingRelay(input.host, input.port, input.fragment) : input.port;
  return new Promise<Record<string, unknown>>((resolve) => {
    let settled = false;
    let socket: Socket | TLSSocket;
    const finish = (result: Record<string, unknown>) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ id, ms: Date.now() - started, ...result });
      if (!result.ok || !input.hold) socket.destroy();
    };
    const timer = setTimeout(() => finish({ ok: false, error: "timed out" }), 8_000);
    const ready = () => {
      const held: Held = { socket, closed: false };
      socket.on("close", () => (held.closed = true));
      const message = `hello-${id}`;
      socket.once("data", (chunk: Buffer) => {
        const echoed = chunk.toString("utf8");
        if (echoed !== message)
          return finish({ ok: false, error: `unexpected reply ${JSON.stringify(echoed.slice(0, 60))}` });
        if (input.hold) sessions.set(id, held);
        const peer = "getPeerCertificate" in socket ? (socket as TLSSocket).getPeerCertificate() : null;
        finish({ ok: true, peerCN: peer?.subject?.CN ?? null });
      });
      socket.write(message);
    };
    if (input.tls) {
      socket = tlsConnect({
        host,
        port,
        servername: input.tls.servername,
        rejectUnauthorized: false,
        ...(input.tls.cert ? { cert: input.tls.cert, key: input.tls.key } : {}),
      });
      socket.on("secureConnect", ready);
    } else {
      socket = netConnect({ host, port });
      socket.on("connect", ready);
    }
    socket.on("error", (error: NodeJS.ErrnoException) =>
      finish({ ok: false, error: error.code ?? error.message }),
    );
    socket.on("close", () => finish({ ok: false, error: "closed" }));
  });
}

Bun.serve({
  hostname: "0.0.0.0",
  port: 9000,
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (request.method === "POST" && pathname === "/open")
      return Response.json(await open(await request.json()));
    if (request.method === "POST" && pathname === "/echo") {
      const { id, message } = (await request.json()) as { id: string; message: string };
      const held = sessions.get(id);
      if (!held || held.closed) return Response.json({ echoed: null });
      const echoed = await new Promise<string | null>((resolve) => {
        const timer = setTimeout(() => resolve(null), 3_000);
        held.socket.once("data", (chunk: Buffer) => {
          clearTimeout(timer);
          resolve(chunk.toString("utf8"));
        });
        held.socket.write(message);
      });
      return Response.json({ echoed });
    }
    if (pathname === "/state") {
      return Response.json({
        sessions: Object.fromEntries([...sessions].map(([id, held]) => [id, { closed: held.closed }])),
      });
    }
    if (request.method === "POST" && pathname === "/close") {
      const { ids } = (await request.json().catch(() => ({}))) as { ids?: string[] };
      for (const [id, held] of sessions) {
        if (ids && !ids.includes(id)) continue;
        held.socket.destroy();
        sessions.delete(id);
      }
      return Response.json({ ok: true });
    }
    return new Response("not found", { status: 404 });
  },
});
console.log("route agent listening on :9000");
