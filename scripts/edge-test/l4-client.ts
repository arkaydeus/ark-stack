// Test-only network client for `mise run test:edge` (FD-25). Runs in the pinned Bun image on a Docker
// network attached to edge-ts (or in its namespace), so the edge sees this container's own address.
// Every command prints one JSON line.
//
//   https <host> <port> <sni> <hostHeader> <path> [headersJSON] [method]
//                                                   HTTPS request; status, headers, body
//   tls <host> <port> <sni>                         TLS handshake without a PROXY header
//   tcp <host> <port>                               plain TCP connect
//   send <host> <port> <base64> <waitMs>            raw bytes; what came back and whether it closed
import { request } from "node:https";
import { connect as netConnect } from "node:net";
import { networkInterfaces } from "node:os";
import { connect as tlsConnect } from "node:tls";

const [command = "", host = "", portText = "", ...rest] = process.argv.slice(2);
const port = Number(portText);

function https(sni: string, hostHeader: string, path: string, extra: Record<string, string>, method: string) {
  return new Promise((resolve) => {
    const req = request(
      {
        host,
        port,
        servername: sni,
        path,
        method,
        headers: { ...extra, host: hostHeader },
        rejectUnauthorized: false,
        timeout: 5_000,
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => (body += chunk));
        response.on("end", () =>
          resolve({ status: response.statusCode, headers: response.headers, body: body.slice(0, 4_000) }),
        );
      },
    );
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", (error: NodeJS.ErrnoException) =>
      resolve({ status: 0, error: error.message, code: error.code ?? null }),
    );
    req.end(method === "GET" ? undefined : "{}");
  });
}

function tls(sni: string) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = tlsConnect({ host, port, servername: sni, rejectUnauthorized: false, timeout: 5_000 });
    socket.on("secureConnect", () => {
      resolve({ handshake: true, ms: Date.now() - started });
      socket.destroy();
    });
    socket.on("timeout", () => socket.destroy(new Error("timed out")));
    socket.on("error", (error: NodeJS.ErrnoException) =>
      resolve({ handshake: false, error: error.message, code: error.code ?? null, ms: Date.now() - started }),
    );
  });
}

function tcp() {
  return new Promise((resolve) => {
    const socket = netConnect({ host, port, timeout: 3_000 });
    socket.on("connect", () => {
      resolve({ connected: true });
      socket.destroy();
    });
    socket.on("timeout", () => socket.destroy(new Error("timed out")));
    socket.on("error", (error: NodeJS.ErrnoException) =>
      resolve({ connected: false, code: error.code ?? null, error: error.message }),
    );
  });
}

function send(payload: Buffer, waitMs: number) {
  return new Promise((resolve) => {
    const started = Date.now();
    const chunks: Buffer[] = [];
    let closed = false;
    const socket = netConnect({ host, port });
    const finish = () =>
      resolve({
        response: Buffer.concat(chunks).toString("latin1").slice(0, 2_000),
        closed,
        ms: Date.now() - started,
      });
    const timer = setTimeout(() => {
      socket.destroy();
      finish();
    }, waitMs);
    socket.on("connect", () => socket.write(payload));
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("close", () => {
      closed = true;
      clearTimeout(timer);
      finish();
    });
    socket.on("error", () => undefined);
  });
}

const result =
  command === "https"
    ? await https(rest[0]!, rest[1]!, rest[2] ?? "/", JSON.parse(rest[3] ?? "{}"), rest[4] ?? "GET")
    : command === "tls"
      ? await tls(rest[0]!)
      : command === "tcp"
        ? await tcp()
        : command === "send"
          ? await send(Buffer.from(rest[0]!, "base64"), Number(rest[1] ?? 3_000))
          : { error: `unknown command ${command}` };
// This container's own IPv4 addresses, so the caller can compare them with what the edge forwarded.
const self = Object.values(networkInterfaces())
  .flat()
  .filter((item) => item && item.family === "IPv4" && !item.internal)
  .map((item) => item!.address);
console.log(JSON.stringify({ ...(result as object), self }));
