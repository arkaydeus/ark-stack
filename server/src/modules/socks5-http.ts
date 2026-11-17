// One HTTP/1.1 request through a SOCKS5 proxy (RFC 1928, no authentication), for the home backup
// target's append-only canary (docs/design/front-door.md §3.18.3, FD-30). Bun's fetch cannot use a
// SOCKS5 proxy, and the canary must take exactly the path restic takes: backup-ts's SOCKS5 listener on
// the internal `backup-tailnet` network. The proxy is passed per request, never through the process
// environment, so no other request of the worker (S3, API, executors) can be proxied by it.
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";

import { backupSocksProxy, parseIpLiteral } from "@ark-stack/shared";

export type SocksHttpResponse = { status: number; headers: Record<string, string>; body: Uint8Array };

const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

const SOCKS_REPLIES: Record<number, string> = {
  1: "general failure",
  2: "connection not allowed by ruleset",
  3: "network unreachable",
  4: "host unreachable",
  5: "connection refused",
  6: "TTL expired",
  7: "command not supported",
  8: "address type not supported",
};

function socksAddress(host: string) {
  const ip = parseIpLiteral(host);
  if (ip?.version === 4) return Buffer.from([1, ...ip.bytes]);
  if (ip?.version === 6) return Buffer.from([4, ...ip.bytes]);
  const name = Buffer.from(host, "ascii");
  if (name.length > 255) throw new Error("Host name is too long for SOCKS5.");
  return Buffer.concat([Buffer.from([3, name.length]), name]);
}

/** Opens a TCP connection to `host:port` through the SOCKS5 proxy. */
export function socks5Connect(
  proxy: string,
  host: string,
  port: number,
  timeoutMs: number,
  signal?: AbortSignal,
) {
  signal?.throwIfAborted();
  const configured = backupSocksProxy(proxy);
  // Test-only (scripts/test-backups-tailnet.ts): the harness process runs outside Docker and reaches
  // backup-ts's SOCKS5 port through a loopback publish; never set in production.
  const dial = process.env.ARK_TEST_SOCKS5_DIAL?.trim().match(/^([\w.-]+):(\d+)$/);
  const proxyHost = dial ? dial[1]! : configured.host;
  const proxyPort = dial ? Number(dial[2]) : configured.port;
  return new Promise<Socket>((resolve, reject) => {
    const socket = netConnect({ host: proxyHost, port: proxyPort });
    let stage: "greeting" | "connect" = "greeting";
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(
      () => fail(new Error(`SOCKS5 proxy did not connect within ${timeoutMs} ms`)),
      timeoutMs,
    );
    const onAbort = () => fail(signal?.reason ?? new Error("SOCKS5 request aborted"));
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    const fail = (error: Error) => {
      cleanup();
      socket.destroy();
      reject(error);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    socket.once("close", () => fail(new Error("SOCKS5 connection closed during handshake.")));
    socket.once("error", (error) =>
      fail(new Error(`SOCKS5 proxy ${proxyHost}:${proxyPort}: ${error.message}`)),
    );
    socket.once("connect", () => socket.write(Buffer.from([5, 1, 0])));
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (stage === "greeting") {
        if (buffer.length < 2) return;
        if (buffer[0] !== 5 || buffer[1] !== 0) return fail(new Error("SOCKS5 proxy refused no-auth."));
        buffer = buffer.subarray(2);
        stage = "connect";
        const portBytes = Buffer.from([(port >> 8) & 0xff, port & 0xff]);
        socket.write(Buffer.concat([Buffer.from([5, 1, 0]), socksAddress(host), portBytes]));
        return;
      }
      if (buffer.length < 5) return;
      if (buffer[0] !== 5) return fail(new Error("Malformed SOCKS5 reply."));
      if (buffer[1] !== 0)
        return fail(
          new Error(`SOCKS5 connect to ${host}:${port} failed: ${SOCKS_REPLIES[buffer[1]!] ?? buffer[1]}`),
        );
      const kind = buffer[3];
      const length = kind === 1 ? 10 : kind === 4 ? 22 : kind === 3 ? 7 + buffer[4]! : -1;
      if (length < 0) return fail(new Error("Malformed SOCKS5 reply address."));
      if (buffer.length < length) return;
      cleanup();
      socket.removeAllListeners("close");
      socket.off("data", onData);
      socket.removeAllListeners("error");
      if (buffer.length > length) socket.unshift(buffer.subarray(length));
      resolve(socket);
    };
    socket.on("data", onData);
  });
}

function decodeChunked(body: Buffer) {
  const parts: Buffer[] = [];
  let offset = 0;
  while (offset < body.length) {
    const end = body.indexOf("\r\n", offset);
    if (end < 0) break;
    const size = Number.parseInt(body.subarray(offset, end).toString("latin1").split(";")[0]!, 16);
    if (!Number.isFinite(size) || size === 0) break;
    parts.push(body.subarray(end + 2, end + 2 + size));
    offset = end + 2 + size + 2;
  }
  return Buffer.concat(parts);
}

/**
 * Sends one request to `url` through the SOCKS5 proxy, connecting to `connectHost` (the pinned
 * address) while keeping the URL's Host header and, for https, its certificate name.
 */
export async function socks5HttpRequest(input: {
  proxy: string;
  url: string;
  connectHost?: string;
  method: string;
  headers?: Record<string, string>;
  body?: Uint8Array | string;
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<SocksHttpResponse> {
  const url = new URL(input.url);
  const https = url.protocol === "https:";
  const port = Number(url.port || (https ? 443 : 80));
  const timeoutMs = input.timeoutMs ?? 30_000;
  const host = input.connectHost ?? url.hostname.replace(/^\[|\]$/g, "");
  // One deadline covers TCP, SOCKS negotiation, TLS and the complete HTTP response.
  const controller = new AbortController();
  let socket: Socket | undefined;
  const abort = () => controller.abort(input.signal?.reason ?? new Error("HTTP request aborted"));
  input.signal?.addEventListener("abort", abort, { once: true });
  if (input.signal?.aborted) abort();
  const timer = setTimeout(
    () => controller.abort(new Error(`No HTTP answer from ${url.host} within ${timeoutMs} ms`)),
    timeoutMs,
  );
  let onAbort: () => void;
  const cancelled = new Promise<never>((_, reject) => {
    onAbort = () => {
      socket?.destroy();
      reject(controller.signal.reason);
    };
    controller.signal.addEventListener("abort", onAbort, { once: true });
    if (controller.signal.aborted) onAbort();
  });
  const request = async (): Promise<SocksHttpResponse> => {
    controller.signal.throwIfAborted();
    socket = await socks5Connect(input.proxy, host, port, timeoutMs, controller.signal);
    controller.signal.throwIfAborted();
    if (https) {
      const raw = socket;
      socket = tlsConnect({ socket: raw, servername: url.hostname });
      const secure = socket;
      await new Promise<void>((resolve, reject) => {
        secure.once("secureConnect", resolve);
        secure.once("error", reject);
        secure.once("close", () => reject(new Error("TLS connection closed during handshake.")));
      });
    }
    controller.signal.throwIfAborted();
    const connection = socket;
    const body = input.body === undefined ? Buffer.alloc(0) : Buffer.from(input.body);
    const head = [
      `${input.method} ${url.pathname}${url.search} HTTP/1.1`,
      `Host: ${url.host}`,
      "Connection: close",
      `Content-Length: ${body.length}`,
      ...Object.entries(input.headers ?? {}).map(([name, value]) => `${name}: ${value}`),
      "",
      "",
    ].join("\r\n");
    return new Promise<SocksHttpResponse>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      connection.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          connection.destroy();
          return reject(new Error("HTTP response is too large."));
        }
        chunks.push(chunk);
      });
      connection.once("error", reject);
      connection.once("close", () => {
        const all = Buffer.concat(chunks);
        const split = all.indexOf("\r\n\r\n");
        if (split < 0) return reject(new Error(`Connection to ${url.host} closed without an HTTP answer.`));
        const [statusLine = "", ...lines] = all.subarray(0, split).toString("latin1").split("\r\n");
        const match = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine);
        if (!match) return reject(new Error(`Malformed HTTP status line: ${statusLine.slice(0, 80)}`));
        const headers = Object.fromEntries(
          lines.map((line) => {
            const index = line.indexOf(":");
            return [line.slice(0, index).trim().toLowerCase(), line.slice(index + 1).trim()];
          }),
        );
        let payload = all.subarray(split + 4);
        if (/chunked/i.test(headers["transfer-encoding"] ?? "")) payload = decodeChunked(payload);
        resolve({ status: Number(match[1]), headers, body: new Uint8Array(payload) });
      });
      connection.write(Buffer.concat([Buffer.from(head, "latin1"), body]));
    });
  };
  try {
    return await Promise.race([request(), cancelled]);
  } finally {
    clearTimeout(timer);
    input.signal?.removeEventListener("abort", abort);
    controller.signal.removeEventListener("abort", onAbort!);
    socket?.destroy();
  }
}
