// Read-only client for the edge node's LocalAPI over the tailscaled unix socket (front door §3.6,
// R10). The domain worker mounts `ark_edge_ts_socket` read-only and runs as the non-root `bun` user,
// so tailscaled grants it read access only: the FD-06 deployment test shows status reads succeed
// while every state-changing endpoint (prefs, start, logout, serve-config, ...) answers 403.
// No Tailscale OAuth client or API key is used anywhere.
import { LOCALAPI_HOST, httpStatusLine, localApiDialRequest } from "@ark-stack/shared";

const MAX_STATUS_BYTES = 8 * 1024 * 1024;

export type ProbeResult = { ok: boolean; detail: string };

export type EdgeLocalApi = {
  status(): Promise<unknown>;
  /** TCP connect from the edge node's network namespace to `ip:port`. */
  probe(ip: string, port: number): Promise<ProbeResult>;
};

export function edgeSocketPath(env: Record<string, string | undefined> = process.env) {
  return env.ARK_EDGE_TS_SOCKET?.trim() || null;
}

/** `GET /localapi/v0/status` through the unix socket. */
export async function readLocalApiStatus(socket: string, timeoutMs = 10_000) {
  const response = await fetch(`http://${LOCALAPI_HOST}/localapi/v0/status`, {
    unix: socket,
    headers: { "Sec-Tailscale": "localapi" },
    signal: AbortSignal.timeout(timeoutMs),
  } as RequestInit);
  if (!response.ok) {
    throw new Error(`LocalAPI status returned ${response.status}: ${(await response.text()).slice(0, 200)}`);
  }
  const body = await response.text();
  if (body.length > MAX_STATUS_BYTES) throw new Error("LocalAPI status is too large.");
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new Error("LocalAPI status is not valid JSON.");
  }
}

/**
 * `POST /localapi/v0/dial` (the `tailscale nc` path): tailscaled opens the TCP connection from the
 * edge-ts namespace, the one Caddy and HAProxy share, so success means the edge can reach that exact
 * port through the tailnet policy. Netmap presence alone is never enough for `ready` (§3.2).
 */
export function probeThroughLocalApi(
  socket: string,
  ip: string,
  port: number,
  timeoutMs = 5_000,
): Promise<ProbeResult> {
  const request = localApiDialRequest(ip, port);
  return new Promise((resolve) => {
    let buffer = "";
    let settled = false;
    let connection: { end(): void } | undefined;
    const finish = (result: ProbeResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      connection?.end();
      resolve(result);
    };
    const timer = setTimeout(
      () => finish({ ok: false, detail: `no answer within ${timeoutMs} ms` }),
      timeoutMs,
    );
    Bun.connect({
      unix: socket,
      socket: {
        open(client) {
          connection = client;
          client.write(request);
        },
        data(_socket, chunk) {
          buffer += chunk.toString("latin1");
          const line = httpStatusLine(buffer);
          if (!line) {
            if (buffer.length > 16_384) finish({ ok: false, detail: "malformed LocalAPI answer" });
            return;
          }
          if (line.status === 101) {
            finish({ ok: true, detail: "connected" });
            return;
          }
          const body = buffer.split("\r\n\r\n")[1]?.trim();
          finish({ ok: false, detail: body ? `${line.line}: ${body.slice(0, 200)}` : line.line });
        },
        close() {
          finish({ ok: false, detail: buffer ? "connection closed before an answer" : "connection closed" });
        },
        error(_socket, error) {
          finish({ ok: false, detail: error.message });
        },
      },
    }).catch((error: Error) => finish({ ok: false, detail: `LocalAPI socket: ${error.message}` }));
  });
}

export function edgeLocalApi(socket: string): EdgeLocalApi {
  return {
    status: () => readLocalApiStatus(socket),
    probe: (ip, port) => probeThroughLocalApi(socket, ip, port),
  };
}
