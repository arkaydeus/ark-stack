import { once } from "node:events";
import { createConnection, type Socket } from "node:net";
import { connect as connectTls } from "node:tls";

import postgres from "postgres";
import {
  IPV6_PREFLIGHT_HTTP_PATH,
  ipv6ProbeRequest,
  publicIpv6,
  secureEqual,
  signIpv6Report,
  type Ipv6ProbeCheck,
  type Ipv6ProbeReport,
  type Ipv6ProbeRequest,
} from "@ark-stack/shared";

export type ProbeCredential = {
  ca?: string;
  cert?: string;
  key?: string;
  username?: string;
  password?: string;
  database?: string;
};

const timeoutMs = 8_000;
const sslRequest = Buffer.from("0000000804d2162f", "hex");

async function probe(
  request: Ipv6ProbeRequest,
  check: Ipv6ProbeCheck,
  credential?: ProbeCredential,
): Promise<Ipv6ProbeReport["checks"][number]> {
  const id = check.id;
  const database = check.protocol === "postgres-classic" || check.protocol === "postgres-direct";
  if (
    (database &&
      (!credential?.username ||
        !credential.database ||
        (!credential.password && !(credential.cert && credential.key)))) ||
    (check.clientCertificate && !(credential?.cert && credential.key))
  ) {
    return { id, outcome: "unverified", reason: "credentials" };
  }

  const socket = createConnection({ host: request.address, port: check.port, family: 6 });
  // The same deadline covers connect, negotiation and the authenticated database query.
  const timer = setTimeout(() => socket.destroy(new Error("Probe timed out")), timeoutMs);
  socket.on("error", () => undefined);
  let reason: "connection" | "http" | "tls" | "postgres" = "connection";
  let transport: Socket = socket;
  try {
    await once(socket, "connect");
    const source = publicIpv6(socket.localAddress);
    const sourcePort = socket.localPort;
    if (!source || !sourcePort) throw new Error("The probe has no global IPv6 source.");

    if (check.protocol === "http") {
      reason = "http";
      const path = IPV6_PREFLIGHT_HTTP_PATH + request.id;
      const chunks: Buffer[] = [];
      let size = 0;
      socket.write(`GET ${path} HTTP/1.1\r\nHost: ${check.hostname}\r\nConnection: close\r\n\r\n`);
      for await (const chunk of socket) {
        size += chunk.length;
        if (size > 8_192) throw new Error("Unexpected HTTP response.");
        chunks.push(chunk);
      }
      const [headers, body] = Buffer.concat(chunks).toString().split("\r\n\r\n");
      const missing = /^HTTP\/1\.[01] 404\b/.test(headers ?? "") && body === "Ark Stack challenge edge";
      const redirect =
        /^HTTP\/1\.[01] 30[1278]\b/.test(headers ?? "") &&
        headers
          ?.split("\r\n")
          .some(
            (header) =>
              header.toLowerCase().startsWith("location:") &&
              header.slice(9).trim() === `https://${check.hostname}${path}`,
          );
      if (!missing && !redirect) throw new Error("Unexpected HTTP response.");
    } else if (check.protocol === "tcp") {
      // A completed handshake can come from HAProxy even when its ACL or backend refuses the
      // client. The result is accepted only with the matching HAProxy backend-connect log.
      await Promise.race([Bun.sleep(250), once(socket, "close")]);
    } else {
      reason = "tls";
      if (check.protocol === "postgres-classic") {
        socket.write(sslRequest);
        const [response] = await Promise.race([
          once(socket, "data"),
          once(socket, "close").then(() => {
            throw new Error("SSLRequest was refused.");
          }),
        ]);
        if (!Buffer.isBuffer(response) || response.length !== 1 || response[0] !== 0x53) {
          throw new Error("The server declined PostgreSQL TLS.");
        }
      }
      const tls = connectTls({
        socket,
        servername: check.hostname,
        rejectUnauthorized: true,
        ca: credential?.ca,
        cert: credential?.cert,
        key: credential?.key,
        ALPNProtocols: check.protocol === "postgres-direct" ? ["postgresql"] : undefined,
      });
      transport = tls;
      tls.on("error", () => undefined);
      await Promise.race([
        once(tls, "secureConnect"),
        once(tls, "close").then(() => {
          throw new Error("TLS was refused.");
        }),
      ]);
      if (check.protocol === "postgres-direct" && tls.alpnProtocol !== "postgresql") {
        throw new Error("The server did not negotiate PostgreSQL ALPN.");
      }

      if (database) {
        reason = "postgres";
        // postgres.js 3.4 accepts a connected custom socket at runtime.
        const options = {
          socket: async () => tls,
          host: check.hostname,
          username: credential!.username,
          password: credential!.password ?? "",
          database: credential!.database,
          ssl: false as const, // PostgreSQL runs over the already verified TLS transport above.
          max: 1,
          fetch_types: false,
          connect_timeout: timeoutMs / 1_000,
          connection: { application_name: "ark-ipv6-preflight" },
        };
        const sql = postgres(options);
        try {
          const [row] = await sql`SELECT 1 AS ready`;
          if (row?.ready !== 1) throw new Error("Unexpected PostgreSQL probe response.");
        } finally {
          await sql.end({ timeout: 1 });
        }
      }
    }
    return { id, outcome: "passed", source, sourcePort };
  } catch {
    return { id, outcome: "failed", reason };
  } finally {
    clearTimeout(timer);
    transport.destroy();
    socket.destroy();
  }
}

export async function runIpv6Probe(
  request: Ipv6ProbeRequest,
  credentials: Record<string, ProbeCredential> = {},
): Promise<Ipv6ProbeReport> {
  if (request.expiresAt < Date.now()) throw new Error("The IPv6 probe request expired.");
  const checks: Ipv6ProbeReport["checks"] = [];
  // Bound concurrent connections to the same listener and stay within its source rate limits.
  for (let index = 0; index < request.checks.length; index += 8) {
    checks.push(
      ...(await Promise.all(
        request.checks
          .slice(index, index + 8)
          .map((check) =>
            probe(request, check, Object.hasOwn(credentials, check.id) ? credentials[check.id] : undefined),
          ),
      )),
    );
  }
  return { id: request.id, checks };
}

async function loadCredentials() {
  const path = process.env.ARK_IPV6_PROBE_CREDENTIALS;
  return path ? ((await Bun.file(path).json()) as Record<string, ProbeCredential>) : {};
}

if (import.meta.main) {
  const [mode, file, callback] = process.argv.slice(2);
  const credentials = await loadCredentials();
  if (mode === "serve") {
    const token = process.env.ARK_OFFHOST_HEARTBEAT_TOKEN;
    const allowed = publicIpv6(process.env.ARK_IPV6_PROBE_ADDRESS);
    if (!token || !allowed) {
      throw new Error("Set ARK_OFFHOST_HEARTBEAT_TOKEN and ARK_IPV6_PROBE_ADDRESS to the approved host.");
    }
    let running = false;
    Bun.serve({
      hostname: process.env.ARK_IPV6_PROBE_BIND ?? "127.0.0.1",
      port: Number(process.env.ARK_IPV6_PROBE_PORT ?? 3106),
      maxRequestBodySize: 128 * 1024,
      idleTimeout: 120,
      async fetch(req) {
        if (req.method !== "POST" || new URL(req.url).pathname !== "/preflight") {
          return new Response(null, { status: 404 });
        }
        if (!secureEqual(req.headers.get("authorization") ?? "", "Bearer " + token)) {
          return new Response(null, { status: 401 });
        }
        const parsed = ipv6ProbeRequest.safeParse(await req.json().catch(() => null));
        if (
          !parsed.success ||
          publicIpv6(parsed.data.address) !== allowed ||
          parsed.data.expiresAt < Date.now()
        ) {
          return new Response(null, { status: 422 });
        }
        if (running) return new Response(null, { status: 409 });
        running = true;
        try {
          return Response.json(await runIpv6Probe(parsed.data, credentials));
        } finally {
          running = false;
        }
      },
    });
  } else if (mode === "run" && file) {
    const { request, token } = await Bun.file(file).json();
    const report = await runIpv6Probe(ipv6ProbeRequest.parse(request), credentials);
    const signed = { signature: signIpv6Report(report, token), report };
    if (!callback) {
      console.log(JSON.stringify(signed, null, 2));
    } else {
      const url = new URL("/api/settings/ipv6/preflight/result", callback);
      if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
        throw new Error("Use an HTTPS admin URL or a local SSH tunnel to submit the report.");
      }
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(signed),
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok)
        throw new Error(`Report submission failed (${response.status}): ${await response.text()}`);
      console.log(await response.text());
    }
  } else {
    throw new Error("Usage: ipv6-preflight-probe.ts serve | run <request.json> [admin-origin]");
  }
}
