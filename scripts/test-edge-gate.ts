// `mise run test:edge` (FD-11): the login gate's edge routing from docs/design/front-door.md §3.5 and
// §3.9, against the literal Caddyfile the production planner and renderer produce, on the shipped
// edge-ts, edge (Caddy 2.11.9 behind its launch guard) and edge-l4 (HAProxy on 443) services in a
// disposable Compose project. No database, tailnet login or Python is needed.
//
// The API behind the edge (`api:3000`) is scripts/edge-test/gate-api.ts: it records every request
// and answers the gate's edge handlers with the production policy from shared/src/gate.ts. A Docker
// network inside 100.64.0.0/10 stands in for the tailnet, with scripts/edge-test/upstream.ts as the
// protected upstream. The edge watchdog is the bundled production code, reading a lease served by
// this process. Covered, all through 443:
//
// - routing: `GET /.ark/gate/callback?…` reaches the API as `/api/gate/callback?…` with the query
//   unchanged, the genuine edge token and `X-Ark-Route`; `POST /.ark/gate/logout` as
//   `/api/gate/logout-route`; wrong methods are 405 and every other `/.ark/gate/*` path (check,
//   users, …) is 404, neither touching the API;
// - forward_auth: an unauthenticated HTML GET is redirected to the login origin, an XHR gets 401;
//   with a session the upstream sees `X-Ark-User`, never the gate cookie, the edge token or a forged
//   identity header;
// - the WebSocket Origin contract (sibling route refused with 403, the route itself and an approved
//   exception accepted, missing and `null` refused) and unsafe methods without the route's Origin;
// - the raw-URI bypass guard: traversal, semicolon, backslash, encoded and malformed variants under a
//   bypass path never reach a protected upstream path (400 or the login redirect);
// - revocation (§3.9.3): a forced reload of the identical configuration closes an open WebSocket
//   after the route's `stream_close_delay` with no other reload, and a route left out of the lease
//   (an overdue revocation) is withdrawn by the watchdog, closing its socket at once (fail closed).
//
// `ARK_EDGE_GATE_ONLY=<text>` runs only the tests whose name contains <text> (setup always runs).
import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { connect as tlsConnect } from "node:tls";

import {
  planEdge,
  type EdgeHttpRoute,
  type EdgeLeaseDocument,
  type EdgePolicyRoute,
  type WatchdogEvent,
} from "@ark-stack/shared";

import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { type EdgeStack, startEdgeStack } from "./edge-test/stack.ts";

const root = resolve(import.meta.dir, "..");
const fixtures = join(import.meta.dir, "edge-test");
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-gate-${suffix}-`));
const network = `ark-edge-gate-${suffix}`;
const runtime = new EdgeTestRuntime(directory, network, bunImage);
const removeSignalHandlers = runtime.installSignalHandlers();
const docker = (...args: string[]) => runtime.docker(...args);

const octet = 64 + (Number.parseInt(randomBytes(1).toString("hex"), 16) % 64);
const third = 1 + (Number.parseInt(randomBytes(1).toString("hex"), 16) % 250);
const peerSubnet = `100.${octet}.${third}.0/24`;
const peerIp = `100.${octet}.${third}.10`;
const peerNetwork = `ark-edge-gate-peer-${suffix}`;
const gateToken = randomBytes(24).toString("base64url");

// The §3.5 SSO example (www, with the /webhooks/* bypass) and a sibling SSO route on the same domain.
// The stream close delay is shortened from the 5m maximum so the revocation case runs in seconds;
// the renderer refuses anything above 5m on an SSO route (shared/src/edge-http.test.ts).
const streamCloseDelayMs = 8_000;
const wwwHost = "www.example.com";
const siblingHost = "b.example.com";
const approvedOrigin = "https://approved.example.com";
const routes: EdgeHttpRoute[] = [
  {
    id: "rt_k3x9",
    hostname: wwwHost,
    stableId: "nHOMEGATE",
    ip: peerIp,
    port: 3000,
    access: "sso",
    bypassPaths: ["/webhooks/*"],
    options: { streamCloseDelay: `${streamCloseDelayMs / 1000}s` },
    internalNames: ["home.tail1234.ts.net", "home"],
  },
  {
    id: "rt_b1",
    hostname: siblingHost,
    stableId: "nHOMEGATE",
    ip: peerIp,
    port: 3000,
    access: "sso",
    options: { streamCloseDelay: `${streamCloseDelayMs / 1000}s` },
  },
];
const policy: EdgePolicyRoute[] = routes.map(({ id, hostname, stableId, ip, port }) => ({
  id,
  kind: "http",
  hostname,
  stableId,
  ip,
  port,
}));
const aliceToken = randomBytes(32).toString("base64url");
const gateRoutes = {
  rt_k3x9: { host: wwwHost, bypassPaths: ["/webhooks/*"], allowedOrigins: [] },
  rt_b1: { host: siblingHost, bypassPaths: [], allowedOrigins: [approvedOrigin] },
};
const gateSessions = {
  [aliceToken]: { user: "usr_alice", email: "alice@example.com", routes: ["rt_k3x9", "rt_b1"] },
};

function fixturePlan() {
  const at = new Date();
  return planEdge({
    adminMode: "tailnet",
    endpoints: routes.map((route) => ({
      id: `end_${route.hostname}`,
      kind: "route",
      hostname: route.hostname,
      exposure: "public",
    })),
    certificates: routes.map((route) => ({
      endpointId: `end_${route.hostname}`,
      status: "issued",
      lastDeployedAt: at,
    })),
    httpRoutes: routes,
  });
}

type Report = { name: string; lines: string[] };

function expect(report: Report, condition: boolean, claim: string, observed: string) {
  if (!condition) throw new Error(`[${report.name}] FAILED: ${claim} (observed: ${observed})`);
  report.lines.push(`  ok  ${claim} [${observed}]`);
}

async function waitFor<T>(
  what: string,
  attempt: () => Promise<T | undefined>,
  timeoutMs = 30_000,
  stepMs = 200,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await attempt().catch(() => undefined);
    if (value !== undefined) return value;
    await Bun.sleep(stepMs);
  }
  throw new Error(`Timed out after ${timeoutMs} ms waiting for ${what}.`);
}

async function bundle(entry: string, name: string) {
  const outdir = join(directory, name);
  const built = await Bun.build({ entrypoints: [entry], target: "bun", outdir });
  if (!built.success) throw new Error(`Bundling ${entry} failed: ${built.logs.join("\n")}`);
  await chmod(outdir, 0o755);
  return outdir;
}

// ---- Lease API (the API's read-only lease endpoint, served by this process) ---------------------------

const watchdogToken = randomBytes(24).toString("base64url");
/** Route IDs the lease leaves out, as the API does for a revocation overdue by more than 5 s. */
const overdue = new Set<string>();
const events: WatchdogEvent[] = [];
const leaseApi = Bun.serve({
  hostname: "0.0.0.0",
  port: 0,
  async fetch(request) {
    if (request.headers.get("authorization") !== `Bearer ${watchdogToken}`)
      return new Response("no", { status: 401 });
    const { pathname } = new URL(request.url);
    if (pathname === "/api/internal/edge/lease") {
      const now = Date.now();
      const document: EdgeLeaseDocument = {
        now: new Date(now).toISOString(),
        lease: {
          generation: "gen-gate",
          completedAt: new Date(now - 1_000).toISOString(),
          validUntil: new Date(now + 360_000).toISOString(),
          valid: true,
        },
        routes: policy.filter((route) => !overdue.has(route.id)),
        revocations: [...overdue].map((routeId) => ({
          id: `grv_${routeId}`,
          routeId,
          createdAt: new Date(now - 6_000).toISOString(),
          overdue: true,
        })),
      };
      return Response.json(document);
    }
    if (pathname === "/api/internal/edge/watchdog-event") {
      events.push((await request.json()) as WatchdogEvent);
      return Response.json({ ok: true });
    }
    return new Response("not found", { status: 404 });
  },
});

// ---- Containers -----------------------------------------------------------------------------------------

let stack!: EdgeStack;
const bundles = { watchdog: "", writeEdge: "", api: "" };
const edgeDir = join(directory, "edge");
const certDir = join(directory, "certs");
const acmeDir = join(directory, "acme");
const apiName = `ark-edge-gate-api-${suffix}`;
const peerName = `ark-edge-gate-peer-${suffix}`;
let watchdogName = "";

function certificate(dir: string, host: string) {
  return `mkdir -p ${dir} && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=${host}" -addext "subjectAltName=DNS:${host}" -keyout ${dir}/privkey.pem -out ${dir}/fullchain.pem 2>/dev/null && chmod 600 ${dir}/privkey.pem`;
}

async function prepareFiles() {
  await mkdir(join(acmeDir, ".well-known", "acme-challenge"), { recursive: true });
  await mkdir(edgeDir);
  // Start from a configuration without tailnet routes; edge.apply below loads the real one.
  await Bun.write(
    join(edgeDir, "Caddyfile"),
    "{\n  admin edge-admin:2019\n  auto_https off\n}\n:80 {\n  respond 404\n}\n",
  );
  await Bun.write(join(edgeDir, "Caddyfile.closed"), await Bun.file(join(edgeDir, "Caddyfile")).text());
  await chmod(directory, 0o755);
  const script = [
    "set -e",
    ...routes.map((route) => certificate(`/out/certs/${route.hostname}`, route.hostname)),
    "chown -R 1000:1000 /out/certs /out/edge",
  ].join("\n");
  await docker("run", "--rm", "--user", "0:0", "--volume", `${directory}:/out`, bunImage, "sh", "-c", script);
}

async function startContainers() {
  runtime.networkCreated = true;
  await docker("network", "create", network);
  await docker("network", "create", "--subnet", peerSubnet, peerNetwork);
  bundles.api = await bundle(join(fixtures, "gate-api.ts"), "gate-api");
  bundles.watchdog = await bundle(join(root, "workers/src/edge-watchdog.ts"), "watchdog");
  bundles.writeEdge = await bundle(join(fixtures, "write-edge.ts"), "write-edge");
  runtime.containers.push(apiName);
  await docker(
    "run",
    "--detach",
    "--name",
    apiName,
    "--network",
    network,
    "--env",
    `ARK_EDGE_GATE_TOKEN=${gateToken}`,
    "--env",
    `GATE_ROUTES=${JSON.stringify(gateRoutes)}`,
    "--env",
    `GATE_SESSIONS=${JSON.stringify(gateSessions)}`,
    "--volume",
    `${bundles.api}:/api:ro`,
    bunImage,
    "bun",
    "/api/gate-api.js",
  );
  stack = await startEdgeStack({
    runtime,
    project: `ark-edge-gate-${suffix}`,
    directory,
    acmeDir,
    certDir,
    edgeDir,
    ports: ["127.0.0.1::80", "127.0.0.1::443", "127.0.0.1::41643/udp"],
    edgeEnvironment: { ARK_EDGE_GATE_TOKEN: gateToken },
    edgeTsCommand: [
      "tailscaled",
      "--state=mem:",
      "--socket=/var/run/tailscale/tailscaled.sock",
      "--port=41643",
      "--tun=tailscale0",
    ],
  });
  await docker("network", "connect", "--alias", "api", stack.networks.admin, apiName);
  await docker("network", "connect", peerNetwork, stack.edgeTs);
  runtime.containers.push(peerName);
  await docker(
    "run",
    "--detach",
    "--name",
    peerName,
    "--network",
    peerNetwork,
    "--ip",
    peerIp,
    "--volume",
    `${join(fixtures, "upstream.ts")}:/fixture/app.ts:ro`,
    bunImage,
    "bun",
    "/fixture/app.ts",
  );
  await startWatchdog();
}

/** The edge watchdog as shipped (uid 1000, read-only root, no capabilities), Caddy only. */
async function startWatchdog() {
  watchdogName = `ark-edge-gate-watchdog-${suffix}`;
  runtime.containers.push(watchdogName);
  await docker(
    "run",
    "--detach",
    "--name",
    watchdogName,
    "--user",
    "1000:1000",
    "--group-add",
    "4400",
    "--read-only",
    "--tmpfs",
    "/tmp",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--network",
    network,
    "--add-host",
    "host.docker.internal:host-gateway",
    "--env",
    `ARK_API_URL=http://host.docker.internal:${leaseApi.port}`,
    "--env",
    `ARK_EDGE_WATCHDOG_TOKEN=${watchdogToken}`,
    "--env",
    "ARK_EDGE_ADMIN_URL=http://edge-admin:2019",
    "--env",
    "ARK_EDGE_DIR=/var/lib/ark/edge",
    "--volume",
    `${edgeDir}:/var/lib/ark/edge`,
    "--volume",
    `${bundles.watchdog}:/watchdog:ro`,
    "--workdir",
    "/tmp",
    bunImage,
    "bun",
    "/watchdog/edge-watchdog.js",
  );
  await docker("network", "connect", "--alias", "edge-watchdog", stack.networks.edgeControl, watchdogName);
  await waitFor(
    "verified watchdog enforcement on Caddy",
    async () => {
      const status = await docker(
        "exec",
        watchdogName,
        "bun",
        "--eval",
        'const r = await fetch("http://127.0.0.1:2021/v1/supervise?proxy=caddy"); console.log(r.ok ? "ready" : "no")',
      );
      return status === "ready" ? true : undefined;
    },
    30_000,
    500,
  );
}

/** `edge.apply` as the domain worker runs it: the production writeEdge on edge-control (forced /load). */
async function edgeApply() {
  const output = await docker(
    "run",
    "--rm",
    "--network",
    stack.networks.edgeControl,
    "--user",
    "1000:1000",
    "--env",
    "HOME=/tmp",
    "--env",
    "ARK_EDGE_DIR=/edge",
    "--env",
    "ARK_EDGE_RELOAD_URL=http://edge-admin:2019",
    "--env",
    "ARK_ACME_WEBROOT=/var/lib/ark/acme",
    "--volume",
    `${bundles.writeEdge}:/harness:ro`,
    "--volume",
    `${edgeDir}:/edge`,
    "--workdir",
    "/tmp",
    bunImage,
    "bun",
    "/harness/write-edge.js",
    "write",
    JSON.stringify(fixturePlan()),
  );
  return JSON.parse(output) as { applied: boolean; httpRoutes: string[]; stoppedForStreams?: string[] };
}

type Seen = { method: string; uri: string; host: string; token: boolean; headers: Record<string, string> };
async function seenBy(container: string) {
  const output = await docker(
    "exec",
    container,
    "bun",
    "--eval",
    'console.log(JSON.stringify(await (await fetch("http://127.0.0.1:3000/__seen")).json()))',
  );
  return JSON.parse(output) as unknown[];
}
const apiSeen = async () => (await seenBy(apiName)) as Seen[];
const upstreamSeen = async () => (await seenBy(peerName)) as string[];

let httpsPort = 0;

type Reply = { status: number; headers: Record<string, string[]>; body: string };

/** One raw HTTP/1.1 request through the published 443 (HAProxy, then Caddy); the target is sent verbatim. */
function request(
  servername: string,
  target: string,
  options: { method?: string; headers?: Record<string, string>; body?: string } = {},
) {
  return new Promise<Reply>((resolveReply, reject) => {
    const socket = tlsConnect({
      host: "127.0.0.1",
      port: httpsPort,
      servername,
      rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"],
    });
    let data = "";
    const timer = setTimeout(() => socket.destroy(new Error("timed out")), 8_000);
    socket.on("secureConnect", () => {
      const headers = { Host: servername, Connection: "close", ...options.headers };
      if (options.body !== undefined)
        headers["Content-Length" as keyof typeof headers] = String(Buffer.byteLength(options.body));
      socket.write(
        `${options.method ?? "GET"} ${target} HTTP/1.1\r\n${Object.entries(headers)
          .map(([name, value]) => `${name}: ${value}`)
          .join("\r\n")}\r\n\r\n${options.body ?? ""}`,
      );
    });
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.on("close", () => {
      clearTimeout(timer);
      const [head = "", ...rest] = data.split("\r\n\r\n");
      const [statusLine = "", ...headerLines] = head.split("\r\n");
      const headers: Record<string, string[]> = {};
      for (const line of headerLines) {
        const index = line.indexOf(":");
        if (index > 0)
          (headers[line.slice(0, index).toLowerCase()] ??= []).push(line.slice(index + 1).trim());
      }
      resolveReply({ status: Number(statusLine.split(" ")[1] ?? 0), headers, body: rest.join("\r\n\r\n") });
    });
  });
}

const sessionCookie = `__Host-ark_gate=${aliceToken}`;

/** A WebSocket through 443 with explicit Origin and Cookie. Resolves with the upgrade status. */
async function websocket(servername: string, headers: Record<string, string>) {
  const socket = tlsConnect({
    host: "127.0.0.1",
    port: httpsPort,
    servername,
    rejectUnauthorized: false,
    ALPNProtocols: ["http/1.1"],
  });
  let closedAt: number | null = null;
  socket.on("close", () => (closedAt = Date.now()));
  socket.on("error", () => undefined);
  let buffer = Buffer.alloc(0);
  const waiters: Array<(text: string) => void> = [];
  const status = await new Promise<number>((resolveOpen, reject) => {
    const timer = setTimeout(() => reject(new Error("WebSocket upgrade timed out")), 8_000);
    socket.once("secureConnect", () =>
      socket.write(
        `GET /ws HTTP/1.1\r\nHost: ${servername}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${randomBytes(16).toString("base64")}\r\n${Object.entries(
          headers,
        )
          .map(([name, value]) => `${name}: ${value}\r\n`)
          .join("")}\r\n`,
      ),
    );
    const onHandshake = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf("\r\n\r\n");
      if (end < 0) return;
      clearTimeout(timer);
      socket.off("data", onHandshake);
      const head = buffer.subarray(0, end).toString("latin1");
      buffer = buffer.subarray(end + 4);
      const code = Number(head.split(" ")[1] ?? 0);
      if (code !== 101) {
        socket.destroy();
        return resolveOpen(code);
      }
      socket.on("data", (data: Buffer) => {
        buffer = Buffer.concat([buffer, data]);
        while (buffer.length >= 2) {
          const length = buffer[1]! & 0x7f;
          if (length > 125 || buffer.length < 2 + length) break;
          const opcode = buffer[0]! & 0x0f;
          const text = buffer.subarray(2, 2 + length).toString("utf8");
          buffer = buffer.subarray(2 + length);
          if (opcode === 0x1) waiters.shift()?.(text);
          if (opcode === 0x8) waiters.shift()?.("closed by server");
        }
      });
      resolveOpen(101);
    };
    socket.on("data", onHandshake);
  });
  const echo = (message: string) =>
    new Promise<string>((resolveEcho) => {
      if (closedAt !== null) return resolveEcho("closed");
      const timer = setTimeout(() => resolveEcho("no echo within 3 s"), 3_000);
      waiters.push((text) => {
        clearTimeout(timer);
        resolveEcho(text);
      });
      const payload = Buffer.from(message);
      const mask = randomBytes(4);
      const masked = Buffer.from(payload.map((byte, index) => byte ^ mask[index % 4]!));
      socket.write(Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]));
    });
  return { status, echo, closedAt: () => closedAt, end: () => socket.destroy() };
}

// ---- Tests -------------------------------------------------------------------------------------------------

async function routingTest(report: Report) {
  const before = (await apiSeen()).length;
  const query = "?code=Abc_123-xyz&state=S%2Ftate%3D1&extra=a+b";
  const callback = await request(wwwHost, `/.ark/gate/callback${query}`);
  const callbackBody = JSON.parse(callback.body || "{}") as { uri?: string; route?: string };
  expect(
    report,
    callback.status === 200 &&
      callbackBody.uri === `/api/gate/callback${query}` &&
      callbackBody.route === "rt_k3x9",
    "GET /.ark/gate/callback reaches the API as /api/gate/callback with the query unchanged and X-Ark-Route",
    `${callback.status} ${callbackBody.uri} route=${callbackBody.route}`,
  );
  const logout = await request(wwwHost, "/.ark/gate/logout", {
    method: "POST",
    headers: { Origin: `https://${wwwHost}`, "Content-Length": "0" },
  });
  const logoutBody = JSON.parse(logout.body || "{}") as { uri?: string; method?: string };
  expect(
    report,
    logout.status === 200 && logoutBody.uri === "/api/gate/logout-route" && logoutBody.method === "POST",
    "POST /.ark/gate/logout reaches the API as POST /api/gate/logout-route",
    `${logout.status} ${logoutBody.method} ${logoutBody.uri}`,
  );
  const seen = (await apiSeen()).slice(before);
  expect(
    report,
    seen.length === 2 && seen.every((item) => item.token && item.host === wwwHost),
    "both carried the genuine edge token and the route's public Host",
    seen.map((item) => `${item.method} ${item.uri} token=${item.token}`).join(", "),
  );
  const mark = (await apiSeen()).length;
  const wrong = await Promise.all([
    request(wwwHost, `/.ark/gate/callback${query}`, { method: "POST", headers: { "Content-Length": "0" } }),
    request(wwwHost, "/.ark/gate/logout"),
  ]);
  expect(
    report,
    wrong.every((reply) => reply.status === 405),
    "wrong callback and logout methods are 405",
    wrong.map((reply) => reply.status).join(","),
  );
  const unknown = [
    "/.ark/gate/check",
    "/.ark/gate/check?route=rt_k3x9",
    "/.ark/gate/users",
    "/.ark/gate/bypass-check",
    "/.ark/gate/logout-route",
    "/.ark/gate/",
    "/.ark/gate/callback/extra",
    "/.ark/gate/x/../users",
  ];
  const statuses: number[] = [];
  for (const path of unknown) statuses.push((await request(wwwHost, path)).status);
  expect(
    report,
    statuses.every((status) => status === 404),
    "every other /.ark/gate/* path, check and users included, is 404",
    unknown.map((path, index) => `${path}=${statuses[index]}`).join(" "),
  );
  const after = (await apiSeen()).length;
  expect(report, after === mark, "none of them touched the API", `${after - mark} API requests`);
  // An encoded traversal out of the namespace is not a /.ark/gate/* path to Caddy's matcher: it is
  // gated like any other path (forward_auth only), never rewritten onto /api/gate/*.
  const escape = await request(wwwHost, "/.ark/gate/%2e%2e/api/gate/users", {
    headers: { Accept: "application/json" },
  });
  const escapeSeen = (await apiSeen()).slice(after);
  expect(
    report,
    escape.status === 401 && escapeSeen.every((item) => item.uri.startsWith("/api/gate/check?")),
    "an encoded traversal out of /.ark/gate/ only reaches the session check, never /api/gate/users",
    `${escape.status} ${escapeSeen.map((item) => item.uri).join(", ")}`,
  );
}

async function forwardAuthTest(report: Report) {
  const html = await request(wwwHost, "/dashboard?tab=1", { headers: { Accept: "text/html" } });
  const location = new URL(html.headers.location?.[0] ?? "https://invalid/");
  expect(
    report,
    html.status === 302 &&
      location.host === "login.example.com" &&
      location.searchParams.get("rd") === "/dashboard?tab=1" &&
      (html.headers["set-cookie"]?.[0] ?? "").startsWith("__Host-ark_gate_state="),
    "an unauthenticated HTML GET is redirected to the login origin with the state cookie",
    `${html.status} ${location.href}`,
  );
  const xhr = await request(wwwHost, "/api/data", { headers: { Accept: "application/json" } });
  expect(
    report,
    xhr.status === 401 && xhr.headers["www-authenticate"]?.[0] === "Ark-Gate",
    "an XHR without a session gets 401, not a redirect",
    `${xhr.status} ${xhr.headers["www-authenticate"]?.[0]}`,
  );
  const headers = await request(wwwHost, "/headers", {
    headers: {
      Cookie: `theme=dark; ${sessionCookie}; __Host-ark_gate_state=zzz; other=1`,
      "X-Ark-User": "usr_forged",
      "X-Ark-Edge-Token": "forged-token",
      Accept: "application/json",
    },
  });
  const seen = JSON.parse(headers.body || "{}") as Record<string, string>;
  expect(
    report,
    headers.status === 200 &&
      seen["x-ark-user"] === "usr_alice" &&
      seen["x-ark-email"] === "alice@example.com" &&
      !("x-ark-edge-token" in seen) &&
      !(seen.cookie ?? "").includes("ark_gate") &&
      (seen.cookie ?? "").includes("theme=dark") &&
      (seen.cookie ?? "").includes("other=1"),
    "with a session the upstream sees X-Ark-User and its own cookies, never the gate cookies, the edge token or a forged identity",
    `${headers.status} user=${seen["x-ark-user"]} cookie=${JSON.stringify(seen.cookie)} token=${"x-ark-edge-token" in seen}`,
  );
  const check = (await apiSeen()).filter((item) => item.uri.startsWith("/api/gate/check")).at(-1);
  expect(
    report,
    Boolean(check?.token) && check?.headers["x-forwarded-uri"] === "/headers",
    "forward_auth calls /api/gate/check with the genuine edge token (a forged one never reaches the API)",
    `token=${check?.token} uri=${check?.headers["x-forwarded-uri"]}`,
  );
}

async function originTest(report: Report) {
  const cases: Array<[string, string, Record<string, string>, number]> = [
    [
      "a page on sibling route www opening an authenticated WebSocket to b",
      siblingHost,
      { Origin: `https://${wwwHost}`, Cookie: sessionCookie },
      403,
    ],
    ["b connecting to itself", siblingHost, { Origin: `https://${siblingHost}`, Cookie: sessionCookie }, 101],
    ["an approved origin exception", siblingHost, { Origin: approvedOrigin, Cookie: sessionCookie }, 101],
    ["a missing Origin", siblingHost, { Cookie: sessionCookie }, 403],
    ["a null Origin", siblingHost, { Origin: "null", Cookie: sessionCookie }, 403],
    ["a suffix origin", siblingHost, { Origin: `https://evil-${siblingHost}`, Cookie: sessionCookie }, 403],
    ["no session at all", siblingHost, { Origin: `https://${siblingHost}` }, 401],
  ];
  for (const [what, host, headers, wanted] of cases) {
    const socket = await websocket(host, headers);
    const echoed = socket.status === 101 ? await socket.echo("hi") : "";
    socket.end();
    expect(
      report,
      socket.status === wanted && (wanted !== 101 || echoed === "hi"),
      `WebSocket: ${what} -> ${wanted}`,
      `${socket.status}${echoed ? ` echo=${echoed}` : ""}`,
    );
  }
  const unsafe: Array<[string, Record<string, string>, number]> = [
    ["POST with the cookie and no Origin", { Cookie: sessionCookie }, 403],
    [
      "POST with the cookie from a sibling route",
      { Cookie: sessionCookie, Origin: `https://${wwwHost}` },
      403,
    ],
    [
      "POST with the cookie from the route itself",
      { Cookie: sessionCookie, Origin: `https://${siblingHost}` },
      200,
    ],
  ];
  for (const [what, headers, wanted] of unsafe) {
    const reply = await request(siblingHost, "/form", { method: "POST", headers, body: "a=1" });
    expect(report, reply.status === wanted, `${what} -> ${wanted}`, String(reply.status));
  }
}

async function bypassTest(report: Report) {
  const legit = await request(wwwHost, "/webhooks/github", { method: "POST", body: "{}" });
  expect(
    report,
    legit.status === 200,
    "a configured bypass path reaches the upstream without a session",
    String(legit.status),
  );
  const attempts = [
    "/webhooks/..;/admin",
    "/webhooks/..;/admin/secret",
    "/webhooks/../admin",
    "/webhooks/%2e%2e/admin",
    "/webhooks/%2E%2E/admin",
    "/webhooks/.%2e/admin",
    "/webhooks%2f..%2fadmin",
    "/webhooks/%2f../admin",
    "/webhooks/..%2fadmin",
    "/webhooks\\..\\admin",
    "/webhooks/..\\admin",
    "/webhooks/%5c..%5cadmin",
    "/webhooks/%5C..%5Cadmin",
    "/webhooks/%252e%252e/admin",
    "/webhooks/%25252e%25252e/admin",
    "/webhooks/%252f..%252fadmin",
    "/webhooks/%zz/admin",
    "/webhooks/%2/admin",
    "/webhooks/%/admin",
    "/webhooks/x;y/../../admin",
    "/WEBHOOKS/../admin",
    "/webhooks//../admin",
  ];
  const before = new Set(await upstreamSeen());
  const outcomes: string[] = [];
  for (const target of attempts) {
    const reply = await request(wwwHost, target, { headers: { Accept: "text/html" } }).catch((error) => ({
      status: 0,
      headers: {} as Record<string, string[]>,
      body: (error as Error).message,
    }));
    const login =
      reply.status === 302 && (reply.headers.location?.[0] ?? "").startsWith("https://login.example.com/");
    outcomes.push(`${target}=${reply.status}`);
    expect(
      report,
      reply.status === 400 || login || reply.status === 401,
      `bypass attempt ${target} -> 400 or the login redirect`,
      `${reply.status}`,
    );
  }
  const reached = (await upstreamSeen()).filter((path) => !before.has(path) && /admin/i.test(path));
  expect(
    report,
    reached.length === 0,
    "no bypass attempt reached a protected upstream path unauthenticated",
    reached.join(", ") || "none",
  );
}

async function revocationReloadTest(report: Report) {
  const socket = await websocket(wwwHost, { Origin: `https://${wwwHost}`, Cookie: sessionCookie });
  expect(
    report,
    socket.status === 101 && (await socket.echo("before")) === "before",
    "an authenticated WebSocket is open",
    String(socket.status),
  );
  // The revocation's forced reload: the identical configuration, /load with must-revalidate.
  const reloadAt = Date.now();
  const applied = await edgeApply();
  expect(
    report,
    applied.applied && !applied.stoppedForStreams,
    "the forced reload of the identical configuration is applied without stopping Caddy",
    JSON.stringify(applied),
  );
  // No other reload happens from here on; the old handler closes the stream after its delay.
  const closedAt = await waitFor(
    "the WebSocket to close after the forced reload",
    async () => socket.closedAt() ?? undefined,
    streamCloseDelayMs + 10_000,
    100,
  );
  const elapsed = closedAt - reloadAt;
  expect(
    report,
    elapsed <= streamCloseDelayMs + 5_000,
    `the socket closes by the reload + stream_close_delay (${streamCloseDelayMs} ms; 5m in production, so revocation + 305 s)`,
    `${elapsed} ms after the reload`,
  );
  const again = await websocket(wwwHost, { Origin: `https://${wwwHost}`, Cookie: sessionCookie });
  expect(
    report,
    again.status === 101,
    "a new upgrade is checked again and the route stays served",
    String(again.status),
  );
  again.end();
}

async function watchdogFailClosedTest(report: Report) {
  const socket = await websocket(wwwHost, { Origin: `https://${wwwHost}`, Cookie: sessionCookie });
  expect(
    report,
    socket.status === 101 && (await socket.echo("held")) === "held",
    "an authenticated WebSocket is open",
    String(socket.status),
  );
  // The revocation's reload did not happen within 5 s (worker killed, or the apply was rejected): the
  // API's lease leaves the route out, and the edge-local watchdog withdraws it on its own.
  const at = Date.now();
  overdue.add("rt_k3x9");
  const closedAt = await waitFor(
    "the watchdog to close the socket",
    async () => socket.closedAt() ?? undefined,
    15_000,
    100,
  );
  expect(
    report,
    closedAt - at <= 5_000,
    "the watchdog withdraws the route (stopping Caddy, whose old handler would keep the stream) and the socket closes",
    `${closedAt - at} ms`,
  );
  const withdrawn = await waitFor(
    "the route to stay withdrawn while the revocation is pending",
    async () => {
      const reply = await request(wwwHost, "/headers", { headers: { Cookie: sessionCookie } }).catch(
        () => null,
      );
      return reply && reply.status !== 200 ? reply.status : undefined;
    },
    30_000,
    500,
  );
  expect(
    report,
    withdrawn !== 200,
    "the route is not served while its revocation is overdue",
    String(withdrawn),
  );
  expect(
    report,
    events.some((event) => event.event === "withdrawn"),
    "the watchdog reports the withdrawal (the API raises the critical alert)",
    events.map((event) => event.event).join(",") || "none",
  );
  // The durable retry's forced reload succeeds: the API marks the revocation applied.
  overdue.delete("rt_k3x9");
  await waitFor(
    "the route to be served again after the revocation is applied",
    async () => {
      try {
        await edgeApply();
      } catch {
        return undefined;
      }
      const reply = await request(wwwHost, "/headers", { headers: { Cookie: sessionCookie } }).catch(
        () => null,
      );
      return reply?.status === 200 ? true : undefined;
    },
    60_000,
    2_000,
  );
  report.lines.push("  ok  the route is served again once the revocation is applied");
}

// ---- Runner -----------------------------------------------------------------------------------------------

const only = process.env.ARK_EDGE_GATE_ONLY ?? "";
const reports: Report[] = [];
async function run(name: string, test: (report: Report) => Promise<void>) {
  if (only && !name.includes(only)) return;
  const report: Report = { name, lines: [] };
  reports.push(report);
  console.log(`\n# ${name}`);
  try {
    await test(report);
  } finally {
    console.log(report.lines.join("\n"));
  }
}

let failed = false;
try {
  await prepareFiles();
  await startContainers();
  httpsPort = await stack.hostPort(443);
  const applied = await edgeApply();
  if (!applied.applied || applied.httpRoutes.join() !== "rt_b1,rt_k3x9")
    throw new Error(`edge.apply did not load both SSO routes: ${JSON.stringify(applied)}`);
  await waitFor("the SSO route through 443", async () => {
    const reply = await request(wwwHost, "/headers", { headers: { Cookie: sessionCookie } });
    return reply.status === 200 ? true : undefined;
  });
  await run("FD-11: callback and logout routing, wildcard 404", routingTest);
  await run("FD-11: forward_auth, identity headers and cookie stripping", forwardAuthTest);
  await run("FD-11: WebSocket Origin and CSRF contract", originTest);
  await run("FD-11: raw-URI bypass guard", bypassTest);
  await run("FD-11: revocation forced reload closes sockets", revocationReloadTest);
  await run("FD-11: overdue revocation, watchdog fail closed", watchdogFailClosedTest);
  console.log(`\nFD-11 edge gate tests passed (${reports.length} groups).`);
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  await runtime.dumpLogs();
} finally {
  leaseApi.stop(true);
  await runtime.cleanup();
  removeSignalHandlers();
}
process.exit(failed ? 1 : 0);
