// `mise run test:edge` (FD-25): the HAProxy SNI router (`edge-l4`) on 443 in front of Caddy, from
// docs/design/front-door.md §3.5, §3.8.5, §3.8.6 and §3.2, in disposable containers. No tailnet login,
// database or Python is needed.
//
// The shipped edge-ts, edge (Caddy behind its launch guard), edge-l4 (HAProxy 3.2.26 behind its launch
// guard) and haproxy-validator (built from the Dockerfile target) Compose services run in a disposable
// project; the edge-l4 configuration volume is seeded by the installer's edge-l4 step. The domain
// worker's side runs the production `writeEdgeL4` and HAProxy adapter, bundled, in the pinned Bun image
// as uid 1000 with `--group-add 4400`, no capabilities and no Docker access. The edge watchdog is the
// bundled production code with the HAProxy adapter enabled; it reads a lease served by this process.
// A Docker network inside 100.64.0.0/10 stands in for the tailnet.
//
// Covered: Caddy's §3.5 global block on the running edge; worker socket permissions, validation,
// refusal of invalid candidates, `show stat`, worker enumeration; PROXY v2 trust (headerless loopback
// TLS refused, real client address in X-Forwarded-For, no Docker peer reaches 8443, :80 never parses
// PROXY); SNI/Host 421; no Alt-Svc; every HTTP route through 443; idle and non-TLS rejection within
// 5 s; master-CLI reload Success=1/0 with old workers serving after a failed reload; a WebSocket across
// HAProxy and Caddy reloads; watchdog withdrawal of an HAProxy-routed tailnet backend on identity
// failure and on lease expiry across current and leaving workers, and the domain worker's own drain;
// the fail-closed HAProxy launch guard.
//
// FD-09 (§3.5) HTTP routes, rendered by the production planner and renderer and reached through 443:
// no Server/Via on success or 502; forged X-Forwarded-For and X-Ark-* never reach the upstream;
// Location (the §3.5 fixture table, compared with the reference evaluator) and Set-Cookie Domain
// rewriting; the static 502 for an unreachable upstream and for an unsupported Location, naming no
// tailnet host; the apex redirect and the :80 list; an enabled SSO route absent from both configs;
// and a WebSocket idle for more than 10 minutes that then survives one edge.apply.
import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { connect as netConnect } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { connect as tlsConnect, type TLSSocket } from "node:tls";

import {
  CADDY_GLOBAL_BLOCK,
  checkedHttpRoute,
  evaluateLocation,
  locationPolicy,
  planEdge,
  routeIdentityKey,
  servedHttpHostnames,
  type EdgeHttpRoute,
  type EdgeLeaseDocument,
  type EdgePolicyRoute,
  type WatchdogEvent,
} from "@ark-stack/shared";

import { composeImages, verifyImageIds } from "./install-edge-l4.ts";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { type EdgeStack, startEdgeStack } from "./edge-test/stack.ts";

const root = resolve(import.meta.dir, "..");
const fixtures = join(import.meta.dir, "edge-test");
const haproxyImage =
  "haproxy:3.2.26-alpine@sha256:1c3568e520453cc8ba98c39501febcf450429c80e6cc27ecad779961d76e597c";
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-l4-${suffix}-`));
const network = `ark-edge-l4-${suffix}`;
const runtime = new EdgeTestRuntime(directory, network, bunImage);
const removeSignalHandlers = runtime.installSignalHandlers();
const docker = (...args: string[]) => runtime.docker(...args);

const octet = 64 + (Number.parseInt(randomBytes(1).toString("hex"), 16) % 64);
const third = 1 + (Number.parseInt(randomBytes(1).toString("hex"), 16) % 250);
const peerSubnet = `100.${octet}.${third}.0/24`;
const peerHttpIp = `100.${octet}.${third}.10`;
const peerTlsIp = `100.${octet}.${third}.11`;
const peerNetwork = `ark-edge-l4-peer-${suffix}`;

const adminHost = "admin.example.com";
const appHost = "app.example.com";
const tailnetHost = "tailnet.example.com";
const wsHost = "ws.example.com";
const mqttHost = "mqtt.example.com";
// FD-09 routes (§3.5 example): www proxies to the peer, the apex redirects to www, broken dials a
// closed port, and sso is enabled with access_mode=sso, which this release must never serve.
const wwwHost = "www.example.com";
const apexHost = "example.com";
const brokenHost = "broken.example.com";
const ssoHost = "sso.example.com";

const webRoute: EdgePolicyRoute = {
  id: "rt_web1",
  kind: "http",
  hostname: tailnetHost,
  stableId: "nWEBL4",
  ip: peerHttpIp,
  port: 3000,
};
const mqttRoute: EdgePolicyRoute = {
  id: "rt_mq1",
  kind: "tls",
  hostname: mqttHost,
  stableId: "nMQTTL4",
  ip: peerTlsIp,
  port: 1883,
};
const mqttL4 = { ...mqttRoute, sourceCidrs: ["0.0.0.0/0"] };

/** The FD-09 routes as `edgeHttpRoutes` reads them from front_routes and the edge observation. */
const peerName = "peer-http.tail1234.ts.net";
const wwwRoute: EdgeHttpRoute = {
  id: "rt_www1",
  hostname: wwwHost,
  stableId: webRoute.stableId,
  ip: peerHttpIp,
  port: 3000,
  access: "public",
  // The observed MagicDNS names and the node's other address, as the coordinator passes them.
  internalNames: [peerName, "peer-http", "home.tail1234.ts.net"],
  internalIps: ["fd7a:115c:a1e0::6465:6667"],
};
const fd09Routes: EdgeHttpRoute[] = [
  {
    id: webRoute.id,
    hostname: tailnetHost,
    stableId: webRoute.stableId,
    ip: webRoute.ip,
    port: 3000,
    access: "public",
  },
  wwwRoute,
  { ...wwwRoute, id: "rt_apex1", hostname: apexHost, redirectTo: wwwHost },
  { ...wwwRoute, id: "rt_brk1", hostname: brokenHost, port: 3999 },
  { ...wwwRoute, id: "rt_sso1", hostname: ssoHost, access: "sso" },
];
/** Lease entries for every FD-09 route, SSO included: the lease alone never makes a route servable. */
const fd09Policy: EdgePolicyRoute[] = fd09Routes
  .filter((route) => route.id !== webRoute.id)
  .map(({ id, hostname, stableId, ip, port }) => ({ id, kind: "http", hostname, stableId, ip, port }));

/** `edge.apply`'s plan: the production planner over fixture endpoint, certificate and route rows. */
function fixturePlan() {
  const at = new Date();
  const rows = [
    { hostname: adminHost, kind: "admin" },
    { hostname: appHost, kind: "http" },
    ...fd09Routes.map((route) => ({ hostname: route.hostname, kind: "route" })),
  ];
  return planEdge({
    adminMode: "public",
    adminHostname: adminHost,
    endpoints: rows.map((row) => ({ id: `end_${row.hostname}`, exposure: "public", ...row })),
    // Every hostname, sso included, has an issued certificate on disk.
    certificates: rows.map((row) => ({
      endpointId: `end_${row.hostname}`,
      status: "issued",
      lastDeployedAt: at,
    })),
    httpRoutes: fd09Routes,
  });
}
/** `edge.l4_apply`'s HTTP hostnames, derived from the same plan as the coordinator does. */
const httpHosts = servedHttpHostnames(fixturePlan());

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
const lease = {
  validUntil: Number.POSITIVE_INFINITY,
  routes: [webRoute, mqttRoute, ...fd09Policy] as EdgePolicyRoute[],
};
const events: WatchdogEvent[] = [];
const api = Bun.serve({
  hostname: "0.0.0.0",
  port: 0,
  async fetch(request) {
    if (request.headers.get("authorization") !== `Bearer ${watchdogToken}`)
      return new Response("no", { status: 401 });
    const { pathname } = new URL(request.url);
    if (pathname === "/api/internal/edge/lease") {
      const now = Date.now();
      const valid = now < lease.validUntil;
      const document: EdgeLeaseDocument = {
        now: new Date(now).toISOString(),
        lease: {
          generation: "gen-l4",
          completedAt: new Date(now - 1_000).toISOString(),
          validUntil: new Date(
            Number.isFinite(lease.validUntil) ? lease.validUntil : now + 360_000,
          ).toISOString(),
          valid,
        },
        routes: valid ? lease.routes : [],
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
let watchdogName = "";
const bundles = { watchdog: "", writeEdge: "", probe: "", client: "" };
const edgeDir = join(directory, "edge");
const certDir = join(directory, "certs");
const acmeDir = join(directory, "acme");
const peerCertDir = join(directory, "peer-certs");
const upstream = `ark-edge-l4-upstream-${suffix}`;

function certificate(dir: string, host: string) {
  return `mkdir -p ${dir} && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=${host}" -addext "subjectAltName=DNS:${host}" -keyout ${dir}/privkey.pem -out ${dir}/fullchain.pem 2>/dev/null && chmod 600 ${dir}/privkey.pem`;
}

async function prepareFiles() {
  await mkdir(join(acmeDir, ".well-known", "acme-challenge"), { recursive: true });
  await mkdir(edgeDir);
  await mkdir(peerCertDir);
  await Bun.write(
    join(edgeDir, "Caddyfile"),
    `{\n  admin edge-admin:2019\n  auto_https off\n}\n${adminHost} {\n  tls /var/lib/ark/certs/${adminHost}/fullchain.pem /var/lib/ark/certs/${adminHost}/privkey.pem\n  respond ok\n}\n`,
  );
  await Bun.write(join(edgeDir, "Caddyfile.closed"), await Bun.file(join(edgeDir, "Caddyfile")).text());
  await chmod(directory, 0o755);
  const script = [
    "set -e",
    ...[adminHost, appHost, tailnetHost, wsHost, wwwHost, apexHost, brokenHost, ssoHost].map((host) =>
      certificate(`/out/certs/${host}`, host),
    ),
    certificate("/out/peer-certs", mqttHost),
    "chmod 644 /out/peer-certs/privkey.pem",
    "chown -R 1000:1000 /out/certs /out/edge",
  ].join("\n");
  await docker("run", "--rm", "--user", "0:0", "--volume", `${directory}:/out`, bunImage, "sh", "-c", script);
}

async function startContainers() {
  runtime.networkCreated = true;
  await docker("network", "create", network);
  await docker("network", "create", "--subnet", peerSubnet, peerNetwork);
  runtime.containers.push(upstream);
  await docker(
    "run",
    "--detach",
    "--name",
    upstream,
    "--network",
    network,
    "--volume",
    `${join(fixtures, "upstream.ts")}:/fixture/upstream.ts:ro`,
    bunImage,
    "bun",
    "/fixture/upstream.ts",
  );
  stack = await startEdgeStack({
    runtime,
    project: `ark-edge-l4-${suffix}`,
    directory,
    acmeDir,
    certDir,
    edgeDir,
    validator: true,
    ports: ["127.0.0.1::80", "127.0.0.1::443", "127.0.0.1::41642/udp"],
    edgeTsCommand: [
      "tailscaled",
      "--state=mem:",
      "--socket=/var/run/tailscale/tailscaled.sock",
      "--port=41642",
      "--tun=tailscale0",
    ],
  });
  // The admin site proxies to api:3000; the WebSocket fixture site too.
  await docker("network", "connect", "--alias", "api", stack.networks.admin, upstream);
  // The simulated tailnet peers, at their pinned 100.64.0.0/10 addresses.
  await docker("network", "connect", peerNetwork, stack.edgeTs);
  for (const [name, ip, args] of [
    [
      `ark-edge-l4-peer-http-${suffix}`,
      peerHttpIp,
      ["--volume", `${join(fixtures, "upstream.ts")}:/fixture/app.ts:ro`],
    ],
    [
      `ark-edge-l4-peer-tls-${suffix}`,
      peerTlsIp,
      [
        "--volume",
        `${join(fixtures, "tls-echo.ts")}:/fixture/app.ts:ro`,
        "--volume",
        `${peerCertDir}:/certs:ro`,
      ],
    ],
  ] as const) {
    runtime.containers.push(name);
    await docker(
      "run",
      "--detach",
      "--name",
      name,
      "--network",
      peerNetwork,
      "--ip",
      ip,
      ...args,
      bunImage,
      "bun",
      "/fixture/app.ts",
    );
  }
  bundles.watchdog = await bundle(join(root, "workers/src/edge-watchdog.ts"), "watchdog");
  bundles.writeEdge = await bundle(join(fixtures, "write-edge.ts"), "write-edge");
  bundles.probe = await bundle(join(fixtures, "l4-worker-probe.ts"), "probe");
  bundles.client = await bundle(join(fixtures, "l4-client.ts"), "client");
  await startWatchdog();
}

/** The edge watchdog as shipped: uid 1000, group 4400, read-only root, no capabilities, with HAProxy. */
async function startWatchdog() {
  watchdogName = `ark-edge-l4-watchdog-${suffix}-${Date.now()}`;
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
    `ARK_API_URL=http://host.docker.internal:${api.port}`,
    "--env",
    `ARK_EDGE_WATCHDOG_TOKEN=${watchdogToken}`,
    "--env",
    "ARK_EDGE_ADMIN_URL=http://edge-admin:2019",
    "--env",
    "ARK_EDGE_DIR=/var/lib/ark/edge",
    "--env",
    "ARK_EDGE_L4_DIR=/usr/local/etc/haproxy",
    "--env",
    "ARK_HAPROXY_MASTER_SOCKET=/var/run/haproxy/master.sock",
    "--volume",
    `${edgeDir}:/var/lib/ark/edge`,
    "--volume",
    `${stack.volumes.edgeL4}:/usr/local/etc/haproxy:ro`,
    "--volume",
    `${stack.volumes.haproxyRun}:/var/run/haproxy`,
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
    "verified watchdog enforcement on Caddy and HAProxy",
    async () => {
      const status = await docker(
        "exec",
        watchdogName,
        "bun",
        "--eval",
        'for (const p of ["caddy","haproxy"]) { const r = await fetch(`http://127.0.0.1:2021/v1/supervise?proxy=${p}`); if (!r.ok) process.exit(1); } console.log("ready")',
      );
      return status === "ready" ? true : undefined;
    },
    30_000,
    500,
  );
}

/** The production worker is already running when it drains. Keep the probe container alive too,
 * so Docker container creation time is not counted as withdrawal latency. */
const probeName = `ark-edge-l4-worker-${suffix}`;
let probeStarted = false;
async function probe<T = Record<string, unknown>>(args: string[], options: { group?: boolean } = {}) {
  const identity = [
    "--user",
    "1000:1000",
    ...(options.group === false ? [] : ["--group-add", "4400"]),
    "--read-only",
    "--tmpfs",
    "/tmp",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--network",
    "none",
    "--env",
    "HOME=/tmp",
    "--env",
    "ARK_EDGE_L4_DIR=/usr/local/etc/haproxy",
    "--env",
    "ARK_HAPROXY_VALIDATOR_SOCKET=/var/run/haproxy-validator/validate.sock",
    "--env",
    "ARK_HAPROXY_MASTER_SOCKET=/var/run/haproxy/master.sock",
    "--env",
    "ARK_HAPROXY_ADMIN_SOCKET=/var/run/haproxy/admin.sock",
    "--volume",
    `${stack.volumes.edgeL4}:/usr/local/etc/haproxy`,
    "--volume",
    `${stack.volumes.validatorRun}:/var/run/haproxy-validator`,
    "--volume",
    `${stack.volumes.haproxyRun}:/var/run/haproxy`,
    "--volume",
    `${bundles.probe}:/probe:ro`,
    "--workdir",
    "/tmp",
  ];
  if (options.group !== false && !probeStarted) {
    runtime.containers.push(probeName);
    await docker("run", "--detach", "--name", probeName, ...identity, bunImage, "sleep", "3600");
    probeStarted = true;
  }
  const output =
    options.group === false
      ? await docker("run", "--rm", ...identity, bunImage, "bun", "/probe/l4-worker-probe.js", ...args)
      : await docker("exec", probeName, "bun", "/probe/l4-worker-probe.js", ...args);
  return JSON.parse(output.split("\n").at(-1) ?? "{}") as T;
}

/** A client container with its own address on a Docker network (or in edge-ts's namespace). */
async function client<T = Record<string, unknown>>(networkName: string, args: string[]) {
  const output = await docker(
    "run",
    "--rm",
    "--network",
    networkName,
    "--volume",
    `${bundles.client}:/client:ro`,
    bunImage,
    "bun",
    "/client/l4-client.js",
    ...args,
  );
  return JSON.parse(output.split("\n").at(-1) ?? "{}") as T;
}

async function edgeTsAddress(networkName: string) {
  const ip = await docker(
    "inspect",
    "--format",
    `{{(index .NetworkSettings.Networks "${networkName}").IPAddress}}`,
    stack.edgeTs,
  );
  if (!ip) throw new Error(`${stack.edgeTs} has no address on ${networkName}`);
  return ip;
}

/** `edge.apply` as the domain worker runs it: the production planner, renderer and writeEdge on edge-control. */
async function edgeApply() {
  const plan = fixturePlan();
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
    JSON.stringify(plan),
  );
  return JSON.parse(output) as { applied: boolean; httpRoutes: string[] };
}

async function caddyAdmin(path: string, init: { method?: string; body?: string; contentType?: string } = {}) {
  const script = `
    const r = await fetch("http://edge-admin:2019${path}", { method: ${JSON.stringify(init.method ?? "GET")},
      headers: { "content-type": ${JSON.stringify(init.contentType ?? "application/json")}, "cache-control": "must-revalidate" },
      body: ${init.method === "POST" ? "await Bun.stdin.text()" : "undefined"} });
    console.log(JSON.stringify({ status: r.status, body: await r.text() }));
  `;
  const child = Bun.spawn(
    [
      "docker",
      "run",
      "--rm",
      "-i",
      "--network",
      stack.networks.edgeControl,
      bunImage,
      "bun",
      "--eval",
      script,
    ],
    { stdin: new TextEncoder().encode(init.body ?? ""), stdout: "pipe", stderr: "pipe" },
  );
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) throw new Error(`caddy admin ${path}: ${stderr.slice(0, 500)}`);
  return JSON.parse(stdout.trim().split("\n").at(-1)!) as { status: number; body: string };
}

const ports = { http: 0, https: 0 };
async function refreshPorts() {
  ports.http = await stack.hostPort(80);
  ports.https = await stack.hostPort(443);
}

type Reply = { status: number; headers: Record<string, string | string[] | undefined>; body: string };

/** HTTPS through the published 443 (HAProxy) from the host. */
function secureGet(servername: string, hostHeader = servername, path = "/") {
  return new Promise<Reply>((resolveReply, reject) => {
    const socket = tlsConnect({
      host: "127.0.0.1",
      port: ports.https,
      servername,
      rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"],
    });
    let data = "";
    const timer = setTimeout(() => socket.destroy(new Error("timed out")), 5_000);
    socket.on("secureConnect", () =>
      socket.write(`GET ${path} HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n\r\n`),
    );
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.on("close", () => {
      clearTimeout(timer);
      const [head = "", ...rest] = data.split("\r\n\r\n");
      const [statusLine = "", ...headerLines] = head.split("\r\n");
      const headers: Record<string, string> = {};
      for (const line of headerLines) {
        const index = line.indexOf(":");
        if (index > 0) headers[line.slice(0, index).toLowerCase()] = line.slice(index + 1).trim();
      }
      resolveReply({ status: Number(statusLine.split(" ")[1] ?? 0), headers, body: rest.join("\r\n\r\n") });
    });
  });
}

function plainGet(host: string, path = "/") {
  return new Promise<Reply>((resolveReply, reject) => {
    const request = httpRequest(
      { host: "127.0.0.1", port: ports.http, path, headers: { host }, timeout: 5_000 },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => (body += chunk));
        response.on("end", () =>
          resolveReply({ status: response.statusCode ?? 0, headers: response.headers, body }),
        );
      },
    );
    request.on("timeout", () => request.destroy(new Error("timed out")));
    request.on("error", reject);
    request.end();
  });
}

/** A held TLS session through 443 to the tailnet TLS echo; `echo` proves it is still relayed. */
async function tlsSession(servername = mqttHost) {
  const socket: TLSSocket = tlsConnect({
    host: "127.0.0.1",
    port: ports.https,
    servername,
    rejectUnauthorized: false,
  });
  const closed = new Promise<number>((resolveClosed) => socket.on("close", () => resolveClosed(Date.now())));
  socket.on("error", () => undefined);
  await new Promise<void>((resolveOpen, reject) => {
    const timer = setTimeout(() => reject(new Error("TLS session did not open")), 5_000);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      resolveOpen();
    });
    socket.once("close", () => {
      clearTimeout(timer);
      reject(new Error("TLS session closed during the handshake"));
    });
  });
  const echo = (message: string) =>
    new Promise<string>((resolveEcho) => {
      if (socket.destroyed) return resolveEcho("closed");
      const timer = setTimeout(() => resolveEcho("no echo"), 3_000);
      socket.once("data", (chunk) => {
        clearTimeout(timer);
        resolveEcho(chunk.toString("utf8"));
      });
      socket.write(message);
    });
  return { socket, closed, echo, end: () => socket.destroy() };
}

async function tlsOutcome(servername = mqttHost) {
  try {
    const session = await tlsSession(servername);
    const echoed = await session.echo("probe");
    session.end();
    return echoed === "probe" ? "relayed" : `opened, ${echoed}`;
  } catch (error) {
    return `refused (${(error as Error).message})`;
  }
}

/** A raw TCP connection to the published 443: what came back and when it closed. */
function rawConnection(payload?: Buffer, waitMs = 9_000) {
  return new Promise<{ closedAfterMs: number | null; response: string }>((resolveRaw) => {
    const started = Date.now();
    const chunks: Buffer[] = [];
    const socket = netConnect({ host: "127.0.0.1", port: ports.https });
    const timer = setTimeout(() => {
      socket.destroy();
      resolveRaw({ closedAfterMs: null, response: Buffer.concat(chunks).toString("latin1") });
    }, waitMs);
    socket.on("connect", () => payload && socket.write(payload));
    socket.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    socket.on("error", () => undefined);
    socket.on("close", () => {
      clearTimeout(timer);
      resolveRaw({ closedAfterMs: Date.now() - started, response: Buffer.concat(chunks).toString("latin1") });
    });
  });
}

async function logsOf(container: string) {
  const { stdout, stderr } = await runtime.dockerOutput("logs", container);
  return stdout + stderr;
}

// ---- WebSocket client over TLS (manual framing, so SNI and Host are explicit) -------------------------------

async function websocket(servername: string) {
  const socket = tlsConnect({
    host: "127.0.0.1",
    port: ports.https,
    servername,
    rejectUnauthorized: false,
    ALPNProtocols: ["http/1.1"],
  });
  let closeAt: number | null = null;
  socket.on("close", () => (closeAt = Date.now()));
  socket.on("error", () => undefined);
  let buffer = Buffer.alloc(0);
  const waiters: Array<(text: string) => void> = [];
  await new Promise<void>((resolveOpen, reject) => {
    const timer = setTimeout(() => reject(new Error("WebSocket upgrade timed out")), 5_000);
    socket.once("secureConnect", () =>
      socket.write(
        `GET /ws HTTP/1.1\r\nHost: ${servername}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${randomBytes(16).toString("base64")}\r\n\r\n`,
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
      if (!head.startsWith("HTTP/1.1 101"))
        return reject(new Error(`upgrade refused: ${head.split("\r\n")[0]}`));
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
      resolveOpen();
    };
    socket.on("data", onHandshake);
  });
  const echo = (message: string) =>
    new Promise<string>((resolveEcho) => {
      if (closeAt !== null) return resolveEcho("closed");
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
  return { echo, closed: () => closeAt !== null, end: () => socket.destroy() };
}

// ---- Tests -------------------------------------------------------------------------------------------------

async function pinsTest(report: Report) {
  const compose = await Bun.file(join(root, "infra/platform/docker-compose.yml")).text();
  const dockerfile = await Bun.file(join(root, "Dockerfile")).text();
  const images = composeImages(compose, dockerfile);
  expect(
    report,
    images.haproxy === haproxyImage,
    "Compose pins edge-l4 to the tested HAProxy 3.2.26 digest",
    images.haproxy,
  );
  expect(
    report,
    dockerfile.includes(`FROM ${haproxyImage} AS haproxy-validator`),
    "the validator image is built on the same HAProxy digest",
    "Dockerfile haproxy-validator stage",
  );
  await verifyImageIds(images);
  expect(
    report,
    true,
    "the pinned HAProxy image runs as uid 99 and GID 4400 is free in the HAProxy and Bun images",
    `${images.haproxy.split("@")[0]}, ${images.bun.split("@")[0]}`,
  );
}

async function permissionsTest(report: Report) {
  const sockets = await probe<
    Record<string, { mode: string; uid: number; gid: number; socket: boolean } | number | number[]>
  >(["sockets"]);
  const at = (name: string) => sockets[name] as { mode: string; uid: number; gid: number; socket: boolean };
  expect(
    report,
    sockets.uid === 1000 && (sockets.groups as number[]).includes(4400),
    "the worker probe runs as the domain worker's uid 1000 with supplementary group 4400",
    `uid ${sockets.uid}, groups ${JSON.stringify(sockets.groups)}`,
  );
  expect(
    report,
    at("haproxyRun").mode === "2770" &&
      at("haproxyRun").uid === 99 &&
      at("haproxyRun").gid === 4400 &&
      at("validatorRun").mode === "2770" &&
      at("validatorRun").gid === 4400,
    "socket directories are 99:4400 mode 2770",
    `haproxy ${JSON.stringify(at("haproxyRun"))}, validator ${JSON.stringify(at("validatorRun"))}`,
  );
  expect(
    report,
    ["master", "admin", "validator"].every(
      (name) => at(name).socket && at(name).mode === "660" && at(name).gid === 4400,
    ),
    "master, admin and validator sockets are 0660 group 4400",
    ["master", "admin", "validator"]
      .map((name) => `${name} ${at(name).mode} gid ${at(name).gid} uid ${at(name).uid}`)
      .join(", "),
  );
  expect(
    report,
    at("generations").mode === "2750" &&
      at("generations").uid === 1000 &&
      at("generations").gid === 4400 &&
      at("currentConfig").mode === "640",
    "generations are bun:4400, directories 2750 and files 0640",
    `generations ${JSON.stringify(at("generations"))}, current/haproxy.cfg ${at("currentConfig").mode}`,
  );
  const users = await Promise.all(
    [stack.edgeL4, `${stack.project}-haproxy-validator-1`].map((name) =>
      docker("exec", name, "sh", "-c", "id -u; grep CapEff /proc/1/status | tr -s '\\t ' ' '"),
    ),
  );
  expect(
    report,
    users.every((text) => text.startsWith("99\n") && /CapEff: 0+$/.test(text)),
    "edge-l4 and the validator run as the image's uid 99 with no effective capabilities",
    users.map((text) => text.replace(/\n/g, " ")).join(" | "),
  );

  const applied = await probe<{
    applied: boolean;
    reloaded: boolean;
    generation: string;
    reloadLog?: string;
    error?: string;
  }>(["apply", JSON.stringify({ httpHostnames: httpHosts })]);
  expect(
    report,
    applied.applied && applied.reloaded && /^[a-f0-9]{64}$/.test(applied.generation),
    "the worker writes a generation, the validator accepts it, `current` is swapped and the master reloads",
    applied.error ??
      `generation ${applied.generation?.slice(0, 12)}, reload ${applied.reloadLog?.split("\n").find((line) => /Loading success|Initializing new worker/.test(line)) ?? "ok"}`,
  );
  const stat = await probe<Array<{ pxname: string; svname: string; status: string }>>(["stat"]);
  expect(
    report,
    stat.some((row) => row.pxname === "fe_tls443" && row.svname === "FRONTEND" && row.status === "OPEN") &&
      stat.some((row) => row.pxname === "be_caddy" && row.svname === "caddy"),
    "the worker reads `show stat` through the admin socket",
    stat
      .filter((row) => ["FRONTEND", "caddy"].includes(row.svname))
      .map((row) => `${row.pxname}/${row.svname} ${row.status}`)
      .join(", "),
  );
  const proc = await probe<{ workers: Array<{ pid: number; section: string }>; reloads: number }>(["proc"]);
  expect(
    report,
    proc.workers.length >= 1,
    "the worker enumerates HAProxy workers through the master socket",
    `${JSON.stringify(proc.workers)}, master reloads ${proc.reloads}`,
  );
  const invalid = await probe<{
    refused: boolean;
    before: { current: string; reloads: number };
    after: { current: string; reloads: number };
    candidateKept: boolean;
    diagnostics: string;
  }>(["invalid"]);
  expect(
    report,
    invalid.refused &&
      invalid.before.current === invalid.after.current &&
      invalid.before.reloads === invalid.after.reloads &&
      !invalid.candidateKept,
    "an invalid candidate is refused before `current` changes or a reload is sent",
    `current ${invalid.after.current?.slice(0, 12)} unchanged, master reloads ${invalid.before.reloads} -> ${invalid.after.reloads}; ${invalid.diagnostics.split("\n")[0]?.slice(0, 160)}`,
  );
  const outsider = await probe<{ error?: string; code?: string }>(["proc"], { group: false });
  expect(
    report,
    outsider.code === "EACCES",
    "without group 4400 the same uid cannot use the master socket",
    `${outsider.code}: ${outsider.error}`,
  );
}

async function caddyBlockTest(report: Report) {
  const config = JSON.parse((await caddyAdmin("/config/")).body) as {
    apps: {
      http: {
        https_port: number;
        servers: Record<
          string,
          {
            listen: string[];
            listener_wrappers?: Array<Record<string, string>>;
            strict_sni_host?: boolean;
            protocols?: string[];
          }
        >;
      };
    };
  };
  const servers = Object.values(config.apps.http.servers);
  const tlsServer = servers.find((server) => server.listen.includes("127.0.0.1:8443"));
  const plain = servers.find((server) => server.listen.includes(":80"));
  expect(
    report,
    config.apps.http.https_port === 8443 &&
      tlsServer?.listener_wrappers?.[0]?.wrapper === "proxy_protocol" &&
      tlsServer.listener_wrappers[0].fallback_policy === "REQUIRE" &&
      !("allow" in tlsServer.listener_wrappers[0]) &&
      tlsServer.listener_wrappers[1]?.wrapper === "tls" &&
      tlsServer.strict_sni_host === true &&
      JSON.stringify(tlsServer.protocols) === '["h1","h2"]',
    "the running Caddy serves HTTPS only on 127.0.0.1:8443 with a required PROXY header, strict SNI and h1/h2",
    JSON.stringify({
      listen: tlsServer?.listen,
      wrappers: tlsServer?.listener_wrappers,
      strict: tlsServer?.strict_sni_host,
      protocols: tlsServer?.protocols,
    }),
  );
  expect(
    report,
    Boolean(plain) &&
      !plain!.listener_wrappers &&
      JSON.stringify(plain!.protocols) === '["h1","h2"]' &&
      !servers.some((server) => server.listen.some((address) => address.endsWith(":443"))),
    "the :80 server has no PROXY wrapper, and Caddy listens on no 443",
    servers
      .map((server) => `${server.listen.join(",")} wrappers=${server.listener_wrappers?.length ?? 0}`)
      .join("; "),
  );
  expect(
    report,
    CADDY_GLOBAL_BLOCK.includes("servers 127.0.0.1:8443"),
    "the rendered global block is the §3.5 block",
    "CADDY_GLOBAL_BLOCK",
  );
}

async function proxyTrustTest(report: Report) {
  const local = await client<{ handshake: boolean; error?: string }>(`container:${stack.edgeTs}`, [
    "tls",
    "127.0.0.1",
    "8443",
    adminHost,
  ]);
  expect(
    report,
    !local.handshake,
    "headerless loopback TLS to 127.0.0.1:8443 is refused",
    local.error ?? "handshake completed",
  );
  const admin = await edgeTsAddress(stack.networks.admin);
  for (const [host, path] of [
    [adminHost, "/headers"],
    [tailnetHost, "/headers"],
  ] as const) {
    const reply = await client<{ status: number; body: string; self: string[] }>(stack.networks.admin, [
      "https",
      admin,
      "443",
      host,
      host,
      path,
    ]);
    const seen = (JSON.parse(reply.body || "{}") as Record<string, string>)["x-forwarded-for"];
    expect(
      report,
      reply.status === 200 && reply.self.includes(seen ?? "") && seen !== "127.0.0.1",
      `HAProxy's PROXY v2 carries the real client address to ${host === adminHost ? "the admin site" : "a tailnet HTTP route"}`,
      `client ${reply.self.join(",")} -> X-Forwarded-For ${seen}`,
    );
  }
  for (const networkName of [stack.networks.admin, stack.networks.edgeControl, peerNetwork]) {
    const address = await edgeTsAddress(networkName);
    const forged = Buffer.concat([
      Buffer.from("0d0a0d0a000d0a515549540a2111000c", "hex"),
      Buffer.from([6, 6, 6, 6, 127, 0, 0, 1, 0x04, 0x57, 0x20, 0xfb]),
    ]).toString("base64");
    const connect = await client<{ connected: boolean; code: string }>(networkName, ["tcp", address, "8443"]);
    const sent = await client<{ response: string; closed: boolean }>(networkName, [
      "send",
      address,
      "8443",
      forged,
      "1500",
    ]);
    expect(
      report,
      !connect.connected && connect.code === "ECONNREFUSED" && sent.response === "",
      `a container on ${networkName.replace(`${stack.project}_`, "")} cannot reach 8443, forged PROXY or not`,
      `${address}:8443 -> ${connect.code}`,
    );
  }
  const v1 = Buffer.from(
    `PROXY TCP4 6.6.6.6 10.0.0.1 1111 80\r\nGET / HTTP/1.1\r\nHost: ${adminHost}\r\n\r\n`,
  ).toString("base64");
  const plain = await client<{ response: string }>(stack.networks.admin, ["send", admin, "80", v1, "2000"]);
  expect(
    report,
    plain.response.startsWith("HTTP/1.1 400"),
    "Caddy's :80 server does not parse a PROXY header",
    plain.response.split("\r\n")[0] ?? "no answer",
  );
  const toRouter = await client<{ response: string; closed: boolean; ms: number }>(stack.networks.admin, [
    "send",
    admin,
    "443",
    v1,
    "7000",
  ]);
  expect(
    report,
    toRouter.closed && toRouter.response === "",
    "a PROXY header sent to 443 is rejected as non-TLS",
    `closed after ${toRouter.ms} ms, no answer`,
  );
}

async function sniHostTest(report: Report) {
  const mismatch = await secureGet(appHost, adminHost, "/");
  expect(
    report,
    mismatch.status === 421,
    "an SNI/Host mismatch between two Ark sites returns 421",
    `SNI ${appHost}, Host ${adminHost} -> ${mismatch.status}`,
  );
  const unknown = await secureGet("unknown.example.net", "unknown.example.net").then(
    (reply) => `HTTP ${reply.status}`,
    (error: Error) => `refused (${error.message})`,
  );
  expect(
    report,
    unknown.startsWith("refused"),
    "unknown SNI goes to Caddy, which fails the handshake (no certificate)",
    unknown,
  );
  const replies = await Promise.all([
    secureGet(adminHost),
    secureGet(appHost),
    secureGet(tailnetHost),
    plainGet(adminHost),
  ]);
  expect(
    report,
    replies.every((reply) => !("alt-svc" in reply.headers)),
    "no Alt-Svc header is sent (HTTPS through 443, and :80)",
    replies.map((reply) => `${reply.status} alt-svc=${reply.headers["alt-svc"] ?? "none"}`).join(", "),
  );
}

async function everyRouteTest(report: Report) {
  const admin = await secureGet(adminHost);
  const app = await secureGet(appHost);
  const tailnet = await secureGet(tailnetHost);
  expect(
    report,
    admin.status === 200 &&
      admin.body === "ok" &&
      app.status === 503 &&
      app.body.includes("not routed") &&
      tailnet.status === 200 &&
      tailnet.body === "ok",
    "every HTTP route answers through 443: admin site, unrouted route, tailnet route",
    `${adminHost} ${admin.status} "${admin.body}", ${appHost} ${app.status}, ${tailnetHost} ${tailnet.status} "${tailnet.body}"`,
  );
}

async function idleTest(report: Report) {
  const idle = await rawConnection(undefined, 9_000);
  expect(
    report,
    idle.closedAfterMs !== null && idle.closedAfterMs <= 5_500 && idle.response === "",
    "an idle TCP connection that sends nothing is closed within 5 s",
    idle.closedAfterMs === null ? "still open after 9 s" : `closed after ${idle.closedAfterMs} ms`,
  );
  const text = await rawConnection(Buffer.from(`GET / HTTP/1.1\r\nHost: ${adminHost}\r\n\r\n`), 9_000);
  expect(
    report,
    text.closedAfterMs !== null && text.closedAfterMs <= 5_500 && text.response === "",
    "plaintext HTTP on 443 is rejected without an answer",
    text.closedAfterMs === null ? "still open after 9 s" : `closed after ${text.closedAfterMs} ms`,
  );
}

async function reloadTest(report: Report) {
  // With no tailnet servers, a master re-exec may drop an in-flight watchdog CLI connection.
  // Repeated real reloads must preserve both established and fresh public HTTP traffic.
  const failures: string[] = [];
  const reloadTraffic = { done: false };
  const traffic = (async () => {
    while (!reloadTraffic.done) {
      const reply = await secureGet(adminHost).catch(() => ({ status: 0 }));
      if (reply.status !== 200) failures.push(String(reply.status));
      await Bun.sleep(100);
    }
  })();
  try {
    for (let i = 0; i < 3; i++) {
      const reply = await probe<{ reload?: { success: boolean }; error?: string }>(["reload"]);
      if (!reply.reload?.success) throw new Error(reply.error ?? "reload failed");
    }
  } finally {
    reloadTraffic.done = true;
    await traffic;
  }
  expect(
    report,
    failures.length === 0,
    "watchdog ticks and concurrent HAProxy reloads preserve public HTTP",
    failures.join(", ") || "all requests returned 200",
  );
  const good = await probe<{ reload: { success: boolean; log: string }; workers: unknown[] }>(["reload"]);
  expect(
    report,
    good.reload.success,
    "`reload` on the master socket returns Success=1 for a valid configuration",
    good.reload.log
      .split("\n")
      .filter((line) => /Loading success|Initializing/.test(line))
      .join(" | "),
  );
  const broken = await probe<{
    reload: { success: boolean; log: string };
    restored: boolean;
    workers: Array<{ pid: number }>;
    failed: number;
  }>(["broken-reload"]);
  const after = await secureGet(adminHost);
  expect(
    report,
    !broken.reload.success && broken.restored && broken.workers.length >= 1 && after.status === 200,
    "`reload` returns Success=0 for an invalid configuration and the old workers keep serving",
    `${
      broken.reload.log
        .split("\n")
        .find((line) => /ALERT/.test(line))
        ?.slice(0, 120) ?? "Success=0"
    }; failed reloads ${broken.failed}; GET https://${adminHost}/ -> ${after.status}`,
  );
}

async function websocketTest(report: Report) {
  // The rendered global block with a WebSocket site that keeps upgraded streams across Caddy reloads.
  const site = `${CADDY_GLOBAL_BLOCK}

${wsHost} {
  bind 127.0.0.1
  tls /var/lib/ark/certs/${wsHost}/fullchain.pem /var/lib/ark/certs/${wsHost}/privkey.pem
  reverse_proxy api:3000 {
    flush_interval -1
    stream_close_delay 5m
  }
}
`;
  const loaded = await caddyAdmin("/load", { method: "POST", body: site, contentType: "text/caddyfile" });
  if (loaded.status !== 200) throw new Error(`/load returned ${loaded.status}: ${loaded.body}`);
  const ws = await websocket(wsHost);
  const before = await ws.echo("before");
  const haproxy = await probe<{ reload: { success: boolean } }>(["reload"]);
  const afterHaproxy = await ws.echo("after-haproxy-reload");
  expect(
    report,
    haproxy.reload.success && before === "before" && afterHaproxy === "after-haproxy-reload",
    "a WebSocket survives an HAProxy master-CLI reload (the old worker keeps it)",
    `reload Success=${haproxy.reload.success ? 1 : 0}; echo ${afterHaproxy}`,
  );
  const reloaded = await caddyAdmin("/load", { method: "POST", body: site, contentType: "text/caddyfile" });
  const afterCaddy = await ws.echo("after-caddy-reload");
  expect(
    report,
    reloaded.status === 200 && afterCaddy === "after-caddy-reload" && !ws.closed(),
    "the same WebSocket survives a Caddy /load behind HAProxy",
    `/load ${reloaded.status}; echo ${afterCaddy}`,
  );
  ws.end();
  // Back to the production configuration for the remaining tests.
  const restored = await edgeApply();
  if (!restored.applied) throw new Error("writeEdge did not re-apply the production configuration");
}

async function serversWith(predicate: (server: { key: string | null; adminState: number }) => boolean) {
  const servers = await probe<
    Record<
      string,
      { section: string; servers: Array<{ key: string | null; adminState: number; server: string }> }
    >
  >(["servers"]);
  return Object.entries(servers).map(([pid, worker]) => ({
    pid,
    section: worker.section,
    matching: worker.servers.filter(predicate).length,
  }));
}

async function sessionsAcrossWorkers() {
  const applied = await probe<{ reloaded: boolean; error?: string }>([
    "apply",
    JSON.stringify({ httpHostnames: httpHosts, tlsRoutes: [mqttL4] }),
    "force",
  ]);
  if (applied.error) throw new Error(applied.error);
  await waitFor(
    "the TLS route to relay",
    async () => ((await tlsOutcome()) === "relayed" ? true : undefined),
    15_000,
  );
  const leaving = await tlsSession();
  if ((await leaving.echo("a")) !== "a") throw new Error("the first session does not relay");
  const reload = await probe<{ reload: { success: boolean }; workers: Array<{ pid: number }> }>(["reload"]);
  if (!reload.reload.success) throw new Error("reload failed");
  const current = await tlsSession();
  if ((await current.echo("b")) !== "b") throw new Error("the second session does not relay");
  const workers = await serversWith((server) => server.key === `${peerTlsIp}:1883`);
  return { leaving, current, workers };
}

async function identityWithdrawalTest(report: Report) {
  const { leaving, current, workers } = await sessionsAcrossWorkers();
  expect(
    report,
    workers.length >= 2 && workers.every((worker) => worker.matching === 1),
    "two HAProxy workers (current and leaving) each hold a session to the tailnet TLS backend",
    workers.map((worker) => `pid ${worker.pid} (${worker.section})`).join(", "),
  );
  const eventsBefore = events.length;
  const changedAt = Date.now();
  lease.routes = [webRoute, { ...mqttRoute, stableId: "nIMPOSTOR" }];
  const closedAt = await Promise.all(
    [leaving.closed, current.closed].map((closed) =>
      Promise.race([closed, Bun.sleep(10_000).then(() => null)]),
    ),
  );
  expect(
    report,
    closedAt.every((at) => at !== null && at - changedAt <= 5_000),
    "identity failure withdraws the HAProxy-routed backend: sessions in the current and leaving workers close within detection + 5 s",
    closedAt.map((at) => (at === null ? "still open" : `${at - changedAt} ms`)).join(", "),
  );
  const fresh = await tlsOutcome();
  const fenced = await serversWith(
    (server) => server.key === `${peerTlsIp}:1883` && (server.adminState & 1) === 1,
  );
  expect(
    report,
    fresh.startsWith("refused") &&
      fenced.filter((worker) => worker.section === "current").every((worker) => worker.matching === 1),
    "new connections are not admitted: the server is disabled in the accepting worker",
    `${fresh}; ${fenced.map((worker) => `pid ${worker.pid} ${worker.section} fenced=${worker.matching}`).join(", ")}`,
  );
  const reported = await waitFor(
    "the withdrawal report",
    async () =>
      events.slice(eventsBefore).find((event) => event.event === "withdrawn" && event.proxy === "haproxy"),
    10_000,
  );
  expect(report, Boolean(reported), "the watchdog reports the HAProxy withdrawal", reported.detail);
}

/** `edge.drain` as the domain worker runs it: the HAProxy adapter through the shared master socket. */
async function workerDrainTest(report: Report) {
  lease.routes = [webRoute, mqttRoute];
  lease.validUntil = Number.POSITIVE_INFINITY;
  await Bun.sleep(1_500);
  const { leaving, current, workers } = await sessionsAcrossWorkers();
  const started = Date.now();
  // The drained policy no longer allows the TLS route; the HTTP route stays allowed.
  const result = await probe<{ withdrawn: string[]; active: string[]; error?: string }>([
    "withdraw",
    JSON.stringify([routeIdentityKey(webRoute)]),
  ]);
  const closedAt = await Promise.all(
    [leaving.closed, current.closed].map((closed) =>
      Promise.race([closed, Bun.sleep(5_000).then(() => null)]),
    ),
  );
  expect(
    report,
    !result.error &&
      result.withdrawn.includes(`${peerTlsIp}:1883`) &&
      closedAt.every((at) => at !== null && at - started <= 5_000),
    "the domain worker (uid 1000, group 4400, no Docker) shuts down route sessions in current and leaving workers",
    result.error ??
      `${workers.length} workers; withdrew ${result.withdrawn.join(", ")}; sessions closed after ${closedAt.map((at) => (at === null ? "never" : `${at - started} ms`)).join(", ")}`,
  );
  const admin = await secureGet(adminHost);
  expect(
    report,
    admin.status === 200,
    "HTTP routes are unaffected by the drain",
    `${adminHost}: ${admin.status}`,
  );
}

async function leaseExpiryTest(report: Report) {
  lease.routes = [webRoute, mqttRoute];
  lease.validUntil = Number.POSITIVE_INFINITY;
  await Bun.sleep(1_500);
  const { leaving, current, workers } = await sessionsAcrossWorkers();
  const eventsBefore = events.length;
  const expiresAt = Date.now() + 4_000;
  lease.validUntil = expiresAt;
  const closedAt = await Promise.all(
    [leaving.closed, current.closed].map((closed) =>
      Promise.race([closed, Bun.sleep(15_000).then(() => null)]),
    ),
  );
  expect(
    report,
    closedAt.every((at) => at !== null && at >= expiresAt - 500 && at - expiresAt <= 5_000),
    "lease expiry withdraws the HAProxy-routed backend across current and leaving workers by expiry + 5 s",
    `${workers.length} workers; closed ${closedAt.map((at) => (at === null ? "never" : `${at - expiresAt} ms after expiry`)).join(", ")}`,
  );
  // The adapters now enforce independently. HAProxy may close its sessions while Caddy is still
  // inside /load; wait for Caddy's verified withdrawal before asserting its post-withdrawal reply.
  await waitFor(
    "Caddy to verify its independent lease withdrawal",
    async () =>
      events.slice(eventsBefore).find((event) => event.event === "withdrawn" && event.proxy === "caddy"),
    5_000,
    50,
  );
  const fresh = await tlsOutcome();
  const admin = await secureGet(adminHost);
  expect(
    report,
    fresh.startsWith("refused") && admin.status === 200,
    "unrelated HTTP routes keep serving while tailnet backends are withdrawn",
    `${mqttHost}: ${fresh}; ${adminHost}: ${admin.status}`,
  );
}

async function launchGuardTest(report: Report) {
  // The lease is expired and the current generation contains the tailnet route.
  const starts = async () =>
    (await logsOf(stack.edgeL4)).split("\n").filter((line) => line.includes("launch guard: starting from"));
  const before = (await starts()).length;
  await docker("restart", "--time", "3", stack.edgeL4);
  await refreshPorts();
  const started = await waitFor(
    "the edge-l4 launch guard decision",
    async () => {
      const lines = await starts();
      return lines.length > before ? lines.at(-1)! : undefined;
    },
    30_000,
    500,
  );
  await waitFor(
    "HAProxy to serve after the restart",
    async () => ((await secureGet(adminHost)).status === 200 ? true : undefined),
    20_000,
  );
  const tailnetServers = await serversWith((server) => server.key !== null);
  const outcome = await tlsOutcome();
  expect(
    report,
    started.includes("closed configuration") &&
      tailnetServers.every((worker) => worker.matching === 0) &&
      outcome.startsWith("refused"),
    "with an expired lease the launch guard starts HAProxy from the closed configuration (no tailnet backend)",
    `${started.trim()}; ${mqttHost}: ${outcome}`,
  );
  // Make the first closed-to-full reload fail at the real master CLI, then repair its input.
  await probe(["guard-reload-fault"]);
  const renewedAt = Date.now();
  lease.validUntil = Number.POSITIVE_INFINITY;
  await waitFor(
    "the guard to reject a failed reopen",
    async () => ((await logsOf(stack.edgeL4)).includes("full reload unconfirmed") ? true : undefined),
    15_000,
    250,
  );
  await probe(["guard-reload-fault", "restore"]);
  await waitFor(
    "the guard to switch to the full configuration",
    async () => ((await tlsOutcome()) === "relayed" ? true : undefined),
    20_000,
    500,
  );
  const switched = (await logsOf(stack.edgeL4))
    .split("\n")
    .findLast((line) => line.includes("switched to the full"));
  expect(
    report,
    Boolean(switched),
    "once the lease is valid, the guard switches to the full configuration and reloads",
    `${Date.now() - renewedAt} ms; ${switched?.trim()}`,
  );

  // Freeze a live watchdog (hung HTTP, not connection refusal) at several polling phases.
  // Remove the last route during the final freeze while both old/current workers retain sessions.
  for (const phase of [0, 400, 900]) {
    const { leaving, current } = await sessionsAcrossWorkers();
    await Bun.sleep(phase);
    if (phase === 900) {
      const applied = await probe<{ error?: string }>([
        "apply",
        JSON.stringify({ httpHostnames: httpHosts, tlsRoutes: [] }),
      ]);
      if (applied.error) throw new Error(applied.error);
      // The lease still allows the removed route, so the watchdog leaves these old sessions alone.
      // Freeze after the new unguarded generation is live to exercise the retained supervision.
      if ((await leaving.echo("old-worker")) !== "old-worker")
        throw new Error("old worker session lost before freeze");
    }
    const frozenAt = Date.now();
    await docker("pause", watchdogName);
    try {
      const closes = await Promise.all(
        [leaving.closed, current.closed].map((closed) =>
          Promise.race([closed, Bun.sleep(8_000).then(() => null)]),
        ),
      );
      expect(
        report,
        closes.every((at) => at !== null && at - frozenAt <= 5_000),
        `frozen watchdog closes current and leaving sessions within 5 s (phase ${phase} ms, final route removed=${phase === 900})`,
        closes.map((at) => (at === null ? "never" : `${at - frozenAt} ms`)).join(", "),
      );
    } finally {
      await docker("unpause", watchdogName);
    }
    await docker("restart", "--time", "1", stack.edgeL4);
    await refreshPorts();
    await waitFor(
      "HAProxy after freeze",
      async () => ((await secureGet(adminHost)).status === 200 ? true : undefined),
      30_000,
      500,
    );
    await Bun.sleep(1_000);
  }
  // Restore the route before exercising stopped-watchdog recovery as well.
  await sessionsAcrossWorkers().then(({ leaving, current }) => {
    leaving.socket.destroy();
    current.socket.destroy();
  });

  // Losing the watchdog while a tailnet route exists stops HAProxy (listeners and sessions).
  const session = await tlsSession();
  const restarts = Number(await docker("inspect", "--format", "{{.RestartCount}}", stack.edgeL4));
  const stoppedAt = Date.now();
  await docker("stop", "--time", "1", watchdogName);
  const closed = await Promise.race([session.closed, Bun.sleep(10_000).then(() => null)]);
  expect(
    report,
    closed !== null && closed - stoppedAt <= 5_000,
    "without verified watchdog enforcement the guard kills HAProxy, closing established tailnet sessions",
    closed === null ? "still open after 10 s" : `closed ${closed - stoppedAt} ms after the watchdog stopped`,
  );
  await waitFor(
    "edge-l4 to restart closed",
    async () => {
      const count = Number(await docker("inspect", "--format", "{{.RestartCount}}", stack.edgeL4));
      return count > restarts ? true : undefined;
    },
    20_000,
    500,
  );
  await refreshPorts();
  // Without a watchdog both guards restart-loop by design: each starts closed after five launch
  // attempts, serves through its 2 s grace, then stops on the first missed heartbeats. 443 answers
  // only while HAProxy and Caddy are up together. Where the stopped watchdog's name takes seconds to
  // fail to resolve (Docker behind systemd-resolved, as on the CI runner), each attempt runs to its
  // `timeout`: Caddy cycles in ~25 s and HAProxy in ~16 s, so allow several cycles to overlap.
  await waitFor(
    "HTTP through 443 after the restart",
    async () => ((await secureGet(adminHost)).status === 200 ? true : undefined),
    120_000,
    500,
  );
  const after = await tlsOutcome();
  expect(
    report,
    after.startsWith("refused"),
    "restarted without a watchdog it serves HTTP but no tailnet route",
    `${adminHost}: 200; ${mqttHost}: ${after}`,
  );
}

// ---- FD-09: HTTP routes through the SNI router (§3.5) ---------------------------------------------------------

type FullReply = { status: number; headers: Array<[string, string]>; body: string };

function decodeChunked(raw: string) {
  let out = "";
  let rest = raw;
  while (rest.length) {
    const end = rest.indexOf("\r\n");
    const size = Number.parseInt(rest.slice(0, end), 16);
    if (!size) break;
    out += rest.slice(end + 2, end + 2 + size);
    rest = rest.slice(end + 2 + size + 2);
  }
  return out;
}

/** One HTTPS request through the published 443 (HAProxy, then Caddy), keeping every header line. */
function secureRequest(servername: string, path: string, extra: Record<string, string> = {}) {
  return new Promise<FullReply>((resolveReply, reject) => {
    const socket = tlsConnect({
      host: "127.0.0.1",
      port: ports.https,
      servername,
      rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"],
    });
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => socket.destroy(new Error("timed out")), 10_000);
    const lines = Object.entries(extra).map(([name, value]) => `${name}: ${value}\r\n`);
    socket.on("secureConnect", () =>
      socket.write(
        `GET ${path} HTTP/1.1\r\nHost: ${servername}\r\n${lines.join("")}Connection: close\r\n\r\n`,
      ),
    );
    socket.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.on("close", () => {
      clearTimeout(timer);
      const data = Buffer.concat(chunks).toString("utf8");
      const split = data.indexOf("\r\n\r\n");
      const [statusLine = "", ...headerLines] = data.slice(0, split).split("\r\n");
      const headers = headerLines.map((line): [string, string] => {
        const index = line.indexOf(":");
        return [line.slice(0, index).toLowerCase(), line.slice(index + 1).trim()];
      });
      const raw = data.slice(split + 4);
      const chunked = headers.some(([name, value]) => name === "transfer-encoding" && /chunked/i.test(value));
      resolveReply({
        status: Number(statusLine.split(" ")[1] ?? 0),
        headers,
        body: chunked ? decodeChunked(raw) : raw,
      });
    });
  });
}

const values = (reply: FullReply, name: string) =>
  reply.headers.filter(([field]) => field === name).map(([, value]) => value);

/** Tailnet names and addresses that must never appear in a response from a public route. */
const tailnetLeak = new RegExp(
  [peerHttpIp, "100.88.", "tail1234", "ts.net", "fd7a", "peer-http", ":3999"]
    .map((item) => item.replaceAll(".", "\\."))
    .join("|"),
  "i",
);

function leakIn(reply: FullReply) {
  const text = `${reply.headers.map(([name, value]) => `${name}: ${value}`).join("\n")}\n${reply.body}`;
  return tailnetLeak.exec(text)?.[0] ?? null;
}

function noLeakHeaders(reply: FullReply) {
  return ["server", "via", "x-powered-by"].filter((name) => values(reply, name).length > 0);
}

async function fd09AbsentTest(report: Report) {
  const plan = fixturePlan();
  expect(
    report,
    plan.omitted.map((route) => route.id).join(",") === "rt_sso1" &&
      !plan.httpRoutes.some((route) => route.access !== "public"),
    "the planner omits the enabled access_mode=sso route before FD-11 (lease and certificate notwithstanding)",
    plan.omitted.map((route) => `${route.id}: ${route.reason}`).join("; "),
  );
  const active = (await caddyAdmin("/config/")).body;
  expect(
    report,
    !active.includes(ssoHost) && active.includes(wwwHost) && active.includes(apexHost),
    "the running Caddy config has sites for www, the apex and broken, and none for the SSO route",
    `sso ${active.includes(ssoHost) ? "present" : "absent"}, www ${active.includes(wwwHost) ? "present" : "absent"}`,
  );
  const applied = await probe<{ httpHostnames?: string[]; error?: string }>([
    "apply",
    JSON.stringify({ httpHostnames: httpHosts, tlsRoutes: [] }),
  ]);
  const mapped = applied.httpHostnames ?? [];
  expect(
    report,
    [tailnetHost, wwwHost, apexHost, brokenHost].every((host) => mapped.includes(host)) &&
      !mapped.includes(ssoHost),
    "edge.l4_apply puts every served HTTP hostname in the 443 map, and not the SSO route",
    applied.error ?? mapped.join(" "),
  );
  const sso = await secureRequest(ssoHost, "/").then(
    (reply) => `HTTP ${reply.status}`,
    (error: Error) => `refused (${error.message})`,
  );
  expect(
    report,
    sso.startsWith("refused"),
    "the SSO hostname cannot be reached on 443 (no site, no certificate)",
    sso,
  );
}

async function fd09HeadersTest(report: Report) {
  const forged = {
    "X-Forwarded-For": "6.6.6.6",
    "X-Ark-User": "usr_forged_mallory",
    "X-Ark-Email": "mallory@evil.example",
    Cookie: "a=1; __Host-ark_gate=gate-secret; b=2",
  };
  const reply = await secureRequest(wwwHost, "/headers", forged);
  const seen = JSON.parse(reply.body || "{}") as Record<string, string>;
  expect(
    report,
    reply.status === 200 && noLeakHeaders(reply).length === 0,
    "a proxied 200 has no Server, Via or X-Powered-By",
    `status ${reply.status}; present: ${noLeakHeaders(reply).join(",") || "none"}`,
  );
  expect(
    report,
    values(reply, "strict-transport-security")[0] === "max-age=31536000" &&
      values(reply, "x-content-type-options")[0] === "nosniff" &&
      values(reply, "referrer-policy")[0] === "strict-origin-when-cross-origin",
    "HSTS, nosniff and the referrer policy are set",
    ["strict-transport-security", "x-content-type-options", "referrer-policy"]
      .map((name) => `${name}: ${values(reply, name)[0]}`)
      .join("; "),
  );
  const ark = Object.keys(seen).filter((name) => name.startsWith("x-ark-"));
  expect(
    report,
    Boolean(seen["x-forwarded-for"]) && !seen["x-forwarded-for"]!.includes("6.6.6.6") && ark.length === 0,
    "forged X-Forwarded-For and X-Ark-User/X-Ark-Email are not passed upstream",
    `upstream X-Forwarded-For ${seen["x-forwarded-for"]}; X-Ark-*: ${JSON.stringify(ark)}`,
  );
  expect(
    report,
    seen.cookie === "a=1; b=2" && seen.host === wwwHost,
    "the gate cookie is stripped and the upstream sees the public Host",
    `Cookie ${seen.cookie}; Host ${seen.host}`,
  );
}

async function fd09LocationTest(report: Report) {
  const policy = locationPolicy(checkedHttpRoute(wwwRoute));
  const locations = [
    `http://${peerHttpIp}:3000/next?x=1`,
    "//home.tail1234.ts.net/login",
    `//${peerName}/login`,
    `//${peerHttpIp}?x=1`,
    "http://[fd7a:115c:a1e0::6465:6667]/v6",
    "http://[fd7a:115c:a1e0:0:0:0:6465:6667]:3000/v6",
    "http://[FD7A:115C:A1E0:0000:0000:0000:6465:6667]#top",
    `http://${peerHttpIp}:3000`,
    `https://${peerName}.:3000`,
    `//${peerName}`,
    "http://peer-http/x?y#z",
    "/login",
    "?page=2",
    "https://accounts.example.net/oauth?client=1",
    "mailto:ops@example.com",
    `http://${peerHttpIp}:8080/x`,
    "http://[fd7a:115c:a1e0:0::6465:6667]/",
    "http://100.88.1.20/",
    "https://nas.tail1234.ts.net/",
    "//1684366951/",
    "https://user@www.example.com/",
    "///evil.example.net/",
    "/\\evil.example.net",
    "http:evil.example.net",
    `https://www.example.com/?next=http://${peerHttpIp}/`,
    `/ok, //${peerHttpIp}/`,
  ];
  const outcomes: string[] = [];
  for (const location of locations) {
    const reply = await secureRequest(
      wwwHost,
      `/redirect-to?l=${Buffer.from(location).toString("base64url")}`,
    );
    const expected = evaluateLocation(policy, location);
    const sent = values(reply, "location");
    const ok =
      "status" in expected
        ? reply.status === 502 && sent.length === 0 && reply.body.includes("ark-static-error-502")
        : reply.status === 302 && sent.length === 1 && sent[0] === expected.location;
    const leaked = leakIn(reply);
    outcomes.push(`${JSON.stringify(location)} -> ${reply.status} ${sent.join(" | ")}`);
    if (!ok || leaked || noLeakHeaders(reply).length) {
      expect(
        report,
        false,
        "every Location fixture matches the reference policy and leaks nothing",
        `${JSON.stringify(location)}: got ${reply.status} ${JSON.stringify(sent)}, expected ${JSON.stringify(expected)}; leak ${leaked}; ${noLeakHeaders(reply).join(",")}`,
      );
    }
  }
  expect(
    report,
    true,
    `${locations.length} Location fixtures (MagicDNS, IPv4, compressed/expanded IPv6, ports, authority-only, no trailing slash) match the reference policy; no tailnet name or address reaches a response`,
    outcomes.slice(0, 4).join("; "),
  );
  const first = await secureRequest(
    wwwHost,
    `/redirect-to?l=${Buffer.from(locations[0]!).toString("base64url")}`,
  );
  const cookies = values(first, "set-cookie");
  expect(
    report,
    values(first, "location")[0] === "https://www.example.com/next?x=1" &&
      cookies.length === 2 &&
      cookies.every((cookie) => !/domain=/i.test(cookie)),
    `upstream Location: http://${peerHttpIp}:3000/… and Set-Cookie Domain=…ts.net are rewritten`,
    `Location ${values(first, "location")[0]}; Set-Cookie ${cookies.join(" | ")}`,
  );
}

async function fd09ErrorTest(report: Report) {
  const reply = await secureRequest(brokenHost, "/anything?x=1");
  expect(
    report,
    reply.status === 502 && reply.body.includes("ark-static-error-502") && noLeakHeaders(reply).length === 0,
    "an unreachable upstream serves the static 502 with no Server or Via",
    `status ${reply.status}; ${reply.body.match(/<h1>[^<]*/)?.[0] ?? reply.body.slice(0, 60)}; present: ${noLeakHeaders(reply).join(",") || "none"}`,
  );
  expect(
    report,
    leakIn(reply) === null,
    "the 502 names no tailnet host or address in its body or headers",
    leakIn(reply) ?? `${reply.headers.length} headers, ${reply.body.length} bytes checked`,
  );
}

async function fd09RedirectTest(report: Report) {
  const apex = await secureRequest(apexHost, "/x?y=1");
  expect(
    report,
    apex.status === 308 &&
      values(apex, "location")[0] === "https://www.example.com/x?y=1" &&
      values(apex, "strict-transport-security")[0] === "max-age=31536000" &&
      noLeakHeaders(apex).length === 0,
    "https://example.com/x redirects to https://www.example.com/x (redirectTo) with HSTS and no Server",
    `${apex.status} ${values(apex, "location")[0]}`,
  );
  const replies = await Promise.all([
    plainGet(apexHost, "/x"),
    plainGet(wwwHost, "/p?q"),
    plainGet(ssoHost, "/"),
  ]);
  expect(
    report,
    replies[0].status === 308 &&
      replies[0].headers.location === "https://example.com/x" &&
      replies[1].status === 308 &&
      replies[1].headers.location === "https://www.example.com/p?q" &&
      replies[2].status === 404,
    ":80 redirects served route hostnames to HTTPS and not the omitted SSO hostname",
    replies.map((reply) => `${reply.status} ${reply.headers.location ?? ""}`).join(", "),
  );
}

/** More than the 10 minutes FD-09 requires, with no Caddy or HAProxy reload in between. */
const websocketIdleMs = 630_000;

async function fd09WebsocketTest(report: Report) {
  const ws = await websocket(wwwHost);
  const opened = await ws.echo("hello");
  const started = Date.now();
  await Bun.sleep(websocketIdleMs);
  const afterIdle = await ws.echo("after-idle");
  expect(
    report,
    opened === "hello" && afterIdle === "after-idle" && !ws.closed(),
    "a WebSocket through 443 stays connected for more than 10 minutes idle",
    `idle ${((Date.now() - started) / 60_000).toFixed(1)} min; echo ${afterIdle}`,
  );
  const applied = await edgeApply();
  const afterApply = await ws.echo("after-apply");
  await Bun.sleep(2_000);
  expect(
    report,
    applied.applied && afterApply === "after-apply" && !ws.closed(),
    "the same WebSocket survives one edge.apply (Caddy /load with must-revalidate)",
    `applied ${applied.applied}; echo ${afterApply}`,
  );
  ws.end();
}

/**
 * stream_close_delay keeps a withdrawn handler's WebSockets open after a reload, so the watchdog stops
 * Caddy when a withdrawn route holds one; the guard restarts it and the watchdog restores the rest.
 */
async function fd09WithdrawalTest(report: Report) {
  const ws = await websocket(wwwHost);
  const opened = await ws.echo("before-withdrawal");
  const closedAt = new Promise<number>((resolveClosed) => {
    const timer = setInterval(() => {
      if (ws.closed()) {
        clearInterval(timer);
        resolveClosed(Date.now());
      }
    }, 50);
  });
  const revokedAt = Date.now();
  lease.routes = lease.routes.filter((route) => route.id !== wwwRoute.id);
  const closed = await Promise.race([closedAt, Bun.sleep(10_000).then(() => 0)]);
  // Detection (watchdog pass, at most 1 s plus the 300 ms lease read) + 5 s.
  expect(
    report,
    opened === "before-withdrawal" && closed > 0 && closed - revokedAt <= 6_500,
    "withdrawing a route closes its open WebSocket despite stream_close_delay 5m",
    closed ? `closed +${closed - revokedAt} ms` : "still open after 10 s",
  );
  const restored = await waitFor(
    "the other routes after the withdrawal restart",
    async () => ((await secureGet(tailnetHost)).body === "ok" ? Date.now() : undefined),
    30_000,
    250,
  );
  const www = await secureGet(wwwHost).then(
    (reply) => `${reply.status}`,
    (error: Error) => `refused (${error.message})`,
  );
  expect(
    report,
    www !== "200",
    "the other routes serve again without an edge.apply; the withdrawn one does not",
    `${tailnetHost} restored +${restored - revokedAt} ms; ${wwwHost} -> ${www}`,
  );
  lease.routes = [webRoute, mqttRoute, ...fd09Policy];
  await Bun.sleep(1_500);
  const applied = await edgeApply();
  const back = await waitFor(
    "the route after it is allowed again",
    async () => ((await secureGet(wwwHost)).status === 200 ? true : undefined),
    15_000,
  );
  expect(report, applied.applied && back, "allowed again, edge.apply serves it again", wwwHost);
}

async function run(name: string, test: (report: Report) => Promise<unknown>) {
  const report: Report = { name, lines: [] };
  const started = Date.now();
  await test(report);
  console.log(`${name} (${((Date.now() - started) / 1000).toFixed(1)} s)\n${report.lines.join("\n")}`);
}

let failed = false;
try {
  console.log(`edge-l4 tests on ${haproxyImage.split("@")[0]} (${haproxyImage.split("@")[1]}):`);
  await run("pins and image users", pinsTest);
  await prepareFiles();
  await startContainers();
  await refreshPorts();
  await waitFor(
    "HTTPS after the pre-FD-25 maintenance cutover",
    async () => ((await secureGet(adminHost)).status === 200 ? true : undefined),
    30_000,
  );
  const applied = await edgeApply();
  if (!applied.applied) throw new Error("writeEdge did not apply the configuration.");
  await waitFor(
    "HTTPS through 443",
    async () => ((await secureGet(adminHost)).status === 200 ? true : undefined),
    30_000,
  );
  await run("worker sockets, validation and reload (§3.8.6)", permissionsTest);
  await run("Caddy global block on the running edge (§3.5)", caddyBlockTest);
  await run("PROXY v2 trust", proxyTrustTest);
  await run("SNI/Host and Alt-Svc", sniHostTest);
  await run("every HTTP route through 443", everyRouteTest);
  await run("idle and non-TLS connections", idleTest);
  await run("master-CLI reload", reloadTest);
  await run("WebSocket across HAProxy and Caddy reloads", websocketTest);
  await run("FD-09: an enabled SSO route is absent from both configs", fd09AbsentTest);
  await run("FD-09: no-leak headers through 443", fd09HeadersTest);
  await run("FD-09: Location and Set-Cookie through 443", fd09LocationTest);
  await run("FD-09: static 502 through 443", fd09ErrorTest);
  await run("FD-09: apex redirect and the :80 list", fd09RedirectTest);
  await run("FD-09: WebSocket idle over 10 minutes, then one edge.apply", fd09WebsocketTest);
  await run("FD-09: withdrawal closes a route's WebSockets despite stream_close_delay", fd09WithdrawalTest);
  await run("watchdog: identity failure across HAProxy workers", identityWithdrawalTest);
  await run("domain worker drain (edge.drain) across HAProxy workers", workerDrainTest);
  await run("watchdog: lease expiry across HAProxy workers", leaseExpiryTest);
  await run("HAProxy launch guard", launchGuardTest);
  console.log("\nAll edge-l4 tests passed.");
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  await runtime.dumpLogs();
} finally {
  void api.stop(true);
  removeSignalHandlers();
  await runtime.cleanup();
  // The simulated tailnet network is not part of the runtime's own resources; edge-ts is gone by now.
  await Bun.spawn(["docker", "network", "rm", peerNetwork], { stdout: "ignore", stderr: "ignore" }).exited;
}
process.exit(failed ? 1 : 0);
