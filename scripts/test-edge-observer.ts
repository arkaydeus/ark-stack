// `mise run test:edge` (FD-06): the edge observer, identity pinning and the edge-local lease watchdog
// from docs/design/front-door.md §3.2 and §3.6, in disposable containers. No tailnet login is needed.
//
// 1. LocalAPI deployment test. The shipped edge-ts service (real tailscaled, offline) shares its
//    socket volume; a process with the domain worker's uid reads `GET /localapi/v0/status` through a
//    read-only mount, while `PATCH /localapi/v0/prefs`, `POST /localapi/v0/prefs` and the other
//    state-changing endpoints are refused. A root control proves the same mount accepts writes from a
//    privileged caller, so the refusals come from tailscaled's uid check.
// 2. Withdrawal runtime tests. The shipped edge-ts and edge services (Caddy behind the launch guard),
//    the edge watchdog (bundled production code, as uid 1000 with no capabilities), the API's lease
//    endpoint and `edge.observe` against a mocked LocalAPI. A Docker network inside 100.64.0.0/10
//    connected to edge-ts stands in for the tailnet peer, so Caddy really proxies (and holds a
//    WebSocket) to the pinned address. Measured:
//    - replacing the target identity withdraws the route from the active Caddy config, and closes its
//      session, within detection + 5 s, with no edge.apply processed;
//    - with observation stopped, the route is withdrawn by last completion + lease + 5 s (the lease is
//      shortened to 8 s through ARK_EDGE_LEASE_VALIDITY_MS);
//    - starting Caddy with an expired lease (or without the watchdog) serves no tailnet route;
//    - hostnames sharing a backend remain independently revocable, including stale-file restarts;
//    - stopping or freezing the watchdog while serving closes listeners and existing sessions;
//    - when config inspection or withdrawal fails, Caddy stops and a critical alert is raised.
// HAProxy withdrawal is covered by scripts/test-edge-l4.ts (FD-25). It needs a local PostgreSQL (DATABASE_URL), like
// `mise run test`; it creates and drops its own database.
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { connect as tlsConnect } from "node:tls";

import { parseEnvFile } from "@ark-stack/shared";
import postgres from "postgres";

import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { type EdgeStack, startEdgeStack } from "./edge-test/stack.ts";

const root = resolve(import.meta.dir, "..");
if (!process.env.DATABASE_URL && existsSync(join(root, ".env"))) {
  Object.assign(process.env, parseEnvFile(await Bun.file(join(root, ".env")).text()), { ...process.env });
}
const sourceUrl = process.env.DATABASE_URL ?? "";
if (!sourceUrl || !["localhost", "127.0.0.1", "::1"].includes(new URL(sourceUrl).hostname)) {
  console.error("test-edge-observer needs DATABASE_URL pointing at a local PostgreSQL (see mise run db:up).");
  process.exit(1);
}

const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
const fixtures = join(import.meta.dir, "edge-test");
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-observer-${suffix}-`));
const network = `ark-edge-observer-${suffix}`;
const runtime = new EdgeTestRuntime(directory, network, bunImage);
const removeSignalHandlers = runtime.installSignalHandlers();
const docker = (...args: string[]) => runtime.docker(...args);
const leaseMs = 8_000;
const routeHost = "www.example.com";
const sharedHost = "shared.example.com";
const tailnet = ".tail9fd6.ts.net";
// A random /24 inside 100.64.0.0/10 for the simulated tailnet peer.
const octet = 64 + (Number.parseInt(randomBytes(1).toString("hex"), 16) % 64);
const third = 1 + (Number.parseInt(randomBytes(1).toString("hex"), 16) % 250);
const peerSubnet = `100.${octet}.${third}.0/24`;
const peerIp = `100.${octet}.${third}.10`;
const peerBackend = `${peerIp}:3000`;
const peerNetwork = `ark-edge-observer-peer-${suffix}`;
const extraNetworks: string[] = [];

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

// ---- Database, API and the mocked LocalAPI (in this process, as the API and domain worker) -------------

const admin = postgres(sourceUrl, { max: 1 });
const databaseName = `ark_edge_obs_${randomBytes(6).toString("hex")}`;
const targetUrl = new URL(sourceUrl);
targetUrl.pathname = `/${databaseName}`;
await admin.unsafe(`CREATE DATABASE "${databaseName}"`);
const watchdogToken = randomBytes(24).toString("base64url");
const socket = join(tmpdir(), `ark-edge-observer-${suffix}.sock`);
const edgeDir = join(directory, "edge");
const certDir = join(directory, "certs");
const acmeDir = join(directory, "acme");
Object.assign(process.env, {
  DATABASE_URL: targetUrl.toString(),
  ARK_EDGE_WATCHDOG_TOKEN: watchdogToken,
  ARK_EDGE_LEASE_VALIDITY_MS: String(leaseMs),
  ARK_EDGE_TS_SOCKET: socket,
  ARK_EDGE_DIR: edgeDir,
  ARK_SKIP_LISTEN: "1",
});
delete process.env.ARK_EDGE_RELOAD_URL;

async function migrate() {
  const child = Bun.spawn(["bun", "server/src/migrate.ts"], {
    cwd: root,
    env: process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
  if (code !== 0) throw new Error(`migrations failed: ${stderr}`);
}

type Server = typeof import("../server/src/coordinator.ts");
let coordinator: Server;
let sql!: typeof import("../server/src/db.ts").sql;
let apiServer: ReturnType<typeof Bun.serve> | undefined;
let mock!: import("../server/src/mock-localapi.ts").MockLocalApi;

const self = { id: "nEDGEOBS", name: "ark-edge", ips: ["100.64.0.1"], tags: ["tag:ark-edge"] };
const home = { id: "nHOMEOBS", name: "home", ips: [peerIp] };
const impostor = { id: "nIMPOSTOR", name: "home", ips: [peerIp] };
let routeId = "";

async function startControlPlane() {
  await migrate();
  coordinator = await import("../server/src/coordinator.ts");
  ({ sql } = await import("../server/src/db.ts"));
  const { app } = await import("../server/src/app.ts");
  const { MockLocalApi } = await import("../server/src/mock-localapi.ts");
  mock = new MockLocalApi({
    backendState: "Running",
    suffix: tailnet,
    self,
    peers: [home],
    reachable: new Set([peerBackend]),
  });
  await mock.listen(socket);
  apiServer = Bun.serve({ hostname: "0.0.0.0", port: 0, fetch: app.fetch });
  await sql`INSERT INTO platform_settings (id, admin_mode) VALUES ('default', 'tailnet') ON CONFLICT (id) DO UPDATE SET admin_mode = 'tailnet'`;
  await sql`INSERT INTO endpoints (id, kind, hostname) VALUES ('end_www', 'route', ${routeHost})`;
  await sql`
    INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
    VALUES ('crt_www', 'end_www', ${JSON.stringify([routeHost])}::jsonb, 'issued', now())
  `;
  routeId = "rt_obs1";
  await sql`
    INSERT INTO front_routes (id, kind, endpoint_id, listen_port, target_input, target_node_stable_id,
      target_ip, target_port, access_mode, status, enabled)
    VALUES (${routeId}, 'http', 'end_www', 443, ${`home${tailnet}`}, ${home.id}, ${peerIp}, 3000,
      'public', 'awaiting_acl', true)
  `;
}

/** One `edge.observe` through the coordinator, exactly as the domain worker runs it. */
async function observe() {
  const operation = await coordinator.enqueue({
    kind: "edge.observe",
    targetIds: ["tailnet:edge"],
    payload: { at: Date.now() },
  });
  const started = Date.now();
  const result = (await coordinator.runOperation("edge.observe", operation)) as {
    completedAt: string;
    validUntil: string;
  };
  await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${operation.id}`;
  return { ...result, detectedAt: Date.now(), took: Date.now() - started };
}

/** Observes every `everyMs` (the five-minute schedule at test scale) until the returned stop is awaited. */
function keepObserving(everyMs = 2_000) {
  const state = { running: true };
  const loop = (async () => {
    while (state.running) {
      await observe();
      await Bun.sleep(everyMs);
    }
  })();
  return async () => {
    state.running = false;
    await loop;
  };
}

async function routeStatus() {
  const [row] = await sql`SELECT status FROM front_routes WHERE id = ${routeId}`;
  return String(row?.status);
}

// ---- Containers ----------------------------------------------------------------------------------------

let stack!: EdgeStack;
let watchdogBundle = "";
let writeEdgeBundle = "";
let watchdogName = "";

async function prepareFiles() {
  await mkdir(join(acmeDir, ".well-known", "acme-challenge"), { recursive: true });
  await Bun.write(join(acmeDir, ".well-known", "acme-challenge", "obs-token"), "obs-token.key-auth");
  await mkdir(edgeDir);
  await Bun.write(join(edgeDir, "Caddyfile"), await Bun.file(join(root, "infra/platform/Caddyfile")).text());
  await chmod(directory, 0o755);
  const script = [
    "set -e",
    ...[routeHost, sharedHost].flatMap((host) => [
      `mkdir -p /out/certs/${host}`,
      `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=${host}" -addext "subjectAltName=DNS:${host}" -keyout /out/certs/${host}/privkey.pem -out /out/certs/${host}/fullchain.pem 2>/dev/null`,
      `chmod 600 /out/certs/${host}/privkey.pem`,
    ]),
    "chown -R 1000:1000 /out/certs /out/edge",
  ].join("\n");
  await docker("run", "--rm", "--user", "0:0", "--volume", `${directory}:/out`, bunImage, "sh", "-c", script);
}

async function startContainers() {
  runtime.networkCreated = true;
  await docker("network", "create", network);
  await docker("network", "create", "--subnet", peerSubnet, peerNetwork);
  extraNetworks.push(peerNetwork);
  stack = await startEdgeStack({
    runtime,
    project: `ark-edge-observer-${suffix}`,
    directory,
    acmeDir,
    certDir,
    edgeDir,
    ports: ["127.0.0.1::80", "127.0.0.1::443", "127.0.0.1::41642/udp"],
    // The pinned image's tailscaled, started directly in kernel mode on the shipped socket path:
    // containerboot would give up after 60 s without a login and restart edge-ts, stranding edge.
    edgeTsCommand: [
      "tailscaled",
      "--state=mem:",
      "--socket=/var/run/tailscale/tailscaled.sock",
      "--port=41642",
      "--tun=tailscale0",
    ],
  });
  // The simulated tailnet peer, reachable from the edge namespace at its pinned 100.64.0.0/10 address.
  await docker("network", "connect", peerNetwork, stack.edgeTs);
  const peer = `ark-edge-observer-peer-${suffix}`;
  runtime.containers.push(peer);
  await docker(
    "run",
    "--detach",
    "--name",
    peer,
    "--network",
    peerNetwork,
    "--ip",
    peerIp,
    "--volume",
    `${join(fixtures, "upstream.ts")}:/fixture/upstream.ts:ro`,
    bunImage,
    "bun",
    "/fixture/upstream.ts",
  );
  watchdogBundle = await bundle(join(root, "workers/src/edge-watchdog.ts"), "watchdog");
  writeEdgeBundle = await bundle(join(fixtures, "write-edge.ts"), "write-edge");
  await startWatchdog("http://edge-admin:2019");
}

/** The edge watchdog as shipped: uid 1000, read-only root, no capabilities, on edge-control. */
async function startWatchdog(adminUrl: string) {
  if (watchdogName) await docker("rm", "--force", watchdogName);
  watchdogName = `ark-edge-observer-watchdog-${suffix}-${Date.now()}`;
  runtime.containers.push(watchdogName);
  await docker(
    "run",
    "--detach",
    "--name",
    watchdogName,
    "--user",
    "1000:1000",
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
    `ARK_API_URL=http://host.docker.internal:${apiServer!.port}`,
    "--env",
    `ARK_EDGE_WATCHDOG_TOKEN=${watchdogToken}`,
    "--env",
    `ARK_EDGE_ADMIN_URL=${adminUrl}`,
    "--env",
    "ARK_EDGE_DIR=/var/lib/ark/edge",
    "--volume",
    `${edgeDir}:/var/lib/ark/edge:ro`,
    "--volume",
    `${watchdogBundle}:/watchdog:ro`,
    "--workdir",
    "/tmp",
    bunImage,
    "bun",
    "/watchdog/edge-watchdog.js",
  );
  await docker("network", "connect", "--alias", "edge-watchdog", stack.networks.edgeControl, watchdogName);
  await waitFor("the watchdog to read the lease", async () => {
    const logs = await runtime.dockerOutput("logs", watchdogName);
    return /edge watchdog on :2021/.test(logs.stdout) ? true : undefined;
  });
  await waitFor("verified watchdog enforcement", async () => {
    const status = await docker(
      "exec",
      watchdogName,
      "bun",
      "--eval",
      'const r = await fetch("http://127.0.0.1:2021/v1/supervise"); if (!r.ok) process.exit(1); console.log("ready")',
    );
    return status === "ready" ? true : undefined;
  });
}

/** `edge.apply` as the domain worker runs it: the production plan, rendered and loaded by writeEdge. */
async function edgeApply() {
  const plan = await coordinator.edgePlan("tailnet", null);
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
    `${writeEdgeBundle}:/harness:ro`,
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
  return JSON.parse(output) as { applied: boolean; tailnetRoutes: string[] };
}

/** Tailnet backends in Caddy's active config, read through the admin API from edge-control. */
async function activeBackends() {
  const script = `
    const config = await (await fetch("http://edge-admin:2019/config/", { signal: AbortSignal.timeout(3000) })).json();
    const found = new Set();
    const visit = (v) => { if (Array.isArray(v)) return v.forEach(visit); if (!v || typeof v !== "object") return;
      if (v.handler === "reverse_proxy") for (const u of v.upstreams ?? []) if (/^100\\./.test(u.dial ?? "")) found.add(u.dial);
      Object.values(v).forEach(visit); };
    visit(config);
    console.log(JSON.stringify([...found]));
  `;
  const output = await docker(
    "run",
    "--rm",
    "--network",
    stack.networks.edgeControl,
    bunImage,
    "bun",
    "--eval",
    script,
  );
  return JSON.parse(output.split("\n").at(-1) ?? "[]") as string[];
}

type Reply = { status: number; body: string };

// Each probe opens a new connection (`agent: false`). With the default pooled keep-alive agent, a
// poll kept reusing a connection accepted by the pre-reload Caddy, which kept answering with the
// old configuration, so waitUntilServing() could time out although new clients were served.
function secureGet(path = "/", hostname = routeHost) {
  return new Promise<Reply>((resolveReply, reject) => {
    const request = httpsRequest(
      {
        agent: false,
        host: "127.0.0.1",
        port: ports.https,
        servername: hostname,
        path,
        headers: { host: hostname },
        rejectUnauthorized: false,
        timeout: 3_000,
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => (body += chunk));
        response.on("end", () => resolveReply({ status: response.statusCode ?? 0, body }));
      },
    );
    request.on("timeout", () => request.destroy(new Error("timed out")));
    request.on("error", reject);
    request.end();
  });
}

function plainGet(host: string, path: string) {
  return new Promise<Reply>((resolveReply, reject) => {
    const request = httpRequest(
      { agent: false, host: "127.0.0.1", port: ports.http, path, headers: { host }, timeout: 3_000 },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => (body += chunk));
        response.on("end", () => resolveReply({ status: response.statusCode ?? 0, body }));
      },
    );
    request.on("timeout", () => request.destroy(new Error("timed out")));
    request.on("error", reject);
    request.end();
  });
}

const ports = { http: 0, https: 0 };
async function refreshPorts() {
  ports.http = await stack.hostPort(80);
  ports.https = await stack.hostPort(443);
}

/** A routed request outcome: `upstream` when the tailnet peer answered through Caddy. */
async function outcome(hostname = routeHost) {
  const reply = await secureGet("/", hostname).catch((error: Error) => ({ status: 0, body: error.message }));
  if (reply.status === 200 && reply.body === "ok") return "upstream";
  if (reply.status === 503) return "withdrawn (503)";
  return `not served (${reply.status || reply.body})`;
}

/** An upgraded (WebSocket) session through the route; resolves `closed` with the time it ended. */
async function openSession(hostname = routeHost) {
  return new Promise<{ closed: Promise<number>; end: () => void }>((resolveOpen, reject) => {
    const connection = tlsConnect({
      host: "127.0.0.1",
      port: ports.https,
      servername: hostname,
      rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"],
    });
    let buffer = "";
    const closed = new Promise<number>((resolveClosed) =>
      connection.on("close", () => resolveClosed(Date.now())),
    );
    const timer = setTimeout(() => reject(new Error("WebSocket upgrade timed out")), 5_000);
    connection.on("secureConnect", () =>
      connection.write(
        `GET /ws HTTP/1.1\r\nHost: ${hostname}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${randomBytes(16).toString("base64")}\r\n\r\n`,
      ),
    );
    connection.on("data", (chunk) => {
      buffer += chunk.toString("latin1");
      if (!buffer.includes("\r\n")) return;
      clearTimeout(timer);
      if (buffer.startsWith("HTTP/1.1 101")) resolveOpen({ closed, end: () => connection.destroy() });
      else reject(new Error(`upgrade refused: ${buffer.split("\r\n")[0]}`));
    });
    connection.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function waitUntilServing(report: Report, claim: string) {
  const served = await waitFor(
    `${routeHost} to reach the peer`,
    async () => ((await outcome()) === "upstream" ? true : undefined),
    30_000,
  );
  expect(report, served, claim, `GET https://${routeHost}/ -> peer ${peerBackend} answered "ok"`);
}

/** Polls until the route is withdrawn; returns when, in ms since the epoch. */
async function withdrawnAt(timeoutMs: number) {
  return waitFor(
    "the route to be withdrawn",
    async () => ((await outcome()) === "upstream" ? undefined : Date.now()),
    timeoutMs,
    100,
  );
}

async function edgeLogs() {
  const { stdout, stderr } = await runtime.dockerOutput("logs", stack.edge);
  return stdout + stderr;
}

// ---- 1. LocalAPI deployment test -----------------------------------------------------------------------

async function localApiTest(report: Report) {
  const volume = `${stack.project}_ark_edge_ts_socket`;
  await waitFor(
    "tailscaled's LocalAPI socket",
    async () =>
      (await docker("exec", stack.edgeTs, "test", "-S", "/var/run/tailscale/tailscaled.sock").then(
        () => true,
      )) || undefined,
  );
  const uid = await docker("run", "--rm", "--entrypoint", "id", bunImage, "-u", "bun");
  const dockerfile = await Bun.file(join(root, "Dockerfile")).text();
  expect(
    report,
    uid === "1000" && /FROM runtime AS domain-worker[\s\S]*?\nUSER bun\n/.test(dockerfile),
    "the domain worker runs as the image's non-root `bun` user, uid 1000",
    `id -u bun = ${uid}; Dockerfile domain-worker stage ends with USER bun`,
  );
  const probe = `
    const sock = "/var/run/tailscale/tailscaled.sock";
    const call = async (method, path, body) => {
      try {
        const response = await fetch("http://local-tailscaled.sock" + path, { method, unix: sock, body,
          headers: { "Sec-Tailscale": "localapi", ...(body ? { "content-type": "application/json" } : {}) },
          signal: AbortSignal.timeout(5000) });
        return response.status + " " + (await response.text()).replace(/\\s+/g, " ").slice(0, 60);
      } catch (error) { return "error " + (error.code ?? error.name); }
    };
    const out = { uid: process.getuid() };
    out.status = await call("GET", "/localapi/v0/status");
    out.prefsRead = await call("GET", "/localapi/v0/prefs");
    out.prefsPatch = await call("PATCH", "/localapi/v0/prefs", JSON.stringify({ ShieldsUpSet: true, ShieldsUp: false }));
    out.prefsPost = await call("POST", "/localapi/v0/prefs", "{}");
    out.start = await call("POST", "/localapi/v0/start", "{}");
    out.logout = await call("POST", "/localapi/v0/logout");
    out.serveConfig = await call("POST", "/localapi/v0/serve-config", "{}");
    out.resetAuth = await call("POST", "/localapi/v0/reset-auth");
    try { await Bun.write("/var/run/tailscale/ark-write-test", "x"); out.mountWrite = "allowed"; }
    catch (error) { out.mountWrite = "refused (" + (error.code ?? error.name) + ")"; }
    console.log(JSON.stringify(out));
  `;
  const probeAs = async (user: string) => {
    const output = await docker(
      "run",
      "--rm",
      "--user",
      user,
      "--read-only",
      "--tmpfs",
      "/tmp",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges:true",
      "--volume",
      `${volume}:/var/run/tailscale:ro`,
      bunImage,
      "bun",
      "--eval",
      probe,
    );
    return JSON.parse(output.split("\n").at(-1)!) as Record<string, string>;
  };
  const worker = await probeAs("bun");
  report.lines.push(`      evidence (uid ${worker.uid}, ${volume} mounted :ro): ${JSON.stringify(worker)}`);
  expect(
    report,
    (worker.status ?? "").startsWith('200 { "Version": "1.86.2') && worker.status!.includes("BackendState"),
    "connect() through the :ro mount works and GET /localapi/v0/status succeeds for uid 1000",
    worker.status ?? "",
  );
  expect(
    report,
    worker.prefsPatch?.startsWith("403 prefs write access denied") === true &&
      worker.prefsPost?.startsWith("405") === true &&
      ["start", "logout", "serveConfig", "resetAuth"].every((key) => worker[key]?.startsWith("403")),
    "every state-changing endpoint is refused: PATCH /prefs 403, POST /prefs 405, start/logout/serve-config/reset-auth 403",
    `PATCH /prefs ${worker.prefsPatch}; POST /prefs ${worker.prefsPost}; start ${worker.start}; logout ${worker.logout}; serve-config ${worker.serveConfig}; reset-auth ${worker.resetAuth}`,
  );
  expect(
    report,
    worker.mountWrite?.startsWith("refused") === true,
    "the socket directory is mounted read-only",
    worker.mountWrite ?? "",
  );
  // Control: root through the same read-only mount may write (an empty, no-op prefs patch), so the
  // refusals above come from tailscaled's per-uid permission, not from the mount or the endpoint.
  const rootProbe = probe.replace("JSON.stringify({ ShieldsUpSet: true, ShieldsUp: false })", '"{}"');
  const control = JSON.parse(
    (
      await docker(
        "run",
        "--rm",
        "--user",
        "0:0",
        "--volume",
        `${volume}:/var/run/tailscale:ro`,
        bunImage,
        "bun",
        "--eval",
        rootProbe,
      )
    )
      .split("\n")
      .at(-1)!,
  ) as Record<string, string>;
  expect(
    report,
    control.prefsPatch?.startsWith("200") === true,
    "control: root through the same :ro mount is allowed to PATCH /prefs, so writes are detectable",
    `root PATCH /prefs ${control.prefsPatch}`,
  );
  // The production client and parser against the real (logged-out) tailscaled, as uid 1000. The
  // probe uses LocalAPI dial, which tailscaled grants to read-only callers; it fails here because
  // the node is offline, and a logged-out node never yields a generation.
  const harness = await bundle(join(fixtures, "observe-status.ts"), "observe-status");
  const client = JSON.parse(
    (
      await docker(
        "run",
        "--rm",
        "--user",
        "1000:1000",
        "--volume",
        `${volume}:/var/run/tailscale:ro`,
        "--volume",
        `${harness}:/harness:ro`,
        bunImage,
        "bun",
        "/harness/observe-status.js",
        "/var/run/tailscale/tailscaled.sock",
        "100.64.0.1",
        "80",
      )
    )
      .split("\n")
      .at(-1)!,
  ) as {
    backendState?: string;
    parsed?: { ok: boolean; reason?: string };
    probe?: { ok: boolean; detail: string };
  };
  expect(
    report,
    client.backendState !== undefined &&
      client.parsed?.ok === false &&
      client.probe?.ok === false &&
      !/403/.test(client.probe.detail),
    "the production client reads status as uid 1000; a logged-out node is refused as a partial observation; dial is permitted but fails offline",
    `BackendState ${client.backendState}; parse: ${client.parsed?.reason}; dial: ${client.probe?.detail}`,
  );
}

// ---- 2. Withdrawal -------------------------------------------------------------------------------------

async function identityWithdrawalTest(report: Report) {
  const first = await observe();
  expect(
    report,
    (await routeStatus()) === "ready",
    "edge.observe commits a generation and the passing probe makes the route ready",
    `probe ${peerBackend} connected; lease until ${first.validUntil}`,
  );
  const applied = await edgeApply();
  expect(
    report,
    applied.tailnetRoutes.includes(routeId),
    "edge.apply renders the route with its pinned address",
    JSON.stringify(applied),
  );
  await waitUntilServing(report, "the route serves through Caddy to the pinned tailnet address");
  const session = await openSession();
  // The apply above stands in for the worker; nothing processes the queue from here on.
  await sql`UPDATE operations SET status = 'cancelled' WHERE kind IN ('edge.apply', 'edge.drain') AND status = 'queued'`;
  const queuedBefore =
    await sql`SELECT count(*)::int AS n FROM operations WHERE kind IN ('edge.apply', 'edge.drain') AND status = 'queued'`;

  // Replace the target: the same MagicDNS name (and address) now belongs to another machine.
  mock.state.peers = [impostor];
  const detection = await observe();
  const status = await routeStatus();
  const gone = await withdrawnAt(10_000);
  const sessionClosed = await Promise.race([session.closed, Bun.sleep(10_000).then(() => 0)]);
  const backends = await activeBackends();
  const latency = gone - detection.detectedAt;
  const sessionLatency = sessionClosed ? sessionClosed - detection.detectedAt : Number.POSITIVE_INFINITY;
  report.lines.push(
    `      timing: detection (edge.observe) ${detection.took} ms; config withdrawn ${latency} ms and session closed ${sessionLatency} ms after detection`,
  );
  expect(
    report,
    status === "identity_mismatch",
    "the replaced identity flips the name-pinned route to identity_mismatch",
    status,
  );
  expect(
    report,
    latency <= 5_000 && sessionLatency <= 5_000,
    "the active Caddy config stops routing to the old address and its session closes within detection + 5 s",
    `withdrawn +${latency} ms, session closed +${sessionLatency} ms; GET now ${await outcome()}`,
  );
  expect(
    report,
    !backends.includes(peerBackend),
    "Caddy's active config no longer dials the old address",
    `active tailnet dials ${JSON.stringify(backends)}`,
  );
  const queued =
    await sql`SELECT kind, status FROM operations WHERE kind IN ('edge.apply', 'edge.drain') AND status = 'queued' ORDER BY kind`;
  expect(
    report,
    queued.some((row) => row.kind === "edge.apply") && queued.some((row) => row.kind === "edge.drain"),
    "without any manual or worker apply: edge.apply and edge.drain are durably queued, the watchdog withdrew",
    `queued before ${queuedBefore[0]?.n}, now ${JSON.stringify(queued.map((row) => row.kind))}`,
  );
  await sql`UPDATE operations SET status = 'cancelled' WHERE kind IN ('edge.apply', 'edge.drain') AND status = 'queued'`;
}

/** The owner re-confirms the original machine (FD-08 does this through PATCH /api/front/routes/:id with step-up); the route is live again. */
async function restoreRoute(report: Report) {
  mock.state.peers = [home];
  await sql`UPDATE front_routes SET enabled = true, status = 'awaiting_acl', target_node_stable_id = ${home.id} WHERE id = ${routeId}`;
  // The preceding fault may have stopped Caddy. Keep the short fixture lease renewed throughout
  // restart and reload, and wait for its admin listener rather than racing /adapt against startup.
  await observe();
  const stopObserving = keepObserving();
  try {
    await waitFor("Caddy admin API after re-confirmation", async () => {
      await activeBackends();
      return true;
    });
    await edgeApply();
    await waitUntilServing(report, "after re-confirmation the route serves again");
  } finally {
    await stopObserving();
  }
  // Start the expiry measurement after the last apply and its container startup have finished.
  return observe();
}

async function leaseExpiryTest(report: Report) {
  const last = await restoreRoute(report);
  const session = await openSession();
  // Observation stops entirely: no edge.observe runs from here on.
  const completedAt = Date.parse(last.completedAt);
  const deadline = completedAt + leaseMs + 5_000;
  const gone = await withdrawnAt(leaseMs + 15_000);
  const sessionClosed = await Promise.race([session.closed, Bun.sleep(10_000).then(() => 0)]);
  const watchdogLines = (await runtime.dockerOutput("logs", "--timestamps", watchdogName)).stdout
    .split("\n")
    .filter((line) => /withdrawn|unavailable|unreachable|tick failed/.test(line))
    .map((line) => {
      const at = Date.parse(line.split(" ")[0] ?? "");
      return `+${at - completedAt} ms ${line.split(" ").slice(2).join(" ").slice(0, 120)}`;
    });
  report.lines.push(`      watchdog: ${JSON.stringify(watchdogLines.slice(-6))}`);
  report.lines.push(
    `      timing: lease ${leaseMs} ms from completion; route withdrawn at completion + ${gone - completedAt} ms, session closed at completion + ${sessionClosed ? sessionClosed - completedAt : "never"} ms (bound ${leaseMs + 5_000} ms)`,
  );
  expect(
    report,
    gone <= deadline && sessionClosed > 0 && sessionClosed <= deadline,
    "with observation stopped, the route and its session are withdrawn by last completion + lease + 5 s",
    `withdrawn +${gone - completedAt} ms, closed +${sessionClosed - completedAt} ms <= +${leaseMs + 5_000} ms`,
  );
  expect(
    report,
    gone >= completedAt + leaseMs - 1_000,
    "control: nothing is withdrawn while the lease is still valid",
    `first withdrawal at +${gone - completedAt} ms`,
  );
  expect(
    report,
    !(await activeBackends()).includes(peerBackend),
    "the active config no longer dials the peer",
    JSON.stringify(await activeBackends()),
  );
}

async function expiredStartTest(report: Report) {
  // The lease is expired and the on-disk Caddyfile still names the route (nothing re-applied it).
  // The worker stand-in (uid 1000) wrote it with mode 0600. Read it as uid 1000: on a Linux host
  // whose user is not uid 1000 (a CI runner is 1001), a direct read fails with EACCES.
  const caddyfile = await docker(
    "run",
    "--rm",
    "--network",
    "none",
    "--user",
    "1000:1000",
    "--volume",
    `${edgeDir}:/edge:ro`,
    bunImage,
    "cat",
    "/edge/Caddyfile",
  );
  expect(
    report,
    caddyfile.includes(`# ark-tailnet-route ${routeId} ${peerBackend}`),
    "control: the rendered Caddyfile still contains the route",
    "marker present",
  );
  const restart = async () => {
    await docker("restart", stack.edge);
    await refreshPorts();
    await waitFor("edge to serve :80 again", async () =>
      (await plainGet("example.com", "/.well-known/acme-challenge/obs-token")).status === 200
        ? true
        : undefined,
    );
  };
  await restart();
  const logs = await edgeLogs();
  const result = await outcome();
  expect(
    report,
    /starting from \/etc\/caddy\/ark\/Caddyfile\.closed: no valid lease \(watchdog: closed\)/.test(logs) &&
      result !== "upstream",
    "starting with an expired lease, the launch guard runs the closed config: the tailnet route fails closed while :80 serves",
    `${logs.match(/ark launch guard: [^\n]+/g)?.at(-1)}; GET ${result}`,
  );
  // Without the watchdog at all, the guard cannot obtain a lease and stays closed too.
  await docker("stop", watchdogName);
  await restart();
  const unreachable = (await edgeLogs()).match(/ark launch guard: [^\n]+/g)?.at(-1) ?? "";
  expect(
    report,
    /Caddyfile\.closed: no valid lease \(watchdog: unreachable\)/.test(unreachable) &&
      (await outcome()) !== "upstream",
    "with the watchdog unreachable, the guard also starts closed",
    unreachable,
  );
  await startWatchdog("http://edge-admin:2019");
}

async function withdrawalFailureTest(report: Report, failure: "load" | "read" = "load") {
  // A fresh lease kept fresh, Caddy restarted through the guard (now open), and the route live again.
  await restoreRoute(report);
  const stopObserving = keepObserving();
  try {
    await docker("restart", stack.edge);
    await refreshPorts();
    await waitUntilServing(report, "with a valid lease the launch guard opens the full config");
    expect(
      report,
      /starting from \/etc\/caddy\/ark\/Caddyfile: the watchdog confirmed a valid lease/.test(
        await edgeLogs(),
      ),
      "the guard logged an open start",
      "open",
    );
    // Route the watchdog through a proxy that refuses POST /load, so withdrawal cannot be applied.
    const fault = `ark-edge-observer-fault-${suffix}-${failure}`;
    runtime.containers.push(fault);
    await docker(
      "run",
      "--detach",
      "--name",
      fault,
      "--network",
      stack.networks.edgeControl,
      "--network-alias",
      `admin-fault-${failure}`,
      "--env",
      `ARK_TEST_ADMIN_FAULT=${failure}`,
      "--volume",
      `${join(fixtures, "admin-fault.ts")}:/fixture/admin-fault.ts:ro`,
      bunImage,
      "bun",
      "/fixture/admin-fault.ts",
    );
    await startWatchdog(`http://admin-fault-${failure}:2019`);
    // Replacing the watchdog can intentionally restart Caddy closed. Restore the test route only
    // after the new enforcer has verified that state; no apply runs after injecting the fault.
    await edgeApply();
    await Bun.sleep(1_200); // Complete an inspection through the fault proxy before enabling read errors.
    const restartsBefore = Number(await docker("inspect", "-f", "{{.RestartCount}}", stack.edge));
    await waitUntilServing(report, "control: the route is still served through the fault-injecting watchdog");
    await stopObserving();
    await sql`DELETE FROM alerts WHERE dedup_key = 'edge-withdrawal'`;
    const session = await openSession();
    if (failure === "read")
      await docker(
        "exec",
        fault,
        "bun",
        "--eval",
        'await fetch("http://127.0.0.1:2019/fault/enable", { method: "POST" })',
      );
    mock.state.peers = [impostor];
    const detection = await observe();
    const gone = await withdrawnAt(15_000);
    const sessionClosed = await Promise.race([session.closed, Bun.sleep(5_000).then(() => 0)]);
    expect(
      report,
      sessionClosed > 0 && sessionClosed - detection.detectedAt <= 5_000,
      "admin failure closes the existing public session within detection + 5 s",
      String(sessionClosed),
    );
    const stopped = await waitFor("Caddy to be restarted after the stop", async () => {
      const count = Number(await docker("inspect", "-f", "{{.RestartCount}}", stack.edge));
      return count > restartsBefore ? count : undefined;
    });
    const [alert] =
      await sql`SELECT severity, title FROM alerts WHERE dedup_key = 'edge-withdrawal' AND resolved_at IS NULL`;
    const watchdogLogs = (await runtime.dockerOutput("logs", watchdogName)).stdout;
    await startWatchdog("http://edge-admin:2019");
    await refreshPorts();
    await waitFor("edge to come back closed", async () =>
      (await plainGet("example.com", "/.well-known/acme-challenge/obs-token")).status === 200
        ? true
        : undefined,
    );
    const guard = (await edgeLogs()).match(/ark launch guard: [^\n]+/g)?.at(-1) ?? "";
    report.lines.push(
      `      timing: route stopped serving ${gone - detection.detectedAt} ms after detection`,
    );
    expect(
      report,
      /withdrawal_failed \[caddy\]/.test(watchdogLogs) &&
        (/proxy_stopped \[caddy\]/.test(watchdogLogs) ||
          /watchdog enforcement unavailable/.test(await edgeLogs())) &&
        stopped > restartsBefore,
      "when the withdrawal cannot be applied, the watchdog stops Caddy (POST /stop)",
      `watchdog: ${watchdogLogs.match(/withdrawal_failed[^\n]*/)?.[0]}; edge restart count ${restartsBefore} -> ${stopped}`,
    );
    expect(report, alert?.severity === "critical", "and raises a critical alert", String(alert?.title));
    expect(
      report,
      /Caddyfile\.closed/.test(guard) &&
        (await outcome()) !== "upstream" &&
        gone - detection.detectedAt <= 5_000,
      "the restarted Caddy comes back through the launch guard with the route closed",
      `${guard}; GET ${await outcome()}`,
    );
  } finally {
    await stopObserving();
  }
}

/** Lose enforcement while a live route/session is running, without any worker or Caddy restart. */
async function watchdogLossTest(report: Report) {
  for (const mode of ["pause", "stop"] as const) {
    await startWatchdog("http://edge-admin:2019");
    await restoreRoute(report);
    const session = await openSession();
    const lostAt = Date.now();
    try {
      await docker(mode, watchdogName);
      const gone = await withdrawnAt(5_000);
      const closed = await Promise.race([session.closed, Bun.sleep(5_000).then(() => 0)]);
      expect(
        report,
        gone - lostAt <= 5_000 && closed > 0 && closed - lostAt <= 5_000,
        `${mode}: independent supervisor closes listener and session within 5 s`,
        `listener +${gone - lostAt} ms, session +${closed - lostAt} ms`,
      );
      await Bun.sleep(1_000);
      expect(
        report,
        (await outcome()) !== "upstream",
        `${mode}: route stays closed without enforcement`,
        await outcome(),
      );
    } finally {
      session.end();
      if (mode === "pause") await docker("unpause", watchdogName);
    }
  }
  await startWatchdog("http://edge-admin:2019");
}

async function sharedBackendTest(report: Report) {
  await restoreRoute(report);
  await sql`INSERT INTO endpoints (id, kind, hostname) VALUES ('end_shared', 'route', ${sharedHost})`;
  await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
    VALUES ('crt_shared', 'end_shared', ${JSON.stringify([sharedHost])}::jsonb, 'issued', now())`;
  await sql`INSERT INTO front_routes (id, kind, endpoint_id, listen_port, target_input, target_node_stable_id, target_ip, target_port, access_mode, status, enabled)
    VALUES ('rt_shared', 'http', 'end_shared', 443, ${peerIp}, ${home.id}, ${peerIp}, 3000, 'public', 'ready', true)`;
  const stopObserving = keepObserving();
  try {
    await edgeApply();
    await waitFor("both shared-backend hostnames serving", async () =>
      (await outcome()) === "upstream" && (await outcome(sharedHost)) === "upstream" ? true : undefined,
    );
    const session = await openSession();
    await sql`UPDATE front_routes SET enabled = false WHERE id = ${routeId}`;
    const revokedAt = Date.now();
    const gone = await withdrawnAt(5_000);
    const closed = await Promise.race([session.closed, Bun.sleep(5_000).then(() => 0)]);
    expect(
      report,
      gone - revokedAt <= 5_000 && closed > 0 && closed - revokedAt <= 5_000,
      "revoking one hostname closes its handler and session on a shared backend",
      `withdrawn +${gone - revokedAt} ms; closed +${closed - revokedAt} ms`,
    );
    expect(
      report,
      (await outcome(sharedHost)) === "upstream",
      "the other hostname still reaches the same backend",
      await outcome(sharedHost),
    );
    await docker("restart", stack.edge);
    await refreshPorts();
    await waitFor("stale file refused on restart", async () =>
      /Caddyfile.closed/.test((await edgeLogs()).match(/ark launch guard: starting[^\n]+/g)?.at(-1) ?? "")
        ? true
        : undefined,
    );
    expect(
      report,
      (await outcome()) !== "upstream",
      "restart refuses the stale file containing the revoked hostname",
      await outcome(),
    );
  } finally {
    await stopObserving();
    await sql`DELETE FROM front_routes WHERE id = 'rt_shared'`;
    await sql`DELETE FROM certificates WHERE id = 'crt_shared'`;
    await sql`DELETE FROM endpoints WHERE id = 'end_shared'`;
  }
}

// ---- Runner --------------------------------------------------------------------------------------------

async function run(name: string, test: (report: Report) => Promise<unknown>) {
  const report: Report = { name, lines: [] };
  const started = Date.now();
  try {
    await test(report);
    console.log(
      `\n[${name}] passed in ${((Date.now() - started) / 1000).toFixed(1)} s\n${report.lines.join("\n")}`,
    );
    return true;
  } catch (error) {
    console.error(`\n[${name}] FAILED\n${report.lines.join("\n")}\n  ${(error as Error).message}`);
    return false;
  }
}

let failed = false;
try {
  await prepareFiles();
  await startControlPlane();
  await startContainers();
  await refreshPorts();
  const results = [
    await run("localapi read-only deployment (FD-06)", localApiTest),
    await run("identity withdrawal within detection + 5 s", identityWithdrawalTest),
    await run("shared backend per-route withdrawal and restart", sharedBackendTest),
    await run("watchdog loss while Caddy is serving", watchdogLossTest),
    await run("lease expiry with observation stopped", leaseExpiryTest),
    await run("start with an expired lease", expiredStartTest),
    await run("withdrawal failure stops the proxy", withdrawalFailureTest),
    await run("unreadable admin config stops the proxy", (report) => withdrawalFailureTest(report, "read")),
  ];
  failed = results.includes(false);
  const restarts = await docker("inspect", "-f", "{{.RestartCount}}", stack.edgeTs);
  console.log(`\nedge-ts restarts during the run: ${restarts}`);
  if (failed) await runtime.dumpLogs();
  else
    console.log(
      "\nAll edge observer tests passed. HAProxy-generation withdrawal runs in scripts/test-edge-l4.ts.",
    );
} catch (error) {
  failed = true;
  console.error((error as Error).message);
  await runtime.dumpLogs();
} finally {
  mock?.stop();
  await apiServer?.stop(true);
  await sql?.end().catch(() => undefined);
  await runtime.cleanup();
  for (const name of extraNetworks)
    await Bun.spawn(["docker", "network", "rm", name], { stdout: "ignore", stderr: "ignore" }).exited;
  await admin.unsafe(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`).catch(() => undefined);
  await admin.end();
  removeSignalHandlers();
}
if (failed) process.exit(1);
