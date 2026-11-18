// `mise run test:edge` (FD-14): TLS-TCP routes by SNI and raw-TCP routes on dedicated ports through the
// shipped HAProxy SNI router (`edge-l4`), from docs/design/front-door.md §3.8.4-§3.8.6, in disposable
// containers. No tailnet login, database or Python is needed.
//
// The shipped edge-ts, edge (Caddy), edge-l4 (HAProxy 3.2.26 behind its launch guard) and
// haproxy-validator run in a disposable Compose project, as in scripts/test-edge-l4.ts. Generations are
// written by the production `writeEdgeL4` in the domain worker's identity (uid 1000, group 4400, no
// capabilities, no Docker); the production edge watchdog enforces a lease served by this process, whose
// L4 routes carry their policy fingerprints. Route CAs, client certificates and CRLs come from the
// production PKI code (server/src/modules/pki.ts). Simulated tailnet peers (a TLS echo with its own
// certificate, and a plaintext TCP echo) sit at 100.64.0.0/10 addresses; client agents sit at fixed
// addresses on a client network attached to edge-ts, so HAProxy sees distinct sources.
//
// Covered (the FD-14 acceptance criteria):
// - the literal §3.8.5 route (rt_p7q2, SNI mqtt.example.com) in passthrough, terminate and
//   terminate_mtls, each with a full and a fragmented ClientHello: an allowed source with the required
//   authentication succeeds, an outside-CIDR source fails; mTLS refuses no certificate and a rogue CA;
//   passthrough presents the target's own certificate;
// - two TLS routes on 443 at 10 connections per source: the 11th fails, another source and the other
//   route keep capacity, and the original source is visible after the PROXY loop; maxconn enforced;
// - sessions opened across several reloads, then new connections racing a revocation: all affected
//   sessions close within 5 s across current and leaving workers, admission stays closed, the other
//   route's live session survives;
// - a revoked client certificate is refused after the CRL update and reload;
// - a shared SNI port (8883): an outside-CIDR source is refused for that route only;
// - a raw TCP route on 20001: allowlist, per-source and total limits, deny-all for an empty list, and
//   edge.drain (domain worker) closing its sessions within 5 s while other routes' sessions survive;
// - HTTP routes on the same 443 keep working throughout;
// - the raw-port nftables table: `nft -c`, and in network namespaces an empty list drops, a closed
//   range port drops, an allowlist admits only its sources and only allowInternet opens.
//
// `ARK_EDGE_L4_ONLY=<text>` runs only the named tests whose name contains <text> (setup always runs).
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { connect as tlsConnect } from "node:tls";

import {
  L4_LIMIT_DEFAULTS,
  haproxyServerName,
  l4PolicyFingerprint,
  routeIdentityKey,
  renderFrontIngress,
  type EdgeL4Input,
  type EdgeL4TcpRoute,
  type EdgeL4TlsRoute,
  type EdgeLeaseDocument,
  type EdgePolicyRoute,
  type L4Limits,
  type WatchdogEvent,
} from "@ark-stack/shared";

import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { type EdgeStack, startEdgeStack } from "./edge-test/stack.ts";

// The PKI module is pure apart from persistence; it only needs a (never used) database URL to load.
process.env.DATABASE_URL ??= "postgres://unused@127.0.0.1:1/unused";
const pki = await import("../server/src/modules/pki.ts");
const x509 = await import("../server/src/modules/x509.ts");

const root = resolve(import.meta.dir, "..");
const fixtures = join(import.meta.dir, "edge-test");
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const nftImage = `ark-db-ingress-test:${suffix}`;
let nftImageBuilt = false;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-l4-routes-${suffix}-`));
const network = `ark-edge-l4r-${suffix}`;
const runtime = new EdgeTestRuntime(directory, network, bunImage);
const removeSignalHandlers = runtime.installSignalHandlers();
const docker = (...args: string[]) => runtime.docker(...args);
const extraNetworks: string[] = [];

const random = (span: number) => Number.parseInt(randomBytes(2).toString("hex"), 16) % span;
const peerSubnet = `100.${64 + random(64)}.${1 + random(250)}.0/24`;
const peerPrefix = peerSubnet.slice(0, peerSubnet.lastIndexOf("."));
const peerTlsIp = `${peerPrefix}.11`;
const peerPlainIp = `${peerPrefix}.12`;
const peerNetwork = `ark-edge-l4r-peer-${suffix}`;
const clientNetwork = `ark-edge-l4r-client-${suffix}`;
let clientPrefix = "";

const appHost = "app.example.com";
const mqttHost = "mqtt.example.com";
const amqpHost = "amqp.example.com";
const sharedHost = "shared.example.com";
const tcpHost = "ssh-box.example.com";
const targetCn = "nas-target.internal";

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

// ---- Certificates ---------------------------------------------------------------------------------------

/** A route CA and client certificates from the production PKI code. */
function routeCa(id: string) {
  const ca = pki.createCaMaterial({ id, purpose: "tcp-client", name: `Route ${id}` });
  const signer = { certPem: ca.certPem, privateKey: ca.privateKey };
  const client = (cn: string) => {
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const key = pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    return { key, ...pki.signClientCertificate({ ca: signer, subjectCn: cn, publicKey: pair.publicKey }) };
  };
  const crl = (revoked: string[] = []) =>
    pki.buildCrl({
      ca: signer,
      revoked: revoked.map((serial) => ({ serial, revokedAt: new Date(Date.now() - 1_000) })),
      thisUpdate: new Date(Date.now() - 60_000),
      nextUpdate: new Date(Date.now() + 14 * 86_400_000),
      crlNumber: BigInt(Date.now()),
    }).crlPem;
  return { certPem: ca.certPem, client, crl };
}

const edgeCert = { chain: "", key: "" };

const certificate = (dir: string, host: string) =>
  `mkdir -p ${dir} && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=${host}" -addext "subjectAltName=DNS:${host}" -keyout ${dir}/privkey.pem -out ${dir}/fullchain.pem 2>/dev/null && chmod 644 ${dir}/privkey.pem`;

async function prepareFiles() {
  const edgeDir = join(directory, "edge");
  await mkdir(join(directory, "acme", ".well-known", "acme-challenge"), { recursive: true });
  await mkdir(edgeDir);
  await mkdir(join(directory, "peer-certs"));
  await Bun.write(
    join(edgeDir, "Caddyfile"),
    `{\n  admin edge-admin:2019\n  auto_https off\n}\n${appHost} {\n  tls /var/lib/ark/certs/${appHost}/fullchain.pem /var/lib/ark/certs/${appHost}/privkey.pem\n  respond "http ok"\n}\n`,
  );
  await Bun.write(join(edgeDir, "Caddyfile.closed"), await Bun.file(join(edgeDir, "Caddyfile")).text());
  await chmod(directory, 0o755);
  const script = [
    "set -e",
    certificate(`/out/certs/${appHost}`, appHost),
    certificate("/out/edge-route", mqttHost),
    certificate("/out/peer-certs", targetCn),
    "chown -R 1000:1000 /out/certs /out/edge",
  ].join("\n");
  await docker("run", "--rm", "--user", "0:0", "--volume", `${directory}:/out`, bunImage, "sh", "-c", script);
  edgeCert.chain = await Bun.file(join(directory, "edge-route", "fullchain.pem")).text();
  edgeCert.key = await Bun.file(join(directory, "edge-route", "privkey.pem")).text();
}

// ---- Lease API (the API's read-only lease endpoint, served by this process) -----------------------------

const watchdogToken = randomBytes(24).toString("base64url");
const lease = { routes: [] as EdgePolicyRoute[] };
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
      const document: EdgeLeaseDocument = {
        now: new Date(now).toISOString(),
        lease: {
          generation: "gen-l4-routes",
          completedAt: new Date(now - 1_000).toISOString(),
          validUntil: new Date(now + 360_000).toISOString(),
          valid: true,
        },
        routes: lease.routes,
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

// ---- Containers ------------------------------------------------------------------------------------------

let stack!: EdgeStack;
const bundles = { watchdog: "", probe: "", agent: "" };

async function createSubnetNetwork(name: string) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const prefix = `10.${200 + random(50)}.${1 + random(250)}`;
    try {
      await docker("network", "create", "--subnet", `${prefix}.0/24`, name);
      extraNetworks.push(name);
      return prefix;
    } catch (error) {
      if (!/overlap|in use/i.test((error as Error).message)) throw error;
    }
  }
  throw new Error(`could not find a free subnet for ${name}`);
}

async function startContainers() {
  runtime.networkCreated = true;
  await docker("network", "create", network);
  stack = await startEdgeStack({
    runtime,
    project: `ark-edge-l4r-${suffix}`,
    directory,
    acmeDir: join(directory, "acme"),
    certDir: join(directory, "certs"),
    edgeDir: join(directory, "edge"),
    validator: true,
    ports: ["127.0.0.1::80", "127.0.0.1::443", "127.0.0.1::8883", "127.0.0.1::20001", "127.0.0.1::41642/udp"],
    edgeTsCommand: [
      "tailscaled",
      "--state=mem:",
      "--socket=/var/run/tailscale/tailscaled.sock",
      "--port=41642",
      "--tun=tailscale0",
    ],
  });
  await docker("network", "create", "--subnet", peerSubnet, peerNetwork);
  extraNetworks.push(peerNetwork);
  await docker("network", "connect", peerNetwork, stack.edgeTs);
  clientPrefix = await createSubnetNetwork(clientNetwork);
  await docker("network", "connect", "--ip", `${clientPrefix}.2`, clientNetwork, stack.edgeTs);
  for (const [name, ip, script, mounts] of [
    [
      `ark-edge-l4r-peer-tls-${suffix}`,
      peerTlsIp,
      "tls-echo.ts",
      ["--volume", `${join(directory, "peer-certs")}:/certs:ro`],
    ],
    [`ark-edge-l4r-peer-plain-${suffix}`, peerPlainIp, "tcp-echo.ts", []],
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
      "--volume",
      `${join(fixtures, script)}:/fixture/app.ts:ro`,
      ...mounts,
      bunImage,
      "bun",
      "/fixture/app.ts",
    );
  }
  bundles.watchdog = await bundle(join(root, "workers/src/edge-watchdog.ts"), "watchdog");
  bundles.probe = await bundle(join(fixtures, "l4-worker-probe.ts"), "probe");
  bundles.agent = await bundle(join(fixtures, "route-agent.ts"), "agent");
  await startWatchdog();
  for (const [key, octet] of [
    ["A", 10],
    ["B", 11],
    ["C", 12],
  ] as const)
    agents[key] = await startAgent(key, octet);
}

const watchdogName = `ark-edge-l4r-watchdog-${suffix}`;

/** Wait for two distinct completed, verified passes; a busy-pass heartbeat is not readiness. */
async function settle() {
  let previous: string | undefined;
  let completed = 0;
  await waitFor(
    "two completed watchdog enforcement passes",
    async () => {
      const text = await docker(
        "exec",
        watchdogName,
        "bun",
        "--eval",
        'const r = await fetch("http://127.0.0.1:2021/v1/health?proxy=haproxy"); console.log(JSON.stringify((await r.json()).proxies.haproxy))',
      );
      const state = JSON.parse(text) as {
        policyError: string | null;
        lastTick: { at: string; errors: string[] } | null;
      };
      const tick = state.lastTick;
      if (!tick || state.policyError || tick.errors.length) {
        completed = 0;
        return undefined;
      }
      if (previous !== tick.at) {
        if (previous !== undefined) completed++;
        previous = tick.at;
      }
      return completed >= 2 ? true : undefined;
    },
    30_000,
    300,
  );
}

/** The edge watchdog as shipped (uid 1000, group 4400, read-only root, no capabilities), with HAProxy. */
async function startWatchdog() {
  const name = watchdogName;
  runtime.containers.push(name);
  await docker(
    "run",
    "--detach",
    "--name",
    name,
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
    `${join(directory, "edge")}:/var/lib/ark/edge`,
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
  await docker("network", "connect", "--alias", "edge-watchdog", stack.networks.edgeControl, name);
  await waitFor(
    "verified watchdog enforcement on HAProxy",
    async () => {
      const status = await docker(
        "exec",
        name,
        "bun",
        "--eval",
        'const r = await fetch("http://127.0.0.1:2021/v1/supervise?proxy=haproxy"); if (!r.ok) process.exit(1); console.log("ready")',
      );
      return status === "ready" ? true : undefined;
    },
    30_000,
    500,
  );
}

const probeName = `ark-edge-l4r-worker-${suffix}`;
let probeStarted = false;
/** The domain worker's edge-l4 side: production writeEdgeL4 and the HAProxy adapter. */
async function probe<T = Record<string, unknown>>(args: string[]) {
  if (!probeStarted) {
    runtime.containers.push(probeName);
    await docker(
      "run",
      "--detach",
      "--name",
      probeName,
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
      bunImage,
      "sleep",
      "3600",
    );
    probeStarted = true;
  }
  const output = await docker("exec", probeName, "bun", "/probe/l4-worker-probe.js", ...args);
  return JSON.parse(output.split("\n").at(-1) ?? "{}") as T;
}

// ---- Client agents -----------------------------------------------------------------------------------------

type Agent = { ip: string; port: number };
const agents = {} as Record<"A" | "B" | "C", Agent>;
type Opened = { id: string; ok: boolean; error?: string; peerCN?: string | null; ms: number };

async function startAgent(key: string, octet: number): Promise<Agent> {
  const name = `ark-edge-l4r-agent-${key.toLowerCase()}-${suffix}`;
  const ip = `${clientPrefix}.${octet}`;
  runtime.containers.push(name);
  await docker(
    "run",
    "--detach",
    "--name",
    name,
    "--network",
    clientNetwork,
    "--ip",
    ip,
    "--publish",
    "127.0.0.1::9000",
    "--volume",
    `${bundles.agent}:/agent:ro`,
    bunImage,
    "bun",
    "/agent/route-agent.js",
  );
  const mapped = await docker("port", name, "9000/tcp");
  const port = Number(/:(\d+)\s*$/m.exec(mapped)?.[1]);
  const agent = { ip, port };
  await waitFor(
    `agent ${key}`,
    async () => ((await agentCall(agent, "GET", "/state")) ? true : undefined),
    20_000,
  );
  return agent;
}

async function agentCall(agent: Agent, method: string, path: string, body?: unknown) {
  const response = await fetch(`http://127.0.0.1:${agent.port}${path}`, {
    method,
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  return (await response.json()) as Record<string, any>;
}

let edgeIp = "";
type OpenOptions = {
  port?: number;
  sni?: string;
  tls?: boolean;
  cert?: { certPem: string; key: string };
  fragment?: number;
  hold?: boolean;
};
function open(agent: Agent, options: OpenOptions = {}) {
  return agentCall(agent, "POST", "/open", {
    host: edgeIp,
    port: options.port ?? 443,
    tls:
      options.tls === false
        ? undefined
        : {
            servername: options.sni ?? mqttHost,
            ...(options.cert ? { cert: options.cert.certPem, key: options.cert.key } : {}),
          },
    fragment: options.fragment,
    hold: options.hold,
  }) as Promise<Opened>;
}
const closeAll = async () =>
  Promise.all(Object.values(agents).map((agent) => agentCall(agent, "POST", "/close", {})));
async function closedState(agent: Agent) {
  return (await agentCall(agent, "GET", "/state")).sessions as Record<string, { closed: boolean }>;
}
async function echo(agent: Agent, id: string) {
  return (await agentCall(agent, "POST", "/echo", { id, message: `still-${id}` })).echoed === `still-${id}`;
}

// ---- Routes, lease and apply ----------------------------------------------------------------------------------

type TlsSpec = Omit<EdgeL4TlsRoute, "stableId" | "ip" | "port" | "policy"> & { target?: "tls" | "plain" };
function tlsRoute(spec: TlsSpec): EdgeL4TlsRoute {
  const plain = (spec.target ?? (spec.tlsMode === "passthrough" ? "tls" : "plain")) === "plain";
  const limits: L4Limits = { ...L4_LIMIT_DEFAULTS.tls, ...spec.limits };
  const route = {
    ...spec,
    stableId: `n${spec.id.replace(/_/g, "")}`,
    ip: plain ? peerPlainIp : peerTlsIp,
    port: plain ? 1884 : 1883,
    limits,
  };
  delete (route as { target?: unknown }).target;
  return {
    ...route,
    policy: l4PolicyFingerprint({
      kind: "tls",
      listenPort: spec.listenPort ?? 443,
      tlsMode: spec.tlsMode ?? "passthrough",
      sourceCidrs: spec.sourceCidrs,
      allowInternet: Boolean(spec.allowInternet),
      limits,
      clientCaId: spec.tlsMode === "terminate_mtls" ? spec.id : null,
      revokedSerials: spec.clientCrlPem
        ? x509.parseCrl(x509.fromPem(spec.clientCrlPem, ["X509 CRL"])).revoked.map((entry) => entry.serial)
        : [],
    }),
    ...(spec.tlsMode && spec.tlsMode !== "passthrough"
      ? { certificatePem: `${edgeCert.chain.trim()}\n${edgeCert.key.trim()}\n` }
      : {}),
  };
}
function tcpRoute(spec: Omit<EdgeL4TcpRoute, "stableId" | "ip" | "port" | "policy">): EdgeL4TcpRoute {
  const limits: L4Limits = { ...L4_LIMIT_DEFAULTS.tcp, ...spec.limits };
  return {
    ...spec,
    stableId: `n${spec.id.replace(/_/g, "")}`,
    ip: peerPlainIp,
    port: 1884,
    limits,
    policy: l4PolicyFingerprint({
      kind: "tcp",
      listenPort: spec.listenPort,
      tlsMode: "plain",
      sourceCidrs: spec.sourceCidrs,
      allowInternet: Boolean(spec.allowInternet),
      limits,
    }),
  };
}
const policyOf = (route: EdgeL4TlsRoute | EdgeL4TcpRoute, kind: "tls" | "tcp"): EdgePolicyRoute => ({
  id: route.id,
  kind,
  hostname: route.hostname,
  stableId: route.stableId,
  ip: route.ip,
  port: route.port,
  policy: route.policy,
});

/** Production transition: publish the desired policy first, fence old identities, then install. */
async function apply(input: { tlsRoutes?: EdgeL4TlsRoute[]; tcpRoutes?: EdgeL4TcpRoute[] }) {
  const next = [
    ...(input.tlsRoutes ?? []).map((route) => policyOf(route, "tls")),
    ...(input.tcpRoutes ?? []).map((route) => policyOf(route, "tcp")),
  ];
  lease.routes = next;
  await settle();
  const full: EdgeL4Input = { httpHostnames: [appHost], sniPorts: [8883], ...input };
  // The launch guard reacts to the lease too (it re-points or reloads); a reload racing it can go
  // unanswered, which the installer reports and restores, exactly as edge.l4_apply then retries.
  for (let attempt = 0; ; attempt++) {
    const result = await probe<{ applied?: boolean; error?: string }>([
      "apply",
      JSON.stringify(full),
      "force",
    ]);
    if (!result.error && result.applied) break;
    if (attempt >= 5 || !/answer|reload|timed out/i.test(result.error ?? "")) {
      throw new Error(`apply failed: ${result.error ?? JSON.stringify(result)}`);
    }
    await Bun.sleep(1_500);
  }
  // Serving: the guard runs the full configuration and the current worker has every route server.
  const expected = [...(input.tlsRoutes ?? []), ...(input.tcpRoutes ?? [])].map(haproxyServerName);
  await waitFor(
    "the generation to be served",
    async () => {
      if ((await guardMode()) !== "full") return undefined;
      const workers = await probe<
        Record<string, { section: string; servers: Array<{ server: string; adminState: number }> }>
      >(["servers"]);
      const names = new Set(
        Object.values(workers)
          .filter((worker) => worker.section === "current")
          .flatMap((worker) =>
            worker.servers.filter((server) => (server.adminState & 1) === 0).map((server) => server.server),
          ),
      );
      return expected.every((name) => names.has(name)) ? true : undefined;
    },
    30_000,
    300,
  );
  lease.routes = next;
  await settle();
}

/** The HAProxy launch guard's mode, from its latest mode line. */
async function guardMode() {
  const line = (await logsOf(stack.edgeL4))
    .split("\n")
    .findLast((entry) =>
      /launch guard: (starting from the (full|closed) configuration|lease valid; switched|lease no longer allows|full reload unconfirmed)/.test(
        entry,
      ),
    );
  if (!line) return undefined;
  return /starting from the full|switched to the full/.test(line) ? "full" : "closed";
}
const cidr = (agent: Agent) => `${agent.ip}/32`;

/** HTTPS to the HTTP route through 443, from the host. */
function httpOk() {
  return new Promise<boolean>((resolveOk) => {
    const socket = tlsConnect({
      host: "127.0.0.1",
      port: httpsPort,
      servername: appHost,
      rejectUnauthorized: false,
    });
    let data = "";
    const timer = setTimeout(() => socket.destroy(), 5_000);
    socket.on("secureConnect", () =>
      socket.write(`GET / HTTP/1.1\r\nHost: ${appHost}\r\nConnection: close\r\n\r\n`),
    );
    socket.on("data", (chunk) => (data += chunk.toString()));
    socket.on("error", () => undefined);
    socket.on("close", () => {
      clearTimeout(timer);
      resolveOk(data.startsWith("HTTP/1.1 200") && data.includes("http ok"));
    });
  });
}
let httpsPort = 0;

async function logsOf(container: string) {
  const { stdout, stderr } = await runtime.dockerOutput("logs", container);
  return stdout + stderr;
}

// ---- Tests -----------------------------------------------------------------------------------------------

const ca = {
  route: undefined as unknown as ReturnType<typeof routeCa>,
  rogue: undefined as unknown as ReturnType<typeof routeCa>,
};
const certs = {} as Record<"valid" | "second" | "rogue", { certPem: string; key: string; serial: string }>;

async function literalExampleTest(report: Report) {
  for (const mode of ["passthrough", "terminate", "terminate_mtls"] as const) {
    const route = tlsRoute({
      id: "rt_p7q2",
      hostname: mqttHost,
      tlsMode: mode,
      // A and B are inside the list; C is outside it.
      sourceCidrs: [cidr(agents.A), cidr(agents.B)],
      ...(mode === "terminate_mtls" ? { clientCaPem: ca.route.certPem, clientCrlPem: ca.route.crl() } : {}),
    });
    await apply({ tlsRoutes: [route] });
    const auth = mode === "terminate_mtls" ? { cert: certs.valid } : {};
    for (const fragment of [undefined, 48] as const) {
      const label = fragment ? "fragmented ClientHello" : "full ClientHello";
      const allowed = await waitFor(
        `${mode} to admit A`,
        async () => {
          const result = await open(agents.A, { ...auth, fragment });
          return result.ok ? result : undefined;
        },
        15_000,
        300,
      );
      const expectedCn = mode === "passthrough" ? targetCn : mqttHost;
      expect(
        report,
        allowed.ok && allowed.peerCN === expectedCn,
        `${mode}, ${label}: an allowed source${mode === "terminate_mtls" ? " with a route-CA client certificate" : ""} is relayed and sees ${mode === "passthrough" ? "the target's own certificate" : "the edge certificate"}`,
        `ok=${allowed.ok} peer CN=${allowed.peerCN}`,
      );
      const outside = await open(agents.C, { ...auth, fragment });
      expect(
        report,
        !outside.ok,
        `${mode}, ${label}: a source outside the CIDR list fails`,
        outside.error ?? "relayed",
      );
      if (mode === "terminate_mtls") {
        const none = await open(agents.A, { fragment });
        const rogue = await open(agents.A, { cert: certs.rogue, fragment });
        expect(
          report,
          !none.ok && !rogue.ok,
          `${mode}, ${label}: no client certificate and a rogue-CA certificate are refused`,
          `${none.error}; ${rogue.error}`,
        );
      }
    }
  }
  expect(report, await httpOk(), "HTTP routes on the same 443 keep working", appHost);
}

async function crlRevocationTest(report: Report) {
  const base = {
    id: "rt_p7q2",
    hostname: mqttHost,
    tlsMode: "terminate_mtls" as const,
    sourceCidrs: [cidr(agents.A)],
  };
  await apply({
    tlsRoutes: [tlsRoute({ ...base, clientCaPem: ca.route.certPem, clientCrlPem: ca.route.crl() })],
  });
  const before = await waitFor("the second certificate to be accepted", async () => {
    const result = await open(agents.A, { cert: certs.second });
    return result.ok ? result : undefined;
  });
  expect(report, before.ok, "a second client certificate is accepted before revocation", "relayed");
  // The serial is revoked: a new CRL, a new policy fingerprint (lease first), then the reload.
  await apply({
    tlsRoutes: [
      tlsRoute({ ...base, clientCaPem: ca.route.certPem, clientCrlPem: ca.route.crl([certs.second.serial]) }),
    ],
  });
  const revoked = await waitFor(
    "the revoked certificate to be refused",
    async () => {
      const result = await open(agents.A, { cert: certs.second });
      return result.ok ? undefined : result;
    },
    15_000,
    300,
  );
  const valid = await open(agents.A, { cert: certs.valid });
  expect(
    report,
    !revoked.ok && valid.ok,
    "after the CRL update and reload the revoked serial is refused and a valid certificate still works",
    `revoked: ${revoked.error}; valid: ${valid.ok ? "relayed" : valid.error}`,
  );
}

function limitRoutes(limits: Partial<L4Limits> = {}) {
  return [
    tlsRoute({
      id: "rt_lim1",
      hostname: mqttHost,
      tlsMode: "terminate",
      sourceCidrs: [cidr(agents.A), cidr(agents.B)],
      limits: { perSourceRate: 200, ...limits },
    }),
    tlsRoute({
      id: "rt_lim2",
      hostname: amqpHost,
      tlsMode: "passthrough",
      sourceCidrs: [cidr(agents.A), cidr(agents.B)],
      limits: { perSourceRate: 200 },
    }),
  ];
}

async function perSourceLimitTest(report: Report) {
  await apply({ tlsRoutes: limitRoutes() });
  await waitFor("the limit route", async () => ((await open(agents.A)).ok ? true : undefined), 15_000, 300);
  const held: Opened[] = [];
  for (let index = 0; index < 10; index++) held.push(await open(agents.A, { hold: true }));
  const eleventh = await open(agents.A, { hold: true });
  expect(
    report,
    held.every((item) => item.ok) && !eleventh.ok,
    "two TLS routes on 443, limit 10 per source: ten sessions from A are relayed and the eleventh fails",
    `${held.filter((item) => item.ok).length}/10 ok; 11th: ${eleventh.error ?? "relayed"}`,
  );
  await probe(["reload"]);
  await settle();
  const afterReload = await open(agents.A, { hold: true });
  expect(
    report,
    !afterReload.ok,
    "TLS per-source limit includes leaving workers after unchanged reload",
    JSON.stringify(afterReload),
  );
  await agentCall(agents.A, "POST", "/close", { ids: [held[0]!.id] });
  await waitFor("TLS capacity released by a leaving worker", async () => {
    const result = await open(agents.A, { hold: true });
    return result.ok ? result : undefined;
  });
  const other = await open(agents.B, { hold: true });
  const otherRoute = await open(agents.A, { sni: amqpHost, hold: true });
  expect(
    report,
    other.ok && otherRoute.ok && otherRoute.peerCN === targetCn,
    "another allowed source and the other route keep their capacity",
    `B: ${other.ok ? "relayed" : other.error}; A to ${amqpHost}: ${otherRoute.ok ? "relayed" : otherRoute.error}`,
  );
  await closeAll();
  // The inner terminating frontend (behind the abns PROXY loop) logs the original source address when
  // the session ends; `show sess` only shows the abns peer. The dual-stack socket can log this
  // IPv4 source in mapped form. Use isolated sessions from B to avoid discarded burst log lines.
  let fromB = "";
  for (let attempt = 0; attempt < 5 && !fromB; attempt++) {
    await Bun.sleep(1_000);
    const single = await open(agents.B);
    if (!single.ok) continue;
    await Bun.sleep(1_000);
    fromB =
      (await logsOf(stack.edgeL4))
        .split("\n")
        .findLast(
          (line) =>
            (line.startsWith(`${agents.B.ip}:`) || line.startsWith(`::ffff:${agents.B.ip}:`)) &&
            line.includes(" fe_rt_lim1_tls~ "),
        ) ?? "";
  }
  expect(
    report,
    Boolean(fromB),
    "the original source address is visible after the PROXY loop (inner terminating frontend)",
    fromB.slice(0, 110) || `no inner log line from ${agents.B.ip}`,
  );
  // The total cap (maxconn) of a route: 3, with a per-source limit above it.
  await apply({ tlsRoutes: limitRoutes({ maxConn: 3 }) });
  await Bun.sleep(1_500);
  const total: Opened[] = [];
  for (const agent of [agents.A, agents.A, agents.B]) total.push(await open(agent, { hold: true }));
  const fourth = await open(agents.B, { hold: true });
  expect(
    report,
    total.every((item) => item.ok) && !fourth.ok,
    "maxconn is enforced: with maxConn 3 the fourth concurrent session fails, whatever its source",
    `${total.filter((item) => item.ok).length}/3 ok; 4th: ${fourth.error ?? "relayed"}`,
  );
  await probe(["reload"]);
  await settle();
  const fifth = await open(agents.B, { hold: true });
  expect(
    report,
    !fifth.ok,
    "TLS total cap includes leaving workers after unchanged reload",
    JSON.stringify(fifth),
  );
  await agentCall(agents.A, "POST", "/close", { ids: [total[0]!.id] });
  await waitFor("TLS total capacity released by a leaving worker", async () => {
    const result = await open(agents.B, { hold: true });
    return result.ok ? result : undefined;
  });
  await closeAll();
}

/** Polls the agents until every listed session is closed; returns per-session close times. */
async function closeTimes(sessions: Array<{ agent: Agent; id: string }>, since: number, limitMs: number) {
  const closed = new Map<string, number>();
  while (Date.now() - since < limitMs && closed.size < sessions.length) {
    for (const session of sessions) {
      if (closed.has(session.id)) continue;
      const state = await closedState(session.agent);
      if (state[session.id]?.closed !== false) closed.set(session.id, Date.now() - since);
    }
    await Bun.sleep(100);
  }
  return sessions.map((session) => closed.get(session.id) ?? null);
}

async function revocationRaceTest(report: Report) {
  const routes = limitRoutes();
  await apply({ tlsRoutes: routes });
  await waitFor("the routes", async () => ((await open(agents.A)).ok ? true : undefined), 15_000, 300);
  const affected: Array<{ agent: Agent; id: string }> = [];
  for (let round = 0; round < 3; round++) {
    const session = await open(agents.A, { hold: true });
    if (!session.ok) throw new Error(`session ${round} did not open: ${session.error}`);
    affected.push({ agent: agents.A, id: session.id });
    // Each reload leaves the previous worker draining with its sessions.
    const reload = await probe<{ reload: { success: boolean } }>(["reload"]);
    if (!reload.reload.success) throw new Error("reload failed");
    await settle();
  }
  const survivor = await open(agents.B, { sni: amqpHost, hold: true });
  const survivorTrace = [`opened ${survivor.ok}`, `before revocation ${await echo(agents.B, survivor.id)}`];
  const workers = await probe<
    Record<string, { section: string; servers: Array<{ server: string; backend: string }> }>
  >(["servers"]);
  const holding = Object.keys(workers).length;
  expect(
    report,
    holding >= 3 && survivor.ok,
    "sessions are open in the current and several leaving workers",
    `${holding} workers`,
  );
  // Revoke rt_lim1 (route disabled): the lease drops it, then new connections race the fence.
  const revokedAt = Date.now();
  lease.routes = lease.routes.filter((route) => route.id !== "rt_lim1");
  const racing: Opened[] = [];
  const raceState = { done: false };
  const race = (async () => {
    while (Date.now() - revokedAt < 3_000) {
      const attempt = await open(agents.A, { hold: true });
      racing.push(attempt);
      if (attempt.ok) affected.push({ agent: agents.A, id: attempt.id });
    }
    raceState.done = true;
  })();
  // Poll while the race runs, so each close is timed from the revocation, not from the race's end.
  const closedAt = new Map<string, number>();
  while ((!raceState.done || closedAt.size < affected.length) && Date.now() - revokedAt < 10_000) {
    for (const session of affected) {
      if (closedAt.has(session.id)) continue;
      if ((await closedState(session.agent))[session.id]?.closed !== false)
        closedAt.set(session.id, Date.now() - revokedAt);
    }
    await Bun.sleep(100);
  }
  await race;
  const times = affected.map((session) => closedAt.get(session.id) ?? null);
  survivorTrace.push(`after the drain ${await echo(agents.B, survivor.id)}`);
  await settle();
  expect(
    report,
    times.every((ms) => ms !== null && ms <= 5_000),
    "all affected sessions (current and leaving workers, and racing admissions) close within 5 s of revocation",
    `${affected.length} sessions closed after ${times.map((ms) => (ms === null ? "never" : `${ms} ms`)).join(", ")}; ${racing.filter((item) => item.ok).length} racing admissions`,
  );
  // edge.l4_apply then renders the generation without the route.
  await apply({ tlsRoutes: routes.slice(1) });
  survivorTrace.push(`after the reload ${await echo(agents.B, survivor.id)}`);
  console.log(`survivor: ${survivorTrace.join(", ")}`);
  const after: Opened[] = [];
  for (let index = 0; index < 3; index++) after.push(await open(agents.A));
  expect(
    report,
    after.every((item) => !item.ok),
    "new admission stays closed",
    after.map((item) => item.error).join(", "),
  );
  expect(
    report,
    await echo(agents.B, survivor.id),
    "another route's live session survives the revocation and the reload",
    `${amqpHost} session ${survivor.id}`,
  );
  expect(report, await httpOk(), "HTTP routes on the same 443 keep working", appHost);
  await closeAll();
}

async function sharedPortTest(report: Report) {
  const onlyA = tlsRoute({
    id: "rt_sni1",
    hostname: mqttHost,
    listenPort: 8883,
    tlsMode: "passthrough",
    sourceCidrs: [cidr(agents.A)],
  });
  const both = tlsRoute({
    id: "rt_sni2",
    hostname: sharedHost,
    listenPort: 8883,
    tlsMode: "passthrough",
    sourceCidrs: [cidr(agents.A), cidr(agents.C)],
  });
  await apply({ tlsRoutes: [onlyA, both] });
  await waitFor(
    "the shared port",
    async () => ((await open(agents.A, { port: 8883 })).ok ? true : undefined),
    15_000,
    300,
  );
  const refused = await open(agents.C, { port: 8883 });
  const other = await open(agents.C, { port: 8883, sni: sharedHost });
  const unknown = await open(agents.A, { port: 8883, sni: "unknown.example.com" });
  expect(
    report,
    !refused.ok && other.ok && !unknown.ok,
    "shared SNI port 8883: a source outside one route's list is refused for that route only; unknown SNI is rejected",
    `C to ${mqttHost}: ${refused.error}; C to ${sharedHost}: ${other.ok ? "relayed" : other.error}; unknown: ${unknown.error}`,
  );
}

async function rawTcpTest(report: Report) {
  const raw = tcpRoute({
    id: "rt_t001",
    hostname: tcpHost,
    listenPort: 20001,
    sourceCidrs: [cidr(agents.A), cidr(agents.B)],
    limits: { perSourceRate: 100 },
  });
  const tls = tlsRoute({
    id: "rt_keep",
    hostname: amqpHost,
    tlsMode: "passthrough",
    sourceCidrs: [cidr(agents.B)],
  });
  await apply({ tlsRoutes: [tls], tcpRoutes: [raw] });
  await waitFor(
    "the raw TCP route",
    async () => ((await open(agents.A, { port: 20001, tls: false })).ok ? true : undefined),
    15_000,
    300,
  );
  const outside = await open(agents.C, { port: 20001, tls: false });
  expect(
    report,
    !outside.ok,
    "raw TCP on 20001: a source outside the CIDR list is refused",
    outside.error ?? "relayed",
  );
  const held: Opened[] = [];
  for (let index = 0; index < 5; index++)
    held.push(await open(agents.A, { port: 20001, tls: false, hold: true }));
  const sixth = await open(agents.A, { port: 20001, tls: false, hold: true });
  expect(
    report,
    held.every((item) => item.ok) && !sixth.ok,
    "raw TCP: the per-source limit (5) admits five sessions and refuses the sixth",
    `${held.filter((item) => item.ok).length}/5; 6th: ${sixth.error ?? "relayed"}`,
  );
  await probe(["reload"]);
  await settle();
  const rawReload = await open(agents.A, { port: 20001, tls: false, hold: true });
  expect(report, !rawReload.ok, "raw per-source cap includes leaving workers", JSON.stringify(rawReload));
  await agentCall(agents.A, "POST", "/close", { ids: [held[0]!.id] });
  held[0] = await waitFor("raw capacity released by a leaving worker", async () => {
    const result = await open(agents.A, { port: 20001, tls: false, hold: true });
    return result.ok ? result : undefined;
  });
  const keep = await open(agents.B, { sni: amqpHost, hold: true });
  const rawB = await open(agents.B, { port: 20001, tls: false, hold: true });
  // Disable: edge.drain as the domain worker runs it (the policy no longer allows rt_t001).
  const drainedAt = Date.now();
  lease.routes = lease.routes.filter((route) => route.id !== "rt_t001");
  const drained = await probe<{ withdrawn: string[]; error?: string }>([
    "withdraw",
    JSON.stringify(lease.routes.map(routeIdentityKey)),
  ]);
  const sessions = [
    ...held.map((item) => ({ agent: agents.A, id: item.id })),
    { agent: agents.B, id: rawB.id },
  ];
  const times = await closeTimes(sessions, drainedAt, 8_000);
  expect(
    report,
    !drained.error && times.every((ms) => ms !== null && ms <= 5_000),
    "disabling the raw route (edge.drain) closes its established sessions within 5 s",
    drained.error ?? `closed after ${times.map((ms) => (ms === null ? "never" : `${ms} ms`)).join(", ")}`,
  );
  expect(
    report,
    keep.ok && (await echo(agents.B, keep.id)),
    "another route's session is untouched",
    `${amqpHost} ${keep.id}`,
  );
  await closeAll();
  // maxconn on a raw route, and an empty list rendered as deny-all.
  await apply({
    tcpRoutes: [tcpRoute({ ...raw, limits: { maxConn: 2, perSourceConn: 5, perSourceRate: 100 } })],
  });
  await settle();
  const capped = [
    await open(agents.A, { port: 20001, tls: false, hold: true }),
    await open(agents.B, { port: 20001, tls: false, hold: true }),
  ];
  const third = await open(agents.A, { port: 20001, tls: false, hold: true });
  expect(
    report,
    capped.every((item) => item.ok) && !third.ok,
    "raw TCP: maxconn 2 refuses the third concurrent session",
    `held: ${JSON.stringify(capped)}; third: ${JSON.stringify(third)}`,
  );
  await probe(["reload"]);
  await settle();
  const reloadedThird = await open(agents.A, { port: 20001, tls: false, hold: true });
  expect(report, !reloadedThird.ok, "raw total cap includes leaving workers", JSON.stringify(reloadedThird));
  await agentCall(agents.A, "POST", "/close", { ids: [capped[0]!.id] });
  await waitFor("raw total capacity released by a leaving worker", async () => {
    const result = await open(agents.A, { port: 20001, tls: false, hold: true });
    return result.ok ? result : undefined;
  });
  await closeAll();
  await apply({ tcpRoutes: [tcpRoute({ ...raw, sourceCidrs: [] })] });
  await settle();
  const denied = await Promise.all(
    [agents.A, agents.B, agents.C].map((agent) => open(agent, { port: 20001, tls: false })),
  );
  expect(
    report,
    denied.every((item) => !item.ok),
    "an empty CIDR list renders deny-all in HAProxy",
    denied.map((item) => item.error).join(", "),
  );
}

async function stalledWithdrawalTest(report: Report) {
  const route = tlsRoute({
    id: "rt_stall",
    hostname: mqttHost,
    tlsMode: "passthrough",
    sourceCidrs: [cidr(agents.A)],
    limits: { perSourceRate: 200 },
  });
  await apply({ tlsRoutes: [route] });
  const oldSession = await open(agents.A, { hold: true });
  await probe(["reload"]);
  await settle();
  const currentSession = await open(agents.A, { hold: true });
  expect(
    report,
    oldSession.ok && currentSession.ok,
    "sessions exist in current and leaving workers before stalled enforcement",
    JSON.stringify([oldSession, currentSession]),
  );
  const { workers } = await probe<{ workers: Array<{ pid: number; section: string }> }>(["proc"]);
  const leaving = workers.find((worker) => worker.section === "old")!;
  expect(
    report,
    Boolean(leaving),
    "a leaving worker can be stalled before its drain",
    JSON.stringify(workers),
  );
  const revokedAt = Date.now();
  // A stopped leaving worker cannot answer any inspection or drain command. Supervision must
  // include the busy-pass grace, polling and kill time, measured at real client sockets.
  await docker("exec", stack.edgeL4, "kill", "-STOP", String(leaving.pid));
  lease.routes = [];
  const times = await closeTimes(
    [
      { agent: agents.A, id: oldSession.id },
      { agent: agents.A, id: currentSession.id },
    ],
    revokedAt,
    7_000,
  );
  expect(
    report,
    times.every((ms) => ms !== null && ms <= 5_000),
    "the shipped launch guard closes sessions within five seconds when leaving-worker enforcement stalls",
    JSON.stringify(times),
  );
  expect(
    report,
    (await logsOf(stack.edgeL4)).includes("watchdog enforcement unavailable; terminating HAProxy"),
    "the launch guard performed the fail-closed shutdown",
    "guard log",
  );
}

async function nftTest(report: Report) {
  const rules = join(directory, "nft");
  await mkdir(rules);
  const client = "10.99.0.2";
  const files = {
    "raw.nft": renderFrontIngress([
      { id: "rt_t001", listenPort: 20001, sourceCidrs: [`${client}/32`] },
      { id: "rt_t002", listenPort: 20002, sourceCidrs: [] },
      { id: "rt_t004", listenPort: 20004, sourceCidrs: [], allowInternet: true },
      { id: "rt_t005", listenPort: 20005, sourceCidrs: ["10.99.1.0/24"] },
    ]),
    "empty.nft": renderFrontIngress([]),
  };
  for (const [name, text] of Object.entries(files)) await writeFile(join(rules, name), text);
  await chmod(rules, 0o755);
  const child = Bun.spawn(["docker", "build", "--quiet", "-t", nftImage, "-"], {
    stdin: new TextEncoder().encode(
      `FROM ${bunImage}\nRUN apt-get update \\\n  && apt-get install -y --no-install-recommends nftables iproute2 \\\n  && rm -rf /var/lib/apt/lists/*\n`,
    ),
    stdout: "pipe",
    stderr: "pipe",
  });
  if ((await child.exited) !== 0)
    throw new Error(`building ${nftImage} failed: ${await new Response(child.stderr).text()}`);
  nftImageBuilt = true;
  const script = `set -e
for f in /rules/*.nft; do nft -c -f "$f"; echo "nft -c ok: $(basename "$f")"; done
ip netns add srv; ip netns add cli
ip link add v0 type veth peer name v1
ip link set v0 netns srv; ip link set v1 netns cli
ip -n srv addr add 10.99.0.1/24 dev v0; ip -n cli addr add ${client}/24 dev v1
ip -n srv link set v0 up; ip -n cli link set v1 up; ip -n srv link set lo up; ip -n cli link set lo up
ip netns exec srv nft -f /rules/raw.nft
ip netns exec srv bun -e 'for (const port of [20001,20002,20003,20004,20005]) Bun.listen({hostname:"0.0.0.0",port,socket:{data(){}}})' &
sleep 1
for port in 20001 20002 20003 20004 20005; do
  ip netns exec cli bun -e "const s=require('node:net').connect({host:'10.99.0.1',port:$port});const t=setTimeout(()=>{console.log('$port dropped');process.exit(0)},1500);s.on('connect',()=>{clearTimeout(t);console.log('$port open');process.exit(0)});s.on('error',e=>{clearTimeout(t);console.log('$port '+e.code);process.exit(0)})"
done
# Actual Docker-style DNAT: srv forwards published ports to a separate backend namespace.
ip netns add backend
ip link add v2 type veth peer name v3
ip link set v2 netns srv; ip link set v3 netns backend
ip -n srv addr add 10.98.0.1/24 dev v2; ip -n backend addr add 10.98.0.2/24 dev v3
ip -n srv link set v2 up; ip -n backend link set v3 up; ip -n backend link set lo up
ip -n backend route add default via 10.98.0.1
ip netns exec srv sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
ip netns exec srv nft 'add table ip published'
ip netns exec srv nft 'add chain ip published prerouting { type nat hook prerouting priority -100; }'
ip netns exec srv nft 'add rule ip published prerouting ip daddr 10.99.0.1 tcp dport { 20001, 20002, 20003, 21000 } dnat to 10.98.0.2'
ip netns exec backend bun -e 'for (const port of [20001,20002,20003,21000]) Bun.listen({hostname:"0.0.0.0",port,socket:{data(s,d){s.write(d)}}})' &
sleep 1
for pair in 20001:20003 21000:20002 21000:20001; do
  port=\${pair%:*}; source=\${pair#*:}
  ip netns exec cli bun -e "const s=require('node:net').connect({host:'10.99.0.1',port:$port,localPort:$source});const t=setTimeout(()=>{console.log('dnat $pair dropped');process.exit(0)},1500);s.on('connect',()=>s.write('ping'));s.on('data',d=>{clearTimeout(t);console.log('dnat $pair '+(d.toString()==='ping'?'ok':'bad'));process.exit(0)});s.on('error',e=>{clearTimeout(t);console.log('dnat $pair '+e.code);process.exit(0)})"
done
ip netns exec cli bun -e "const s=require('node:net').connect({host:'10.99.0.1',port:20003});setTimeout(()=>{console.log('dnat closed dropped');process.exit(0)},1500);s.on('connect',()=>{console.log('dnat closed open');process.exit(0)});s.on('error',()=>{console.log('dnat closed refused');process.exit(0)})"
`;
  const name = `ark-edge-l4r-nft-${suffix}`;
  runtime.containers.push(name);
  const output = await docker(
    "run",
    "--name",
    name,
    "--privileged",
    "--network",
    "none",
    "--volume",
    `${rules}:/rules:ro`,
    nftImage,
    "sh",
    "-c",
    script,
  );
  const lines = output.split("\n");
  const verdict = (port: number) => lines.find((line) => line.startsWith(`${port} `))?.split(" ")[1];
  expect(
    report,
    lines.filter((line) => line.startsWith("nft -c ok")).length === 2,
    "the raw-port ruleset passes nft -c",
    lines.filter((line) => line.startsWith("nft -c")).join("; "),
  );
  expect(
    report,
    verdict(20001) === "open" &&
      verdict(20002) === "dropped" &&
      verdict(20003) === "dropped" &&
      verdict(20004) === "open" &&
      verdict(20005) === "dropped",
    "nftables: an allowlisted source is admitted, an empty list drops (deny-all), a port without a route drops, only allowInternet opens to every source, and an outside source is dropped",
    [20001, 20002, 20003, 20004, 20005].map((port) => `${port} ${verdict(port)}`).join(", "),
  );
  expect(
    report,
    ["20001:20003", "21000:20002", "21000:20001"].every((pair) => lines.includes(`dnat ${pair} ok`)) &&
      lines.includes("dnat closed dropped"),
    "DNAT replies reach clients using raw-range source ports, including unrelated published services; closed inbound raw ports still drop",
    lines.filter((line) => line.startsWith("dnat ")).join("; "),
  );
}

async function run(name: string, test: (report: Report) => Promise<unknown>) {
  const only = process.env.ARK_EDGE_L4_ONLY;
  if (only && !name.includes(only)) {
    console.log(`${name}: skipped (ARK_EDGE_L4_ONLY=${only})`);
    return;
  }
  const report: Report = { name, lines: [] };
  const started = Date.now();
  await test(report);
  console.log(`${name} (${((Date.now() - started) / 1000).toFixed(1)} s)\n${report.lines.join("\n")}`);
}

let failed = false;
try {
  console.log("edge-l4 TLS-TCP and raw-TCP routes (FD-14):");
  await prepareFiles();
  ca.route = routeCa("rt_p7q2");
  ca.rogue = routeCa("rogue");
  for (const [key, authority, cn] of [
    ["valid", ca.route, "sensor-1"],
    ["second", ca.route, "sensor-2"],
    ["rogue", ca.rogue, "sensor-1"],
  ] as const) {
    const issued = authority.client(cn);
    certs[key] = { certPem: issued.certPem, key: issued.key, serial: issued.serial };
  }
  await startContainers();
  httpsPort = await stack.hostPort(443);
  edgeIp = `${clientPrefix}.2`;
  await waitFor("HTTPS through 443", async () => ((await httpOk()) ? true : undefined), 30_000);
  await run(
    "§3.8.5 literal example: passthrough, terminate, terminate_mtls, full and fragmented",
    literalExampleTest,
  );
  await run("terminate_mtls: a revoked serial after the CRL update and reload", crlRevocationTest);
  await run("two TLS routes on 443: per-source limit, PROXY loop source and maxconn", perSourceLimitTest);
  await run("revocation racing new connections across reloads", revocationRaceTest);
  await run("shared SNI port 8883", sharedPortTest);
  await run("raw TCP route on 20001: allowlist, limits, deny-all and edge.drain", rawTcpTest);
  await run("stalled leaving-worker enforcement deadline", stalledWithdrawalTest);
  await run("raw-port nftables: deny-all and closed ports", nftTest);
  console.log("\nAll FD-14 route tests passed.");
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  console.error(`watchdog events: ${JSON.stringify(events.slice(-10))}`);
  await runtime.dumpLogs();
} finally {
  void api.stop(true);
  removeSignalHandlers();
  await runtime.cleanup();
  for (const name of extraNetworks)
    await Bun.spawn(["docker", "network", "rm", name], { stdout: "ignore", stderr: "ignore" }).exited;
  if (nftImageBuilt) await docker("image", "rm", nftImage).catch(() => undefined);
}
process.exit(failed ? 1 : 0);
