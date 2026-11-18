// `mise run test:edge` (FD-23, docs/design/front-door.md §5): HTTP route rate limits and HTTP mTLS on the
// shipped edge, reached through HAProxy on 443. The shipped edge-ts, edge (the custom Caddy 2.11.9 build
// with the pinned caddy-ratelimit plugin, behind its launch guard), edge-l4 (HAProxy 3.2.26) and
// haproxy-validator Compose services run in a disposable project (scripts/edge-test/gate-edge.ts), with
// the production planner, renderer and `writeEdge`/`writeEdgeL4` applying each configuration.
//
// Covered:
// - a per-route rate limit answers 429 (Retry-After, no Server header, never reaching the upstream)
//   above its threshold, while another route from the same client is unaffected;
// - an mTLS route refuses, in the TLS handshake (no HTTP response at all): no certificate, a
//   certificate from a rogue CA, a certificate of the route CA that is not admitted (an empty list),
//   and a revoked serial once the CRL update is applied, the revoking apply also closing that
//   client's open connection; a valid certificate is served;
// - SNI/Host 421 still holds in both directions between an mTLS and a plain route, and an
//   upper-case SNI still requires the certificate;
// - mTLS combined with Ark login: a certificate and a gate session are both required.
//
// Client certificates are issued with the production PKI functions (route CA, rogue CA, CRL) and
// admitted with the production `admittedClientCertificates`. `ARK_EDGE_HTTP_CONTROLS_ONLY=<text>`
// runs only matching groups (setup always runs).
import { generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tlsConnect } from "node:tls";

import { planEdge, type EdgeHttpRoute } from "@ark-stack/shared";

import { bunImage, cleanupGateEdge, startGateEdge, waitFor, type GateEdge } from "./edge-test/gate-edge.ts";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";

process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:9/unused";
const { buildCrl, createCaMaterial, signClientCertificate } = await import("../server/src/modules/pki.ts");
const { admittedClientCertificates, caCertificateDer } = await import("../server/src/modules/route-crl.ts");

const fixtures = join(import.meta.dir, "edge-test");
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-controls-${suffix}-`));
const runName = `ark-edge-controls-${suffix}`;
const runtime = new EdgeTestRuntime(directory, runName, bunImage);
const removeSignalHandlers = runtime.installSignalHandlers();
const gateToken = randomBytes(24).toString("base64url");

const openHost = "open.example.com";
const limitedHost = "limited.example.com";
const mtlsHost = "mtls.example.com";
const closedHost = "closed.example.com";
const bothHost = "both.example.com";
const limit = { requests: 3, window: "1m" };

// ---- Client PKI (production functions) ------------------------------------------------------------------

type Client = { cert: string; key: string; serial: string };
const now = new Date();
const routeCa = createCaMaterial({
  id: "pca_fd23_route",
  purpose: "http-client",
  name: "Route rt_mtls",
  now,
});
const rogueCa = createCaMaterial({ id: "pca_fd23_rogue", purpose: "http-client", name: "Rogue", now });
function client(ca: typeof routeCa, name: string): Client {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const issued = signClientCertificate({ ca, subjectCn: name, publicKey: pair.publicKey as KeyObject, now });
  return {
    cert: issued.certPem,
    key: pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    serial: issued.serial,
  };
}
const good = client(routeCa, "laptop");
const doomed = client(routeCa, "phone");
const rogue = client(rogueCa, "laptop");
const crl = (revoked: Client[]) =>
  buildCrl({
    ca: routeCa,
    revoked: revoked.map((item) => ({ serial: item.serial, revokedAt: now })),
    thisUpdate: now,
    nextUpdate: new Date(now.getTime() + 14 * 86_400_000),
    crlNumber: BigInt(revoked.length + 1),
  }).crlPem;
const rows = (statuses: Record<string, string>) =>
  [good, doomed].map((item) => ({
    serial: item.serial,
    status: statuses[item.serial] ?? "issued",
    notBefore: now,
    notAfter: new Date(now.getTime() + 90 * 86_400_000),
    certPem: item.cert,
  }));
/** The route CA's admitted set, as `edge.apply` reads it: before and after revoking `doomed`. */
const admitted = {
  before: admittedClientCertificates({ crlPem: crl([]), certificates: rows({}) }),
  after: admittedClientCertificates({
    crlPem: crl([doomed]),
    certificates: rows({ [doomed.serial]: "revoked" }),
  }),
};

// ---- Routes ---------------------------------------------------------------------------------------------

const gateSessionToken = randomBytes(32).toString("base64url");
function fixtureRoutes(peerIp: string, phase: "before" | "after"): EdgeHttpRoute[] {
  const base = { stableId: "nHOMECTRL", ip: peerIp, port: 3000, access: "public" as const };
  const clientAuth = { caCertificate: caCertificateDer(routeCa.certPem)!, certificates: admitted[phase] };
  return [
    { ...base, id: "rt_open", hostname: openHost },
    { ...base, id: "rt_lim", hostname: limitedHost, rateLimit: limit },
    { ...base, id: "rt_mtls", hostname: mtlsHost, clientAuth },
    // The route CA, but an empty admitted list: nobody gets in.
    { ...base, id: "rt_closed", hostname: closedHost, clientAuth: { ...clientAuth, certificates: [] } },
    { ...base, id: "rt_both", hostname: bothHost, access: "sso", clientAuth },
  ];
}

function fixturePlan(peerIp: string, phase: "before" | "after") {
  const routes = fixtureRoutes(peerIp, phase);
  const plan = planEdge({
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
      lastDeployedAt: now,
    })),
    httpRoutes: routes,
  });
  if (plan.omitted.length) throw new Error(`The planner omitted ${JSON.stringify(plan.omitted)}`);
  return plan;
}

type Report = { name: string; lines: string[] };

function expect(report: Report, condition: boolean, claim: string, observed: string) {
  if (!condition) throw new Error(`[${report.name}] FAILED: ${claim} (observed: ${observed})`);
  report.lines.push(`  ok  ${claim} [${observed}]`);
}

let edge!: GateEdge;
let httpsPort = 0;

type Reply = { status: number; headers: Record<string, string[]>; body: string };
type Outcome = { kind: "http"; reply: Reply } | { kind: "tls"; code: string; message: string; bytes: number };

/**
 * One HTTP/1.1 request through the published 443 with an optional client certificate. A failure
 * before any response byte arrives is reported as a TLS-layer outcome with the alert it carried.
 */
function attempt(
  servername: string,
  path = "/headers",
  options: { client?: Client; host?: string; headers?: Record<string, string> } = {},
) {
  return new Promise<Outcome>((resolveOutcome) => {
    const socket = tlsConnect({
      host: "127.0.0.1",
      port: httpsPort,
      servername,
      rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"],
      ...(options.client ? { cert: options.client.cert, key: options.client.key } : {}),
    });
    let data = "";
    let settled = false;
    const finish = (outcome: Outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolveOutcome(outcome);
    };
    const timer = setTimeout(
      () => finish({ kind: "tls", code: "TIMEOUT", message: "no answer in 8 s", bytes: data.length }),
      8_000,
    );
    socket.on("secureConnect", () => {
      const headers = { Host: options.host ?? servername, Connection: "close", ...options.headers };
      socket.write(
        `GET ${path} HTTP/1.1\r\n${Object.entries(headers)
          .map(([name, value]) => `${name}: ${value}`)
          .join("\r\n")}\r\n\r\n`,
      );
    });
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
    socket.on("error", (error: Error & { code?: string }) => {
      if (!data) finish({ kind: "tls", code: error.code ?? "ERROR", message: error.message, bytes: 0 });
    });
    socket.on("close", () => {
      if (!data) {
        finish({ kind: "tls", code: "CLOSED", message: "closed without a response", bytes: 0 });
        return;
      }
      const [head = "", ...rest] = data.split("\r\n\r\n");
      const [statusLine = "", ...headerLines] = head.split("\r\n");
      const headers: Record<string, string[]> = {};
      for (const line of headerLines) {
        const index = line.indexOf(":");
        if (index > 0)
          (headers[line.slice(0, index).toLowerCase()] ??= []).push(line.slice(index + 1).trim());
      }
      finish({
        kind: "http",
        reply: { status: Number(statusLine.split(" ")[1] ?? 0), headers, body: rest.join("\r\n\r\n") },
      });
    });
  });
}

const describe = (outcome: Outcome) =>
  outcome.kind === "http" ? `HTTP ${outcome.reply.status}` : `TLS ${outcome.code}: ${outcome.message}`;

/** A refusal in the handshake: an alert from the server, and no HTTP response byte. */
const tlsRefused = (outcome: Outcome) =>
  outcome.kind === "tls" &&
  outcome.bytes === 0 &&
  /alert|ERR_SSL/i.test(`${outcome.code} ${outcome.message}`);

async function upstreamPaths() {
  return (await edge.seen(edge.peerName)) as string[];
}

// ---- Tests ----------------------------------------------------------------------------------------------

async function rateLimitTest(report: Report) {
  const seenBefore = (await upstreamPaths()).filter((path) => path === "/limited").length;
  const statuses: number[] = [];
  let over: Reply | undefined;
  for (let index = 0; index < limit.requests + 2; index++) {
    const outcome = await attempt(limitedHost, "/limited");
    if (outcome.kind !== "http") throw new Error(`[${report.name}] ${describe(outcome)}`);
    statuses.push(outcome.reply.status);
    if (outcome.reply.status === 429) over ??= outcome.reply;
  }
  expect(
    report,
    statuses.join() === "200,200,200,429,429",
    `${limit.requests} requests per ${limit.window} are served, then the route answers 429`,
    statuses.join(" "),
  );
  expect(
    report,
    Number(over?.headers["retry-after"]?.[0]) > 0 &&
      !over?.headers.server &&
      over?.body.trim() === "Too many requests.",
    "the 429 carries Retry-After, the static body and no Server header",
    `Retry-After ${over?.headers["retry-after"]?.[0]}; Server ${over?.headers.server?.[0] ?? "absent"}; body ${JSON.stringify(over?.body.trim())}`,
  );
  const reached = (await upstreamPaths()).filter((path) => path === "/limited").length - seenBefore;
  expect(
    report,
    reached === limit.requests,
    "requests over the limit never reach the upstream",
    `${reached} reached`,
  );
  const other: number[] = [];
  for (let index = 0; index < 12; index++) {
    const outcome = await attempt(openHost, "/headers");
    other.push(outcome.kind === "http" ? outcome.reply.status : 0);
  }
  expect(
    report,
    other.every((status) => status === 200),
    "another route from the same client is unaffected (12 requests, all 200)",
    other.join(" "),
  );
  const still = await attempt(limitedHost, "/limited");
  expect(
    report,
    still.kind === "http" && still.reply.status === 429,
    "the limited route still refuses the same client within the window",
    describe(still),
  );
}

async function mtlsTest(report: Report) {
  const none = await attempt(mtlsHost);
  expect(
    report,
    tlsRefused(none),
    "without a certificate the TLS handshake fails (no HTTP status)",
    describe(none),
  );
  const rogueOutcome = await attempt(mtlsHost, "/headers", { client: rogue });
  expect(
    report,
    tlsRefused(rogueOutcome),
    "a certificate from a rogue CA fails the TLS handshake",
    describe(rogueOutcome),
  );
  const valid = await attempt(mtlsHost, "/headers", { client: good });
  expect(
    report,
    valid.kind === "http" && valid.reply.status === 200,
    "a certificate the route CA issued and the edge admits is served",
    describe(valid),
  );
  const closed = await attempt(closedHost, "/headers", { client: good });
  expect(
    report,
    tlsRefused(closed),
    "a route whose admitted list is empty refuses even a route-CA certificate",
    describe(closed),
  );
  const upper = await attempt("MTLS.Example.COM", "/headers", { host: mtlsHost });
  expect(report, tlsRefused(upper), "an upper-case SNI still requires the certificate", describe(upper));
}

async function strictSniTest(report: Report) {
  const fromPlain = await attempt(openHost, "/headers", { host: mtlsHost });
  expect(
    report,
    fromPlain.kind === "http" && fromPlain.reply.status === 421,
    "a connection for the plain route cannot reach the mTLS route by Host (421)",
    describe(fromPlain),
  );
  const fromMtls = await attempt(mtlsHost, "/headers", { client: good, host: openHost });
  expect(
    report,
    fromMtls.kind === "http" && fromMtls.reply.status === 421,
    "an mTLS connection cannot reach another route by Host (421)",
    describe(fromMtls),
  );
}

async function combinedTest(report: Report) {
  const cookie = { Cookie: `__Host-ark_gate=${gateSessionToken}` };
  const both = await attempt(bothHost, "/headers", { client: good, headers: cookie });
  expect(
    report,
    both.kind === "http" && both.reply.status === 200,
    "a certificate and a gate session together are served",
    describe(both),
  );
  const certOnly = await attempt(bothHost, "/headers", { client: good });
  expect(
    report,
    certOnly.kind === "http" && certOnly.reply.status === 401,
    "a certificate without a gate session gets the gate's 401",
    describe(certOnly),
  );
  const sessionOnly = await attempt(bothHost, "/headers", { headers: cookie });
  expect(
    report,
    tlsRefused(sessionOnly),
    "a gate session without a certificate fails the TLS handshake",
    describe(sessionOnly),
  );
}

/** Revoking a serial: CRL update, forced apply with the route revoked, open connection closed. */
async function revocationTest(report: Report) {
  const before = await attempt(mtlsHost, "/headers", { client: doomed });
  expect(
    report,
    before.kind === "http" && before.reply.status === 200,
    "the certificate is served before it is revoked",
    describe(before),
  );
  // An idle keep-alive connection admitted with the certificate.
  const socket = tlsConnect({
    host: "127.0.0.1",
    port: httpsPort,
    servername: mtlsHost,
    rejectUnauthorized: false,
    ALPNProtocols: ["http/1.1"],
    cert: doomed.cert,
    key: doomed.key,
  });
  let closedAt = 0;
  let firstReply = "";
  socket.on("close", () => (closedAt = Date.now()));
  socket.on("error", () => undefined);
  await new Promise<void>((resolveOpen, reject) => {
    const timer = setTimeout(() => reject(new Error("keep-alive request timed out")), 8_000);
    socket.once("secureConnect", () =>
      socket.write(`GET /headers HTTP/1.1\r\nHost: ${mtlsHost}\r\nConnection: keep-alive\r\n\r\n`),
    );
    socket.on("data", (chunk) => {
      firstReply += chunk.toString("utf8");
      if (firstReply.includes("\r\n\r\n")) {
        clearTimeout(timer);
        resolveOpen();
      }
    });
  });
  expect(
    report,
    firstReply.startsWith("HTTP/1.1 200"),
    "a keep-alive connection is open",
    firstReply.split("\r\n")[0]!,
  );
  // The CRL lists the serial; `edge.apply` renders the CA's admitted set from it and, as the gate
  // revocation journal makes it do, applies with the route revoked (forced reload, sessions drained).
  const revokedAt = Date.now();
  const applied = await edge.edgeApply({
    ...fixturePlan(edge.peerIp, "after"),
    revokedRouteIds: ["rt_mtls"],
  });
  if (!applied.applied) throw new Error(`[${report.name}] the revoking apply was not applied`);
  await waitFor(
    "the revoked client's connection to close",
    async () => (closedAt ? true : undefined),
    10_000,
    50,
  );
  expect(
    report,
    closedAt - revokedAt < 10_000,
    "the revoking apply closes the open connection admitted with that certificate",
    `${closedAt - revokedAt} ms after the apply started`,
  );
  const after = await attempt(mtlsHost, "/headers", { client: doomed });
  expect(
    report,
    tlsRefused(after),
    "after the CRL update the revoked serial fails the TLS handshake",
    describe(after),
  );
  const kept = await attempt(mtlsHost, "/headers", { client: good });
  expect(
    report,
    kept.kind === "http" && kept.reply.status === 200,
    "an unrevoked certificate of the same CA is still served",
    describe(kept),
  );
  const open = await attempt(openHost, "/headers");
  expect(
    report,
    open.kind === "http" && open.reply.status === 200,
    "a route without controls keeps serving across the revocation",
    describe(open),
  );
}

const reports: Report[] = [];
async function run(name: string, test: (report: Report) => Promise<void>) {
  const only = process.env.ARK_EDGE_HTTP_CONTROLS_ONLY;
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
  edge = await startGateEdge({
    runtime,
    directory,
    name: runName,
    gateToken,
    hostnames: [openHost, limitedHost, mtlsHost, closedHost, bothHost],
    targetedHttp: true,
    policy: (peerIp) =>
      fixtureRoutes(peerIp, "before").map(({ id, hostname, stableId, ip, port }) => ({
        id,
        kind: "http",
        hostname,
        stableId,
        ip,
        port,
      })),
    api: {
      entry: join(fixtures, "gate-api.ts"),
      env: {
        ARK_EDGE_GATE_TOKEN: gateToken,
        GATE_ROUTES: JSON.stringify({ rt_both: { host: bothHost, bypassPaths: [], allowedOrigins: [] } }),
        GATE_SESSIONS: JSON.stringify({
          [gateSessionToken]: { user: "usr_alice", email: "alice@example.com", routes: ["rt_both"] },
        }),
      },
    },
  });
  httpsPort = edge.httpsPort;
  const applied = await edge.edgeApply(fixturePlan(edge.peerIp, "before"));
  if (!applied.applied || applied.httpRoutes.toSorted().join() !== "rt_both,rt_closed,rt_lim,rt_mtls,rt_open")
    throw new Error(`edge.apply did not load every route: ${JSON.stringify(applied)}`);
  await waitFor("the plain route through 443", async () => {
    const outcome = await attempt(openHost, "/headers");
    return outcome.kind === "http" && outcome.reply.status === 200 ? true : undefined;
  });
  await run("FD-23: per-route rate limit through HAProxy", rateLimitTest);
  await run("FD-23: HTTP mTLS refuses in the TLS handshake", mtlsTest);
  await run("FD-23: SNI/Host 421 between mTLS and plain routes", strictSniTest);
  await run("FD-23: mTLS combined with Ark login", combinedTest);
  await run("FD-23: revocation after a CRL update", revocationTest);
  console.log(`\nFD-23 HTTP control tests passed (${reports.length} groups).`);
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  await runtime.dumpLogs();
} finally {
  removeSignalHandlers();
  await cleanupGateEdge(runtime, runName, edge);
}
process.exit(failed ? 1 : 0);
