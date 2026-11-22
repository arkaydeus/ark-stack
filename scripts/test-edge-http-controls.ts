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
// A disposable database holds real route CAs and certificates. The real API journals revocations,
// the domain worker processes them, and the watchdog reads the production lease.
// `ARK_EDGE_HTTP_CONTROLS_ONLY=<text>`
// runs only matching groups (setup always runs).
import { randomBytes } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tlsConnect } from "node:tls";

import { type EdgeHttpRoute } from "@ark-stack/shared";

import { cleanupGateEdge, startGateEdge, waitFor, type GateEdge } from "./edge-test/gate-edge.ts";
import { bunImage } from "./test-images.ts";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { startHttpControlsDb } from "./edge-test/http-controls-db.ts";

const fixtures = join(import.meta.dir, "edge-test");
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-controls-${suffix}-`));
const runName = `ark-edge-controls-${suffix}`;
const runtime = new EdgeTestRuntime(directory, runName, bunImage);
const removeSignalHandlers = runtime.installSignalHandlers();
const gateToken = randomBytes(24).toString("base64url");

const openHost = "open.example.com";
const limitedHost = "limited.example.com";
const alsoLimitedHost = "also-limited.example.com";
const mtlsHost = "mtls.example.com";
const closedHost = "closed.example.com";
const bothHost = "both.example.com";
const limit = { requests: 3, window: "1m" };

type ControlsDb = Awaited<ReturnType<typeof startHttpControlsDb>>;
type Client = Awaited<ReturnType<ControlsDb["issue"]>>;
let database: ControlsDb | undefined;
let good: Client;
let doomed: Client;
let overdueClient: Client;
let goodBoth: Client;
let rogue: Client;
let caIds: Record<string, string>;

// Policy is seeded into the disposable database; a temporary lease permits edge setup.
const gateSessionToken = randomBytes(32).toString("base64url");
function fixtureRoutes(peerIp: string): EdgeHttpRoute[] {
  const base = { stableId: "nHOMECTRL", ip: peerIp, port: 3000, access: "public" as const };
  return [
    { ...base, id: "rt_open", hostname: openHost },
    { ...base, id: "rt_lim", hostname: limitedHost, rateLimit: limit },
    { ...base, id: "rt_limtwo", hostname: alsoLimitedHost, rateLimit: limit },
    { ...base, id: "rt_mtls", hostname: mtlsHost },
    { ...base, id: "rt_closed", hostname: closedHost },
    { ...base, id: "rt_both", hostname: bothHost, access: "sso" },
  ];
}

type Report = { name: string; lines: string[] };

function expect(report: Report, condition: boolean, claim: string, observed: string) {
  if (!condition) throw new Error(`[${report.name}] FAILED: ${claim} (observed: ${observed})`);
  report.lines.push(`  ok  ${claim} [${observed}]`);
}

let edge!: GateEdge;
let httpsPort = 0;

type Reply = { status: number; headers: Record<string, string[]>; body: string };
type Outcome =
  | { kind: "http"; reply: Reply }
  | { kind: "tls"; code: string; message: string; bytes: number; connected: boolean };

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
      maxVersion: "TLSv1.2",
      port: httpsPort,
      servername,
      rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"],
      ...(options.client ? { cert: options.client.cert, key: options.client.key } : {}),
    });
    let data = "";
    let settled = false;
    let connected = false;
    const finish = (outcome: Outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolveOutcome(outcome);
    };
    const timer = setTimeout(
      () =>
        finish({ kind: "tls", code: "TIMEOUT", message: "no answer in 8 s", bytes: data.length, connected }),
      8_000,
    );
    socket.on("secureConnect", () => {
      connected = true;
      const headers = { Host: options.host ?? servername, Connection: "close", ...options.headers };
      socket.write(
        `GET ${path} HTTP/1.1\r\n${Object.entries(headers)
          .map(([name, value]) => `${name}: ${value}`)
          .join("\r\n")}\r\n\r\n`,
      );
    });
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
    socket.on("error", (error: Error & { code?: string }) => {
      if (!data)
        finish({ kind: "tls", code: error.code ?? "ERROR", message: error.message, bytes: 0, connected });
    });
    socket.on("close", () => {
      if (!data) {
        finish({ kind: "tls", code: "CLOSED", message: "closed without a response", bytes: 0, connected });
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

/** TLS 1.2 authenticates the client before secureConnect. Some Bun versions report the alert as close. */
const tlsRefused = (outcome: Outcome) =>
  outcome.kind === "tls" &&
  outcome.bytes === 0 &&
  !outcome.connected &&
  (outcome.code === "CLOSED" || /alert|ERR_SSL/i.test(`${outcome.code} ${outcome.message}`));

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

/** Two ordinary clients on the edge's admin test network enter HAProxy directly on 443. */
async function proxyClientQuota(container: string, hosts: string[]) {
  return JSON.parse(
    await runtime.docker(
      "exec",
      container,
      "bun",
      "-e",
      String.raw`
      import { lookup } from "node:dns/promises";
      import { connect } from "node:tls";
      const { address } = await lookup(process.argv[1]);
      const result = [];
      for (const host of JSON.parse(process.argv[2])) {
        result.push(await new Promise((resolve, reject) => {
          let response = "";
          const socket = connect({ host: address, port: 443, servername: host, rejectUnauthorized: false },
            () => socket.write("GET /headers HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"));
          socket.on("data", chunk => response += chunk);
          socket.on("close", () => resolve(Number(response.split(" ")[1])));
          socket.on("error", reject);
          socket.setTimeout(5_000, () => socket.destroy(new Error("quota request timed out")));
        }));
      }
      console.log(JSON.stringify(result));
    `,
      edge.stack.edgeTs,
      JSON.stringify(hosts),
    ),
  ) as number[];
}

async function quotaIsolationTest(report: Report) {
  const first = [...Array<string>(4).fill(limitedHost), alsoLimitedHost];
  const second = [limitedHost, ...Array<string>(4).fill(alsoLimitedHost)];
  const clients = [`${runName}-client-a`, `${runName}-client-b`];
  for (const name of clients) {
    runtime.containers.push(name);
    await runtime.docker(
      "run",
      "-d",
      "--name",
      name,
      "--network",
      edge.stack.networks.admin,
      bunImage,
      "sleep",
      "infinity",
    );
  }
  const addresses = await Promise.all(
    clients.map((name) =>
      runtime.docker("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name),
    ),
  );
  expect(
    report,
    !!addresses[0] && !!addresses[1] && addresses[0] !== addresses[1],
    "both clients have distinct source addresses at HAProxy",
    addresses.join(", "),
  );
  const a = await proxyClientQuota(clients[0]!, first);
  const b = await proxyClientQuota(clients[1]!, second);
  expect(
    report,
    a.join() === "200,200,200,429,200",
    "one client exhausts only its first route quota",
    a.join(),
  );
  expect(
    report,
    b.join() === "200,200,200,200,429",
    "a second client has independent quotas on both routes",
    b.join(),
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
  const both = await attempt(bothHost, "/headers", { client: goodBoth, headers: cookie });
  expect(
    report,
    both.kind === "http" && both.reply.status === 200,
    "a certificate and a gate session together are served",
    describe(both),
  );
  const certOnly = await attempt(bothHost, "/headers", { client: goodBoth });
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

/** Revoke through the real API. Exercise both the worker drain and the watchdog fallback. */
async function revocationTest(report: Report, client: Client, delayWorker: boolean) {
  const before = await attempt(mtlsHost, "/headers", { client });
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
    cert: client.cert,
    key: client.key,
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
  const db = database!;
  try {
    const revoked = await db.revoke("rt_mtls", client.id);
    if (delayWorker) {
      await waitFor(
        "the real watchdog to fence the overdue route",
        async () => closedAt || undefined,
        10_000,
        50,
      );
      const fenced = await attempt(mtlsHost, "/headers", { client: good });
      expect(
        report,
        fenced.kind === "tls",
        "after the journal deadline the whole route is fenced",
        describe(fenced),
      );
      expect(
        report,
        closedAt - revoked.at >= 4_500 && closedAt - revoked.at < 10_000,
        "the watchdog closes the open connection after the 5 s deadline",
        `${closedAt - revoked.at} ms`,
      );
    }
    const operationId = await db.run(edge, "edge.drain");
    await waitFor("the revoked client's connection to close", async () => closedAt || undefined, 5_000, 50);
    expect(
      report,
      await db.applied(revoked.id, operationId),
      "the domain worker loaded the new policy and marked the API's journal row applied",
      operationId,
    );
    if (!delayWorker) {
      expect(
        report,
        closedAt - revoked.at < 5_000,
        "the worker closes the open connection within the revocation deadline",
        `${closedAt - revoked.at} ms`,
      );
    }
    await db.run(edge, "edge.l4_apply");
  } finally {
    socket.destroy();
  }
  const after = await attempt(mtlsHost, "/headers", { client });
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

async function damagedPkiTest(report: Report) {
  const db = database!;
  for (const crl of [null, "unreadable"]) {
    await db.corruptCrl(caIds.rt_mtls!, crl);
    // HAProxy reconfigures independently while Caddy has to refuse this route's client certificates.
    await db.run(edge, "edge.l4_apply", true);
    await db.queueApply();
    await db.run(edge, "edge.apply");
    const refused = await attempt(mtlsHost, "/headers", { client: good });
    expect(report, tlsRefused(refused), "a damaged or missing CRL admits no client", describe(refused));
    const repaired = await db.recoverCrls();
    expect(
      report,
      repaired.refreshed.includes(caIds.rt_mtls!) && !repaired.errors.length,
      "CRL repair schedules a new Caddy apply",
      JSON.stringify(repaired),
    );
    await db.run(edge, "edge.apply");
    const restored = await attempt(mtlsHost, "/headers", { client: good });
    expect(
      report,
      restored.kind === "http" && restored.reply.status === 200,
      "a valid unrevoked certificate works after CRL repair",
      describe(restored),
    );
  }

  // Canonical PEM containing DER that is not a certificate. Caddy must still load unrelated routes.
  const invalid = "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----";
  await db.corruptCertificate(caIds.rt_closed!, goodBoth.id, invalid);
  await db.queueApply();
  await db.run(edge, "edge.apply");
  const omitted = (await db.plan()).omitted;
  expect(
    report,
    omitted.some(({ id }) => id === "rt_closed"),
    "the malformed route CA omits only its route",
    omitted.map(({ id }) => id).join(", "),
  );
  const leaf = await attempt(bothHost, "/headers", { client: goodBoth });
  expect(
    report,
    tlsRefused(leaf),
    "the malformed leaf is skipped without breaking the shared reload",
    describe(leaf),
  );
  const plain = await attempt(openHost);
  expect(
    report,
    plain.kind === "http" && plain.reply.status === 200,
    "an unrelated route still serves",
    describe(plain),
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
  database = await startHttpControlsDb(runtime);
  const db = database;
  const [routeCa, closedCa, bothCa, rogueCa] = await Promise.all(
    ["Route rt_mtls", "Route rt_closed", "Route rt_both", "Rogue"].map((name) => db.clientCa(name)),
  );
  caIds = { rt_mtls: routeCa!.id, rt_closed: closedCa!.id, rt_both: bothCa!.id };
  [good, doomed, overdueClient, goodBoth, rogue] = await Promise.all([
    db.issue(routeCa!.id, "laptop"),
    db.issue(routeCa!.id, "phone"),
    db.issue(routeCa!.id, "watchdog"),
    db.issue(bothCa!.id, "laptop"),
    db.issue(rogueCa!.id, "rogue"),
  ]);
  let seeded = false;
  edge = await startGateEdge({
    runtime,
    directory,
    name: runName,
    gateToken,
    hostnames: [openHost, limitedHost, alsoLimitedHost, mtlsHost, closedHost, bothHost],
    targetedHttp: true,
    lease: () => (seeded ? db.lease() : Promise.resolve(undefined)),
    policy: (peerIp) =>
      fixtureRoutes(peerIp).map(({ id, hostname, stableId, ip, port }) => ({
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
  const routes = fixtureRoutes(edge.peerIp);
  await db.seed(edge, routes, caIds);
  seeded = true;
  const applied = await edge.edgeApply(await db.plan());
  if (
    !applied.applied ||
    applied.httpRoutes.toSorted().join() !==
      routes
        .map(({ id }) => id)
        .toSorted()
        .join()
  )
    throw new Error(`edge.apply did not load every route: ${JSON.stringify(applied)}`);
  await waitFor("the plain route through 443", async () => {
    const outcome = await attempt(openHost, "/headers");
    return outcome.kind === "http" && outcome.reply.status === 200 ? true : undefined;
  });
  await run("FD-23: per-route rate limit through HAProxy", rateLimitTest);
  await run("FD-23: two HAProxy clients and independent route quotas", quotaIsolationTest);
  await run("FD-23: HTTP mTLS refuses in the TLS handshake", mtlsTest);
  await run("FD-23: SNI/Host 421 between mTLS and plain routes", strictSniTest);
  await run("FD-23: mTLS combined with Ark login", combinedTest);
  await run("FD-23: HTTP revocation and domain worker drain", (report) =>
    revocationTest(report, doomed, false),
  );
  await run("FD-23: watchdog withdrawal after the revocation deadline", (report) =>
    revocationTest(report, overdueClient, true),
  );
  await run("FD-23: malformed certificate isolation and CRL repair", damagedPkiTest);
  console.log(`\nFD-23 HTTP control tests passed (${reports.length} groups).`);
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  await runtime.dumpLogs();
} finally {
  removeSignalHandlers();
  await database?.close();
  await cleanupGateEdge(runtime, runName, edge);
}
process.exit(failed ? 1 : 0);
