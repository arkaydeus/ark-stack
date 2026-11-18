// `mise run test:edge` (FD-26): the PostgreSQL router on 5432 through the shipped HAProxy edge
// (`edge-l4`), from docs/design/front-door.md §3.8.3 and the §3.8.5 `fe_pg5432` example, in disposable
// containers. No tailnet login, platform database or Python is needed.
//
// The shipped edge-ts, edge (Caddy), edge-l4 (HAProxy 3.2.26 behind its launch guard) and
// haproxy-validator run in a disposable Compose project (scripts/edge-test/stack.ts). Generations are
// written by the production `writeEdgeL4` in the domain worker's identity; the production edge
// watchdog enforces a lease served by this process, whose postgres routes carry their policy
// fingerprints. The pinned `pgbouncer-public` image runs Ark's rendered configuration (planPgbouncer:
// mTLS verify-full, TLS 1.3, SCRAM) against a disposable `app-postgres` on a separate internal network
// standing in for `database-management`, and joins the project's real `pgbouncer-ingress` network with
// the `pgbouncer-public` alias, exactly as in production. Tailnet targets (PostgreSQL 17 with ssl=on,
// PostgreSQL 16 without TLS) sit at 100.64.0.0/10 addresses; clients run at fixed addresses on a client
// network attached to edge-ts, so HAProxy sees distinct sources.
//
// Covered (the FD-26 acceptance criteria):
// - the V-13 matrix: psql 17 and node-postgres 8.23 classic -> PgBouncer (the Vercel-style client:
//   node-postgres, client certificate, SCRAM, classic negotiation); psql, node-postgres and postgres.js
//   4.1.1 direct -> PgBouncer, by the database hostname and without SNI; direct with a route SNI -> the
//   PG 17 passthrough target; direct -> PG 16 through edge termination (ALPN postgresql); plaintext
//   startup and unknown SNI rejected; an idle connection closed at 5 s; classic to a route hostname
//   lands on PgBouncer and fails on the certificate name;
// - the pooler-wide policy in be_pgbouncer: a source outside it is refused while a Postgres route on
//   the same port admits that source; an empty policy denies everybody; only allowInternet opens it;
// - no public database (no pooler rendered): SSLRequest connections are rejected, routes keep working;
// - the compatibility port relays classic SSLRequest TLS to the PG 17 target behind the route's
//   allowlist, and the raw-port nftables table drops sources outside the route's CIDR list;
// - app-postgres is unreachable from the edge-ts namespace, while PgBouncer is reachable by name;
// - static Compose checks: no 15432 publish, database-ingress has no listener, edge-ts never joins
//   database-management. FD-18's per-source limits on the forward hook (the Docker DNAT path to the
//   published 5432) are proven by scripts/test-db-ingress.ts, which runs in the same task.
//
// `ARK_EDGE_PG5432_ONLY=<text>` runs only the named tests whose name contains <text> (setup always runs).
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  L4_LIMIT_DEFAULTS,
  POOLER_ALLOWLIST_FILE,
  haproxyServerName,
  l4PolicyFingerprint,
  renderFrontRawPorts,
  type EdgeL4Input,
  type EdgeL4Pooler,
  type EdgeL4PostgresRoute,
  type EdgeLeaseDocument,
  type EdgePolicyRoute,
  type WatchdogEvent,
} from "@ark-stack/shared";

import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { type EdgeStack, composeFile, startEdgeStack } from "./edge-test/stack.ts";

// The PKI and PgBouncer modules are pure apart from persistence; give them a (never used) database URL.
process.env.DATABASE_URL ??= "postgres://unused@127.0.0.1:1/unused";
const pki = await import("../server/src/modules/pki.ts");
const { planPgbouncer, renderPgbouncerFiles } = await import("../server/src/modules/pgbouncer.ts");

const root = resolve(import.meta.dir, "..");
const fixtures = join(import.meta.dir, "edge-test");
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
// Same pin as scripts/test-db.ts and the Dockerfile's postgres stage: psql 17 and the PG 17 target.
const pg17Image = "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929";
const pg16Image = process.env.ARK_TEST_PG16_IMAGE ?? "postgres:16.10";
const nftImage = "ark-db-ingress-test:local";
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-pg5432-${suffix}-`));
const network = `ark-edge-pg-${suffix}`;
const runtime = new EdgeTestRuntime(directory, network, bunImage);
const removeSignalHandlers = runtime.installSignalHandlers();
const docker = (...args: string[]) => runtime.docker(...args);
const extraNetworks: string[] = [];
const extraVolumes: string[] = [];

const random = (span: number) => Number.parseInt(randomBytes(2).toString("hex"), 16) % span;
const peerSubnet = `100.${64 + random(64)}.${1 + random(250)}.0/24`;
const peerPrefix = peerSubnet.slice(0, peerSubnet.lastIndexOf("."));
const pg17Ip = `${peerPrefix}.21`;
const pg16Ip = `${peerPrefix}.22`;
const peerNetwork = `ark-edge-pg-peer-${suffix}`;
const clientNetwork = `ark-edge-pg-client-${suffix}`;
const dbNetwork = `ark-edge-pg-dbm-${suffix}`;
let clientPrefix = "";
let edgeIp = "";

const appHost = "app.example.com";
const dbHost = "db.example.com";
const pg17Host = "pg17.example.com";
const pg16Host = "pg16.example.com";
const database = "shop";
const role = "shop_production";
const password = randomBytes(18).toString("base64url");
const targetPassword = randomBytes(18).toString("base64url");

type Report = { name: string; lines: string[] };

function expect(report: Report, condition: boolean, claim: string, observed: string) {
  if (!condition) throw new Error(`[${report.name}] FAILED: ${claim} (observed: ${observed})`);
  report.lines.push(`  ok  ${claim} [${observed}]`);
}

async function waitFor<T>(
  what: string,
  attempt: () => Promise<T | undefined>,
  timeoutMs = 30_000,
  stepMs = 250,
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

async function spawn(command: string[], options: { cwd?: string } = {}) {
  const child = Bun.spawn(command, { cwd: options.cwd, stdout: "pipe", stderr: "pipe" });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { status, stdout: stdout.trim(), stderr: stderr.trim() };
}

// ---- Files: certificates, Caddy, client modules ------------------------------------------------------

const certificate = (dir: string, host: string) =>
  `mkdir -p ${dir} && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=${host}" -addext "subjectAltName=DNS:${host}" -keyout ${dir}/privkey.pem -out ${dir}/fullchain.pem 2>/dev/null && chmod 644 ${dir}/privkey.pem`;

const pem = { db: { chain: "", key: "" }, pg16: { chain: "", key: "" } };
const client = { certPem: "", key: "" };
let caMaterial!: ReturnType<typeof pki.createCaMaterial>;
let issuedNotAfter = new Date();

async function prepareFiles() {
  const edgeDir = join(directory, "edge");
  await mkdir(join(directory, "acme", ".well-known", "acme-challenge"), { recursive: true });
  await mkdir(edgeDir);
  await Bun.write(
    join(edgeDir, "Caddyfile"),
    `{\n  admin edge-admin:2019\n  auto_https off\n}\n${appHost} {\n  tls /var/lib/ark/certs/${appHost}/fullchain.pem /var/lib/ark/certs/${appHost}/privkey.pem\n  respond "http ok"\n}\n`,
  );
  await Bun.write(join(edgeDir, "Caddyfile.closed"), await Bun.file(join(edgeDir, "Caddyfile")).text());
  await chmod(directory, 0o755);
  const script = [
    "set -e",
    certificate(`/out/certs/${appHost}`, appHost),
    certificate("/out/pki/db", dbHost),
    certificate("/out/pki/pg17", pg17Host),
    certificate("/out/pki/pg16", pg16Host),
    "chown -R 1000:1000 /out/certs /out/edge",
    "chmod -R a+rX /out/pki",
  ].join("\n");
  await docker("run", "--rm", "--user", "0:0", "--volume", `${directory}:/out`, bunImage, "sh", "-c", script);
  for (const name of ["db", "pg16"] as const) {
    pem[name].chain = await Bun.file(join(directory, "pki", name, "fullchain.pem")).text();
    pem[name].key = await Bun.file(join(directory, "pki", name, "privkey.pem")).text();
  }
  // An Ark database client: its own db-client CA (FD-13 PKI) and a client certificate, as Vercel uses.
  caMaterial = pki.createCaMaterial({ id: "pca_fd26_vercel", purpose: "db-client", name: "fd26/production" });
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const issued = pki.signClientCertificate({
    ca: { certPem: caMaterial.certPem, privateKey: caMaterial.privateKey },
    subjectCn: role,
    publicKey: pair.publicKey,
  });
  client.certPem = issued.certPem;
  client.key = pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  issuedNotAfter = issued.notAfter;
  await mkdir(join(directory, "client"));
  await Bun.write(join(directory, "client", "client.crt"), client.certPem);
  await Bun.write(join(directory, "client", "client.key"), client.key);
  await Bun.write(join(directory, "client", "db.crt"), pem.db.chain);
  await chmod(join(directory, "client"), 0o755);
  // node-postgres (>= 8.22 for sslnegotiation) and postgres.js 4.1.1 in a throwaway module tree.
  const work = join(directory, "clientjs");
  await mkdir(work);
  await Bun.write(
    join(work, "package.json"),
    JSON.stringify({
      name: "fd26-clients",
      private: true,
      dependencies: { pg: "8.23.1", postgres: "4.1.1" },
    }),
  );
  const installed = await spawn(["bun", "install", "--no-save", "--linker=hoisted", "--backend=copyfile"], {
    cwd: work,
  });
  if (installed.status !== 0) throw new Error(`installing the client drivers failed: ${installed.stderr}`);
  await Bun.write(join(work, "pg-client.ts"), await Bun.file(join(fixtures, "pg-client.ts")).text());
  await spawn(["chmod", "-R", "a+rX", work]);
}

// ---- Lease API (the API's read-only lease endpoint, served by this process) ---------------------------

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
          generation: "gen-pg5432",
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

// ---- Containers ----------------------------------------------------------------------------------------

let stack!: EdgeStack;
const bundles = { watchdog: "", probe: "" };
const watchdogName = `ark-edge-pg-watchdog-${suffix}`;
const probeName = `ark-edge-pg-worker-${suffix}`;
const appPostgres = `ark-edge-pg-app-${suffix}`;
const pgbouncer = `ark-edge-pg-bouncer-${suffix}`;
const pg17 = `ark-edge-pg-target17-${suffix}`;
const pg16 = `ark-edge-pg-target16-${suffix}`;
let appPostgresIp = "";

async function createSubnetNetwork(name: string, internal = false) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const prefix = `10.${200 + random(50)}.${1 + random(250)}`;
    try {
      await docker(
        "network",
        "create",
        ...(internal ? ["--internal"] : []),
        "--subnet",
        `${prefix}.0/24`,
        name,
      );
      extraNetworks.push(name);
      return prefix;
    } catch (error) {
      if (!/overlap|in use/i.test((error as Error).message)) throw error;
    }
  }
  throw new Error(`could not find a free subnet for ${name}`);
}

async function pgReady(container: string, user: string) {
  await waitFor(
    `${container} to accept connections`,
    async () => {
      const result = await spawn(["docker", "exec", container, "pg_isready", "-U", user, "-h", "127.0.0.1"]);
      return result.status === 0 ? true : undefined;
    },
    90_000,
    500,
  );
}

async function startPostgres() {
  // app-postgres stand-in on its own internal network: the edge namespace must never reach it.
  await createSubnetNetwork(dbNetwork, true);
  runtime.containers.push(appPostgres);
  await docker(
    "run",
    "--detach",
    "--name",
    appPostgres,
    "--network",
    dbNetwork,
    "--network-alias",
    "app-postgres",
    "--env",
    `POSTGRES_PASSWORD=${randomBytes(12).toString("hex")}`,
    pg17Image,
  );
  await pgReady(appPostgres, "postgres");
  await docker(
    "exec",
    appPostgres,
    "psql",
    "-U",
    "postgres",
    "-v",
    "ON_ERROR_STOP=1",
    "-c",
    `CREATE ROLE ${role} LOGIN PASSWORD '${password}'`,
    "-c",
    `CREATE DATABASE ${database} OWNER ${role}`,
  );
  appPostgresIp = await docker(
    "inspect",
    "--format",
    `{{(index .NetworkSettings.Networks "${dbNetwork}").IPAddress}}`,
    appPostgres,
  );

  // PgBouncer with Ark's rendered configuration (mTLS verify-full, TLS 1.3, SCRAM, one mapping).
  const plan = planPgbouncer({
    databases: [{ id: "mdb_fd26", name: database, exposure: "public" }],
    clients: [
      {
        id: "dbc_fd26",
        databaseId: "mdb_fd26",
        environment: "production",
        status: "active",
        caId: "pca_fd26_vercel",
        role: { name: role, connectionLimit: 20, password },
      },
    ],
    certificates: [
      {
        id: "ccert_fd26",
        caId: "pca_fd26_vercel",
        status: "issued",
        rolloverState: "current",
        supersededBy: null,
        notAfter: issuedNotAfter,
      },
    ],
    cas: [
      {
        id: "pca_fd26_vercel",
        purpose: "db-client",
        status: "active",
        certPem: caMaterial.certPem,
        notAfter: caMaterial.notAfter,
      },
    ],
    now: new Date(),
    host: "app-postgres",
  });
  if (!plan.routed) throw new Error("The PgBouncer plan admitted no client.");
  const files = renderPgbouncerFiles({
    plan,
    adminPassword: randomBytes(18).toString("base64url"),
    certificateDir: "/var/lib/ark/pgbouncer/certs",
  });
  const state = join(directory, "pgbouncer");
  await mkdir(join(state, "certs"), { recursive: true });
  for (const [name, text] of Object.entries(files)) await writeFile(join(state, name), text);
  await writeFile(join(state, "certs", "fullchain.pem"), pem.db.chain);
  await writeFile(join(state, "certs", "privkey.pem"), pem.db.key);
  await spawn(["chmod", "-R", "a+rX", state]);
  const volume = `ark-edge-pg-bouncer-state-${suffix}`;
  extraVolumes.push(volume);
  await docker("volume", "create", volume);
  // The installer's ownership: uid 1000, 0700 directory, 0600 files.
  await docker(
    "run",
    "--rm",
    "--user",
    "0:0",
    "--network",
    "none",
    "--volume",
    `${state}:/fixtures:ro`,
    "--volume",
    `${volume}:/state`,
    bunImage,
    "sh",
    "-ec",
    "cp -R /fixtures/. /state/; chown -R 1000:1000 /state; chmod 700 /state /state/certs; find /state -type f -exec chmod 600 {} +",
  );
  const compose = Bun.YAML.parse(await Bun.file(composeFile).text()) as {
    services: Record<string, { image: string }>;
  };
  runtime.containers.push(pgbouncer);
  await docker(
    "run",
    "--detach",
    "--name",
    pgbouncer,
    "--user",
    "1000:1000",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--network",
    dbNetwork,
    "--volume",
    `${volume}:/var/lib/ark/pgbouncer:ro`,
    "--tmpfs",
    "/var/run/pgbouncer:uid=1000,gid=1000,mode=0700",
    "--entrypoint",
    "/usr/bin/pgbouncer",
    compose.services["pgbouncer-public"]!.image,
    "/var/lib/ark/pgbouncer/pgbouncer.ini",
  );
  // The production pgbouncer-ingress network (internal; members edge-ts and pgbouncer-public).
  await docker(
    "network",
    "connect",
    "--alias",
    "pgbouncer-public",
    `${stack.project}_pgbouncer-ingress`,
    pgbouncer,
  );

  // Tailnet targets: PostgreSQL 17 terminating TLS itself (passthrough), PostgreSQL 16 without TLS.
  runtime.containers.push(pg17, pg16);
  await docker(
    "run",
    "--detach",
    "--name",
    pg17,
    "--network",
    peerNetwork,
    "--ip",
    pg17Ip,
    "--env",
    `POSTGRES_PASSWORD=${targetPassword}`,
    "--volume",
    `${join(directory, "pki", "pg17")}:/c:ro`,
    "--entrypoint",
    "sh",
    pg17Image,
    "-c",
    "cp /c/fullchain.pem /tmp/server.crt && cp /c/privkey.pem /tmp/server.key && chown postgres /tmp/server.* && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key",
  );
  await docker(
    "run",
    "--detach",
    "--name",
    pg16,
    "--network",
    peerNetwork,
    "--ip",
    pg16Ip,
    "--env",
    `POSTGRES_PASSWORD=${targetPassword}`,
    // Edge termination forwards plaintext over WireGuard: a `host` line (not hostssl), scram-sha-256.
    "--env",
    "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
    pg16Image,
  );
  await pgReady(pg17, "postgres");
  await pgReady(pg16, "postgres");
}

async function startContainers() {
  runtime.networkCreated = true;
  await docker("network", "create", network);
  stack = await startEdgeStack({
    runtime,
    project: `ark-edge-pg-${suffix}`,
    directory,
    acmeDir: join(directory, "acme"),
    certDir: join(directory, "certs"),
    edgeDir: join(directory, "edge"),
    validator: true,
    ports: ["127.0.0.1::80", "127.0.0.1::443", "127.0.0.1::5432", "127.0.0.1::20007", "127.0.0.1::41642/udp"],
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
  edgeIp = `${clientPrefix}.2`;
  await startPostgres();
  bundles.watchdog = await bundle(join(root, "workers/src/edge-watchdog.ts"), "watchdog");
  bundles.probe = await bundle(join(fixtures, "l4-worker-probe.ts"), "probe");
  await startWatchdog();
}

/** The edge watchdog as shipped (uid 1000, group 4400, read-only root, no capabilities). */
async function startWatchdog() {
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
  await docker("network", "connect", "--alias", "edge-watchdog", stack.networks.edgeControl, watchdogName);
  await waitFor(
    "verified watchdog enforcement on HAProxy",
    async () => {
      const status = await docker(
        "exec",
        watchdogName,
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

/** Wait for two distinct completed, verified watchdog passes. */
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

// ---- Routes, lease and apply -----------------------------------------------------------------------------

type PgSpec = Pick<
  EdgeL4PostgresRoute,
  "id" | "hostname" | "sourceCidrs" | "tlsMode" | "compatPort" | "allowInternet"
>;
function pgRoute(spec: PgSpec): EdgeL4PostgresRoute {
  const terminated = spec.tlsMode !== undefined && spec.tlsMode !== "passthrough";
  const limits = { ...L4_LIMIT_DEFAULTS.postgres };
  return {
    ...spec,
    stableId: `n${spec.id.replace(/_/g, "")}`,
    ip: terminated ? pg16Ip : pg17Ip,
    port: 5432,
    limits,
    policy: l4PolicyFingerprint({
      kind: "postgres",
      listenPort: 5432,
      tlsMode: spec.tlsMode ?? "passthrough",
      sourceCidrs: spec.sourceCidrs,
      allowInternet: Boolean(spec.allowInternet),
      limits,
      clientCaId: null,
      revokedSerials: [],
      compatPort: spec.compatPort ?? null,
    }),
    ...(terminated ? { certificatePem: `${pem.pg16.chain.trim()}\n${pem.pg16.key.trim()}\n` } : {}),
  };
}

/** The HAProxy launch guard's mode, from its latest mode line. */
async function guardMode() {
  const { stdout, stderr } = await runtime.dockerOutput("logs", stack.edgeL4);
  const line = (stdout + stderr)
    .split("\n")
    .findLast((entry) =>
      /launch guard: (starting from the (full|closed) configuration|lease valid; switched|lease no longer allows|full reload unconfirmed)/.test(
        entry,
      ),
    );
  if (!line) return undefined;
  return /starting from the full|switched to the full/.test(line) ? "full" : "closed";
}

/** Production transition: publish the lease first, then install the generation and wait until served. */
async function apply(input: { postgresRoutes: EdgeL4PostgresRoute[]; pooler: EdgeL4Pooler | null }) {
  lease.routes = input.postgresRoutes.map((route) => ({
    id: route.id,
    kind: "postgres",
    hostname: route.hostname,
    stableId: route.stableId,
    ip: route.ip,
    port: route.port,
    policy: route.policy,
  }));
  await settle();
  const full: EdgeL4Input = { httpHostnames: [appHost], ...input };
  for (let attempt = 0; ; attempt++) {
    const result = await probe<{ applied?: boolean; error?: string; pooler?: unknown }>([
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
  const expected = input.postgresRoutes.map(haproxyServerName);
  await waitFor(
    "the generation to be served",
    async () => {
      if (expected.length && (await guardMode()) !== "full") return undefined;
      const workers = await probe<
        Record<
          string,
          { section: string; servers: Array<{ server: string; backend: string; adminState: number }> }
        >
      >(["servers"]);
      const current = Object.values(workers).filter((worker) => worker.section === "current");
      const names = new Set(
        current.flatMap((worker) =>
          worker.servers.filter((server) => (server.adminState & 1) === 0).map((server) => server.server),
        ),
      );
      const pooler = current.some((worker) =>
        worker.servers.some((server) => server.backend === "be_pgbouncer"),
      );
      return expected.every((name) => names.has(name)) && pooler === Boolean(input.pooler) ? true : undefined;
    },
    30_000,
    300,
  );
  await settle();
}

// ---- Clients -------------------------------------------------------------------------------------------------

const sourceIp = { A: "", B: "", C: "" };
type Result = { status: number; stdout: string; stderr: string };

/** psql 17 from a fixed client address. `conninfo` is a libpq keyword string. */
async function psql(source: string, conninfo: string): Promise<Result> {
  const name = `ark-edge-pg-psql-${suffix}-${randomBytes(3).toString("hex")}`;
  runtime.containers.push(name);
  const script = `cp /c/* /tmp/ && chmod 600 /tmp/client.key && exec psql "$1" -X -tA -c "SELECT current_database() || ' ' || current_setting('server_version_num')"`;
  return spawn([
    "docker",
    "run",
    "--rm",
    "--name",
    name,
    "--network",
    clientNetwork,
    "--ip",
    source,
    "--env",
    `PGPASSWORD=${conninfo.includes(`user=${role}`) ? password : targetPassword}`,
    "--env",
    "PGCONNECT_TIMEOUT=8",
    "--volume",
    `${join(directory, "client")}:/c:ro`,
    "--entrypoint",
    "sh",
    pg17Image,
    "-c",
    script,
    "psql",
    conninfo,
  ]);
}

type Driver = { ok: boolean; database?: string; version?: string; error?: string; ms: number };
async function driver(
  source: string,
  spec: {
    driver: "pg" | "postgres";
    port?: number;
    servername?: string;
    direct: boolean;
    target?: "pooler" | "pg";
  },
): Promise<Driver> {
  const pooler = (spec.target ?? "pooler") === "pooler";
  const name = `ark-edge-pg-node-${suffix}-${randomBytes(3).toString("hex")}`;
  runtime.containers.push(name);
  const result = await spawn([
    "docker",
    "run",
    "--rm",
    "--name",
    name,
    "--network",
    clientNetwork,
    "--ip",
    source,
    "--volume",
    `${join(directory, "clientjs")}:/work:ro`,
    "--workdir",
    "/work",
    bunImage,
    "bun",
    "/work/pg-client.ts",
    JSON.stringify({
      driver: spec.driver,
      host: edgeIp,
      port: spec.port ?? 5432,
      servername: spec.servername,
      direct: spec.direct,
      user: pooler ? role : "postgres",
      password: pooler ? password : targetPassword,
      database: pooler ? database : "postgres",
      ...(pooler ? { cert: client.certPem, key: client.key } : {}),
    }),
  ]);
  try {
    return JSON.parse(result.stdout.split("\n").at(-1) ?? "") as Driver;
  } catch {
    return { ok: false, error: result.stderr || result.stdout, ms: 0 };
  }
}

const pooledConn = (extra: string) =>
  `host=${dbHost} hostaddr=${edgeIp} port=5432 dbname=${database} user=${role} sslcert=/tmp/client.crt sslkey=/tmp/client.key ${extra}`;
const targetConn = (host: string, extra: string, port = 5432) =>
  `host=${host} hostaddr=${edgeIp} port=${port} dbname=postgres user=postgres ${extra}`;
const okPg = (result: Result, version: string) =>
  result.status === 0 && new RegExp(`^\\S+ ${version}\\d{4}$`).test(result.stdout);
const okPooler = (result: Result) => result.status === 0 && result.stdout.startsWith(`${database} `);
const brief = (result: Result) =>
  result.status === 0
    ? result.stdout
    : `exit ${result.status}: ${result.stderr.split("\n").at(-1)?.slice(0, 160)}`;

/** Connect and send nothing: HAProxy's 5 s inspect delay must close the connection. */
async function idleClose(source: string) {
  const name = `ark-edge-pg-idle-${suffix}`;
  runtime.containers.push(name);
  const result = await spawn([
    "docker",
    "run",
    "--rm",
    "--name",
    name,
    "--network",
    clientNetwork,
    "--ip",
    source,
    bunImage,
    "bun",
    "-e",
    `const s=require('node:net').connect({host:${JSON.stringify(edgeIp)},port:5432});let t0=0;s.on('connect',()=>{t0=Date.now()});s.on('data',()=>{});s.on('close',()=>{console.log(JSON.stringify({ms:Date.now()-t0}));process.exit(0)});s.on('error',()=>{});setTimeout(()=>{console.log(JSON.stringify({ms:-1}));process.exit(0)},15000)`,
  ]);
  return (JSON.parse(result.stdout || '{"ms":-2}') as { ms: number }).ms;
}

// ---- Tests -----------------------------------------------------------------------------------------------------

const routes = () => ({
  pg17: pgRoute({
    id: "rt_pg17",
    hostname: pg17Host,
    tlsMode: "passthrough",
    sourceCidrs: [`${sourceIp.A}/32`, `${sourceIp.B}/32`],
    compatPort: 20007,
  }),
  pg16: pgRoute({
    id: "rt_pg16",
    hostname: pg16Host,
    tlsMode: "terminate",
    sourceCidrs: [`${sourceIp.A}/32`, `${sourceIp.B}/32`],
  }),
});
const poolerFor = (sourceCidrs: string[], allowInternet = false): EdgeL4Pooler => ({
  hostname: dbHost,
  sourceCidrs,
  allowInternet,
});

async function staticComposeTest(report: Report) {
  const text = await Bun.file(composeFile).text();
  const compose = Bun.YAML.parse(text) as {
    services: Record<
      string,
      {
        ports?: string[];
        networks?: string[] | Record<string, unknown>;
        environment?: Record<string, string>;
      }
    >;
  };
  const networksOf = (name: string) => {
    const value = compose.services[name]?.networks;
    return Array.isArray(value) ? value : Object.keys(value ?? {});
  };
  expect(report, !text.includes("15432"), "no 127.0.0.1:15432 publish remains", "15432 absent");
  expect(
    report,
    !compose.services["pgbouncer-public"]?.ports &&
      compose.services["edge-ts"]?.ports?.includes("5432:5432") === true,
    "public 5432 is published by edge-ts (edge-l4), and pgbouncer-public publishes nothing",
    `edge-ts publishes 5432; pgbouncer-public ports ${JSON.stringify(compose.services["pgbouncer-public"]?.ports ?? [])}`,
  );
  const ingress = await Bun.file(join(root, "scripts", "database-ingress.ts")).text();
  expect(
    report,
    !/createServer|\.listen\(|startListener/.test(ingress) &&
      !("ARK_PUBLIC_DB_PORT" in (compose.services["database-ingress"]?.environment ?? {})),
    "the database-ingress 5432 relay is gone; it is only the nft reconciler",
    "no listener in scripts/database-ingress.ts",
  );
  expect(
    report,
    !networksOf("edge-ts").includes("database-management") &&
      networksOf("edge-ts").includes("pgbouncer-ingress"),
    "edge-ts joins pgbouncer-ingress and never database-management",
    networksOf("edge-ts").join(", "),
  );
}

async function matrixTest(report: Report) {
  const { A } = sourceIp;
  // Classic (SSLRequest) -> PgBouncer.
  const classic = await psql(A, pooledConn(`sslmode=verify-full sslrootcert=/tmp/db.crt`));
  expect(
    report,
    okPooler(classic),
    "psql 17, classic SSLRequest -> PgBouncer (verify-full on the DB hostname)",
    brief(classic),
  );
  const vercel = await driver(A, { driver: "pg", direct: false, servername: dbHost });
  expect(
    report,
    vercel.ok && vercel.database === database,
    "node-postgres 8.23 classic, Vercel-style (client certificate + SCRAM) -> PgBouncer",
    vercel.ok ? `${vercel.database} in ${vercel.ms} ms` : String(vercel.error),
  );
  // Direct TLS -> PgBouncer, by the database hostname and with no SNI.
  const directSni = await psql(
    A,
    pooledConn("sslmode=verify-full sslrootcert=/tmp/db.crt sslnegotiation=direct"),
  );
  expect(report, okPooler(directSni), "psql direct, SNI = database hostname -> PgBouncer", brief(directSni));
  const directNoSni = await psql(
    A,
    `host=${edgeIp} port=5432 dbname=${database} user=${role} sslcert=/tmp/client.crt sslkey=/tmp/client.key sslmode=require sslnegotiation=direct`,
  );
  expect(report, okPooler(directNoSni), "psql direct, no SNI (IP address) -> PgBouncer", brief(directNoSni));
  for (const [label, spec] of [
    ["node-postgres direct, SNI = database hostname", { driver: "pg", direct: true, servername: dbHost }],
    ["node-postgres direct, no SNI", { driver: "pg", direct: true }],
    ["postgres.js 4.1.1 direct, no SNI", { driver: "postgres", direct: true }],
    [
      "postgres.js 4.1.1 direct, SNI = database hostname",
      { driver: "postgres", direct: true, servername: dbHost },
    ],
  ] as const) {
    const result = await driver(A, spec);
    expect(
      report,
      result.ok && result.database === database,
      `${label} -> PgBouncer`,
      result.ok ? String(result.database) : String(result.error),
    );
  }
  // Direct with a route SNI -> PG 17 passthrough; -> PG 16 through edge termination.
  const pg17Direct = await psql(A, targetConn(pg17Host, "sslmode=require sslnegotiation=direct"));
  expect(
    report,
    okPg(pg17Direct, "17"),
    "psql direct, route SNI -> PostgreSQL 17 passthrough target",
    brief(pg17Direct),
  );
  const pg17Node = await driver(A, { driver: "pg", direct: true, servername: pg17Host, target: "pg" });
  expect(
    report,
    pg17Node.ok && (pg17Node.version ?? "").startsWith("17"),
    "node-postgres direct, route SNI -> PG 17",
    String(pg17Node.version ?? pg17Node.error),
  );
  const pg17Js = await driver(A, { driver: "postgres", direct: true, servername: pg17Host, target: "pg" });
  expect(
    report,
    pg17Js.ok && (pg17Js.version ?? "").startsWith("17"),
    "postgres.js direct, route SNI -> PG 17",
    String(pg17Js.version ?? pg17Js.error),
  );
  const pg16Direct = await psql(A, targetConn(pg16Host, "sslmode=require sslnegotiation=direct"));
  expect(
    report,
    okPg(pg16Direct, "16"),
    "psql direct, route SNI -> PostgreSQL 16 through edge termination (ALPN postgresql)",
    brief(pg16Direct),
  );
  const pg16Node = await driver(A, { driver: "pg", direct: true, servername: pg16Host, target: "pg" });
  expect(
    report,
    pg16Node.ok && (pg16Node.version ?? "").startsWith("16"),
    "node-postgres direct -> PG 16 through edge termination",
    String(pg16Node.version ?? pg16Node.error),
  );
  // Rejections.
  const plaintext = await psql(A, pooledConn("sslmode=disable"));
  expect(
    report,
    plaintext.status !== 0,
    "a plaintext StartupMessage (sslmode=disable) is rejected",
    brief(plaintext),
  );
  const unknown = await psql(A, targetConn("unknown.example.com", "sslmode=require sslnegotiation=direct"));
  expect(report, unknown.status !== 0, "direct TLS with an unknown SNI is rejected", brief(unknown));
  const classicToRoute = await psql(A, targetConn(pg17Host, "sslmode=verify-full sslrootcert=/tmp/db.crt"));
  expect(
    report,
    classicToRoute.status !== 0,
    "classic SSLRequest to a route hostname lands on PgBouncer and fails on the certificate name (fails safely)",
    brief(classicToRoute),
  );
  const idle = await idleClose(A);
  expect(
    report,
    idle >= 4_500 && idle <= 6_500,
    "an idle connection (no bytes) is closed at 5 s",
    `${idle} ms`,
  );
}

async function poolerPolicyTest(report: Report) {
  const { A, B } = sourceIp;
  const { pg17: route17, pg16: route16 } = routes();
  // The default for this suite: the pooler admits A only; routes admit A and B.
  const outside = await psql(B, pooledConn("sslmode=require"));
  expect(
    report,
    outside.status !== 0,
    "a client outside pooler_source_cidrs is refused by be_pgbouncer",
    brief(outside),
  );
  const sameClientRoute = await psql(B, targetConn(pg17Host, "sslmode=require sslnegotiation=direct"));
  expect(
    report,
    okPg(sameClientRoute, "17"),
    "that same client still reaches a Postgres route on the same port",
    brief(sameClientRoute),
  );
  await apply({ postgresRoutes: [route17, route16], pooler: poolerFor([]) });
  const files = await docker(
    "exec",
    stack.edgeL4,
    "cat",
    `/usr/local/etc/haproxy/current/${POOLER_ALLOWLIST_FILE}`,
  );
  const empty = await psql(A, pooledConn("sslmode=require"));
  expect(
    report,
    files === "" && empty.status !== 0,
    "an empty pooler policy renders an empty allowlist and denies everybody",
    brief(empty),
  );
  await apply({ postgresRoutes: [route17, route16], pooler: poolerFor([], true) });
  const open = await psql(B, pooledConn("sslmode=require"));
  expect(report, okPooler(open), "only allowInternet opens the pooler (0.0.0.0/0, ::/0)", brief(open));
  await apply({ postgresRoutes: [route17, route16], pooler: poolerFor([`${A}/32`]) });
}

async function noPublicDatabaseTest(report: Report) {
  const { A } = sourceIp;
  const { pg17: route17, pg16: route16 } = routes();
  await apply({ postgresRoutes: [route17, route16], pooler: null });
  const classic = await psql(A, pooledConn("sslmode=require"));
  expect(
    report,
    classic.status !== 0,
    "with no public database, SSLRequest connections are rejected",
    brief(classic),
  );
  const noSni = await driver(A, { driver: "pg", direct: true });
  expect(report, !noSni.ok, "direct TLS without SNI is rejected too", String(noSni.error));
  const route = await psql(A, targetConn(pg17Host, "sslmode=require sslnegotiation=direct"));
  expect(report, okPg(route, "17"), "Postgres routes keep working without a pooler", brief(route));
  await apply({ postgresRoutes: [route17, route16], pooler: poolerFor([`${A}/32`]) });
  const back = await psql(A, pooledConn("sslmode=require"));
  expect(report, okPooler(back), "publishing a database renders be_pgbouncer again", brief(back));
}

/** In the nft namespace test: connect to the compatibility port from `source` and report the verdict. */
const probeConnect = (source: string, label: string) =>
  `ip netns exec cli bun -e "const s=require('node:net').connect({host:'10.99.0.1',port:20007,localAddress:'${source}'});const t=setTimeout(()=>{console.log('${label} dropped');process.exit(0)},1500);s.on('connect',()=>{clearTimeout(t);console.log('${label} open');process.exit(0)});s.on('error',e=>{clearTimeout(t);console.log('${label} '+e.code);process.exit(0)})"`;

/** From the edge-ts namespace: does a TCP connect to `host`:5432 succeed? */
const connectProbe = (host: string) =>
  `const s=require('node:net').connect({host:${JSON.stringify(host)},port:5432});const t=setTimeout(()=>{console.log('timeout');process.exit(0)},3000);s.on('connect',()=>{clearTimeout(t);console.log('connected');process.exit(0)});s.on('error',e=>{clearTimeout(t);console.log(e.code);process.exit(0)})`;

async function compatPortTest(report: Report) {
  const { A, C } = sourceIp;
  const relayed = await psql(A, targetConn(pg17Host, "sslmode=require", 20007));
  expect(
    report,
    okPg(relayed, "17"),
    "the compatibility port relays classic SSLRequest TLS to the PG 17 target",
    brief(relayed),
  );
  const outside = await psql(C, targetConn(pg17Host, "sslmode=require", 20007));
  expect(
    report,
    outside.status !== 0,
    "HAProxy refuses a source outside the route's CIDR list on the compatibility port",
    brief(outside),
  );

  // nftables: the raw-port table renders the compatibility port with the route's allowlist.
  const rules = join(directory, "nft");
  await mkdir(rules);
  const allowed = "10.99.0.2";
  const denied = "10.99.0.3";
  await writeFile(
    join(rules, "raw.nft"),
    renderFrontRawPorts([
      {
        id: "rt_pg17",
        listenPort: 20007,
        sourceCidrs: [`${allowed}/32`],
        limits: L4_LIMIT_DEFAULTS.postgres,
      },
    ]),
  );
  await chmod(rules, 0o755);
  const built = Bun.spawn(["docker", "build", "--quiet", "-t", nftImage, "-"], {
    stdin: new TextEncoder().encode(
      `FROM ${bunImage}\nRUN apt-get update \\\n  && apt-get install -y --no-install-recommends nftables iproute2 \\\n  && rm -rf /var/lib/apt/lists/*\n`,
    ),
    stdout: "pipe",
    stderr: "pipe",
  });
  if ((await built.exited) !== 0)
    throw new Error(`building ${nftImage} failed: ${await new Response(built.stderr).text()}`);
  const script = `set -e
nft -c -f /rules/raw.nft; echo "nft -c ok"
ip netns add srv; ip netns add cli
ip link add v0 type veth peer name v1
ip link set v0 netns srv; ip link set v1 netns cli
ip -n srv addr add 10.99.0.1/24 dev v0; ip -n cli addr add ${allowed}/24 dev v1; ip -n cli addr add ${denied}/24 dev v1
ip -n srv link set v0 up; ip -n cli link set v1 up; ip -n srv link set lo up; ip -n cli link set lo up
ip netns exec srv nft -f /rules/raw.nft
ip netns exec srv bun -e 'Bun.listen({hostname:"0.0.0.0",port:20007,socket:{data(){}}})' &
sleep 1
${probeConnect(allowed, "allowed")}
${probeConnect(denied, "denied")}
`;
  const name = `ark-edge-pg-nft-${suffix}`;
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
  expect(
    report,
    lines.includes("nft -c ok") && lines.includes("allowed open") && lines.includes("denied dropped"),
    "nftables refuses sources outside the route's CIDR list on the compatibility port (and passes nft -c)",
    lines.filter((line) => /^(nft|allowed|denied)/.test(line)).join("; "),
  );
}

async function isolationTest(report: Report) {
  const fromEdge = async (host: string) => {
    const name = `ark-edge-pg-iso-${suffix}-${randomBytes(3).toString("hex")}`;
    runtime.containers.push(name);
    return docker(
      "run",
      "--rm",
      "--name",
      name,
      "--network",
      `container:${stack.edgeTs}`,
      bunImage,
      "bun",
      "-e",
      connectProbe(host),
    );
  };
  const byIp = await fromEdge(appPostgresIp);
  const byName = await fromEdge("app-postgres");
  expect(
    report,
    byIp !== "connected" && byName !== "connected",
    "app-postgres is unreachable from the edge-ts namespace (by address and by name)",
    `${appPostgresIp}: ${byIp}; app-postgres: ${byName}`,
  );
  const bouncer = await fromEdge("pgbouncer-public");
  expect(
    report,
    bouncer === "connected",
    "PgBouncer is reachable from the edge-ts namespace over pgbouncer-ingress",
    bouncer,
  );
}

async function run(name: string, test: (report: Report) => Promise<unknown>) {
  const only = process.env.ARK_EDGE_PG5432_ONLY;
  if (only && !name.includes(only)) {
    console.log(`${name}: skipped (ARK_EDGE_PG5432_ONLY=${only})`);
    return;
  }
  const report: Report = { name, lines: [] };
  const started = Date.now();
  await test(report);
  console.log(`${name} (${((Date.now() - started) / 1000).toFixed(1)} s)\n${report.lines.join("\n")}`);
}

let failed = false;
try {
  console.log("edge-l4 PostgreSQL router on 5432 (FD-26):");
  await run("static Compose topology", staticComposeTest);
  await prepareFiles();
  await startContainers();
  sourceIp.A = `${clientPrefix}.10`;
  sourceIp.B = `${clientPrefix}.11`;
  sourceIp.C = `${clientPrefix}.12`;
  const { pg17: route17, pg16: route16 } = routes();
  await apply({ postgresRoutes: [route17, route16], pooler: poolerFor([`${sourceIp.A}/32`]) });
  await run(
    "V-13 matrix: classic and direct to PgBouncer, routes by SNI, rejections, idle close",
    matrixTest,
  );
  await run("pooler-wide policy in be_pgbouncer", poolerPolicyTest);
  await run("no public database", noPublicDatabaseTest);
  await run("compatibility port: relay and nftables", compatPortTest);
  await run("isolation of app-postgres from the edge namespace", isolationTest);
  console.log("\nAll FD-26 PostgreSQL router tests passed.");
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
  for (const name of extraVolumes)
    await Bun.spawn(["docker", "volume", "rm", name], { stdout: "ignore", stderr: "ignore" }).exited;
}
process.exit(failed ? 1 : 0);
