// `mise run test:e2e-gate` (FD-11): the login gate end to end in a real browser (docs/design/front-door.md
// §3.9.2). The real Ark API runs on this host against a disposable database; the shipped edge
// (edge-ts, Caddy behind its launch guard, HAProxy on 443) runs in a disposable Compose project with a
// TCP relay as `api:3000`, the edge watchdog, and scripts/edge-test/upstream.ts as the protected
// tailnet service. Chromium reaches the edge's 443 through a local CONNECT proxy, so the public
// hostnames, SNI and `__Host-` cookies are exactly what a browser sees in production.
//
// e2e/gate.spec.ts then checks: an unauthenticated GET is redirected to the login origin; after
// password and TOTP the browser lands on the original path with `__Host-ark_gate` (Secure, HttpOnly,
// SameSite=Lax, no Domain); the upstream sees `X-Ark-User` and never the gate cookie.
//
// Needs Docker, a loopback PostgreSQL in DATABASE_URL (as `mise run test:e2e`) and Playwright's
// Chromium (`bunx playwright install chromium`).
import { spawn } from "node:child_process";
import { createServer, connect, type Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { createId, generateInstallSecrets, planEdge, type EdgeHttpRoute } from "@ark-stack/shared";
import postgres from "postgres";

import { bunImage, cleanupGateEdge, startGateEdge, waitFor, type GateEdge } from "./edge-test/gate-edge.ts";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";

const root = resolve(import.meta.dir, "..");
const sourceUrl = process.env.DATABASE_URL;
if (!sourceUrl) throw new Error("DATABASE_URL is required for the disposable gate browser harness.");
if (!["127.0.0.1", "localhost", "::1"].includes(new URL(sourceUrl).hostname))
  throw new Error("The gate browser harness refuses a non-loopback PostgreSQL endpoint.");

const suffix = randomBytes(6).toString("hex");
const databaseName = `ark_e2e_gate_${suffix}`;
const databaseUrl = new URL(sourceUrl);
databaseUrl.pathname = `/${databaseName}`;
const zone = "gate-e2e.example.com";
const adminHost = `admin.${zone}`;
const loginHost = `login.${zone}`;
const appHost = `app.${zone}`;
const routeId = `rt_${suffix}`;
const password = "Gate-Browser-Acceptance-Password-123!";
const email = `alice-${suffix}@example.test`;
const gateToken = randomBytes(32).toString("base64url");
const apiPort = 33_000 + Math.floor(Math.random() * 1_000);
const apiBase = `http://127.0.0.1:${apiPort}`;
const name = `ark-e2e-gate-${suffix}`;

const serverEnv: Record<string, string | undefined> = {
  ...process.env,
  ...generateInstallSecrets(),
  DATABASE_URL: databaseUrl.toString(),
  ARK_LISTEN_PORT: String(apiPort),
  BETTER_AUTH_URL: `https://${adminHost}`,
  BETTER_AUTH_TRUSTED_ORIGINS: `https://${adminHost}`,
  ARK_EDGE_GATE_TOKEN: gateToken,
  ARK_EDGE_PEER_ADDRESSES: "",
  ARK_EMBEDDED_WORKERS: "0",
  ARK_DNS_STUB: "1",
};

function run(args: string[], env = serverEnv) {
  return new Promise<void>((resolveRun, reject) => {
    const child = spawn("bun", args, { cwd: root, env, stdio: "inherit" });
    child.once("exit", (code) =>
      code === 0 ? resolveRun() : reject(new Error(`bun ${args.join(" ")} exited ${code}`)),
    );
  });
}

// ---- Talking to the API as the login origin's edge site does ----------------------------------------------

const jar = new Map<string, string>();
async function login(path: string, body?: unknown) {
  const headers = new Headers({
    host: loginHost,
    "x-ark-edge-token": gateToken,
    "x-forwarded-for": "198.51.100.77",
    cookie: [...jar].map(([key, value]) => `${key}=${value}`).join("; "),
  });
  if (body !== undefined) {
    headers.set("content-type", "application/json");
    headers.set("origin", `https://${loginHost}`);
  }
  const response = await fetch(`${apiBase}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual",
  });
  for (const header of response.headers.getSetCookie()) {
    const pair = header.split(";")[0]!;
    const at = pair.indexOf("=");
    if (/max-age=0/i.test(header) || pair.slice(at + 1) === "") jar.delete(pair.slice(0, at));
    else jar.set(pair.slice(0, at), pair.slice(at + 1));
  }
  return response;
}

// ---- A CONNECT proxy that sends the test hostnames' 443 to the edge -------------------------------------

function connectProxy(httpsPort: number, allowed: Set<string>) {
  const server = createServer((client: Socket) => {
    client.on("error", () => undefined);
    client.once("data", (chunk: Buffer) => {
      const head = chunk.toString("latin1");
      const match = /^CONNECT ([^\s:]+):(\d+) HTTP\/1\.[01]\r\n/.exec(head);
      if (!match || !allowed.has(match[1]!.toLowerCase()) || match[2] !== "443") {
        client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
        return;
      }
      const upstream = connect(httpsPort, "127.0.0.1", () => {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const rest = chunk.subarray(chunk.indexOf("\r\n\r\n") + 4);
        if (rest.length) upstream.write(rest);
        client.pipe(upstream);
        upstream.pipe(client);
      });
      upstream.on("error", () => client.destroy());
      client.on("close", () => upstream.destroy());
    });
  });
  return new Promise<{ port: number; close: () => void }>((resolveListen) =>
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolveListen({
        port: typeof address === "object" && address ? address.port : 0,
        close: () => server.close(),
      });
    }),
  );
}

// ---- Run ---------------------------------------------------------------------------------------------

const directory = await mkdtemp(join(tmpdir(), `${name}-`));
const runtime = new EdgeTestRuntime(directory, name, bunImage);
const removeSignalHandlers = runtime.installSignalHandlers();
const admin = postgres(sourceUrl, { max: 1 });
let api: ReturnType<typeof spawn> | undefined;
let edge: GateEdge | undefined;
let proxy: { port: number; close: () => void } | undefined;
let failed = false;

try {
  await admin.unsafe(`CREATE DATABASE "${databaseName}"`);
  await run(["server/src/migrate.ts"]);
  const db = postgres(databaseUrl.toString(), { max: 1 });
  try {
    await db`
      UPDATE platform_settings
      SET gate_login_mode = 'public', gate_login_hostname = ${loginHost}, public_ipv4 = '203.0.113.10'
      WHERE id = 'default'
    `;
  } finally {
    await db.end();
  }

  // The protected service and the edge first: the route pins the simulated peer's address.
  edge = await startGateEdge({
    runtime,
    directory,
    name,
    gateToken,
    hostnames: [loginHost, appHost],
    policy: (peerIp) => [
      { id: routeId, kind: "http", hostname: appHost, stableId: "nHOMEE2E", ip: peerIp, port: 3000 },
    ],
    api: {
      entry: join(import.meta.dir, "edge-test", "tcp-relay.ts"),
      env: { RELAY_TARGET: `host.docker.internal:${apiPort}` },
      hostGateway: true,
    },
  });

  api = spawn("bun", ["server/src/index.ts"], { cwd: root, env: serverEnv, stdio: "inherit" });
  await waitFor(
    "the Ark API",
    async () => ((await fetch(`${apiBase}/api/health`)).ok ? true : undefined),
    30_000,
  );

  // A gate user with TOTP and access to the route (gate-user management itself is FD-12).
  Object.assign(process.env, serverEnv);
  const { auth } = await import("../server/src/auth.ts");
  const { sql } = await import("../server/src/db.ts");
  const ctx = await auth.$context;
  const user = await ctx.internalAdapter.createUser(
    { name: "Alice", email, emailVerified: true },
    { method: "email-password" },
  );
  await ctx.internalAdapter.linkAccount({
    userId: user.id,
    providerId: "credential",
    accountId: user.id,
    password: await ctx.password.hash(password),
  });
  if ((await login("/api/auth/sign-in/email", { email, password })).status !== 200)
    throw new Error("Seeding: sign-in on the login origin failed.");
  const enabled = await login("/api/auth/two-factor/enable", { password });
  if (enabled.status !== 200) throw new Error(`Seeding: TOTP enrollment failed (${enabled.status}).`);
  const totpSecret = new URL(((await enabled.json()) as { totpURI: string }).totpURI).searchParams.get(
    "secret",
  )!;
  const { totpCode } = await import("../e2e/totp.ts");
  if ((await login("/api/auth/two-factor/verify-totp", { code: totpCode(totpSecret) })).status !== 200)
    throw new Error("Seeding: TOTP verification failed.");
  await login("/api/auth/sign-out", {});
  await sql`UPDATE "user" SET mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${user.id}`;

  // The SSO route, ready and enabled, with the user on its access list.
  const endpointId = createId("end");
  await sql`INSERT INTO endpoints (id, kind, hostname, exposure) VALUES (${endpointId}, 'route', ${appHost}, 'public')`;
  await sql`
    INSERT INTO front_routes (id, kind, endpoint_id, listen_port, target_input, target_node_stable_id,
      target_ip, target_port, access_mode, status, enabled)
    VALUES (${routeId}, 'http', ${endpointId}, 443, 'home.tail1234.ts.net', 'nHOMEE2E', ${edge.peerIp}, 3000,
      'sso', 'ready', true)
  `;
  await sql`INSERT INTO front_route_access (route_id, user_id) VALUES (${routeId}, ${user.id})`;
  await sql.end();

  const route: EdgeHttpRoute = {
    id: routeId,
    hostname: appHost,
    stableId: "nHOMEE2E",
    ip: edge.peerIp,
    port: 3000,
    access: "sso",
  };
  const at = new Date();
  const hosts = [
    { hostname: loginHost, kind: "gate" },
    { hostname: appHost, kind: "route" },
  ];
  const applied = await edge.edgeApply(
    planEdge({
      adminMode: "tailnet",
      gateHostname: loginHost,
      endpoints: hosts.map((host) => ({ id: `end_${host.hostname}`, exposure: "public", ...host })),
      certificates: hosts.map((host) => ({
        endpointId: `end_${host.hostname}`,
        status: "issued",
        lastDeployedAt: at,
      })),
      httpRoutes: [route],
    }),
  );
  if (!applied.applied || applied.httpRoutes.join() !== routeId)
    throw new Error(`edge.apply did not load the SSO route: ${JSON.stringify(applied)}`);

  proxy = await connectProxy(edge.httpsPort, new Set([loginHost, appHost]));
  await run(["x", "playwright", "test", "e2e/gate.spec.ts"], {
    ...process.env,
    ARK_E2E_GATE_PROXY: `http://127.0.0.1:${proxy.port}`,
    ARK_E2E_GATE_APP_URL: `https://${appHost}`,
    ARK_E2E_GATE_LOGIN_HOST: loginHost,
    ARK_E2E_GATE_EMAIL: email,
    ARK_E2E_GATE_PASSWORD: password,
    ARK_E2E_GATE_TOTP_SECRET: totpSecret,
    ARK_E2E_GATE_USER_ID: user.id,
  });
  console.log("FD-11 gate browser test passed.");
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  await runtime.dumpLogs();
} finally {
  proxy?.close();
  api?.kill("SIGTERM");
  removeSignalHandlers();
  await cleanupGateEdge(runtime, name, edge);
  await admin`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ${databaseName} AND pid <> pg_backend_pid()`;
  await admin.unsafe(`DROP DATABASE IF EXISTS "${databaseName}"`);
  await admin.end();
}
process.exit(failed ? 1 : 0);
