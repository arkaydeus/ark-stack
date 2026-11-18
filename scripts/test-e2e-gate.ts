// `mise run test:e2e-gate` (FD-11): the login gate end to end in a real browser (docs/design/front-door.md
// §3.9.2). The real Ark API runs on this host against a disposable database; the shipped edge
// (edge-ts, Caddy behind its launch guard, HAProxy on 443) runs in a disposable Compose project with a
// TCP relay as `api:3000`, the edge watchdog, and scripts/edge-test/upstream.ts as the protected
// tailnet service. Chromium reaches the edge's 443 through a local CONNECT proxy, so the public
// hostnames, SNI and `__Host-` cookies are exactly what a browser sees in production.
//
// e2e/gate.spec.ts then checks: an unauthenticated GET is redirected to the login origin; after
// password and TOTP the browser lands on the original path with `__Host-ark_gate` (Secure, HttpOnly,
// SameSite=Lax, no Domain); the upstream sees `X-Ark-User` and never the gate cookie. FD-12: a gate
// user created through the owner API must enroll TOTP in the browser before the route opens, and
// deleting them closes their open WebSocket through the revocation journal.
//
// Needs Docker, a loopback PostgreSQL in DATABASE_URL (as `mise run test:e2e`) and Playwright's
// Chromium (`bunx playwright install chromium`).
import { spawn } from "node:child_process";
import { createServer, connect, type Socket } from "node:net";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  createId,
  generateInstallSecrets,
  planEdge,
  type EdgeHttpRoute,
  type EdgeLeaseDocument,
} from "@ark-stack/shared";
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
async function login(path: string, body?: unknown, host = loginHost, cookies = jar) {
  const headers = new Headers({
    host,
    "x-ark-edge-token": gateToken,
    "x-forwarded-for": "198.51.100.77",
    cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join("; "),
  });
  if (body !== undefined) {
    headers.set("content-type", "application/json");
    headers.set("origin", `https://${host}`);
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
    if (/max-age=0/i.test(header) || pair.slice(at + 1) === "") cookies.delete(pair.slice(0, at));
    else cookies.set(pair.slice(0, at), pair.slice(at + 1));
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
let control: ReturnType<typeof Bun.serve> | undefined;
let adminBridge: ReturnType<typeof Bun.serve> | undefined;
let leaseReady = false;

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
    lease: async () => {
      if (!leaseReady) return undefined;
      const response = await fetch(`${apiBase}/api/internal/edge/lease`, {
        headers: { host: "api:3000", authorization: `Bearer ${serverEnv.ARK_EDGE_WATCHDOG_TOKEN}` },
      });
      if (!response.ok) throw new Error(`Real lease returned ${response.status}`);
      return (await response.json()) as EdgeLeaseDocument;
    },
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

  // A user with TOTP and access to the route, seeded directly (the FD-12 case creates its gate user
  // through the owner API instead).
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

  const [enrollment] = await sql`SELECT * FROM two_factor WHERE user_id = ${user.id}`;

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
  await sql`UPDATE front_routes SET http_options = '{"streamCloseDelay":"2s"}'::jsonb WHERE id = ${routeId}`;
  for (const [id, host, kind] of [
    [endpointId, appHost, "route"],
    [createId("end"), loginHost, "gate"],
  ]) {
    await sql`INSERT INTO endpoints (id, kind, hostname, exposure) VALUES (${id!}, ${kind!}, ${host!}, 'public') ON CONFLICT DO NOTHING`;
    await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at) VALUES (${createId("crt")}, ${id!}, ${JSON.stringify([host])}::jsonb, 'issued', now())`;
  }
  const { commitTailnetGeneration } = await import("../server/src/modules/tailnet-snapshot.ts");
  const node = (stableId: string, ip: string, self: boolean) => ({
    source: "edge" as const,
    generation: name,
    stableId,
    dnsName: self ? "edge.tail1234.ts.net." : "home.tail1234.ts.net.",
    hostName: self ? "edge" : "home",
    ipv4: ip,
    ipv6: null,
    tags: self ? ["tag:ark-edge"] : [],
    isSelf: self,
    online: true,
  });
  await commitTailnetGeneration("edge", {
    generation: name,
    self: node("nEDGE", "100.64.0.1", true),
    peers: [node("nHOMEE2E", edge.peerIp, false)],
    completedAt: new Date(),
    validUntil: new Date(Date.now() + 360_000),
  });
  leaseReady = true;
  const { edgePolicy } = await import("../server/src/modules/edge-observe.ts");
  if (!(await edgePolicy()).routes.some((route) => route.id === routeId))
    throw new Error("Seeded route is missing from the real lease");

  const route: EdgeHttpRoute = {
    id: routeId,
    hostname: appHost,
    stableId: "nHOMEE2E",
    ip: edge.peerIp,
    port: 3000,
    access: "sso",
    options: { streamCloseDelay: "2s" },
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

  // Worker calls go through the actual Caddy admin on its isolated network. This bridge only
  // transports HTTP; claimQueued/runOperation/writeEdge remain the production implementations.
  let rejectLoad = false;
  adminBridge = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      if (rejectLoad && path === "/load") return new Response("fixture rejected load", { status: 500 });
      const body = Buffer.from(await request.arrayBuffer()).toString("base64");
      const script = `const r=await fetch(${JSON.stringify(`http://edge-admin:2019${path}`)}, {method:${JSON.stringify(request.method)},headers:${JSON.stringify(Object.fromEntries([...request.headers].filter(([key]) => !["host", "content-length"].includes(key))))},${["GET", "HEAD"].includes(request.method) ? "" : `body:Buffer.from(${JSON.stringify(body)},"base64"),`}}); console.log(JSON.stringify({status:r.status,headers:Object.fromEntries(r.headers),body:await r.text()}))`;
      const output = await runtime.docker("exec", `${name}-watchdog`, "bun", "--eval", script);
      const result = JSON.parse(output) as { status: number; headers: Record<string, string>; body: string };
      return new Response(result.body || null, { status: result.status, headers: result.headers });
    },
  });
  process.env.ARK_EDGE_RELOAD_URL = `http://127.0.0.1:${adminBridge.port}`;
  process.env.ARK_EDGE_DIR = join(directory, "edge");
  const { claimQueued, runOperation, enqueue } = await import("../server/src/coordinator.ts");
  const worker = async () => {
    const claimed = await claimQueued({ kindPrefix: "edge.drain", limit: 1 });
    for (const op of claimed.rows) {
      try {
        await runOperation("edge.drain", op);
        await sql`UPDATE operations SET status = 'succeeded', updated_at = now() WHERE id = ${op.id}`;
      } catch (error) {
        await sql`UPDATE operations SET status = 'failed', updated_at = now(), error = ${String(error)} WHERE id = ${op.id}`;
        throw error;
      }
    }
    return claimed.rows.length;
  };
  // FD-12: an owner with assured MFA calls the real admin API (`/api/step-up`, `/api/gate/users`,
  // `PUT /api/front/routes/:id/access`) exactly as the admin SPA does.
  const ownerEmail = `owner-${suffix}@example.test`;
  const owner = await ctx.internalAdapter.createUser(
    { name: "Owner", email: ownerEmail, emailVerified: true },
    { method: "email-password" },
  );
  await ctx.internalAdapter.linkAccount({
    userId: owner.id,
    providerId: "credential",
    accountId: owner.id,
    password: await ctx.password.hash(password),
  });
  await sql`INSERT INTO platform_access (user_id, role) VALUES (${owner.id}, 'owner')`;
  await sql`UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${owner.id}`;
  const ownerSession = await ctx.internalAdapter.createSession(owner.id, false, { origin: "admin" });
  const { authCookieName: ownerCookieName } = await import("../server/src/auth.ts");
  const ownerCookie = `${ownerCookieName("session_token")}=${encodeURIComponent(
    `${ownerSession.token}.${createHmac("sha256", ctx.secret).update(ownerSession.token).digest("base64")}`,
  )}`;
  const adminApi = async (path: string, method: string, body: unknown) => {
    const response = await fetch(`${apiBase}${path}`, {
      method,
      headers: {
        host: adminHost,
        origin: `https://${adminHost}`,
        "content-type": "application/json",
        cookie: ownerCookie,
      },
      body: JSON.stringify(body),
    });
    const result = (await response.json()) as Record<string, unknown>;
    if (!response.ok) throw new Error(`${method} ${path}: ${response.status} ${JSON.stringify(result)}`);
    return result;
  };
  const stepUp = (action: string, request: Record<string, unknown>) =>
    adminApi("/api/step-up", "POST", { password, action, request });
  let gateUser: { id: string; email: string } | null = null;

  control = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      try {
        const action = new URL(request.url).pathname.slice(1);
        if (action === "gate-user-create") {
          // Created, revealed once and granted the route through the real owner API (FD-12).
          const body = { email: `gate-${createId("x").slice(2, 10)}@example.test` };
          await stepUp("role.grant", { ...body, gateUsers: "create" });
          const created = (await adminApi("/api/gate/users", "POST", body)).user as {
            id: string;
            email: string;
          };
          await stepUp("secret.reveal", { gateUserTemporaryPassword: created.id });
          const { password: temporary } = await adminApi(
            `/api/gate/users/${created.id}/temporary-password`,
            "POST",
            {},
          );
          const userIds = [user.id, created.id];
          await stepUp("role.grant", { routeId, userIds });
          await adminApi(`/api/front/routes/${routeId}/access`, "PUT", { userIds });
          gateUser = created;
          return Response.json({ id: created.id, email: created.email, password: temporary });
        } else if (action === "gate-user-delete") {
          if (!gateUser) throw new Error("No gate user was created.");
          await stepUp("role.grant", { gateUsers: "delete", userId: gateUser.id });
          const result = await adminApi(`/api/gate/users/${gateUser.id}`, "DELETE", {});
          gateUser = null;
          return Response.json(result);
        } else if (action === "prepare") {
          rejectLoad = false;
          await sql`UPDATE operations SET status = 'queued', heartbeat_at = NULL WHERE status = 'running' AND payload ->> 'reason' = 'gate_revocation'`;
          await sql`INSERT INTO two_factor (id, user_id, secret, backup_codes, verified)
            VALUES (${enrollment!.id}, ${user.id}, ${enrollment!.secret}, ${enrollment!.backup_codes}, true)
            ON CONFLICT (id) DO NOTHING`;
          await sql`UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${user.id}`;
          await sql`INSERT INTO front_route_access (route_id, user_id) VALUES (${routeId}, ${user.id}) ON CONFLICT DO NOTHING`;
          await sql`UPDATE front_routes SET access_mode = 'sso' WHERE id = ${routeId}`;
          // Finish earlier event's pending drain before opening this event's socket.
          await sql`UPDATE operations SET updated_at = now() - interval '10 minutes' WHERE status = 'failed'`;
          // A previous case can end the moment the watchdog stops Caddy (its socket closes then);
          // the launch guard restarts it within a moment. Drain only once its admin API answers.
          await waitFor(
            "the Caddy admin API after a watchdog stop",
            async () =>
              (await fetch(`http://127.0.0.1:${adminBridge!.port}/config/`)).ok ? true : undefined,
            30_000,
          );
          await worker();
          await edge!.edgeApply(
            planEdge({
              adminMode: "tailnet",
              gateHostname: loginHost,
              endpoints: hosts.map((host) => ({ id: `end_${host.hostname}`, exposure: "public", ...host })),
              certificates: hosts.map((host) => ({
                endpointId: `end_${host.hostname}`,
                status: "issued",
                lastDeployedAt: new Date(),
              })),
              httpRoutes: [route],
            }),
          );
        } else if (action === "browser-session") {
          const session = await ctx.internalAdapter.createSession(user.id, false, { origin: "gate" });
          const { authCookieName } = await import("../server/src/auth.ts");
          const signature = createHmac("sha256", ctx.secret).update(session.token).digest("base64");
          return Response.json({
            cookies: {
              [authCookieName("session_token")]: encodeURIComponent(`${session.token}.${signature}`),
            },
          });
        } else if (action === "access" || action === "expired-access") {
          if (action === "expired-access")
            await sql`UPDATE gate_sessions SET expires_at = now() - interval '1 second' WHERE user_id = ${user.id}`;
          await sql`DELETE FROM front_route_access WHERE route_id = ${routeId} AND user_id = ${user.id}`;
        } else if (action === "session" || action === "expired-session") {
          if (action === "expired-session")
            await sql`UPDATE gate_sessions SET expires_at = now() - interval '1 second' WHERE user_id = ${user.id}`;
          await sql`DELETE FROM session WHERE user_id = ${user.id} AND origin = 'gate'`;
        } else if (action === "mfa-assurance") {
          await sql`UPDATE "user" SET mfa_enrolled_at = now() WHERE id = ${user.id}`;
        } else if (action === "mode") {
          const op = await enqueue({
            kind: "admin.mode_change",
            targetIds: ["platform"],
            payload: { adminMode: "tailnet", nonce: crypto.randomUUID() },
          });
          process.env.ARK_TAILNET_AUTH_ORIGIN = `https://${adminHost}`;
          await runOperation("admin.mode_change", op!);
        } else if (action === "user-delete") {
          await sql`DELETE FROM "user" WHERE id = ${user.id}`;
        } else if (action === "mfa-reset") {
          await sql`INSERT INTO platform_access (user_id, role) VALUES (${user.id}, 'owner') ON CONFLICT DO NOTHING`;
          await run(["scripts/recover-mfa.ts", email, `RESET:${email}`, serverEnv.ARK_MFA_RECOVERY_TOKEN!]);
        } else if (action === "mfa-disable" || action === "logout-everywhere") {
          // Real admin-origin auth endpoint; the gate parent session is a different session.
          await sql`INSERT INTO platform_access (user_id, role) VALUES (${user.id}, 'owner') ON CONFLICT DO NOTHING`;
          const adminCookies = new Map<string, string>();
          const first = await login("/api/auth/sign-in/email", { email, password }, adminHost, adminCookies);
          if (first.status !== 200) throw new Error(`Admin sign-in failed: ${first.status}`);
          const second = await login(
            "/api/auth/two-factor/verify-totp",
            { code: totpCode(totpSecret) },
            adminHost,
            adminCookies,
          );
          if (second.status !== 200) throw new Error(`Admin TOTP failed: ${second.status}`);
          const response = await login(
            action === "mfa-disable" ? "/api/auth/two-factor/disable" : "/api/auth/revoke-sessions",
            action === "mfa-disable" ? { password } : {},
            adminHost,
            adminCookies,
          );
          if (response.status !== 200)
            throw new Error(`MFA disable: ${response.status} ${await response.text()}`);
        } else if (action === "reject") {
          rejectLoad = true;
        } else if (action === "worker") {
          await worker();
        } else if (action === "lost-worker") {
          await claimQueued({ kindPrefix: "edge.drain", limit: 1 });
        } else if (action === "status") {
          const pending = await sql`SELECT route_id FROM gate_revocations WHERE applied_at IS NULL`;
          const sessions =
            await sql`SELECT id FROM gate_sessions WHERE revoked_at IS NULL AND user_id = ${user.id}`;
          return Response.json({ pending: pending.length, sessions: sessions.length });
        } else throw new Error(`Unknown control action ${action}`);
        return Response.json({ ok: true });
      } catch (error) {
        console.error(error);
        return Response.json({ error: String(error) }, { status: 500 });
      }
    },
  });

  proxy = await connectProxy(edge.httpsPort, new Set([loginHost, appHost]));
  await run(
    ["x", "playwright", "test", "e2e/gate.spec.ts", "--output", join(directory, "playwright-results")],
    {
      ...process.env,
      ARK_E2E_GATE_CONTROL: `http://127.0.0.1:${control.port}`,
      ARK_E2E_GATE_ROUTE_ID: routeId,
      ARK_E2E_GATE_PROXY: `http://127.0.0.1:${proxy.port}`,
      ARK_E2E_GATE_APP_URL: `https://${appHost}`,
      ARK_E2E_GATE_LOGIN_HOST: loginHost,
      ARK_E2E_GATE_EMAIL: email,
      ARK_E2E_GATE_PASSWORD: password,
      ARK_E2E_GATE_TOTP_SECRET: totpSecret,
      ARK_E2E_GATE_USER_ID: user.id,
    },
  );
  console.log("FD-11/FD-12 gate browser tests passed.");
} catch (error) {
  failed = true;
  console.error(`\n${(error as Error).stack ?? error}`);
  await runtime.dumpLogs();
} finally {
  control?.stop(true);
  adminBridge?.stop(true);
  proxy?.close();
  api?.kill("SIGTERM");
  removeSignalHandlers();
  await cleanupGateEdge(runtime, name, edge);
  await admin`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ${databaseName} AND pid <> pg_backend_pid()`;
  await admin.unsafe(`DROP DATABASE IF EXISTS "${databaseName}"`);
  await admin.end();
}
process.exit(failed ? 1 : 0);
