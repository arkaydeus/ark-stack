// HTTP route rate limits and HTTP mTLS (docs/design/front-door.md FD-23) through the real app, Better
// Auth sessions, step-up grants and the edge render input:
//
// - `rateLimit` and `mtls` are validated on create and update, refused on L4 kinds, and stored in
//   `front_routes.rate_limit` and `client_ca_id` (no migration: both were reserved by FD-04);
// - tightening (adding or lowering a limit, switching certificates on) needs no step-up; removing or
//   raising a limit and switching certificates off need exposure.public;
// - switching certificates on creates the route's `http-client` CA with a CRL and journals a gate
//   revocation (connections admitted without a certificate are drained); switching off retires the CA;
// - issuing a client certificate re-renders the edge; revoking one updates the CRL and journals a gate
//   revocation, and the render input then admits only the remaining certificates.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "node:crypto";

import { createId, parseEnvFile, planEdge, renderCaddyfile, type Role } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { sql } = await import("./db.ts");
const { runOperation, enqueue } = await import("./coordinator.ts");
const { edgePolicy } = await import("./modules/edge-observe.ts");
const { edgeHttpRoutes } = await import("./modules/edge-routes.ts");
const { routeCrlCovers } = await import("./modules/route-crl.ts");
const { MockLocalApi } = await import("./mock-localapi.ts");

const origin = new URL(process.env.BETTER_AUTH_URL ?? "http://localhost:3000").origin;
const password = "Http-Controls-Test-Password-123!";
const suffix = createId("t").slice(2, 10);
const tailnet = ".tail1234.ts.net";
const zone = `fd23-${suffix}.com`;
const domainId = createId("dom");
const homeIp = "100.88.2.30";
const self = { id: `nEDGE${suffix}`, name: "ark-edge", ips: ["100.64.0.1"], tags: ["tag:ark-edge"] };
const home = { id: `nHOME${suffix}`, name: "home", ips: [homeIp] };
const startedAt = new Date();
const socket = join(tmpdir(), `ark-fd23-${suffix}.sock`);
const mock = new MockLocalApi({
  backendState: "Running",
  suffix: tailnet,
  self,
  peers: [home],
  reachable: new Set([`${homeIp}:3000`]),
});
const savedEnv: Record<string, string | undefined> = {};
let savedSettings: Record<string, unknown> | undefined;
let owner!: { userId: string; cookie: string };

type Json = Record<string, any>;

async function signUp(role: Role) {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `FD23 ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
    { method: "email-password" },
  );
  await ctx.internalAdapter.linkAccount({
    userId: created.id,
    providerId: "credential",
    accountId: created.id,
    password: await ctx.password.hash(password),
  });
  await sql`INSERT INTO platform_access (user_id, role) VALUES (${created.id}, ${role})`;
  await sql`UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${created.id}`;
  const session = await ctx.internalAdapter.createSession(created.id, false, { origin: "admin" });
  const signed = `${session.token}.${await makeSignature(session.token, ctx.secret)}`;
  return { userId: created.id, cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(signed)}` };
}

async function call(method: string, path: string, body?: unknown) {
  const response = await app.request(`${origin}${path}`, {
    method,
    headers: {
      cookie: owner.cookie,
      origin,
      ...(method === "GET" ? {} : { "content-type": "application/json" }),
    },
    body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
  });
  const text = await response.text();
  return { status: response.status, body: (text ? JSON.parse(text) : {}) as Json };
}

async function stepUp(action: string, request: Record<string, unknown>) {
  const response = await call("POST", "/api/step-up", { password, action, request });
  expect(response.status).toBe(200);
}

async function openGrants() {
  const [row] =
    await sql`SELECT count(*)::int AS n FROM step_up_grants WHERE user_id = ${owner.userId} AND consumed_at IS NULL`;
  return Number(row?.n ?? 0);
}

const httpRequest = (name: string, extra: Record<string, unknown> = {}) => ({
  kind: "http",
  hostname: `${name}.${zone}`,
  target: `home${tailnet}`,
  targetPort: 3000,
  accessMode: "public",
  ...extra,
});

async function create(request: Record<string, unknown>) {
  await stepUp("exposure.public", request);
  const response = await call("POST", "/api/front/routes", request);
  expect([response.status, response.body.error]).toEqual([201, undefined]);
  return response.body.route as Json;
}

async function refusedCreate(request: Record<string, unknown>, pattern: RegExp) {
  await stepUp("exposure.public", request);
  const before = await openGrants();
  const response = await call("POST", "/api/front/routes", request);
  expect([response.status, String(response.body.error)]).toEqual([422, expect.stringMatching(pattern)]);
  expect(await openGrants()).toBe(before);
}

async function routeRow(id: string) {
  const [row] = await sql`SELECT * FROM front_routes WHERE id = ${id}`;
  return row as Json;
}

async function caRow(id: string) {
  const [row] = await sql`SELECT * FROM private_cas WHERE id = ${id}`;
  return row as Json;
}

async function pendingRevocations(routeId: string) {
  return (
    await sql`SELECT reason FROM gate_revocations WHERE route_id = ${routeId} AND applied_at IS NULL`
  ).map((row) => String(row.reason));
}

/** Settles every queued edge.apply (enqueue reuses a queued one), so a new request is visible. */
async function settleApplies() {
  await sql`UPDATE operations SET status = 'succeeded' WHERE kind = 'edge.apply' AND status = 'queued'`;
}

async function queuedApplies() {
  const [row] =
    await sql`SELECT count(*)::int AS n FROM operations WHERE kind = 'edge.apply' AND status = 'queued'`;
  return Number(row?.n ?? 0);
}

/** Enabled and ready, so the lease policy allows it and the render input includes it. */
async function serve(id: string) {
  await sql`UPDATE front_routes SET status = 'ready', enabled = true WHERE id = ${id}`;
}

async function renderInput(id: string) {
  const routes = await edgeHttpRoutes((await edgePolicy()).routes);
  return routes.find((route) => route.id === id);
}

beforeAll(async () => {
  for (const key of ["ARK_EDGE_TS_SOCKET", "ARK_EDGE_RELOAD_URL"]) savedEnv[key] = process.env[key];
  delete process.env.ARK_EDGE_RELOAD_URL;
  process.env.ARK_EDGE_TS_SOCKET = socket;
  [savedSettings] = await sql`SELECT public_ipv4 FROM platform_settings WHERE id = 'default'`;
  await sql`
    INSERT INTO platform_settings (id, public_ipv4) VALUES ('default', '203.0.113.10')
    ON CONFLICT (id) DO UPDATE SET public_ipv4 = '203.0.113.10'
  `;
  await sql`INSERT INTO domain_claims (id, name, ownership_token, status) VALUES (${domainId}, ${zone}, 'ark-own-fd23', 'verified')`;
  owner = await signUp("owner");
  await mock.listen(socket);
  await sql`DELETE FROM tailnet_nodes WHERE source = 'edge'`;
  await sql`DELETE FROM tailnet_snapshots WHERE source = 'edge'`;
  await runOperation(
    "edge.observe",
    (await enqueue({ kind: "edge.observe", targetIds: ["tailnet:edge"], payload: { fixture: suffix } }))!,
  );
});

afterAll(async () => {
  mock.stop();
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  const routeRows = await sql`
    SELECT r.id FROM front_routes r JOIN endpoints e ON e.id = r.endpoint_id WHERE e.domain_id = ${domainId}
  `;
  const routeIds = routeRows.map((row) => String(row.id));
  const caIds = (
    await sql`SELECT id FROM private_cas WHERE name LIKE 'Route rt_%' AND created_at >= ${startedAt.toISOString()}::timestamptz`
  ).map((row) => String(row.id));
  if (routeIds.length) {
    await sql`DELETE FROM gate_revocations WHERE route_id IN ${sql(routeIds)}`;
    await sql`DELETE FROM front_routes WHERE id IN ${sql(routeIds)}`;
  }
  if (caIds.length) {
    await sql`DELETE FROM client_certificates WHERE ca_id IN ${sql(caIds)}`;
    const keys = await sql`SELECT key_secret_id FROM private_cas WHERE id IN ${sql(caIds)}`;
    await sql`DELETE FROM private_cas WHERE id IN ${sql(caIds)}`;
    await sql`DELETE FROM secrets WHERE id IN ${sql(keys.map((row) => String(row.key_secret_id)))}`;
  }
  await sql`DELETE FROM secrets WHERE resource_type = 'platform' AND kind = 'pki.client_key' AND created_at >= ${startedAt.toISOString()}::timestamptz`;
  await sql`DELETE FROM audit_events WHERE created_at >= ${startedAt.toISOString()}::timestamptz AND resource_type = 'front_route'`;
  await sql`DELETE FROM dns_records WHERE domain_id = ${domainId}`;
  await sql`DELETE FROM endpoints WHERE domain_id = ${domainId}`;
  await sql`DELETE FROM domain_claims WHERE id = ${domainId}`;
  await sql`DELETE FROM operation_steps WHERE operation_id IN (SELECT id FROM operations WHERE created_at >= ${startedAt.toISOString()}::timestamptz)`;
  await sql`DELETE FROM operations WHERE created_at >= ${startedAt.toISOString()}::timestamptz`;
  await sql`DELETE FROM tailnet_nodes WHERE source = 'edge'`;
  await sql`DELETE FROM tailnet_snapshots WHERE source = 'edge'`;
  await sql`DELETE FROM audit_events WHERE actor_id = ${owner.userId}`;
  await sql`DELETE FROM step_up_grants WHERE user_id = ${owner.userId}`;
  await sql`DELETE FROM "user" WHERE id = ${owner.userId}`;
  if (savedSettings)
    await sql`UPDATE platform_settings SET public_ipv4 = ${savedSettings.public_ipv4 as string | null} WHERE id = 'default'`;
});

describe("rate limits (front_routes.rate_limit)", () => {
  test("validated on create, refused on L4 kinds, stored and listed", async () => {
    await refusedCreate(httpRequest("rl-zero", { rateLimit: { requests: 0, window: "1m" } }), /requests/);
    await refusedCreate(httpRequest("rl-long", { rateLimit: { requests: 10, window: "2h" } }), /window/);
    await refusedCreate(httpRequest("rl-ms", { rateLimit: { requests: 10, window: "500ms" } }), /window/);
    await refusedCreate(
      {
        kind: "tls",
        hostname: `tls.${zone}`,
        target: `home${tailnet}`,
        targetPort: 3000,
        tlsMode: "passthrough",
        sourceCidrs: ["203.0.113.0/24"],
        rateLimit: { requests: 10, window: "1m" },
      },
      /rateLimit cannot be set/,
    );
    const route = await create(httpRequest("rl", { rateLimit: { requests: 20, window: "10s" } }));
    expect(route).toMatchObject({ rateLimit: { requests: 20, window: "10s" }, mtls: false });
    expect((await routeRow(route.id)).rate_limit).toEqual({ requests: 20, window: "10s" });
  });

  test("tightening needs no step-up; removing or raising needs exposure.public", async () => {
    const route = await create(httpRequest("rl-update", { rateLimit: { requests: 20, window: "10s" } }));
    const tighter = await call("PATCH", `/api/front/routes/${route.id}`, {
      rateLimit: { requests: 5, window: "10s" },
    });
    expect([tighter.status, tighter.body.loosening]).toEqual([200, []]);
    // Raising, then removing; adding a limit back afterwards would be a tightening again.
    for (const body of [{ rateLimit: { requests: 50, window: "10s" } }, { rateLimit: null }]) {
      const refused = await call("PATCH", `/api/front/routes/${route.id}`, body);
      expect(refused.status).toBe(403);
      await stepUp("exposure.public", { routeId: route.id, ...body });
      const allowed = await call("PATCH", `/api/front/routes/${route.id}`, body);
      expect([allowed.status, allowed.body.loosening]).toEqual([200, ["rateLimit"]]);
    }
    expect((await routeRow(route.id)).rate_limit).toBeNull();
    const again = await call("PATCH", `/api/front/routes/${route.id}`, {
      rateLimit: { requests: 50, window: "10s" },
    });
    expect([again.status, again.body.loosening]).toEqual([200, []]);
  });

  test("an enabled route renders its limit; an invalid stored limit blocks enabling", async () => {
    const route = await create(httpRequest("rl-render", { rateLimit: { requests: 3, window: "1m" } }));
    await serve(route.id);
    expect((await renderInput(route.id))?.rateLimit).toEqual({ requests: 3, window: "1m" });
    await sql`UPDATE front_routes SET enabled = false, rate_limit = '{"requests": -1}'::jsonb WHERE id = ${route.id}`;
    await stepUp("exposure.public", { routeId: route.id });
    const enabled = await call("POST", `/api/front/routes/${route.id}/enable`, {});
    expect([enabled.status, enabled.body.error]).toEqual([409, expect.stringContaining("rate limit")]);
  });
});

describe("HTTP mTLS (client_ca_id)", () => {
  test("mtls on create gives the route its own http-client CA with a CRL; refused on L4 kinds", async () => {
    await refusedCreate(
      {
        kind: "tcp",
        hostname: `tcp.${zone}`,
        target: `home${tailnet}`,
        targetPort: 3000,
        listenPort: 20021,
        allowPlaintext: true,
        sourceCidrs: ["198.51.100.7/32"],
        mtls: true,
      },
      /mtls cannot be set/,
    );
    const route = await create(httpRequest("mtls", { mtls: true, accessMode: "sso" }));
    expect(route).toMatchObject({ mtls: true, accessMode: "sso" });
    const row = await routeRow(route.id);
    const ca = await caRow(String(row.client_ca_id));
    expect(ca).toMatchObject({ purpose: "http-client", status: "active" });
    expect(routeCrlCovers(ca.crl_pem, [])).toBe(true);
  });

  test("issuing admits the certificate at the next render; revoking drains and removes it", async () => {
    const route = await create(httpRequest("mtls-certs", { mtls: true }));
    await serve(route.id);
    const caId = String((await routeRow(route.id)).client_ca_id);
    expect((await renderInput(route.id))?.clientAuth?.certificates).toEqual([]);
    const issue = async (name: string) => {
      await stepUp("credential.rotate", { routeId: route.id, name });
      await settleApplies();
      const issued = await call("POST", `/api/front/routes/${route.id}/client-certificates`, { name });
      expect(issued.status).toBe(201);
      // The edge admits exact certificates, so issuing re-renders it.
      expect(await queuedApplies()).toBe(1);
      return issued.body as Json;
    };
    const kept = await issue("laptop");
    const lost = await issue("phone");
    const der = (pem: string) => new X509Certificate(pem).raw.toString("base64");
    const input = await renderInput(route.id);
    expect(input?.clientAuth?.caCertificate).toBe(der((await caRow(caId)).cert_pem));
    expect(input?.clientAuth?.certificates).toEqual([der(kept.certPem), der(lost.certPem)].toSorted());

    const revoked = await call(
      "POST",
      `/api/front/routes/${route.id}/client-certificates/${lost.id}/revoke`,
      {},
    );
    expect([revoked.status, revoked.body.status]).toEqual([200, "revoked"]);
    // The gate revocation journal drains the route's sessions around the forced reload (§3.9.3).
    expect(await pendingRevocations(route.id)).toEqual(["client_certificate_revoked"]);
    expect(routeCrlCovers((await caRow(caId)).crl_pem, [lost.serial])).toBe(true);
    expect((await renderInput(route.id))?.clientAuth?.certificates).toEqual([der(kept.certPem)]);

    // The rendered site requires the CA and admits only the kept certificate.
    const policy = (await edgePolicy()).routes.find((item) => item.id === route.id);
    const plan = planEdge({
      adminMode: "tailnet",
      endpoints: [{ id: "end_x", kind: "route", hostname: policy!.hostname, exposure: "public" }],
      certificates: [{ endpointId: "end_x", status: "issued", lastDeployedAt: new Date() }],
      httpRoutes: [(await renderInput(route.id))!],
    });
    const caddyfile = renderCaddyfile({ ...plan, challengeDir: "/acme", apiUpstream: "api:3000" });
    expect(caddyfile).toContain("mode require_and_verify");
    expect(caddyfile.match(/ pem "/g)).toHaveLength(1);
  });

  test("switching on is a tightening that drains; switching off loosens and retires the CA", async () => {
    const route = await create(httpRequest("mtls-toggle"));
    const on = await call("PATCH", `/api/front/routes/${route.id}`, { mtls: true });
    expect([on.status, on.body.loosening, on.body.route.mtls]).toEqual([200, [], true]);
    expect(await pendingRevocations(route.id)).toEqual(["route_gate_tightened"]);
    const caId = String((await routeRow(route.id)).client_ca_id);
    expect(await caRow(caId)).toMatchObject({ purpose: "http-client", status: "active" });

    const refused = await call("PATCH", `/api/front/routes/${route.id}`, { mtls: false });
    expect(refused.status).toBe(403);
    await stepUp("exposure.public", { routeId: route.id, mtls: false });
    const off = await call("PATCH", `/api/front/routes/${route.id}`, { mtls: false });
    expect([off.status, off.body.loosening, off.body.route.mtls]).toEqual([200, ["mtls"], false]);
    expect((await routeRow(route.id)).client_ca_id).toBeNull();
    expect((await caRow(caId)).status).toBe("retired");
    const certificates = await call("GET", `/api/front/routes/${route.id}/client-certificates`);
    expect(certificates.status).toBe(409);
  });

  test("issuance stops at the number of certificates the edge can render", async () => {
    const route = await create(httpRequest("mtls-full", { mtls: true }));
    const caId = String((await routeRow(route.id)).client_ca_id);
    await sql`
      INSERT INTO client_certificates (id, ca_id, subject_cn, serial, fingerprint_sha256, not_before, not_after, status)
      SELECT 'ccert_fd23_' || n, ${caId}, 'filler', lpad(to_hex(n), 8, '0'), 'f' || n, now(), now() + interval '90 days', 'issued'
      FROM generate_series(1, 500) AS n
    `;
    await stepUp("credential.rotate", { routeId: route.id, name: "one-more" });
    const refused = await call("POST", `/api/front/routes/${route.id}/client-certificates`, {
      name: "one-more",
    });
    expect([refused.status, refused.body.error]).toEqual([
      409,
      expect.stringContaining("500 client certificates"),
    ]);
  });

  test("a route whose CA is no longer active admits nobody", async () => {
    const route = await create(httpRequest("mtls-retired", { mtls: true }));
    await serve(route.id);
    await stepUp("credential.rotate", { routeId: route.id, name: "desk" });
    expect(
      (await call("POST", `/api/front/routes/${route.id}/client-certificates`, { name: "desk" })).status,
    ).toBe(201);
    expect((await renderInput(route.id))?.clientAuth?.certificates).toHaveLength(1);
    await sql`UPDATE private_cas SET status = 'revoked' WHERE id = ${(await routeRow(route.id)).client_ca_id}`;
    expect((await renderInput(route.id))?.clientAuth?.certificates).toEqual([]);
  });
});
