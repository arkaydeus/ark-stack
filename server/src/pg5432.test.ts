// The PostgreSQL router on 5432 through the real app, Better Auth sessions, step-up grants and the
// coordinator (docs/design/front-door.md §3.8.3, §3.8.5, FD-26):
//
// - one explicit pooler-wide policy: two public databases with disjoint CIDRs and an unrestricted
//   Vercel client conflict, publication is refused until the owner reviews one common policy (a stale
//   review is refused), the rendered be_pgbouncer allowlist is exactly the saved policy (never a
//   union), and a B-source connection to database A is answered by the pooler-wide policy;
// - `postgres` routes: 5432 only, TLS modes, the passthrough-only compatibility port and its
//   collision with raw TCP routes, the lease policy fingerprint, and the `edge.l4_apply` input.

import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  POOLER_ALLOWLIST_FILE,
  POOLER_POLICY_BOUNDARY,
  createId,
  encryptSecret,
  parseEnvFile,
  renderEdgeL4Generation,
  type Role,
} from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { db, sql } = await import("./db.ts");
const { platformSettings, secrets } = await import("./schema.ts");
const { eq } = await import("drizzle-orm");
const pki = await import("./modules/pki.ts");
const { runOperation, enqueue, edgeL4Input } = await import("./coordinator.ts");
const { edgePolicy } = await import("./modules/edge-observe.ts");
const { edgeL4Routes } = await import("./modules/l4-routes.ts");
const { poolerEdgeInput } = await import("./modules/pooler-policy.ts");
const { MockLocalApi } = await import("./mock-localapi.ts");

const origin = new URL(process.env.BETTER_AUTH_URL ?? "http://localhost:3000").origin;
const password = "PG5432-Route-Test-Password-123!";
const suffix = createId("t").slice(2, 10);
const tailnet = ".tail1234.ts.net";
const zone = `fd26-${suffix}.com`;
const domainId = createId("dom");
const pgIp = "100.90.4.7";
const self = { id: `nEDGE${suffix}`, name: "ark-edge", ips: ["100.64.0.1"], tags: ["tag:ark-edge"] };
const pgHome = { id: `nPG${suffix}`, name: "pg-home", ips: [pgIp] };
const startedAt = new Date();
const socket = join(tmpdir(), `ark-fd26-${suffix}.sock`);
const mock = new MockLocalApi({
  backendState: "Running",
  suffix: tailnet,
  self,
  peers: [pgHome],
  reachable: new Set([`${pgIp}:5432`]),
});
const savedEnv: Record<string, string | undefined> = {};
let savedSettings: Partial<typeof platformSettings.$inferSelect> | undefined;
let owner!: { userId: string; cookie: string };
let operator!: { userId: string; cookie: string };
let viewer!: { userId: string; cookie: string };
const clusterId = createId("dcl");
const databaseA = createId("mdb");
const databaseB = createId("mdb");
const roleId = createId("dbr");
const clientId = createId("dbc");
const tokenSecretId = createId("sec");
const vercelId = createId("vci");
let caId = "";

type Json = Record<string, any>;

async function signUp(role: Role) {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `PG ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
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

async function call(actor: { cookie: string } | null, method: string, path: string, body?: unknown) {
  const response = await app.request(`${origin}${path}`, {
    method,
    headers: {
      ...(actor ? { cookie: actor.cookie } : {}),
      origin,
      ...(method === "GET" ? {} : { "content-type": "application/json" }),
    },
    body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
  });
  const text = await response.text();
  return { status: response.status, body: (text ? JSON.parse(text) : {}) as Json };
}

async function stepUp(action: string, request: Record<string, unknown>) {
  const response = await call(owner, "POST", "/api/step-up", { password, action, request });
  expect(response.status).toBe(200);
}

const pgRequest = (name: string, extra: Record<string, unknown> = {}) => ({
  kind: "postgres",
  hostname: `${name}.${zone}`,
  target: `pg-home${tailnet}`,
  targetPort: 5432,
  tlsMode: "passthrough",
  sourceCidrs: ["198.51.100.0/24"],
  ...extra,
});

async function create(request: Record<string, unknown>) {
  await stepUp("exposure.public", request);
  const response = await call(owner, "POST", "/api/front/routes", request);
  expect([response.status, response.body.error]).toEqual([201, undefined]);
  return response.body.route as Json;
}

async function refused(request: Record<string, unknown>, status: number, pattern: RegExp) {
  await stepUp("exposure.public", request);
  const response = await call(owner, "POST", "/api/front/routes", request);
  expect([response.status, String(response.body.error)]).toEqual([status, expect.stringMatching(pattern)]);
}

beforeAll(async () => {
  for (const key of ["ARK_EDGE_TS_SOCKET", "ARK_EDGE_RELOAD_URL", "ARK_EDGE_SNI_PORTS"])
    savedEnv[key] = process.env[key];
  delete process.env.ARK_EDGE_RELOAD_URL;
  delete process.env.ARK_EDGE_SNI_PORTS;
  process.env.ARK_EDGE_TS_SOCKET = socket;
  const [current] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  savedSettings = current
    ? {
        publicIpv4: current.publicIpv4,
        poolerSourceCidrs: current.poolerSourceCidrs,
        poolerAllowInternet: current.poolerAllowInternet,
        poolerInternetConfirmedAt: current.poolerInternetConfirmedAt,
        poolerInternetConfirmedBy: current.poolerInternetConfirmedBy,
        poolerPolicyReviewedAt: current.poolerPolicyReviewedAt,
        poolerPolicyReviewedBy: current.poolerPolicyReviewedBy,
        poolerPolicyReviewedRequests: current.poolerPolicyReviewedRequests,
        poolerFencedAt: current.poolerFencedAt,
        poolerFenceReason: current.poolerFenceReason,
      }
    : undefined;
  await sql`
    INSERT INTO platform_settings (id, public_ipv4) VALUES ('default', '203.0.113.10')
    ON CONFLICT (id) DO UPDATE SET public_ipv4 = '203.0.113.10', pooler_source_cidrs = '[]',
      pooler_allow_internet = false, pooler_internet_confirmed_at = NULL, pooler_internet_confirmed_by = NULL,
      pooler_policy_reviewed_at = NULL, pooler_policy_reviewed_by = NULL, pooler_policy_reviewed_requests = NULL,
      pooler_fenced_at = NULL, pooler_fence_reason = NULL
  `;
  await sql`INSERT INTO domain_claims (id, name, ownership_token, status) VALUES (${domainId}, ${zone}, 'ark-own-fd26', 'verified')`;
  owner = await signUp("owner");
  operator = await signUp("operator");
  viewer = await signUp("viewer");
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
  await sql`DELETE FROM vercel_integrations WHERE id = ${vercelId}`;
  await sql`DELETE FROM database_clients WHERE id = ${clientId}`;
  await sql`DELETE FROM database_roles WHERE id = ${roleId}`;
  await sql`DELETE FROM managed_databases WHERE id IN ${sql([databaseA, databaseB])}`;
  await sql`DELETE FROM database_clusters WHERE id = ${clusterId}`;
  if (caId) {
    const keys = await sql`SELECT key_secret_id FROM private_cas WHERE id = ${caId}`;
    await sql`DELETE FROM private_cas WHERE id = ${caId}`;
    await sql`DELETE FROM secrets WHERE id IN ${sql(keys.map((row) => String(row.key_secret_id)))}`;
  }
  await sql`DELETE FROM secrets WHERE id = ${tokenSecretId}`;
  const routeIds = (
    await sql`SELECT r.id FROM front_routes r JOIN endpoints e ON e.id = r.endpoint_id WHERE e.domain_id = ${domainId}`
  ).map((row) => String(row.id));
  if (routeIds.length) await sql`DELETE FROM front_routes WHERE id IN ${sql(routeIds)}`;
  await sql`DELETE FROM dns_records WHERE domain_id = ${domainId}`;
  await sql`DELETE FROM endpoints WHERE domain_id = ${domainId}`;
  await sql`DELETE FROM domain_claims WHERE id = ${domainId}`;
  await sql`DELETE FROM operation_steps WHERE operation_id IN (SELECT id FROM operations WHERE created_at >= ${startedAt.toISOString()}::timestamptz)`;
  await sql`DELETE FROM operations WHERE created_at >= ${startedAt.toISOString()}::timestamptz`;
  await sql`DELETE FROM tailnet_nodes WHERE source = 'edge'`;
  await sql`DELETE FROM tailnet_snapshots WHERE source = 'edge'`;
  await sql`DELETE FROM audit_events WHERE created_at >= ${startedAt.toISOString()}::timestamptz AND resource_type IN ('front_route', 'platform', 'database')`;
  for (const user of [owner, operator, viewer]) {
    await sql`DELETE FROM audit_events WHERE actor_id = ${user.userId}`;
    await sql`DELETE FROM step_up_grants WHERE user_id = ${user.userId}`;
    await sql`DELETE FROM "user" WHERE id = ${user.userId}`;
  }
  // Restore the pooler policy and public address this suite replaced.
  if (savedSettings)
    await db.update(platformSettings).set(savedSettings).where(eq(platformSettings.id, "default"));
});

describe("pooler-wide policy (§3.8.3)", () => {
  test("disjoint database CIDRs and an unrestricted Vercel client refuse publication", async () => {
    await sql`INSERT INTO database_clusters (id, name) VALUES (${clusterId}, ${clusterId})`;
    await sql`INSERT INTO managed_databases (id, cluster_id, name, exposure, source_cidrs) VALUES
      (${databaseA}, ${clusterId}, 'shop', 'public', '["198.51.100.0/24"]'),
      (${databaseB}, ${clusterId}, 'crm', 'public', '["203.0.113.0/24"]')`;
    caId = (await pki.createPrivateCa({ purpose: "db-client", name: `fd26-${suffix}` })).id;
    await sql`INSERT INTO database_roles (id, database_id, name, kind) VALUES (${roleId}, ${databaseB}, ${`crm_${suffix}`}, 'runtime')`;
    await sql`INSERT INTO database_clients (id, database_id, name, environment, role_kind, role_id, ca_id)
      VALUES (${clientId}, ${databaseB}, 'vercel-prod', 'production', 'runtime', ${roleId}, ${caId})`;
    await db.insert(secrets).values({
      id: tokenSecretId,
      kind: "vercel_token",
      resourceType: "database",
      resourceId: databaseB,
      ...encryptSecret(process.env.ARK_ROOT_KEY!, "vercel-token", "k1"),
    });
    await sql`INSERT INTO vercel_integrations (id, database_client_id, vercel_project_id, token_secret_id, env_target)
      VALUES (${vercelId}, ${clientId}, 'prj_fd26', ${tokenSecretId}, 'production')`;

    const response = await call(operator, "GET", "/api/databases/pooler-policy");
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      scope: "pooler-wide",
      conflict: true,
      publishable: false,
      boundary: POOLER_POLICY_BOUNDARY,
    });
    expect(response.body.status).toMatch(/deny_all|review_required/);
    expect(response.body.conflicts.map((item: Json) => item.reason).toSorted()).toEqual([
      "different_cidrs",
      "restricted_with_unrestricted",
    ]);
    // Nothing is rendered behind fe_pg5432: no silently unioned allowlist.
    expect((await poolerEdgeInput()).pooler).toBeNull();
    // Viewers see the boundary and the state, not which databases asked for what.
    const state = await call(viewer, "GET", "/api/state");
    expect(state.body.poolerPolicy).toMatchObject({
      scope: "pooler-wide",
      conflict: true,
      publishable: false,
    });
    expect(state.body.poolerPolicy.requests).toBeUndefined();
    expect((await call(viewer, "GET", "/api/databases/pooler-policy")).status).toBe(403);
  });

  test("a B-source connection to database A is never reported as isolated by A's CIDRs", async () => {
    const response = await call(owner, "GET", `/api/databases/${databaseA}/admission?ip=203.0.113.9`);
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      databaseId: databaseA,
      requestedCidrs: ["198.51.100.0/24"],
      scope: "pooler-wide",
      databaseCidrsEnforced: false,
    });
    // Unpublished: refused because of the pooler state, not because A's CIDRs exclude B's source.
    expect(response.body.reason).toMatch(/^pooler-/);
    expect(response.body.reason).not.toBe("source-not-allowlisted");
  });

  test("only an explicit, current review of one common policy publishes it", async () => {
    const current = (await call(owner, "GET", "/api/databases/pooler-policy")).body;
    const stale = { sourceCidrs: [], allowInternet: true, reviewedRequests: "0".repeat(32) };
    await stepUp("exposure.public", stale);
    expect((await call(owner, "PUT", "/api/databases/pooler-policy", stale)).status).toBe(409);
    const body = { sourceCidrs: [], allowInternet: true, reviewedRequests: current.requestsFingerprint };
    // Owner-only, and the exposure.public grant is bound to the exact body.
    expect((await call(operator, "PUT", "/api/databases/pooler-policy", body)).status).toBe(403);
    expect((await call(owner, "PUT", "/api/databases/pooler-policy", body)).status).toBe(403);
    await stepUp("exposure.public", body);
    const saved = await call(owner, "PUT", "/api/databases/pooler-policy", body);
    expect([saved.status, saved.body.error]).toEqual([200, undefined]);
    expect(saved.body).toMatchObject({
      status: "published",
      publishable: true,
      conflict: true,
      reviewed: true,
    });
    const [row] = await sql`SELECT * FROM platform_settings WHERE id = 'default'`;
    expect(row).toMatchObject({
      pooler_allow_internet: true,
      pooler_internet_confirmed_by: owner.userId,
      pooler_policy_reviewed_by: owner.userId,
      pooler_policy_reviewed_requests: current.requestsFingerprint,
    });
    const edge = await poolerEdgeInput();
    expect(edge.pooler).toMatchObject({ allowInternet: true, sourceCidrs: [] });
    const files = renderEdgeL4Generation(edgeL4Input({ certificates: [] }, {}, [], edge.pooler)).files;
    expect(files[POOLER_ALLOWLIST_FILE]).toBe("0.0.0.0/0\n::/0\n");
    expect(files["haproxy.cfg"]).toContain("use_backend be_pgbouncer if pg_ssl_request");
    // The admission check now follows that policy, for every database alike.
    const admission = await call(owner, "GET", `/api/databases/${databaseA}/admission?ip=203.0.113.9`);
    expect(admission.body).toMatchObject({
      allowed: true,
      scope: "pooler-wide",
      databaseCidrsEnforced: false,
    });
  });

  test("a durable fence closes publication and admission without discarding the saved policy", async () => {
    await sql`UPDATE platform_settings SET pooler_fenced_at = now(), pooler_fence_reason = 'test-watchdog' WHERE id = 'default'`;
    try {
      const status = await call(owner, "GET", "/api/databases/pooler-policy");
      expect(status.body).toMatchObject({
        status: "fenced",
        publishable: false,
        policyPublishable: true,
        fence: { reason: "test-watchdog" },
      });
      expect((await poolerEdgeInput()).pooler).toBeNull();
      expect(
        (await call(owner, "GET", `/api/databases/${databaseA}/admission?ip=203.0.113.9`)).body,
      ).toMatchObject({ allowed: false, reason: "pooler-fenced" });
    } finally {
      await sql`UPDATE platform_settings SET pooler_fenced_at = NULL, pooler_fence_reason = NULL WHERE id = 'default'`;
    }
    expect((await call(owner, "GET", "/api/databases/pooler-policy")).body.status).toBe("published");
  });

  test("a restricted common policy renders exactly the saved CIDRs, and a new request needs a new review", async () => {
    // Drop the Vercel client: the remaining requests still differ (two disjoint CIDR lists).
    await sql`UPDATE database_clients SET status = 'revoked' WHERE id = ${clientId}`;
    const current = (await call(owner, "GET", "/api/databases/pooler-policy")).body;
    expect(current).toMatchObject({ conflict: true, publishable: false, status: "review_required" });
    const body = {
      sourceCidrs: ["198.51.100.0/24"],
      allowInternet: false,
      reviewedRequests: current.requestsFingerprint,
    };
    await stepUp("exposure.public", body);
    expect((await call(owner, "PUT", "/api/databases/pooler-policy", body)).status).toBe(200);
    const edge = await poolerEdgeInput();
    // Exactly the reviewed policy: B's requested 203.0.113.0/24 is not silently added.
    expect(edge.pooler).toMatchObject({ allowInternet: false, sourceCidrs: ["198.51.100.0/24"] });
    const blocked = await call(owner, "GET", `/api/databases/${databaseB}/admission?ip=203.0.113.9`);
    expect(blocked.body).toMatchObject({ allowed: false, reason: "source-not-in-pooler-policy" });
    // A changed request (a third CIDR list) makes the review stale: publication is refused again.
    await sql`UPDATE managed_databases SET source_cidrs = '["192.0.2.0/24"]' WHERE id = ${databaseB}`;
    expect((await poolerEdgeInput()).pooler).toBeNull();
    expect((await call(operator, "GET", "/api/databases/pooler-policy")).body.status).toBe("review_required");
  });
});

describe("postgres routes (§3.8.3)", () => {
  test("postgres mTLS certificates can be issued, listed and revoked through the API", async () => {
    const route = await create(pgRequest("pg-mtls", { tlsMode: "terminate_mtls" }));
    const path = `/api/front/routes/${route.id}/client-certificates`;
    const listing = await call(owner, "GET", path);
    expect(listing.status).toBe(200);
    expect(listing.body.ca.certPem).toContain("BEGIN CERTIFICATE");
    const body = { name: "pg-api-client" };
    await stepUp("credential.rotate", { routeId: route.id, ...body });
    const issued = await call(owner, "POST", path, body);
    expect([issued.status, issued.body.error]).toEqual([201, undefined]);
    expect(issued.body.certPem).toContain("BEGIN CERTIFICATE");
    expect((await call(owner, "GET", path)).body.certificates).toEqual([
      expect.objectContaining({ id: issued.body.id, status: "issued" }),
    ]);
    const revoked = await call(owner, "POST", `${path}/${issued.body.id}/revoke`);
    expect([revoked.status, revoked.body.error]).toEqual([200, undefined]);
    expect((await call(owner, "GET", path)).body.certificates).toEqual([
      expect.objectContaining({ id: issued.body.id, status: "revoked" }),
    ]);
  });
  test("5432 only, passthrough-only compatibility port, raw-port collisions refused", async () => {
    await refused(pgRequest("wrong-port", { listenPort: 443 }), 422, /5432/);
    await refused(pgRequest("plain", { tlsMode: "plain" }), 422, /plain/);
    await refused(
      pgRequest("compat-terminate", { tlsMode: "terminate", compatPort: 20017 }),
      422,
      /passthrough/,
    );
    await refused(pgRequest("compat-range", { compatPort: 30000 }), 422, /20000-20049/);
    const route = await create(pgRequest("pg-home", { compatPort: 20017 }));
    expect(route).toMatchObject({
      kind: "postgres",
      listenPort: 5432,
      l4: {
        tlsMode: "passthrough",
        compatPort: 20017,
        limits: { maxConn: 50, perSourceConn: 10, perSourceRate: 20 },
      },
    });
    // The compatibility port and a tcp route's dedicated port share one raw-port space.
    const tcp = {
      kind: "tcp",
      hostname: `ssh.${zone}`,
      target: `pg-home${tailnet}`,
      targetPort: 5432,
      listenPort: 20017,
      allowPlaintext: true,
      sourceCidrs: ["198.51.100.7/32"],
    };
    await refused(tcp, 409, /20017/);
    await refused(pgRequest("pg-second", { compatPort: 20017 }), 409, /20017/);
  });

  test("an enabled route is in the lease with its fingerprint and renders behind fe_pg5432", async () => {
    const [row] = await sql`SELECT r.id FROM front_routes r JOIN endpoints e ON e.id = r.endpoint_id
      WHERE e.hostname = ${`pg-home.${zone}`}`;
    const id = String(row!.id);
    await sql`UPDATE front_routes SET status = 'ready' WHERE id = ${id}`;
    await stepUp("exposure.public", { routeId: id });
    expect((await call(owner, "POST", `/api/front/routes/${id}/enable`, {})).status).toBe(200);
    const policy = (await edgePolicy()).routes.find((item) => item.id === id);
    expect(policy).toMatchObject({ kind: "postgres", ip: pgIp, port: 5432 });
    expect(policy?.policy).toMatch(/^[a-f0-9]{16}$/);
    const l4 = await edgeL4Routes({ policyRoutes: (await edgePolicy()).routes, sniPorts: [] });
    expect(l4.postgresRoutes.map((item) => item.id)).toEqual([id]);
    const config = renderEdgeL4Generation(edgeL4Input({ certificates: [] }, l4, [], null)).files[
      "haproxy.cfg"
    ]!;
    expect(config).toContain(
      `use_backend be_${id}_pg if tls_client_hello { req.ssl_sni -i pg-home.${zone} }`,
    );
    expect(config).toContain(`frontend fe_${id}_compat\n    bind :20017`);
    const { frontIngressRules } = await import("./modules/front-ingress.ts");
    const { DB_INGRESS_LIMIT_DEFAULTS } = await import("@ark-stack/shared");
    const firewall = frontIngressRules(edgeL4Input({ certificates: [] }, l4), DB_INGRESS_LIMIT_DEFAULTS);
    expect(firewall).toContain("chain ark_db_limits");
    expect(firewall).toContain("# ark-front-raw: port=20017 policy=allowlist");
    expect(firewall).toContain("ip saddr 198.51.100.0/24 goto port_20017_limits");
    // Without a published pooler, classic connections have no backend on the same port.
    expect(config).not.toContain("be_pgbouncer");
    // Removing the compatibility port is a tightening (no step-up) that changes the fingerprint.
    const before = policy!.policy;
    const update = await call(owner, "PATCH", `/api/front/routes/${id}`, { compatPort: null });
    expect([update.status, update.body.error]).toEqual([200, undefined]);
    expect((await edgePolicy()).routes.find((item) => item.id === id)?.policy).not.toBe(before);
    const drains =
      await sql`SELECT payload FROM operations WHERE kind = 'edge.drain' AND created_at >= ${startedAt.toISOString()}::timestamptz`;
    expect(drains.some((item) => (item.payload as Json).routeIds?.includes(id))).toBe(true);
    // Re-adding one is a loosening change and needs the step-up.
    expect((await call(owner, "PATCH", `/api/front/routes/${id}`, { compatPort: 20018 })).status).toBe(403);
  });

  test("the listeners endpoint carries the target checklist and driver guidance", async () => {
    const response = await call(operator, "GET", "/api/front/listeners");
    expect(response.body.postgres).toMatchObject({ port: 5432, compatPorts: { start: 20000, end: 20049 } });
    expect(response.body.postgres.checklist.map((item: Json) => item.id)).toContain("reject-superusers");
    expect(response.body.postgres.drivers.find((item: Json) => item.client === "postgres.js")).toMatchObject({
      since: "4.1.1",
      verified: true,
    });
  });
});

test("a pooler mutation during a captured apply leaves a durable successor with the newest policy", async () => {
  const edgeModule = await import("./modules/edge-l4.ts");
  const ingress = await import("./modules/front-ingress.ts");
  const { queuePoolerEdgeApply, processQueued } = await import("./coordinator.ts");
  const previous = { root: process.env.ARK_EDGE_L4_DIR, validator: process.env.ARK_HAPROXY_VALIDATOR_SOCKET };
  process.env.ARK_EDGE_L4_DIR = "/unused-regression";
  process.env.ARK_HAPROXY_VALIDATOR_SOCKET = "/unused-regression.sock";
  let captured!: () => void;
  const ready = new Promise<void>((resolve) => {
    captured = resolve;
  });
  let release!: () => void;
  const barrier = new Promise<void>((resolve) => {
    release = resolve;
  });
  const policies: string[][] = [];
  const firewall = spyOn(ingress, "applyFrontIngress").mockResolvedValue({
    applied: true,
    file: "/test",
    hash: "test",
  });
  const writer = spyOn(edgeModule, "writeEdgeL4").mockImplementation(async (input) => {
    policies.push(input.pooler?.sourceCidrs ?? []);
    if (policies.length === 1) {
      captured();
      await barrier;
    }
    return { applied: false, reason: "test transport" };
  });
  let worker: Promise<void> | undefined;
  try {
    await sql`UPDATE operations SET status = 'failed' WHERE kind = 'edge.l4_apply' AND status = 'queued'`;
    const evaluation = (await call(owner, "GET", "/api/databases/pooler-policy")).body;
    await sql`UPDATE platform_settings SET pooler_source_cidrs = '["198.51.100.0/24"]', pooler_allow_internet = false,
      pooler_policy_reviewed_at = now(), pooler_policy_reviewed_requests = ${evaluation.requestsFingerprint} WHERE id = 'default'`;
    await queuePoolerEdgeApply();
    worker = processQueued(1, "edge.l4_apply");
    await ready;
    await sql`UPDATE platform_settings SET pooler_source_cidrs = '["198.51.100.7/32"]' WHERE id = 'default'`;
    await queuePoolerEdgeApply();
    await queuePoolerEdgeApply();
    const queued = await sql`SELECT id FROM operations WHERE kind = 'edge.l4_apply' AND status = 'queued'`;
    expect(queued).toHaveLength(1);
    release();
    await worker;
    await processQueued(1, "edge.l4_apply");
    expect(policies).toEqual([["198.51.100.0/24"], ["198.51.100.7/32"]]);
    const config = renderEdgeL4Generation(
      edgeL4Input({ certificates: [] }, {}, [], (await poolerEdgeInput()).pooler),
    );
    expect(config.files[POOLER_ALLOWLIST_FILE]).toBe("198.51.100.7/32\n");
    // A missed enqueue (for example a worker crash after saving) is repaired by observation even
    // when every tailnet route server is already present.
    const oldMaster = process.env.ARK_HAPROXY_MASTER_SOCKET;
    process.env.ARK_HAPROXY_MASTER_SOCKET = "/unused-recovery";
    const present = spyOn(edgeModule, "missingL4Routes").mockResolvedValue([]);
    try {
      await sql`UPDATE platform_settings SET pooler_source_cidrs = '["198.51.100.8/32"]' WHERE id = 'default'`;
      await runOperation(
        "edge.observe",
        await enqueue({
          kind: "edge.observe",
          targetIds: ["tailnet:edge"],
          payload: { fixture: "pooler-recovery" },
        }),
      );
      await processQueued(1, "edge.l4_apply");
      expect(policies.at(-1)).toEqual(["198.51.100.8/32"]);
    } finally {
      present.mockRestore();
      if (oldMaster === undefined) delete process.env.ARK_HAPROXY_MASTER_SOCKET;
      else process.env.ARK_HAPROXY_MASTER_SOCKET = oldMaster;
    }
  } finally {
    release();
    await worker;
    writer.mockRestore();
    firewall.mockRestore();
    if (previous.root === undefined) delete process.env.ARK_EDGE_L4_DIR;
    else process.env.ARK_EDGE_L4_DIR = previous.root;
    if (previous.validator === undefined) delete process.env.ARK_HAPROXY_VALIDATOR_SOCKET;
    else process.env.ARK_HAPROXY_VALIDATOR_SOCKET = previous.validator;
  }
}, 15_000);

test.each(["success", "failed", "timeout", "stale", "unapplied"])(
  "managed-edge fence requires a confirmed matching generation (%s)",
  async (mode) => {
    const edgeModule = await import("./modules/edge-l4.ts");
    const ingress = await import("./modules/front-ingress.ts");
    const { fencePoolerListener, processQueued } = await import("./coordinator.ts");
    const previous = {
      root: process.env.ARK_EDGE_L4_DIR,
      validator: process.env.ARK_HAPROXY_VALIDATOR_SOCKET,
    };
    process.env.ARK_EDGE_L4_DIR = "/unused-fence";
    process.env.ARK_HAPROXY_VALIDATOR_SOCKET = "/unused-fence.sock";
    const firewall = spyOn(ingress, "applyFrontIngress").mockResolvedValue({
      applied: true,
      file: "/test",
      hash: "test",
    });
    let applied = false;
    const writer = spyOn(edgeModule, "writeEdgeL4").mockImplementation(async (input) => {
      expect(input.pooler).toBeNull();
      if (mode === "failed") throw new Error("simulated reload failure");
      applied = true;
      return (
        mode === "unapplied" ? { applied: false, reason: "missing edge" } : { applied: true, reloaded: true }
      ) as Awaited<ReturnType<typeof edgeModule.writeEdgeL4>>;
    });
    try {
      await sql`UPDATE operations SET status = 'failed' WHERE kind = 'edge.l4_apply' AND status = 'queued'`;
      let settled = false;
      const fenced = fencePoolerListener(`test-${mode}`, { timeoutMs: mode === "timeout" ? 150 : 2000 }).then(
        () => {
          settled = true;
          return null;
        },
        (error: Error) => {
          settled = true;
          return error;
        },
      );
      let queued = false;
      for (let i = 0; i < 100; i++) {
        const [row] = await sql`SELECT id FROM operations WHERE kind = 'edge.l4_apply' AND status = 'queued'`;
        if (row) {
          queued = true;
          break;
        }
        await Bun.sleep(10);
      }
      expect(queued).toBe(true);
      expect(settled).toBe(false);
      if (mode === "stale")
        await sql`UPDATE platform_settings SET pooler_fenced_at = pooler_fenced_at + interval '1 second' WHERE id = 'default'`;
      if (mode !== "timeout") await processQueued(1, "edge.l4_apply");
      const result = await fenced;
      if (mode === "success") {
        expect(result).toBeNull();
        expect(applied).toBe(true);
      } else expect(result?.message).toContain("did not confirm");
      expect((await poolerEdgeInput()).pooler).toBeNull();
      expect((await call(owner, "GET", "/api/databases/pooler-policy")).body.status).toBe("fenced");
    } finally {
      writer.mockRestore();
      firewall.mockRestore();
      await sql`UPDATE operations SET status = 'failed' WHERE kind = 'edge.l4_apply' AND status = 'queued'`;
      await sql`UPDATE platform_settings SET pooler_fenced_at = NULL, pooler_fence_reason = NULL WHERE id = 'default'`;
      if (previous.root === undefined) delete process.env.ARK_EDGE_L4_DIR;
      else process.env.ARK_EDGE_L4_DIR = previous.root;
      if (previous.validator === undefined) delete process.env.ARK_HAPROXY_VALIDATOR_SOCKET;
      else process.env.ARK_HAPROXY_VALIDATOR_SOCKET = previous.validator;
    }
  },
  10_000,
);
