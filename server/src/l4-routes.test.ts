// TLS-TCP and raw-TCP routes through the real app, Better Auth sessions, step-up grants and the
// coordinator (docs/design/front-door.md §3.8, FD-14):
//
// - listener rules: tcp only on 20000-20049, never platform/mail ports, tls never on raw ports and
//   only on 443 or an install-enabled shared SNI port;
// - default deny: an empty allowlist is stored and rendered as deny-all, enable refuses it, and only
//   allowInternet saved under the exposure.public step-up opens a route (plain also needs
//   owner-confirmed protocol authentication);
// - the lease policy fingerprint: tightening needs no step-up but changes the fingerprint and
//   queues edge.drain; loosening needs a step-up;
// - terminate_mtls: a route CA, its CRL, client certificate issue/revoke, the revoked serial in the
//   fingerprint, and the `edge.l4_apply` input with certificate, CA and CRL.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createId,
  frontRouteCreateInput,
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
const { sql } = await import("./db.ts");
const routeLifecycle = await import("./modules/front-routes.ts");
const pki = await import("./modules/pki.ts");
const x509 = await import("./modules/x509.ts");
const { runOperation, enqueue, edgeL4Input } = await import("./coordinator.ts");
const { edgePolicy } = await import("./modules/edge-observe.ts");
const { edgeL4Routes } = await import("./modules/l4-routes.ts");
const { refreshRouteCrls } = await import("./modules/route-pki.ts");
const { MockLocalApi } = await import("./mock-localapi.ts");

const origin = new URL(process.env.BETTER_AUTH_URL ?? "http://localhost:3000").origin;
const password = "L4-Route-Test-Password-123!";
const suffix = createId("t").slice(2, 10);
const tailnet = ".tail1234.ts.net";
const zone = `fd14-${suffix}.com`;
const domainId = createId("dom");
const token = "ark-own-fd14";
const nasIp = "100.88.1.20";
const self = { id: `nEDGE${suffix}`, name: "ark-edge", ips: ["100.64.0.1"], tags: ["tag:ark-edge"] };
const nas = { id: `nNAS${suffix}`, name: "nas", ips: [nasIp] };
const startedAt = new Date();
const socket = join(tmpdir(), `ark-fd14-${suffix}.sock`);
const mock = new MockLocalApi({
  backendState: "Running",
  suffix: tailnet,
  self,
  peers: [nas],
  reachable: new Set([`${nasIp}:1883`, `${nasIp}:2222`]),
});
const savedEnv: Record<string, string | undefined> = {};
let savedSettings: Record<string, unknown> | undefined;
let owner!: { userId: string; cookie: string };
let operator!: { userId: string; cookie: string };
let certDir = "";

type Json = Record<string, any>;

async function signUp(role: Role) {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `L4 ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
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

async function openGrants() {
  const [row] =
    await sql`SELECT count(*)::int AS n FROM step_up_grants WHERE user_id = ${owner.userId} AND consumed_at IS NULL`;
  return Number(row?.n ?? 0);
}

const tcpRequest = (name: string, extra: Record<string, unknown> = {}) => ({
  kind: "tcp",
  hostname: `${name}.${zone}`,
  target: `nas${tailnet}`,
  targetPort: 2222,
  listenPort: 20001,
  allowPlaintext: true,
  sourceCidrs: ["198.51.100.7/32"],
  ...extra,
});
const tlsRequest = (name: string, extra: Record<string, unknown> = {}) => ({
  kind: "tls",
  hostname: `${name}.${zone}`,
  target: `nas${tailnet}`,
  targetPort: 1883,
  tlsMode: "passthrough",
  sourceCidrs: ["203.0.113.0/24"],
  ...extra,
});

/** Validates without a grant (422 keeps the grant), then creates with a matching grant. */
async function create(request: Record<string, unknown>) {
  await stepUp("exposure.public", request);
  const response = await call(owner, "POST", "/api/front/routes", request);
  expect([response.status, response.body.error]).toEqual([201, undefined]);
  return response.body.route as Json;
}

async function refused(request: Record<string, unknown>, pattern: RegExp) {
  await stepUp("exposure.public", request);
  const before = await openGrants();
  const response = await call(owner, "POST", "/api/front/routes", request);
  expect([response.status, String(response.body.error)]).toEqual([422, expect.stringMatching(pattern)]);
  // Validation never consumes the single-use grant.
  expect(await openGrants()).toBe(before);
}

async function routeRow(id: string) {
  const [row] = await sql`SELECT * FROM front_routes WHERE id = ${id}`;
  return row as Json;
}

async function makeReady(id: string) {
  await sql`UPDATE front_routes SET status = 'ready' WHERE id = ${id}`;
}

async function enable(id: string) {
  await stepUp("exposure.public", { routeId: id });
  return call(owner, "POST", `/api/front/routes/${id}/enable`, {});
}

async function queued(kind: string) {
  const rows =
    await sql`SELECT payload FROM operations WHERE kind = ${kind} AND created_at >= ${startedAt.toISOString()}::timestamptz ORDER BY created_at`;
  return rows.map((row) => row.payload as Json);
}

async function policyOf(id: string) {
  return (await edgePolicy()).routes.find((route) => route.id === id);
}

beforeAll(async () => {
  for (const key of ["ARK_EDGE_TS_SOCKET", "ARK_EDGE_RELOAD_URL", "ARK_CERT_DIR", "ARK_EDGE_SNI_PORTS"])
    savedEnv[key] = process.env[key];
  delete process.env.ARK_EDGE_RELOAD_URL;
  process.env.ARK_EDGE_TS_SOCKET = socket;
  process.env.ARK_EDGE_SNI_PORTS = "8883";
  certDir = await mkdtemp(join(tmpdir(), "ark-fd14-certs-"));
  process.env.ARK_CERT_DIR = certDir;
  [savedSettings] = await sql`SELECT public_ipv4 FROM platform_settings WHERE id = 'default'`;
  await sql`
    INSERT INTO platform_settings (id, public_ipv4) VALUES ('default', '203.0.113.10')
    ON CONFLICT (id) DO UPDATE SET public_ipv4 = '203.0.113.10'
  `;
  await sql`INSERT INTO domain_claims (id, name, ownership_token, status) VALUES (${domainId}, ${zone}, ${token}, 'verified')`;
  owner = await signUp("owner");
  operator = await signUp("operator");
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
  await rm(certDir, { recursive: true, force: true });
  const routeRows = await sql`
    SELECT r.id, r.client_ca_id FROM front_routes r JOIN endpoints e ON e.id = r.endpoint_id WHERE e.domain_id = ${domainId}
  `;
  const routeIds = routeRows.map((row) => String(row.id));
  const caIds = routeRows.map((row) => row.client_ca_id).filter(Boolean) as string[];
  if (routeIds.length) await sql`DELETE FROM front_routes WHERE id IN ${sql(routeIds)}`;
  if (caIds.length) {
    await sql`DELETE FROM client_certificates WHERE ca_id IN ${sql(caIds)}`;
    const keys = await sql`SELECT key_secret_id FROM private_cas WHERE id IN ${sql(caIds)}`;
    await sql`DELETE FROM private_cas WHERE id IN ${sql(caIds)}`;
    await sql`DELETE FROM secrets WHERE id IN ${sql(keys.map((row) => String(row.key_secret_id)))}`;
  }
  await sql`DELETE FROM secrets WHERE resource_type = 'platform' AND kind = 'pki.client_key' AND created_at >= ${startedAt.toISOString()}::timestamptz`;
  await sql`DELETE FROM audit_events WHERE created_at >= ${startedAt.toISOString()}::timestamptz AND resource_type = 'front_route'`;
  await sql`DELETE FROM certificates WHERE endpoint_id IN (SELECT id FROM endpoints WHERE domain_id = ${domainId})`;
  await sql`DELETE FROM dns_records WHERE domain_id = ${domainId}`;
  await sql`DELETE FROM endpoints WHERE domain_id = ${domainId}`;
  await sql`DELETE FROM domain_claims WHERE id = ${domainId}`;
  await sql`DELETE FROM operation_steps WHERE operation_id IN (SELECT id FROM operations WHERE created_at >= ${startedAt.toISOString()}::timestamptz)`;
  await sql`DELETE FROM operations WHERE created_at >= ${startedAt.toISOString()}::timestamptz`;
  await sql`DELETE FROM tailnet_nodes WHERE source = 'edge'`;
  await sql`DELETE FROM tailnet_snapshots WHERE source = 'edge'`;
  for (const user of [owner, operator]) {
    await sql`DELETE FROM audit_events WHERE actor_id = ${user.userId}`;
    await sql`DELETE FROM step_up_grants WHERE user_id = ${user.userId}`;
    await sql`DELETE FROM "user" WHERE id = ${user.userId}`;
  }
  if (savedSettings)
    await sql`UPDATE platform_settings SET public_ipv4 = ${savedSettings.public_ipv4 as string | null} WHERE id = 'default'`;
});

describe("listeners (§3.8.2)", () => {
  test("tcp routes only on 20000-20049, never on platform or mail ports", async () => {
    for (const listenPort of [19999, 20050, 22, 8883])
      await refused(tcpRequest(`out-${listenPort}`, { listenPort }), /outside/);
    for (const listenPort of [25, 80, 443, 465, 587, 993, 2019, 3000, 5432, 41641, 41642])
      await refused(tcpRequest(`reserved-${listenPort}`, { listenPort }), /platform or mail port/);
  });

  test("tls routes never on raw ports, and on shared SNI ports only when enabled at install", async () => {
    await refused(tlsRequest("raw", { listenPort: 20002 }), /raw TCP port/);
    await refused(tlsRequest("ldaps", { listenPort: 636 }), /not enabled at install/);
    await refused(tlsRequest("mail", { listenPort: 993 }), /platform or mail port/);
    await refused({ ...tlsRequest("pg"), kind: "postgres", listenPort: 443 }, /5432/);
    await refused(tlsRequest("plain", { tlsMode: "plain" }), /plain/);
    await refused(tlsRequest("terminate-empty", { tlsMode: "terminate", sourceCidrs: [] }), /restricted/);
    const route = await create(tlsRequest("mqtts", { listenPort: 8883 }));
    expect(route).toMatchObject({ kind: "tls", listenPort: 8883, l4: { tlsMode: "passthrough" } });
  });

  test("L4 routes reject HTTP gate settings on create and update", async () => {
    for (const extra of [{ bypassPaths: ["/hooks/*"] }, { allowedOrigins: ["https://app.example.com"] }]) {
      await refused(tlsRequest("gate-settings", extra), /cannot be set/);
    }
    const route = await create(tlsRequest("gate-update"));
    expect(route.accessMode).toBeNull();
    for (const update of [{ bypassPaths: [] }, { allowedOrigins: [] }]) {
      const response = await call(owner, "PATCH", `/api/front/routes/${route.id}`, update);
      expect(response.status).toBe(422);
      expect(response.body.error).toMatch(/cannot be set/);
    }
  });

  test("the listeners endpoint names the enabled ports and the protocol guidance", async () => {
    const response = await call(operator, "GET", "/api/front/listeners");
    expect(response.status).toBe(200);
    expect(response.body.sharedSniPorts).toEqual({ available: [8883, 5671, 636, 6380], enabled: [8883] });
    expect(response.body.tcpPorts).toEqual({ start: 20000, end: 20049 });
    expect(response.body.guidance.map((row: Json) => row.protocol)).toContain("MySQL / MariaDB");
  });

  test("operators cannot create L4 routes", async () => {
    const request = tcpRequest("operator", { listenPort: 20009 });
    expect((await call(operator, "POST", "/api/front/routes", request)).status).toBe(403);
  });
});

describe("default deny (§3.8.6)", () => {
  test("plain needs allowPlaintext; an open plain route needs protocol authentication", async () => {
    await refused(tcpRequest("noplain", { allowPlaintext: undefined, listenPort: 20003 }), /allowPlaintext/);
    await refused(
      tcpRequest("open", { sourceCidrs: [], allowInternet: true, listenPort: 20003 }),
      /protocolAuthConfirmed/,
    );
    await refused(tcpRequest("slash0", { sourceCidrs: ["0.0.0.0/0"], listenPort: 20003 }), /allowInternet/);
  });

  test("an empty list is saved as deny-all, renders deny-all, and enable is refused", async () => {
    const route = await create(tcpRequest("empty", { sourceCidrs: [], listenPort: 20004 }));
    expect(route.l4).toMatchObject({ sourceCidrs: [], allowInternet: false, admits: "nobody" });
    await makeReady(route.id);
    const before = await openGrants();
    const response = await enable(route.id);
    expect([response.status, response.body.error]).toEqual([
      422,
      expect.stringMatching(/denies every source/),
    ]);
    expect(await openGrants()).toBe(before + 1);
    expect((await routeRow(route.id)).enabled).toBe(false);
    // The database refuses to store an open route without the saved confirmation.
    const violation = await sql`UPDATE front_routes SET allow_internet = true WHERE id = ${route.id}`.then(
      () => "updated",
      (error: Error) => error.message,
    );
    expect(violation).toMatch(/front_routes_internet_confirmed_check/);
  });

  test("allowInternet is saved with the owner's exposure.public confirmation and then enables", async () => {
    const route = await create(
      tcpRequest("internet", {
        sourceCidrs: [],
        allowInternet: true,
        protocolAuthConfirmed: true,
        listenPort: 20005,
      }),
    );
    const row = await routeRow(route.id);
    expect(row).toMatchObject({
      allow_internet: true,
      protocol_auth_confirmed: true,
      internet_confirmed_by: owner.userId,
    });
    expect(row.internet_confirmed_at).toBeTruthy();
    await makeReady(route.id);
    expect((await enable(route.id)).status).toBe(200);
    const policy = await policyOf(route.id);
    expect(policy).toMatchObject({ kind: "tcp", port: 2222 });
    const l4 = await edgeL4Routes({ policyRoutes: [policy!], certDir, sniPorts: [] });
    expect(l4.tcpRoutes).toHaveLength(1);
    const generation = renderEdgeL4Generation(edgeL4Input({ certificates: [] }, l4));
    expect(generation.files[`allow/${route.id}.lst`]).toBe("0.0.0.0/0\n::/0\n");
  });
});

describe("policy changes drain the route (§3.8.6)", () => {
  test("tightening needs no step-up, renames the servers and queues edge.drain; loosening needs one", async () => {
    const route = await create(
      tcpRequest("tighten", { sourceCidrs: ["198.51.100.0/24"], listenPort: 20006 }),
    );
    await makeReady(route.id);
    expect((await enable(route.id)).status).toBe(200);
    const before = (await policyOf(route.id))!.policy;
    expect(before).toMatch(/^[a-f0-9]{16}$/);
    const tightened = await call(owner, "PATCH", `/api/front/routes/${route.id}`, { sourceCidrs: [] });
    expect([tightened.status, tightened.body.loosening]).toEqual([200, []]);
    const after = await policyOf(route.id);
    expect(after!.policy).not.toBe(before);
    // Empty on a live route: it stays in the policy and renders deny-all.
    const l4 = await edgeL4Routes({ policyRoutes: [after!], certDir, sniPorts: [] });
    expect(renderEdgeL4Generation(edgeL4Input({ certificates: [] }, l4)).files[`allow/${route.id}.lst`]).toBe(
      "",
    );
    expect(
      (await queued("edge.drain")).some(
        (payload) => payload.routeIds?.includes(route.id) && payload.reason === "route_policy_changed",
      ),
    ).toBe(true);
    // Loosening without a grant is refused.
    const loosened = await call(owner, "PATCH", `/api/front/routes/${route.id}`, {
      sourceCidrs: ["192.0.2.0/24"],
    });
    expect(loosened.status).toBe(403);
    await stepUp("exposure.public", { routeId: route.id, sourceCidrs: ["192.0.2.0/24"] });
    expect(
      (await call(owner, "PATCH", `/api/front/routes/${route.id}`, { sourceCidrs: ["192.0.2.0/24"] })).status,
    ).toBe(200);
  });

  test("disable and delete drain tls and tcp routes", async () => {
    const route = await create(tlsRequest("disable"));
    await makeReady(route.id);
    expect((await enable(route.id)).status).toBe(200);
    expect((await call(owner, "POST", `/api/front/routes/${route.id}/disable`, {})).status).toBe(200);
    expect(
      (await queued("edge.drain")).some(
        (payload) => payload.routeIds?.includes(route.id) && payload.reason === "route_disabled",
      ),
    ).toBe(true);
    expect(await policyOf(route.id)).toBeUndefined();
  });
});

describe("terminate_mtls (§3.8.4)", () => {
  test("a route CA with a CRL, client certificates, and revocation in the policy and CRL", async () => {
    const route = await create(tlsRequest("mtls", { tlsMode: "terminate_mtls" }));
    const row = await routeRow(route.id);
    expect(row.client_ca_id).toMatch(/^pca_/);
    // A fake public certificate for the route hostname, where the domain worker reads it.
    await mkdir(join(certDir, route.hostname), { recursive: true });
    await writeFile(
      join(certDir, route.hostname, "fullchain.pem"),
      "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n",
    );
    await writeFile(
      join(certDir, route.hostname, "privkey.pem"),
      "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n",
    );
    await makeReady(route.id);
    expect((await enable(route.id)).status).toBe(200);
    // No CRL yet: the route is omitted until edge.l4_apply's refresh generates one.
    let l4 = await edgeL4Routes({ policyRoutes: [(await policyOf(route.id))!], certDir, sniPorts: [] });
    expect(l4.omitted.map((item) => item.reason)).toEqual(["its route CA has no CRL yet"]);
    expect(await refreshRouteCrls()).toContain(row.client_ca_id);
    l4 = await edgeL4Routes({ policyRoutes: [(await policyOf(route.id))!], certDir, sniPorts: [] });
    expect(l4.tlsRoutes[0]).toMatchObject({ tlsMode: "terminate_mtls" });
    const files = renderEdgeL4Generation(edgeL4Input({ certificates: [] }, l4)).files;
    expect(files[`cas/${route.id}.crl`]).toContain("BEGIN X509 CRL");
    expect(files[`certs/${route.id}.pem`]).toContain("PRIVATE KEY");

    // Issuing needs a credential.rotate grant bound to the route and body.
    const body = { name: "sensor-1" };
    expect(
      (await call(owner, "POST", `/api/front/routes/${route.id}/client-certificates`, body)).status,
    ).toBe(403);
    await stepUp("credential.rotate", { routeId: route.id, ...body });
    const issued = await call(owner, "POST", `/api/front/routes/${route.id}/client-certificates`, body);
    expect(issued.status).toBe(201);
    expect(issued.body.certPem).toContain("BEGIN CERTIFICATE");
    expect(issued.body.keySecretId).toMatch(/^sec_/);
    const listed = await call(owner, "GET", `/api/front/routes/${route.id}/client-certificates`);
    expect(listed.body.certificates.map((item: Json) => item.id)).toEqual([issued.body.id]);

    // Revocation: CRL regenerated, a new policy fingerprint, and a drain of the route.
    const before = (await policyOf(route.id))!.policy;
    const revoked = await call(
      owner,
      "POST",
      `/api/front/routes/${route.id}/client-certificates/${issued.body.id}/revoke`,
      {},
    );
    expect([revoked.status, revoked.body.status]).toEqual([200, "revoked"]);
    expect((await policyOf(route.id))!.policy).not.toBe(before);
    expect(
      (await queued("edge.drain")).some((payload) => payload.reason === "client_certificate_revoked"),
    ).toBe(true);

    // Client certificates exist only for terminate_mtls routes.
    const passthrough = await create(tlsRequest("nomtls"));
    expect((await call(owner, "GET", `/api/front/routes/${passthrough.id}/client-certificates`)).status).toBe(
      409,
    );
  });
});

const noEnqueue = async () => ({});

describe("concurrent L4 lifecycle and revocation recovery", () => {
  const actor = () => ({ userId: owner.userId, role: "owner" });

  test("concurrent TCP commits on the same dedicated port have exactly one winner", async () => {
    const plans = await Promise.all(
      ["race-a", "race-b"].map((name) =>
        routeLifecycle.prepareRouteCreate(
          frontRouteCreateInput.parse(tcpRequest(name, { listenPort: 20040 })),
        ),
      ),
    );
    const outcomes = await Promise.allSettled(
      plans.map((plan) => routeLifecycle.commitRouteCreate(plan, actor(), noEnqueue)),
    );
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    const loser = outcomes.find((outcome) => outcome.status === "rejected") as PromiseRejectedResult;
    expect(loser.reason.status).toBe(409);
    const rows = await sql`SELECT id FROM front_routes WHERE kind = 'tcp' AND listen_port = 20040`;
    expect(rows).toHaveLength(1);
  });

  test("concurrent deletes serialize the shared endpoint and remove its last resources", async () => {
    const first = await create(tlsRequest("shared-delete"));
    const second = await create(tlsRequest("shared-delete", { listenPort: 8883 }));
    const row = await routeRow(first.id);
    await sql`INSERT INTO certificates (id, endpoint_id, names, status) VALUES (${createId("crt")}, ${row.endpoint_id}, ${JSON.stringify([first.hostname])}::jsonb, 'issued')`;
    const plans = await Promise.all(
      [first, second].map((route) => routeLifecycle.prepareRouteDelete(route.id)),
    );
    const deleted = await Promise.all(
      plans.map((plan) => routeLifecycle.commitRouteDelete(plan, actor(), noEnqueue)),
    );
    expect(deleted.filter((result) => result.endpointRemoved)).toHaveLength(1);
    expect(await sql`SELECT id FROM front_routes WHERE endpoint_id = ${row.endpoint_id}`).toHaveLength(0);
    expect(await sql`SELECT id FROM endpoints WHERE id = ${row.endpoint_id}`).toHaveLength(0);
    expect(await sql`SELECT id FROM certificates WHERE endpoint_id = ${row.endpoint_id}`).toHaveLength(0);
    expect(
      await sql`SELECT id FROM dns_records WHERE domain_id = ${domainId} AND name = ${first.hostname}`,
    ).toHaveLength(0);
  });

  test("revocation, CRL and durable jobs roll back together at each persistence boundary, then retry", async () => {
    const route = await create(tlsRequest("atomic-revoke", { tlsMode: "terminate_mtls" }));
    const row = await routeRow(route.id);
    await refreshRouteCrls();
    await makeReady(route.id);
    expect((await enable(route.id)).status).toBe(200);
    await mkdir(join(certDir, route.hostname), { recursive: true });
    await writeFile(
      join(certDir, route.hostname, "fullchain.pem"),
      "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----",
    );
    await writeFile(
      join(certDir, route.hostname, "privkey.pem"),
      "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----",
    );
    const issued = await pki.issueClientCertificate({
      caId: row.client_ca_id,
      subjectCn: "atomic-client",
      keyOwner: { resourceType: "platform", resourceId: "platform" },
    });
    const before = (await policyOf(route.id))!;
    for (const table of ["client_certificates", "private_cas", "operations"]) {
      // An exception AFTER the certificate write, AFTER CRL persistence, or BEFORE durable enqueue.
      const trigger = `fd14_failure_${suffix}`;
      await sql.unsafe(
        `CREATE FUNCTION ${trigger}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected revocation failure'; END $$`,
      );
      await sql.unsafe(
        `CREATE TRIGGER ${trigger} ${table === "operations" ? "BEFORE INSERT" : "AFTER UPDATE"} ON ${table} FOR EACH ROW EXECUTE FUNCTION ${trigger}()`,
      );
      try {
        await expect(
          routeLifecycle.revokeRouteClientCertificate(route.id, issued.certificate.id, actor()),
        ).rejects.toThrow("Failed query");
      } finally {
        await sql.unsafe(`DROP TRIGGER ${trigger} ON ${table}`);
        await sql.unsafe(`DROP FUNCTION ${trigger}()`);
      }
      expect((await pki.getClientCertificate(issued.certificate.id))!.status).toBe("issued");
      expect((await policyOf(route.id))!.policy).toBe(before.policy);
      const l4 = await edgeL4Routes({ policyRoutes: [before], certDir });
      expect(l4.tlsRoutes).toHaveLength(1);
      expect(x509.parseCrl(x509.fromPem(l4.tlsRoutes[0]!.clientCrlPem!, ["X509 CRL"])).revoked).toHaveLength(
        0,
      );
      expect(
        await sql`SELECT id FROM operations WHERE payload->>'reason' = 'client_certificate_revoked' AND payload->'routeIds' ? ${route.id}`,
      ).toHaveLength(0);
    }
    // Pause a real production revocation after its certificate write, while the CRL is uncommitted.
    const gate = await sql.reserve();
    const lock = `fd14-revoke-${suffix}`;
    await gate`SELECT pg_advisory_lock(hashtext(${lock}))`;
    const trigger = `fd14_pause_${suffix}`;
    await sql.unsafe(
      `CREATE FUNCTION ${trigger}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtext('${lock}')); RETURN NEW; END $$`,
    );
    await sql.unsafe(
      `CREATE TRIGGER ${trigger} AFTER UPDATE ON client_certificates FOR EACH ROW EXECUTE FUNCTION ${trigger}()`,
    );
    const revoking = routeLifecycle.revokeRouteClientCertificate(route.id, issued.certificate.id, actor());
    try {
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline) {
        const waiting = await sql`SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`;
        if (waiting.length) break;
        await Bun.sleep(10);
      }
      expect(await sql`SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`).not.toHaveLength(
        0,
      );
      expect((await policyOf(route.id))!.policy).toBe(before.policy);
      expect((await edgeL4Routes({ policyRoutes: [before], certDir })).tlsRoutes).toHaveLength(1);
    } finally {
      await gate`SELECT pg_advisory_unlock(hashtext(${lock}))`;
      gate.release();
      await revoking;
      await sql.unsafe(`DROP TRIGGER ${trigger} ON client_certificates`);
      await sql.unsafe(`DROP FUNCTION ${trigger}()`);
    }
    const after = (await policyOf(route.id))!;
    expect(after.policy).not.toBe(before.policy);
    expect((await edgeL4Routes({ policyRoutes: [before], certDir })).tlsRoutes).toHaveLength(0);
    const current = await edgeL4Routes({ policyRoutes: [after], certDir });
    expect(
      x509
        .parseCrl(x509.fromPem(current.tlsRoutes[0]!.clientCrlPem!, ["X509 CRL"]))
        .revoked.map((entry) => entry.serial),
    ).toContain(issued.certificate.serial);
    const jobs =
      await sql`SELECT * FROM operations WHERE payload->>'reason' = 'client_certificate_revoked' AND payload->'routeIds' ? ${route.id}`;
    expect(jobs.map((job) => job.kind).toSorted()).toEqual(["edge.apply", "edge.drain"]);
    // A fresh worker can discover and process the committed apply without the API enqueue callback.
    const { db } = await import("./db.ts");
    const { operations } = await import("./schema.ts");
    const { eq } = await import("drizzle-orm");
    const [apply] = await db
      .select()
      .from(operations)
      .where(eq(operations.id, jobs.find((job) => job.kind === "edge.apply")!.id));
    const savedRoot = process.env.ARK_EDGE_L4_DIR;
    const savedEdge = process.env.ARK_EDGE_DIR;
    process.env.ARK_EDGE_DIR = join(certDir, "recovered-edge");
    process.env.ARK_EDGE_L4_DIR = certDir;
    try {
      await runOperation("edge.apply", apply!);
      expect((await queued("edge.l4_apply")).length).toBeGreaterThan(0);
    } finally {
      if (savedEdge === undefined) delete process.env.ARK_EDGE_DIR;
      else process.env.ARK_EDGE_DIR = savedEdge;
      if (savedRoot === undefined) delete process.env.ARK_EDGE_L4_DIR;
      else process.env.ARK_EDGE_L4_DIR = savedRoot;
    }
    // Recover a stale, still-unexpired CRL left by an older interrupted revocation.
    const another = await pki.issueClientCertificate({
      caId: row.client_ca_id,
      subjectCn: "recovery-client",
      keyOwner: { resourceType: "platform", resourceId: "platform" },
    });
    await pki.revokeClientCertificate({ id: another.certificate.id });
    const stalePolicy = (await policyOf(route.id))!;
    expect((await edgeL4Routes({ policyRoutes: [stalePolicy], certDir })).omitted[0]!.reason).toMatch(
      /CRL does not cover/,
    );
    expect(await refreshRouteCrls()).toContain(row.client_ca_id);
    expect((await edgeL4Routes({ policyRoutes: [stalePolicy], certDir })).tlsRoutes).toHaveLength(1);
  }, 15_000);
});
