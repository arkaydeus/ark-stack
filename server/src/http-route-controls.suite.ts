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
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, X509Certificate } from "node:crypto";

import {
  createId,
  HTTP_CLIENT_CERTIFICATE_LIMIT,
  planEdge,
  renderCaddyfile,
  servedHttpRoutes,
  type Role,
} from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";

const source = process.env.DATABASE_URL;
if (!source || !/^\/ark_fd23_[a-f0-9]{32}$/.test(new URL(source).pathname))
  throw new Error("Run http-route-controls.test.ts to create the isolated FD-23 database.");

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { sql, db } = await import("./db.ts");
const { claimQueued, edgePlan, runOperation, enqueue } = await import("./coordinator.ts");
const { edgePolicy } = await import("./modules/edge-observe.ts");
const { edgeHttpRoutes } = await import("./modules/edge-routes.ts");
const { routeCrlCovers } = await import("./modules/route-crl.ts");
const { issueClientCertificate, generateCaCrl, revokeClientCertificate } = await import("./modules/pki.ts");
const { buildCsr } = await import("./modules/csr-test-kit.ts");
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
const directory = await mkdtemp(join(tmpdir(), "ark-fd23-"));
const socket = join(directory, "localapi.sock");
const mock = new MockLocalApi({
  backendState: "Running",
  suffix: tailnet,
  self,
  peers: [home],
  reachable: new Set([`${homeIp}:3000`]),
});
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
  delete process.env.ARK_EDGE_RELOAD_URL;
  process.env.ARK_EDGE_DIR = directory;
  process.env.ARK_EDGE_TS_SOCKET = socket;
  await sql`
    INSERT INTO platform_settings (id, public_ipv4) VALUES ('default', '203.0.113.10')
    ON CONFLICT (id) DO UPDATE SET public_ipv4 = '203.0.113.10'
  `;
  await sql`INSERT INTO domain_claims (id, name, ownership_token, status) VALUES (${domainId}, ${zone}, 'ark-own-fd23', 'verified')`;
  owner = await signUp("owner");
  await mock.listen(socket);
  await runOperation(
    "edge.observe",
    (await enqueue({ kind: "edge.observe", targetIds: ["tailnet:edge"], payload: { fixture: suffix } }))!,
  );
});

afterAll(async () => {
  mock.stop();
  await rm(directory, { recursive: true, force: true });
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

  test("malformed stored limits stay closed unless explicitly recovered with step-up", async () => {
    const route = await create(httpRequest("invalid-limit", { rateLimit: { requests: 10, window: "10s" } }));
    await serve(route.id);
    await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
      VALUES (${createId("crt")}, ${(await routeRow(route.id)).endpoint_id}, ${JSON.stringify([route.hostname])}::jsonb, 'issued', now())`;
    const malformed = { requests: -1, window: "10s" };
    await sql`UPDATE front_routes SET rate_limit = ${JSON.stringify(malformed)}::jsonb WHERE id = ${route.id}`;
    const path = `/api/front/routes/${route.id}`;
    expect((await call("PATCH", path, { mtls: true })).status).toBe(200);
    expect((await routeRow(route.id)).rate_limit).toEqual(malformed);
    const omitted = await edgePlan("tailnet", null);
    expect(omitted.omitted).toContainEqual(expect.objectContaining({ id: route.id }));
    const refused = await call("PATCH", path, { rateLimit: null });
    expect([refused.status, refused.body.code]).toEqual([403, "exposure_step_up_required"]);
    expect((await routeRow(route.id)).rate_limit).toEqual(malformed);
    await stepUp("exposure.public", { routeId: route.id, rateLimit: null });
    expect((await call("PATCH", path, { rateLimit: null })).status).toBe(200);
    expect((await renderInput(route.id))?.rateLimit).toBeUndefined();
  });

  test("sparse controls preserve mTLS and reject a stale editor version", async () => {
    const route = await create(httpRequest("version"));
    const path = `/api/front/routes/${route.id}`;
    const on = await call("PATCH", path, { version: route.version, mtls: true });
    expect(on.status).toBe(200);
    const caId = String((await routeRow(route.id)).client_ca_id);
    const rateLimit = { requests: 5, window: "10s" };
    const stale = await call("PATCH", path, { version: route.version, rateLimit });
    expect(stale.status).toBe(409);
    const fresh = await call("PATCH", path, { version: on.body.route.version, rateLimit });
    expect([fresh.status, fresh.body.route.mtls, fresh.body.route.rateLimit]).toEqual([200, true, rateLimit]);
    expect((await routeRow(route.id)).client_ca_id).toBe(caId);
    expect((await caRow(caId)).status).toBe("active");
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

  test("concurrent issuance preserves the cap, the route and the rejected request's grant", async () => {
    const route = await create(httpRequest("mtls-full", { mtls: true }));
    await serve(route.id);
    const caId = String((await routeRow(route.id)).client_ca_id);
    const csrPem = buildCsr({ key: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey }).pem;
    // Use real signed leaves so the planner has to render the exact capacity.
    const seed = await db.transaction(async (tx) => {
      let first = "";
      for (let n = 1; n < HTTP_CLIENT_CERTIFICATE_LIMIT; n++) {
        const row = await issueClientCertificate({ caId, subjectCn: `filler-${n}`, csrPem }, tx);
        if (n === 1) first = row.certificate.id;
      }
      return first;
    });
    const path = `/api/front/routes/${route.id}/client-certificates`;
    const bodies = [
      { name: "laptop", csrPem },
      { name: "phone", csrPem },
    ];
    for (const body of bodies) await stepUp("credential.rotate", { routeId: route.id, ...body });
    const grants = await openGrants();
    const responses = await Promise.all(bodies.map((body) => call("POST", path, body)));
    expect(responses.map(({ status }) => status).toSorted()).toEqual([201, 409]);
    expect(await openGrants()).toBe(grants - 1);
    expect((await renderInput(route.id))?.clientAuth?.certificates).toHaveLength(
      HTTP_CLIENT_CERTIFICATE_LIMIT,
    );
    const endpoint = String((await routeRow(route.id)).endpoint_id);
    await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
      VALUES (${createId("crt")}, ${endpoint}, ${JSON.stringify([route.hostname])}::jsonb, 'issued', now())`;
    expect(servedHttpRoutes(await edgePlan("tailnet", null)).some(({ id }) => id === route.id)).toBe(true);
    await revokeClientCertificate({ id: seed, reason: "cessationOfOperation" });
    await generateCaCrl({ caId });
    const retry = await call("POST", path, bodies[responses.findIndex(({ status }) => status === 409)]);
    expect(retry.status).toBe(201);
    expect(await openGrants()).toBe(grants - 2);
  }, 30_000);

  test("a running apply has a queued successor that renders the new certificate and policy", async () => {
    const route = await create(httpRequest("inflight", { mtls: true }));
    await serve(route.id);
    const endpoint = String((await routeRow(route.id)).endpoint_id);
    await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
      VALUES (${createId("crt")}, ${endpoint}, ${JSON.stringify([route.hostname])}::jsonb, 'issued', now())`;
    await settleApplies();
    await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
    const running = (await claimQueued({ exactKinds: ["edge.apply"], limit: 1 })).rows[0]!;
    const blocked = Promise.withResolvers<void>();
    const reached = Promise.withResolvers<void>();
    const rendered: string[] = [];
    const caddy = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(request) {
        if (new URL(request.url).pathname === "/adapt") {
          rendered.push(await request.text());
          if (rendered.length === 1) {
            reached.resolve();
            await blocked.promise;
          }
          return Response.json({ result: {} });
        }
        return Response.json({});
      },
    });
    process.env.ARK_EDGE_RELOAD_URL = caddy.url.origin;
    const applying = runOperation("edge.apply", running);
    try {
      await Promise.race([
        reached.promise,
        applying.then(() => {
          throw new Error("Apply did not reach /adapt.");
        }),
      ]);
      await stepUp("credential.rotate", { routeId: route.id, name: "during-apply" });
      const issued = await call("POST", `/api/front/routes/${route.id}/client-certificates`, {
        name: "during-apply",
      });
      expect(issued.status).toBe(201);
      expect(
        (await call("PATCH", `/api/front/routes/${route.id}`, { rateLimit: { requests: 7, window: "1m" } }))
          .status,
      ).toBe(200);
      expect(await queuedApplies()).toBe(1);
      const leaf = (issued.body.certPem as string).trim();
      expect(rendered[0]).not.toContain(leaf);
      expect(rendered[0]).not.toContain("events 7");
      blocked.resolve();
      await applying;
      await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${running.id}`;
      const successor = (await claimQueued({ exactKinds: ["edge.apply"], limit: 1 })).rows[0]!;
      expect(successor.id).not.toBe(running.id);
      await runOperation("edge.apply", successor);
      expect(rendered[1]).toContain(leaf);
      expect(rendered[1]).toContain("events 7");
      await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${successor.id}`;
    } finally {
      blocked.resolve();
      await applying.catch(() => undefined);
      delete process.env.ARK_EDGE_RELOAD_URL;
      await caddy.stop(true);
    }
  });

  test("a failed queue insert rolls back certificate, key, audit and grant consumption", async () => {
    const route = await create(httpRequest("queue-failure", { mtls: true }));
    const path = `/api/front/routes/${route.id}/client-certificates`;
    const body = { name: "laptop" };
    await settleApplies();
    await stepUp("credential.rotate", { routeId: route.id, ...body });
    const grants = await openGrants();
    const [{ count: keys }] = await sql`SELECT count(*) FROM secrets WHERE kind = 'pki.client_key'`;
    await sql`CREATE FUNCTION fd23_refuse_apply() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.kind = 'edge.apply' THEN RAISE EXCEPTION 'fixture refused edge apply'; END IF; RETURN NEW; END $$`;
    await sql`CREATE TRIGGER fd23_refuse_apply BEFORE INSERT ON operations FOR EACH ROW EXECUTE FUNCTION fd23_refuse_apply()`;
    try {
      expect((await call("POST", path, body)).status).toBe(500);
    } finally {
      await sql`DROP TRIGGER fd23_refuse_apply ON operations`;
      await sql`DROP FUNCTION fd23_refuse_apply()`;
    }
    expect((await call("GET", path)).body.certificates).toEqual([]);
    expect(
      await sql`SELECT id FROM audit_events WHERE resource_id = ${route.id} AND action = 'front_route.client_certificate_issue'`,
    ).toHaveLength(0);
    const [remainingKeys] = await sql`SELECT count(*) FROM secrets WHERE kind = 'pki.client_key'`;
    expect(remainingKeys?.count).toBe(keys);
    expect(await openGrants()).toBe(grants);
    expect(await queuedApplies()).toBe(0);
    expect((await call("POST", path, body)).status).toBe(201);
  });

  test("missing or unreadable HTTP CRLs are repaired by observation and never block L4 apply", async () => {
    const route = await create(httpRequest("crl-repair", { mtls: true }));
    await serve(route.id);
    const { client_ca_id: caId, endpoint_id: endpointId } = await routeRow(route.id);
    await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
      VALUES (${createId("crt")}, ${endpointId}, ${JSON.stringify([route.hostname])}::jsonb, 'issued', now())`;
    await stepUp("credential.rotate", { routeId: route.id, name: "laptop" });
    expect(
      (await call("POST", `/api/front/routes/${route.id}/client-certificates`, { name: "laptop" })).status,
    ).toBe(201);
    for (const pem of [null, "unreadable"]) {
      await settleApplies();
      await sql`UPDATE private_cas SET crl_pem = ${pem} WHERE id = ${caId}`;
      expect((await renderInput(route.id))?.clientAuth?.certificates).toEqual([]);
      await runOperation("edge.l4_apply", await enqueue({ kind: "edge.l4_apply", targetIds: ["platform"] }));
      expect((await caRow(caId)).crl_pem).toBe(pem);
      await runOperation(
        "edge.observe",
        await enqueue({ kind: "edge.observe", targetIds: ["tailnet:edge"], payload: { fixture: suffix } }),
      );
      expect(await queuedApplies()).toBe(1);
      expect((await renderInput(route.id))?.clientAuth?.certificates).toHaveLength(1);
    }
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
