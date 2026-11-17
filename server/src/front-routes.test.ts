// HTTP route lifecycle through the real app, Better Auth sessions, step-up grants, the coordinator
// and a mocked edge LocalAPI (front door §3.3, §3.13, §3.14, FD-08):
//
// - authorisation: owners only (MFA, step-up) for create/update/delete/enable/disable; every role lists;
// - DNS: a verified domain is required; apex and www get A records, AAAA only when allowed;
// - the access-mode guard until FD-11, and `exposure.public` grants that validation never consumes;
// - the state machine draft -> awaiting_acl -> awaiting_dns -> issuing_certificate -> ready, with a
//   stub DNS resolver proving certificates are requested only once the A record resolves to
//   `public_ipv4`, and a fake lego issuing a real certificate; enable is refused before ready;
// - audit events for every route action.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { createId, parseEnvFile, type Role } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";

import { testOpenSsl } from "./modules/test-openssl.ts";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { db, sql } = await import("./db.ts");
const { runOperation, setDnsResolver } = await import("./coordinator.ts");
const { operations } = await import("./schema.ts");
const { MockLocalApi } = await import("./mock-localapi.ts");
const { eq } = await import("drizzle-orm");

const origin = new URL(process.env.BETTER_AUTH_URL ?? "http://localhost:3000").origin;
const password = "Route-Test-Password-123!";
const suffix = createId("t").slice(2, 10);
const tailnet = ".tail1234.ts.net";
const publicIpv4 = "203.0.113.10";
const publicIpv6 = "2001:db8::10";
const zone = `fd08-${suffix}.com`;
const flowZone = `fd08-flow-${suffix}.com`;
const pendingZone = `fd08-pending-${suffix}.com`;
const homeIp = "100.101.102.103";
const self = { id: `nEDGE${suffix}`, name: "ark-edge", ips: ["100.64.0.1"], tags: ["tag:ark-edge"] };
const home = { id: `nHOME${suffix}`, name: "home", ips: [homeIp] };
const nas = { id: `nNAS${suffix}`, name: "nas", ips: ["100.88.1.20"] };
const homeTarget = `home${tailnet}`;

type Actor = { userId: string; cookie: string };
const actors = {} as Record<Role | "ownerWithoutMfa", Actor>;
const domainIds = { verified: createId("dom"), flow: createId("dom"), pending: createId("dom") };
const tokens = { verified: "ark-own-verified", flow: "ark-own-flow", pending: "ark-own-pending" };
const startedAt = new Date();
const socket = join(tmpdir(), `ark-fd08-${suffix}.sock`);
const mock = new MockLocalApi({
  backendState: "Running",
  suffix: tailnet,
  self,
  peers: [home, nas],
  reachable: new Set(),
});
const savedEnv: Record<string, string | undefined> = {};
let savedSettings: Record<string, unknown> | undefined;
let certDir = "";

async function signUp(role: Role, mfa: boolean): Promise<Actor> {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `Route ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
    { method: "email-password" },
  );
  await ctx.internalAdapter.linkAccount({
    userId: created.id,
    providerId: "credential",
    accountId: created.id,
    password: await ctx.password.hash(password),
  });
  await sql`INSERT INTO platform_access (user_id, role) VALUES (${created.id}, ${role})`;
  if (mfa) {
    await sql`
      UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute'
      WHERE id = ${created.id}
    `;
  }
  const session = await ctx.internalAdapter.createSession(created.id, false, { origin: "admin" });
  const signed = `${session.token}.${await makeSignature(session.token, ctx.secret)}`;
  return { userId: created.id, cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(signed)}` };
}

type Json = Record<string, any>;

async function call(actor: Actor | null, method: string, path: string, body?: unknown) {
  const response = await app.request(path, {
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

async function stepUp(actor: Actor, action: string, request: Record<string, unknown>) {
  const response = await call(actor, "POST", "/api/step-up", { password, action, request });
  expect(response.status).toBe(200);
}

async function openGrants(actor: Actor) {
  const [row] = await sql`
    SELECT count(*)::int AS n FROM step_up_grants WHERE user_id = ${actor.userId} AND consumed_at IS NULL
  `;
  return Number(row?.n ?? 0);
}

function routeRequest(hostname: string, extra: Record<string, unknown> = {}) {
  return { kind: "http", hostname, target: homeTarget, targetPort: 3000, accessMode: "public", ...extra };
}

/** Mints the matching `exposure.public` grant and creates the route. */
async function createRoute(hostname: string, extra: Record<string, unknown> = {}) {
  const request = routeRequest(hostname, extra);
  await stepUp(actors.owner, "exposure.public", request);
  const response = await call(actors.owner, "POST", "/api/front/routes", request);
  expect([hostname, response.status, response.body.error]).toEqual([hostname, 201, undefined]);
  return response.body as { route: Json; records: Json[]; acl: Json; operationId: string };
}

async function routeRow(id: string) {
  const [row] = await sql`SELECT * FROM front_routes WHERE id = ${id}`;
  return row as Json | undefined;
}

async function records(hostname: string): Promise<Json[]> {
  return [
    ...(await sql`
    SELECT type, relative_name, expected_value, required FROM dns_records WHERE name = ${hostname} ORDER BY type
  `),
  ];
}

async function auditActions(routeId: string) {
  const rows = await sql`
    SELECT action, actor_id, detail FROM audit_events
    WHERE resource_type = 'front_route' AND resource_id = ${routeId}
    ORDER BY created_at, action
  `;
  return rows as unknown as Array<{ action: string; actor_id: string | null; detail: Json }>;
}

/** Runs the oldest queued operation of a kind (optionally for one target) exactly as a worker would. */
async function runQueued(kind: string, targetId?: string) {
  const rows = await sql`
    SELECT id FROM operations
    WHERE kind = ${kind} AND status = 'queued'
      AND (${targetId ?? null}::text IS NULL OR target_ids ? ${targetId ?? ""})
    ORDER BY created_at LIMIT 1
  `;
  expect([kind, targetId, rows.length]).toEqual([kind, targetId, 1]);
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, String(rows[0]!.id)));
  const result = await runOperation(kind as never, operation!);
  await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${operation!.id}`;
  return result;
}

async function queuedCount(kind: string, targetId: string) {
  const [row] = await sql`
    SELECT count(*)::int AS n FROM operations WHERE kind = ${kind} AND status = 'queued' AND target_ids ? ${targetId}
  `;
  return Number(row?.n ?? 0);
}

let resolvedA: string[] = [];

beforeAll(async () => {
  process.env.PATH = `${dirname(testOpenSsl())}:${process.env.PATH}`;
  for (const key of [
    "ARK_DNS_STUB",
    "ARK_EDGE_TS_SOCKET",
    "ARK_EDGE_RELOAD_URL",
    "ARK_LEGO_BIN",
    "ARK_ACME_EMAIL",
    "ARK_ACME_STAGING",
    "ARK_CERT_DIR",
    "ARK_LEGO_ARGS_FILE",
  ])
    savedEnv[key] = process.env[key];
  // Real lookups through the stub resolver below; never the "accept everything" DNS stub.
  delete process.env.ARK_DNS_STUB;
  delete process.env.ARK_EDGE_RELOAD_URL;
  process.env.ARK_EDGE_TS_SOCKET = socket;
  certDir = await mkdtemp(join(tmpdir(), "ark-fd08-certs-"));
  process.env.ARK_CERT_DIR = join(certDir, "certs");
  process.env.ARK_ACME_EMAIL = "fixture@example.test";
  process.env.ARK_ACME_STAGING = "0";
  process.env.ARK_LEGO_BIN = join(certDir, "lego");
  process.env.ARK_LEGO_ARGS_FILE = join(certDir, "lego-args");
  // A fake lego that writes a real certificate for the requested hostname; no CA is contacted.
  await Bun.write(
    process.env.ARK_LEGO_BIN,
    `#!/bin/sh
set -eu
printf '%s\\n' "$@" > "$ARK_LEGO_ARGS_FILE"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --path) output="$2"; shift 2 ;;
    --domains) hostname="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$output/certificates"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=$hostname" -addext "subjectAltName=DNS:$hostname" -keyout "$output/certificates/$hostname.key" -out "$output/certificates/$hostname.crt" 2>/dev/null
`,
  );
  await chmod(process.env.ARK_LEGO_BIN, 0o755);
  setDnsResolver({
    txt: async (name) => {
      for (const [key, domain] of [
        ["verified", zone],
        ["flow", flowZone],
        ["pending", pendingZone],
      ] as const)
        if (name === `_ark-stack.${domain}`) return [[tokens[key]]];
      return [];
    },
    a: async () => resolvedA,
    aaaa: async () => [],
    mx: async () => [],
    cname: async () => [],
  });

  [savedSettings] =
    await sql`SELECT public_ipv4, public_ipv6, ipv6_status FROM platform_settings WHERE id = 'default'`;
  await sql`
    INSERT INTO platform_settings (id, public_ipv4, public_ipv6, ipv6_status)
    VALUES ('default', ${publicIpv4}, ${publicIpv6}, 'unchecked')
    ON CONFLICT (id) DO UPDATE SET public_ipv4 = ${publicIpv4}, public_ipv6 = ${publicIpv6}, ipv6_status = 'unchecked'
  `;
  for (const [key, name, status] of [
    ["verified", zone, "verified"],
    ["flow", flowZone, "verified"],
    ["pending", pendingZone, "awaiting_dns"],
  ] as const) {
    await sql`
      INSERT INTO domain_claims (id, name, ownership_token, status)
      VALUES (${domainIds[key]}, ${name}, ${tokens[key]}, ${status})
    `;
    await sql`
      INSERT INTO dns_records (id, domain_id, type, name, relative_name, expected_value, purpose, required)
      VALUES (${createId("dns")}, ${domainIds[key]}, 'TXT', ${`_ark-stack.${name}`}, '_ark-stack',
        ${tokens[key]}, 'Installation-bound domain ownership proof', true)
    `;
  }
  actors.owner = await signUp("owner", true);
  actors.operator = await signUp("operator", true);
  actors.viewer = await signUp("viewer", true);
  actors.ownerWithoutMfa = await signUp("owner", false);

  // A complete, fresh edge observation for the target validator.
  await mock.listen(socket);
  await sql`DELETE FROM tailnet_nodes WHERE source = 'edge'`;
  await sql`DELETE FROM tailnet_snapshots WHERE source = 'edge'`;
  await sql`UPDATE operations SET status = 'cancelled' WHERE kind = 'edge.observe' AND status = 'queued'`;
  await runOperation(
    "edge.observe",
    (await (
      await import("./coordinator.ts")
    ).enqueue({
      kind: "edge.observe",
      targetIds: ["tailnet:edge"],
      payload: { fixture: suffix },
    }))!,
  );
});

afterAll(async () => {
  setDnsResolver();
  mock.stop();
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  await rm(certDir, { recursive: true, force: true });
  const ids = Object.values(domainIds);
  const routeRows = await sql`
    SELECT r.id FROM front_routes r JOIN endpoints e ON e.id = r.endpoint_id WHERE e.domain_id IN ${sql(ids)}
  `;
  const routeIds = routeRows.map((row) => String(row.id));
  if (routeIds.length) await sql`DELETE FROM front_routes WHERE id IN ${sql(routeIds)}`;
  await sql`DELETE FROM audit_events WHERE resource_type = 'front_route' AND (resource_id IN ${sql(routeIds.length ? routeIds : ["-"])} OR created_at >= ${startedAt.toISOString()}::timestamptz)`;
  await sql`DELETE FROM certificates WHERE endpoint_id IN (SELECT id FROM endpoints WHERE domain_id IN ${sql(ids)})`;
  await sql`DELETE FROM endpoints WHERE domain_id IN ${sql(ids)}`;
  await sql`DELETE FROM domain_claims WHERE id IN ${sql(ids)}`;
  await sql`DELETE FROM operation_steps WHERE operation_id IN (SELECT id FROM operations WHERE created_at >= ${startedAt.toISOString()}::timestamptz)`;
  await sql`DELETE FROM operations WHERE created_at >= ${startedAt.toISOString()}::timestamptz`;
  await sql`DELETE FROM tailnet_nodes WHERE source = 'edge'`;
  await sql`DELETE FROM tailnet_snapshots WHERE source = 'edge'`;
  const userIds = Object.values(actors).map((actor) => actor.userId);
  if (userIds.length) {
    await sql`DELETE FROM audit_events WHERE actor_id IN ${sql(userIds)}`;
    await sql`DELETE FROM step_up_grants WHERE user_id IN ${sql(userIds)}`;
    await sql`DELETE FROM "user" WHERE id IN ${sql(userIds)}`;
  }
  if (savedSettings) {
    await sql`
      UPDATE platform_settings SET public_ipv4 = ${savedSettings.public_ipv4 as string | null},
        public_ipv6 = ${savedSettings.public_ipv6 as string | null}, ipv6_status = ${savedSettings.ipv6_status as string}
      WHERE id = 'default'
    `;
  }
});

describe("authorisation", () => {
  test("operators get 403 on every mutation even with a matching grant; viewers too; every role lists", async () => {
    const { route } = await createRoute(`matrix.${zone}`);
    const id = route.id as string;
    const mutations: Array<[string, string, Record<string, unknown>, string | null]> = [
      ["POST", "/api/front/routes", routeRequest(`other.${zone}`), "exposure.public"],
      ["PATCH", `/api/front/routes/${id}`, { targetPort: 3001 }, "exposure.public"],
      ["DELETE", `/api/front/routes/${id}`, {}, "resource.delete"],
      ["POST", `/api/front/routes/${id}/enable`, {}, "exposure.public"],
      ["POST", `/api/front/routes/${id}/disable`, {}, null],
    ];
    const matrix: string[] = [];
    for (const role of ["operator", "viewer"] as const) {
      for (const [method, path, body, action] of mutations) {
        // Operators can mint grants; the owner gate still comes first. Viewers cannot mint any.
        if (role === "operator" && action) {
          const request =
            path === "/api/front/routes"
              ? body
              : action === "resource.delete" || path.endsWith("/enable")
                ? { routeId: id }
                : { routeId: id, ...body };
          await stepUp(actors.operator, action, request);
        }
        const response = await call(actors[role], method, path, body);
        matrix.push(`${role} ${method} ${path.replace(id, ":id")} ${response.status} ${response.body.error}`);
      }
    }
    expect(matrix).toEqual(
      ["operator", "viewer"].flatMap((role) =>
        mutations.map(
          ([method, path]) => `${role} ${method} ${path.replace(id, ":id")} 403 Owner access is required.`,
        ),
      ),
    );
    for (const role of ["owner", "operator", "viewer"] as const) {
      const list = await call(actors[role], "GET", "/api/front/routes");
      expect([role, list.status]).toEqual([role, 200]);
      expect((list.body.routes as Json[]).some((item) => item.id === id)).toBe(true);
      const one = await call(actors[role], "GET", `/api/front/routes/${id}`);
      expect(one.body.route).toMatchObject({ id, hostname: `matrix.${zone}`, listenPort: 443 });
    }
    expect((await call(null, "GET", "/api/front/routes")).status).toBe(401);
    expect((await call(actors.owner, "GET", "/api/front/routes/rt_missing")).status).toBe(404);
    // The route is untouched by all the refused calls.
    expect(await routeRow(id)).toMatchObject({ target_port: 3000, enabled: false });
  });

  test("owners need MFA", async () => {
    const response = await call(
      actors.ownerWithoutMfa,
      "POST",
      "/api/front/routes",
      routeRequest(`nomfa.${zone}`),
    );
    expect(response.status).toBe(403);
    expect(response.body.error).toMatch(/MFA/);
  });
});

describe("domains and DNS records", () => {
  test("a hostname under an unverified domain, or under no domain, returns 422 without consuming the grant", async () => {
    for (const hostname of [`www.${pendingZone}`, `www.unclaimed-${suffix}.com`]) {
      const request = routeRequest(hostname);
      await stepUp(actors.owner, "exposure.public", request);
      const before = await openGrants(actors.owner);
      const response = await call(actors.owner, "POST", "/api/front/routes", request);
      expect([hostname, response.status]).toEqual([hostname, 422]);
      expect(response.body.error).toMatch(/not verified|No domain claim/);
      expect(await openGrants(actors.owner)).toBe(before);
    }
  });

  test("the apex and www under a verified domain both work and get A records only (IPv6 unchecked)", async () => {
    for (const [hostname, relative] of [
      [zone, "@"],
      [`www.${zone}`, "www"],
    ] as const) {
      const created = await createRoute(hostname, hostname === zone ? { redirectTo: `www.${zone}` } : {});
      expect(created.records).toEqual([
        { type: "A", name: hostname, relativeName: relative, value: publicIpv4, ttl: 300, required: true },
      ]);
      expect(await records(hostname)).toEqual([
        { type: "A", relative_name: relative, expected_value: publicIpv4, required: true },
      ]);
      expect(created.route).toMatchObject({
        hostname,
        status: "awaiting_acl",
        enabled: false,
        accessMode: "public",
        redirectTo: hostname === zone ? `www.${zone}` : null,
        target: { input: homeTarget, stableId: home.id, ip: homeIp, port: 3000 },
        dns: { endpointStatus: "awaiting_dns" },
      });
      expect(created.acl).toMatchObject({ scope: "route", routeId: created.route.id });
      expect(created.acl.snippet).toContain(`"ark-rt-home": "${homeIp}"`);
      expect(created.acl.snippet).toContain('"ip": ["tcp:3000"]');
    }
  });

  test("AAAA only when ipv6_status = passed and the domain's aaaa_enabled is on", async () => {
    try {
      await sql`UPDATE platform_settings SET ipv6_status = 'passed' WHERE id = 'default'`;
      const v6 = await createRoute(`v6.${zone}`);
      expect(v6.records.map((record) => [record.type, record.value, record.required])).toEqual([
        ["A", publicIpv4, true],
        ["AAAA", publicIpv6, true],
      ]);
      expect((await records(`v6.${zone}`)).map((row) => row.type)).toEqual(["A", "AAAA"]);
      await sql`UPDATE domain_claims SET aaaa_enabled = false WHERE id = ${domainIds.verified}`;
      const off = await createRoute(`v6off.${zone}`);
      expect(off.records.map((record) => record.type)).toEqual(["A"]);
    } finally {
      await sql`UPDATE platform_settings SET ipv6_status = 'unchecked' WHERE id = 'default'`;
      await sql`UPDATE domain_claims SET aaaa_enabled = true WHERE id = ${domainIds.verified}`;
    }
    const failed = await createRoute(`v6failed.${zone}`);
    expect(failed.records.map((record) => record.type)).toEqual(["A"]);
  });

  test("a hostname that already has a route, or belongs to another endpoint, is a conflict", async () => {
    const request = routeRequest(`www.${zone}`);
    await stepUp(actors.owner, "exposure.public", request);
    const response = await call(actors.owner, "POST", "/api/front/routes", request);
    expect(response.status).toBe(409);
  });
});

describe("access mode guard until FD-11", () => {
  test("creating with sso, or without an access mode (schema default sso), is refused", async () => {
    for (const request of [
      routeRequest(`sso.${zone}`, { accessMode: "sso" }),
      (({ accessMode: _mode, ...rest }) => rest)(routeRequest(`default.${zone}`)),
    ]) {
      await stepUp(actors.owner, "exposure.public", request);
      const before = await openGrants(actors.owner);
      const response = await call(actors.owner, "POST", "/api/front/routes", request);
      expect(response.status).toBe(422);
      expect(response.body.error).toMatch(/not supported yet.*FD-11/);
      expect(await openGrants(actors.owner)).toBe(before);
    }
    expect(
      await sql`SELECT 1 FROM endpoints WHERE hostname IN (${`sso.${zone}`}, ${`default.${zone}`})`,
    ).toHaveLength(0);
  });

  test("an sso route cannot be enabled even when ready, and a public route cannot be switched into sso", async () => {
    const { route } = await createRoute(`legacy-sso.${zone}`);
    // An sso row can only exist through the schema default (for example, a pre-FD-08 row).
    await sql`UPDATE front_routes SET access_mode = 'sso', status = 'ready' WHERE id = ${route.id}`;
    await stepUp(actors.owner, "exposure.public", { routeId: route.id });
    const before = await openGrants(actors.owner);
    const enable = await call(actors.owner, "POST", `/api/front/routes/${route.id}/enable`);
    expect(enable.status).toBe(422);
    expect(enable.body.error).toMatch(/"sso" is not supported yet.*cannot be enabled/);
    expect(await openGrants(actors.owner)).toBe(before);
    expect((await routeRow(route.id))?.enabled).toBe(false);

    const publicRoute = await createRoute(`to-sso.${zone}`);
    const update = await call(actors.owner, "PATCH", `/api/front/routes/${publicRoute.route.id}`, {
      accessMode: "sso",
    });
    expect(update.status).toBe(422);
    expect(update.body.error).toMatch(/not supported yet/);
    await sql`UPDATE front_routes SET status = 'ready', enabled = true WHERE id = ${publicRoute.route.id}`;
    const enabledUpdate = await call(actors.owner, "PATCH", `/api/front/routes/${publicRoute.route.id}`, {
      accessMode: "sso",
    });
    expect(enabledUpdate.status).toBe(422);
    expect((await routeRow(publicRoute.route.id))?.access_mode).toBe("public");
  });
});

describe("exposure.public grants", () => {
  test("create needs a grant bound to the exact request; a validation failure does not consume it", async () => {
    const request = routeRequest(`grant.${zone}`);
    const none = await call(actors.owner, "POST", "/api/front/routes", request);
    expect(none.status).toBe(403);
    expect(none.body.error).toMatch(/exposure\.public/);
    // A grant for a different request does not match.
    await stepUp(actors.owner, "exposure.public", { ...request, targetPort: 3001 });
    expect((await call(actors.owner, "POST", "/api/front/routes", request)).status).toBe(403);
    // Matching grants, but the target is not a peer / the port is out of range: 422, grant kept.
    for (const invalid of [
      { ...request, target: `ghost${tailnet}` },
      { ...request, target: "172.17.0.1" },
      { ...request, targetPort: 70000 },
      { ...request, target: `nas${tailnet}`, targetPort: 22 },
      { ...request, redirectTo: "www.elsewhere.com" },
    ]) {
      await stepUp(actors.owner, "exposure.public", invalid);
      const before = await openGrants(actors.owner);
      const response = await call(actors.owner, "POST", "/api/front/routes", invalid);
      expect([JSON.stringify(invalid), response.status]).toEqual([JSON.stringify(invalid), 422]);
      expect(await openGrants(actors.owner)).toBe(before);
    }
    await stepUp(actors.owner, "exposure.public", request);
    const before = await openGrants(actors.owner);
    const created = await call(actors.owner, "POST", "/api/front/routes", request);
    expect(created.status).toBe(201);
    expect(await openGrants(actors.owner)).toBe(before - 1);
    // Replaying the same request is refused by validation (the hostname has a route) before any
    // grant is looked at, so a stale replay cannot burn a fresh grant either.
    expect((await call(actors.owner, "POST", "/api/front/routes", request)).status).toBe(409);
  });

  test("loosening updates need a grant; tightening updates do not", async () => {
    const { route } = await createRoute(`loosen.${zone}`);
    const id = route.id as string;
    const tighten = await call(actors.owner, "PATCH", `/api/front/routes/${id}`, {
      redirectTo: `www.${zone}`,
    });
    expect(tighten.status).toBe(200);
    expect(tighten.body.loosening).toEqual([]);
    expect(tighten.body.route.redirectTo).toBe(`www.${zone}`);

    for (const change of [{ target: `nas${tailnet}` }, { targetPort: 8080 }, { redirectTo: null }]) {
      const refused = await call(actors.owner, "PATCH", `/api/front/routes/${id}`, change);
      expect([JSON.stringify(change), refused.status]).toEqual([JSON.stringify(change), 403]);
    }
    // A matching grant with an invalid value stays unconsumed.
    const invalid = { target: `ghost${tailnet}` };
    await stepUp(actors.owner, "exposure.public", { routeId: id, ...invalid });
    const before = await openGrants(actors.owner);
    expect((await call(actors.owner, "PATCH", `/api/front/routes/${id}`, invalid)).status).toBe(422);
    expect(await openGrants(actors.owner)).toBe(before);

    const change = { target: `nas${tailnet}`, targetPort: 8080 };
    await stepUp(actors.owner, "exposure.public", { routeId: id, ...change });
    const updated = await call(actors.owner, "PATCH", `/api/front/routes/${id}`, change);
    expect(updated.status).toBe(200);
    expect(updated.body.loosening).toEqual(["target", "targetPort"]);
    expect(updated.body.route).toMatchObject({
      status: "awaiting_acl",
      target: { input: `nas${tailnet}`, stableId: nas.id, ip: "100.88.1.20", port: 8080 },
    });
    const actions = (await auditActions(id)).map((row) => row.action);
    expect(actions.filter((action) => action === "front_route.update")).toHaveLength(2);
  });

  test("enable without a matching grant returns 403 on a ready route", async () => {
    const { route } = await createRoute(`enable-grant.${zone}`);
    await sql`UPDATE front_routes SET status = 'ready' WHERE id = ${route.id}`;
    const refused = await call(actors.owner, "POST", `/api/front/routes/${route.id}/enable`);
    expect(refused.status).toBe(403);
    await stepUp(actors.owner, "exposure.public", { routeId: "rt_other" });
    expect((await call(actors.owner, "POST", `/api/front/routes/${route.id}/enable`)).status).toBe(403);
    expect((await routeRow(route.id))?.enabled).toBe(false);
  });
});

describe("state machine walkthrough", () => {
  test("draft -> awaiting_acl -> awaiting_dns -> issuing_certificate -> ready; enable refused before ready", async () => {
    const hostname = `www.${flowZone}`;
    const trail: string[] = [];
    const note = async (id: string, step: string) => {
      const row = await routeRow(id);
      trail.push(`${step}: ${row?.status}${row?.enabled ? " (enabled)" : ""}`);
      return row!;
    };
    const tryEnable = async (id: string) => {
      await stepUp(actors.owner, "exposure.public", { routeId: id });
      const before = await openGrants(actors.owner);
      const response = await call(actors.owner, "POST", `/api/front/routes/${id}/enable`);
      if (response.status !== 200) expect(await openGrants(actors.owner)).toBe(before);
      return response;
    };

    // 1. Create: the row is written as draft and handed to the lifecycle once the ACL snippet exists.
    const created = await createRoute(hostname);
    const id = created.route.id as string;
    const [endpoint] = await sql`SELECT id FROM endpoints WHERE hostname = ${hostname}`;
    const endpointId = String(endpoint!.id);
    expect((await auditActions(id)).map((row) => [row.action, row.detail.status ?? row.detail.to])).toEqual([
      ["front_route.create", "draft"],
      ["front_route.awaiting_acl", "awaiting_acl"],
    ]);
    await note(id, "created");
    let enable = await tryEnable(id);
    expect(enable.status).toBe(409);
    expect(enable.body.error).toMatch(/awaiting_acl; it can be enabled once it is ready/);

    // 2. The edge-netns probe fails until the tailnet grant exists: still awaiting_acl.
    await runQueued("edge.observe");
    expect((await note(id, "probe refused")).last_error).toMatch(
      /cannot open TCP to 100\.101\.102\.103:3000/,
    );
    expect(await queuedCount("certificate.issue", endpointId)).toBe(0);

    // 3. The probe passes: awaiting_dns, and domain.verify is queued.
    mock.state.reachable.add(`${homeIp}:3000`);
    await sql`UPDATE operations SET status = 'cancelled' WHERE kind = 'edge.observe' AND status = 'queued'`;
    await runOperation(
      "edge.observe",
      (await (
        await import("./coordinator.ts")
      ).enqueue({
        kind: "edge.observe",
        targetIds: ["tailnet:edge"],
        payload: { step: "probe-ok" },
      }))!,
    );
    expect((await note(id, "probe passed")).status).toBe("awaiting_dns");
    expect(await queuedCount("domain.verify", domainIds.flow)).toBe(1);

    // 4. DNS does not resolve to public_ipv4 yet: no certificate is requested.
    resolvedA = ["198.51.100.7"];
    await runQueued("domain.verify", domainIds.flow);
    const waiting = await note(id, "A -> 198.51.100.7");
    expect(waiting.status).toBe("awaiting_dns");
    expect(waiting.last_error).toBe(
      `Waiting for DNS: A ${hostname} must resolve to ${publicIpv4} (observed: 198.51.100.7).`,
    );
    expect(await queuedCount("certificate.issue", endpointId)).toBe(0);
    resolvedA = [];
    await call(actors.owner, "POST", `/api/domains/${domainIds.flow}/verify`);
    await runQueued("domain.verify", domainIds.flow);
    expect((await note(id, "A -> nothing")).last_error).toMatch(/observed: nothing\)\.$/);
    expect(await queuedCount("certificate.issue", endpointId)).toBe(0);
    enable = await tryEnable(id);
    expect(enable.status).toBe(409);

    // 5. The A record resolves to public_ipv4: issuing_certificate, and only now certificate.issue.
    resolvedA = [publicIpv4];
    await call(actors.owner, "POST", `/api/domains/${domainIds.flow}/verify`);
    await runQueued("domain.verify", domainIds.flow);
    expect((await note(id, `A -> ${publicIpv4}`)).status).toBe("issuing_certificate");
    expect(await queuedCount("certificate.issue", endpointId)).toBe(1);
    enable = await tryEnable(id);
    expect(enable.status).toBe(409);
    expect(enable.body.error).toMatch(/issuing_certificate/);

    // 6. The certificate is issued (fake lego); edge.observe is queued for the fresh probe.
    await sql`UPDATE operations SET status = 'cancelled' WHERE kind = 'edge.observe' AND status = 'queued'`;
    await runQueued("certificate.issue", endpointId);
    const legoArgs = await Bun.file(process.env.ARK_LEGO_ARGS_FILE!).text();
    expect(legoArgs).toContain(hostname);
    const [certificate] =
      await sql`SELECT status, issuer FROM certificates WHERE endpoint_id = ${endpointId}`;
    expect(certificate).toEqual({ status: "issued", issuer: "letsencrypt" });
    expect((await note(id, "certificate issued")).status).toBe("issuing_certificate");

    // 7. The observer's probe passes with an issued certificate: ready.
    await runQueued("edge.observe");
    expect((await note(id, "probe with certificate")).status).toBe("ready");

    // 8. Enable (exposure.public grant), disable (no grant), delete (resource.delete grant).
    enable = await tryEnable(id);
    expect(enable.status).toBe(200);
    expect(enable.body.route).toMatchObject({ enabled: true, status: "ready", serving: true });
    await note(id, "enable");
    const disable = await call(actors.owner, "POST", `/api/front/routes/${id}/disable`);
    expect(disable.status).toBe(200);
    expect(disable.body.route.enabled).toBe(false);
    expect(await queuedCount("edge.drain", "edge:drain")).toBeGreaterThanOrEqual(1);
    await note(id, "disable");
    expect((await call(actors.owner, "DELETE", `/api/front/routes/${id}`)).status).toBe(403);
    await stepUp(actors.owner, "resource.delete", { routeId: id });
    const removed = await call(actors.owner, "DELETE", `/api/front/routes/${id}`);
    expect(removed.body).toEqual({ id, endpointRemoved: true });
    expect(await routeRow(id)).toBeUndefined();
    expect(await sql`SELECT 1 FROM endpoints WHERE id = ${endpointId}`).toHaveLength(0);
    expect(await records(hostname)).toHaveLength(0);

    expect(trail).toEqual([
      "created: awaiting_acl",
      "probe refused: awaiting_acl",
      "probe passed: awaiting_dns",
      "A -> 198.51.100.7: awaiting_dns",
      "A -> nothing: awaiting_dns",
      `A -> ${publicIpv4}: issuing_certificate`,
      "certificate issued: issuing_certificate",
      "probe with certificate: ready",
      "enable: ready (enabled)",
      "disable: ready",
    ]);
    // Every route action and lifecycle transition is audited; owner actions carry the owner.
    const audit = await auditActions(id);
    expect(audit.map((row) => row.action)).toEqual([
      "front_route.create",
      "front_route.awaiting_acl",
      "front_route.awaiting_dns",
      "front_route.issuing_certificate",
      "front_route.certificate_issued",
      "front_route.ready",
      "front_route.enable",
      "front_route.disable",
      "front_route.delete",
    ]);
    for (const row of audit.filter((item) =>
      ["front_route.create", "front_route.enable", "front_route.disable", "front_route.delete"].includes(
        item.action,
      ),
    ))
      expect(row.actor_id).toBe(actors.owner.userId);
    console.log(`FD-08 walkthrough for ${hostname}:\n  ${trail.join("\n  ")}`);
  });
});
