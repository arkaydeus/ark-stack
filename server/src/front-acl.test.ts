// `GET /api/front/acl` and `GET /api/front/routes/:id/acl` through the real app and Better Auth
// sessions (front door §3.7, FD-07): owner-only, deterministic, no secrets, and a stable diff
// against the last generated snippet.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";

import {
  createId,
  parseEnvFile,
  evaluatePolicyTests,
  parseHujson,
  type TailnetPolicy,
  type Role,
} from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { sql } = await import("./db.ts");

const origin = new URL(process.env.BETTER_AUTH_URL ?? "http://localhost:3000").origin;
const suffix = createId("t").slice(2, 12);
const SECRET_PASSWORD = `rest-password-${suffix}`;

type Actor = { userId: string; cookie: string };
const actors = {} as Record<Role, Actor>;
const routeIds: string[] = [];
const endpointIds: string[] = [];
let secretId = "";
let backupId = "";

async function signUp(role: Role): Promise<Actor> {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `ACL ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
    { method: "email-password" },
  );
  await sql`INSERT INTO platform_access (user_id, role) VALUES (${created.id}, ${role})`;
  await sql`
    UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute'
    WHERE id = ${created.id}
  `;
  const session = await ctx.internalAdapter.createSession(created.id, false, { origin: "admin" });
  const signed = `${session.token}.${await makeSignature(session.token, ctx.secret)}`;
  return {
    userId: created.id,
    cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(signed)}`,
  };
}

function get(actor: Actor, path: string) {
  return app.request(`${origin}${path}`, { headers: { cookie: actor.cookie, origin } });
}

async function addRoute(input: {
  kind: "http" | "tls" | "postgres" | "tcp";
  hostname: string;
  listenPort: number;
  targetIp: string;
  targetPort: number;
  tlsMode?: string | null;
}) {
  const endpointId = createId("end");
  const routeId = createId("rt");
  await sql`INSERT INTO endpoints (id, kind, hostname) VALUES (${endpointId}, 'route', ${input.hostname})`;
  await sql`
    INSERT INTO front_routes (id, kind, endpoint_id, listen_port, target_input, target_node_stable_id,
      target_ip, target_port, tls_mode, access_mode, status)
    VALUES (${routeId}, ${input.kind}, ${endpointId}, ${input.listenPort}, ${input.targetIp},
      ${`nACL${suffix}${routeIds.length}`}, ${input.targetIp}, ${input.targetPort}, ${input.tlsMode ?? null},
      'public', 'awaiting_acl')
  `;
  routeIds.push(routeId);
  endpointIds.push(endpointId);
  return routeId;
}

type AclBody = {
  scope: string;
  routeId: string | null;
  snippet: string;
  digest: string;
  sshExample: string;
  previous: { digest: string } | null;
  diff: Array<{ op: string; line: string }> | null;
  omitted: Array<{ kind: string; id: string; reason: string }>;
  routes: Array<{ id: string; hostname: string }>;
};

beforeAll(async () => {
  for (const role of ["owner", "operator", "viewer"] as const) actors[role] = await signUp(role);
  // The global baseline is a cache of what was last shown; start this file from a clean slate.
  await sql`DELETE FROM tailnet_acl_snippets WHERE scope = 'global'`;
  await addRoute({
    kind: "http",
    hostname: `www-${suffix}.example.com`,
    listenPort: 443,
    targetIp: "100.101.102.103",
    targetPort: 3000,
  });
  await addRoute({
    kind: "postgres",
    hostname: `pg-${suffix}.example.com`,
    listenPort: 5432,
    targetIp: "100.90.4.7",
    targetPort: 5432,
    tlsMode: "passthrough",
  });
  secretId = createId("sec");
  backupId = createId("bkt");
  await sql`
    INSERT INTO secrets (id, kind, key_id, ciphertext, iv, auth_tag)
    VALUES (${secretId}, 'backup-target', 'k1', 'ciphertext', 'iv', 'tag')
  `;
  // FD-30 pins tailnet backup targets (0025): the identity comes from backup-ts's own observation.
  // A legacy URL with embedded credentials must still never leak into the snippet.
  await sql`
    INSERT INTO tailnet_snapshots (source, generation, completed_at, valid_until)
    VALUES ('backup', 'gen_acl_test', now(), now() + interval '6 minutes')
    ON CONFLICT (source) DO NOTHING
  `;
  await sql`
    INSERT INTO tailnet_nodes (source, generation, stable_id, dns_name, host_name, ipv4, observed_at)
    VALUES ('backup', 'gen_acl_test', ${`nBAK${suffix}`}, 'backup-home.tail1234.ts.net', 'backup-home',
      '100.66.2.9', now())
  `;
  await sql`
    INSERT INTO backup_targets (id, kind, provider, name, rest_url, target_node_stable_id, target_ip,
      credential_secret_id)
    VALUES (${backupId}, 'tailnet_rest', 'rest_server', ${`home-${suffix}`},
      ${`http://ark:${SECRET_PASSWORD}@100.66.2.9:8000/ark`}, ${`nBAK${suffix}`}, '100.66.2.9', ${secretId})
  `;
});

afterAll(async () => {
  if (backupId) await sql`DELETE FROM backup_targets WHERE id = ${backupId}`;
  await sql`DELETE FROM tailnet_nodes WHERE source = 'backup' AND stable_id = ${`nBAK${suffix}`}`;
  await sql`DELETE FROM tailnet_snapshots WHERE source = 'backup' AND generation = 'gen_acl_test'`;
  if (secretId) await sql`DELETE FROM secrets WHERE id = ${secretId}`;
  if (routeIds.length) await sql`DELETE FROM front_routes WHERE id IN ${sql(routeIds)}`;
  if (endpointIds.length) await sql`DELETE FROM endpoints WHERE id IN ${sql(endpointIds)}`;
  await sql`DELETE FROM tailnet_acl_snippets WHERE scope = 'global'`;
  const ids = Object.values(actors).map((actor) => actor.userId);
  if (ids.length) await sql`DELETE FROM "user" WHERE id IN ${sql(ids)}`;
});

describe("ACL snippet API", () => {
  test("operators and viewers get 403 from both endpoints, even for unknown routes", async () => {
    for (const role of ["operator", "viewer"] as const) {
      for (const path of [
        "/api/front/acl",
        `/api/front/routes/${routeIds[0]}/acl`,
        "/api/front/routes/rt_missing/acl",
      ]) {
        const response = await get(actors[role], path);
        expect({ role, path, status: response.status }).toEqual({ role, path, status: 403 });
        expect(await response.text()).toContain("Owner access is required.");
      }
    }
  });

  test("the owner gets the global snippet with every route and the backup target, no secrets", async () => {
    const response = await get(actors.owner, "/api/front/acl");
    expect(response.status).toBe(200);
    const raw = await response.text();
    const body = JSON.parse(raw) as AclBody;
    expect(body.scope).toBe("global");
    expect(body.snippet).toContain(`www-${suffix}.example.com (http, 443)`);
    expect(body.snippet).toContain(`pg-${suffix}.example.com (postgres, 5432, passthrough)`);
    expect(body.snippet).toContain(
      '{ "src": ["tag:ark-edge"], "dst": ["ark-rt-100-101-102-103"], "ip": ["tcp:3000"] }',
    );
    expect(body.snippet).toContain('{ "src": ["tag:ark-backup"], "dst": [');
    expect(body.snippet).toContain('"ip": ["tcp:8000"]');
    expect(body.sshExample).toContain('"action": "check"');
    expect(body.routes.map((item) => item.id)).toEqual(expect.arrayContaining(routeIds));
    for (const secret of [SECRET_PASSWORD, secretId, "ark:"]) expect(raw).not.toContain(secret);
    // First generation: nothing to compare against yet.
    expect(body.previous).toBeNull();
    expect(body.diff).toBeNull();

    // Same input, byte-identical output, and the baseline does not move.
    const again = (await (await get(actors.owner, "/api/front/acl")).json()) as AclBody;
    expect(again.snippet).toBe(body.snippet);
    expect(again.digest).toBe(body.digest);
    expect(again.previous).toBeNull();
  });

  test("a per-route snippet grants only that route and keeps backup targets off-limits", async () => {
    const response = await get(actors.owner, `/api/front/routes/${routeIds[1]}/acl`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as AclBody;
    expect(body.scope).toBe("route");
    expect(body.routeId).toBe(routeIds[1] as string);
    expect(body.snippet).toContain(`policy snippet for route ${routeIds[1]} (pg-${suffix}.example.com)`);
    expect(body.snippet).toContain('"ip": ["tcp:5432"]');
    expect(body.snippet).not.toContain("tcp:3000");
    expect(body.snippet).not.toContain('"src": ["tag:ark-backup"]');

    expect((await get(actors.owner, "/api/front/routes/rt_missing/acl")).status).toBe(404);
  });

  test("after a route change the diff against the last snippet is shown, and stays stable", async () => {
    const before = (await (await get(actors.owner, "/api/front/acl")).json()) as AclBody;
    await addRoute({
      kind: "tcp",
      hostname: `ssh-${suffix}.example.com`,
      listenPort: 20049,
      targetIp: "100.77.9.3",
      targetPort: 22,
      tlsMode: "plain",
    });
    const after = (await (await get(actors.owner, "/api/front/acl")).json()) as AclBody;
    expect(after.digest).not.toBe(before.digest);
    expect(after.previous?.digest).toBe(before.digest);
    const added = (after.diff ?? []).filter((line) => line.op === "add").map((line) => line.line);
    expect(added).toContain('    "ark-rt-100-77-9-3": "100.77.9.3",');
    expect(added).toContain(
      '    { "src": ["tag:ark-edge"], "dst": ["ark-rt-100-77-9-3"], "ip": ["tcp:22"] },',
    );

    const reload = (await (await get(actors.owner, "/api/front/acl")).json()) as AclBody;
    expect(reload.digest).toBe(after.digest);
    expect(reload.previous?.digest).toBe(before.digest);
    expect(reload.diff).toEqual(after.diff);
  });

  test("a route backed by the backup target is omitted, not granted to the edge", async () => {
    const id = await addRoute({
      kind: "tcp",
      hostname: `rest-${suffix}.example.com`,
      listenPort: 20048,
      targetIp: "100.66.2.9",
      targetPort: 8000,
      tlsMode: "plain",
    });
    const body = (await (await get(actors.owner, "/api/front/acl")).json()) as AclBody;
    expect(body.omitted).toContainEqual({
      kind: "route",
      id,
      reason: "target is a backup target; the edge must never reach it",
    });
    const route = (await (await get(actors.owner, `/api/front/routes/${id}/acl`)).json()) as AclBody;
    expect(route.snippet).toContain(`// Not granted: route ${id}`);
    expect(route.snippet).not.toContain('"ip": ["tcp:8000"]');
  });

  test("deleting a route removes its stored snippet", async () => {
    const id = routeIds.at(-1) as string;
    const [stored] =
      await sql`SELECT count(*)::int AS count FROM tailnet_acl_snippets WHERE route_id = ${id}`;
    expect(stored?.count).toBe(1);
    await sql`DELETE FROM front_routes WHERE id = ${id}`;
    const [after] =
      await sql`SELECT count(*)::int AS count FROM tailnet_acl_snippets WHERE scope = ${`route:${id}`}`;
    expect(after?.count).toBe(0);
  });
});

test("per-route assertions compose with other routes to the same machine", async () => {
  const id = await addRoute({
    kind: "tcp",
    hostname: `shared-ssh-${suffix}.example.com`,
    listenPort: 20047,
    targetIp: "100.101.102.103",
    targetPort: 22,
    tlsMode: "plain",
  });
  const global = parseHujson(
    ((await (await get(actors.owner, "/api/front/acl")).json()) as AclBody).snippet,
  ) as TailnetPolicy;
  for (const routeId of [routeIds[0], id]) {
    const scoped = parseHujson(
      ((await (await get(actors.owner, `/api/front/routes/${routeId}/acl`)).json()) as AclBody).snippet,
    ) as TailnetPolicy;
    expect(evaluatePolicyTests(scoped)).toEqual([]);
    const merged = { ...global, tests: [...global.tests!, ...scoped.tests!] };
    expect(evaluatePolicyTests(merged)).toEqual([]);
    expect(
      evaluatePolicyTests({
        ...merged,
        grants: [...merged.grants!, { src: ["tag:ark-edge"], dst: ["100.101.102.103"], ip: ["tcp:80"] }],
      }).length,
    ).toBeGreaterThan(0);
  }
});
