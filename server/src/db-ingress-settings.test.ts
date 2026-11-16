// Public database port limits (front door §3.11, FD-18) through the real app, Better Auth
// sessions and step-up grants: `GET/PUT /api/settings/db-ingress`, the pgbouncer.reload that
// renders them into `inet ark_db_ingress`, and the nft drop counters on /api/metrics/prometheus.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createId, parseEnvFile, type Role } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";
import { eq } from "drizzle-orm";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { db, sql } = await import("./db.ts");
const { runOperation } = await import("./coordinator.ts");
const { operations } = await import("./schema.ts");

const authUrl = process.env.BETTER_AUTH_URL ?? "http://localhost:3000";
const origin = new URL(authUrl).origin;
const password = "Ingress-Test-Password-123!";
const scratch = await mkdtemp(join(tmpdir(), "ark-db-ingress-settings-"));
const saved = {
  ARK_PGBOUNCER_DIR: process.env.ARK_PGBOUNCER_DIR,
  ARK_DB_INGRESS_METRICS_DIR: process.env.ARK_DB_INGRESS_METRICS_DIR,
  ARK_APPLY_NFT: process.env.ARK_APPLY_NFT,
};

type Actor = { userId: string; cookie: string };
const actors = {} as Record<Role | "ownerWithoutMfa", Actor>;
let original: Record<string, number> | undefined;
const operationIds: string[] = [];

async function signUp(role: Role, mfa: boolean): Promise<Actor> {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `Ingress ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
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
  return {
    userId: created.id,
    cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(signed)}`,
  };
}

function call(actor: Actor, path: string, init: { method?: string; body?: unknown } = {}) {
  return app.request(path, {
    method: init.method ?? "GET",
    headers: {
      cookie: actor.cookie,
      origin,
      ...(init.body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

const putLimits = (actor: Actor, body: unknown) =>
  call(actor, "/api/settings/db-ingress", { method: "PUT", body });

async function stepUp(actor: Actor, request: Record<string, unknown>) {
  const response = await call(actor, "/api/step-up", {
    method: "POST",
    body: { password, action: "platform.update", request },
  });
  expect(response.status).toBe(200);
}

function metrics() {
  return app.request("/api/metrics/prometheus", {
    headers: { authorization: `Bearer ${process.env.ARK_METRICS_TOKEN}` },
  });
}

beforeAll(async () => {
  process.env.ARK_PGBOUNCER_DIR = join(scratch, "pgbouncer");
  process.env.ARK_DB_INGRESS_METRICS_DIR = join(scratch, "metrics");
  // Render the file but never touch the host's nftables.
  process.env.ARK_APPLY_NFT = "0";
  [original] = await sql`
    SELECT db_ingress_max_connections, db_ingress_rate_per_second, db_ingress_rate_burst
    FROM platform_settings WHERE id = 'default'
  `;
  await sql`
    INSERT INTO platform_settings (id) VALUES ('default') ON CONFLICT (id) DO UPDATE
    SET db_ingress_max_connections = 128, db_ingress_rate_per_second = 30, db_ingress_rate_burst = 60
  `;
  actors.owner = await signUp("owner", true);
  actors.operator = await signUp("operator", true);
  actors.viewer = await signUp("viewer", true);
  actors.ownerWithoutMfa = await signUp("owner", false);
});

afterAll(async () => {
  const ids = Object.values(actors).map((actor) => actor.userId);
  if (operationIds.length) {
    await sql`DELETE FROM operation_steps WHERE operation_id IN ${sql(operationIds)}`;
    await sql`DELETE FROM operations WHERE id IN ${sql(operationIds)}`;
  }
  if (ids.length) {
    await sql`DELETE FROM audit_events WHERE actor_id IN ${sql(ids)}`;
    await sql`DELETE FROM step_up_grants WHERE user_id IN ${sql(ids)}`;
    await sql`DELETE FROM "user" WHERE id IN ${sql(ids)}`;
  }
  if (original) {
    await sql`
      UPDATE platform_settings SET
        db_ingress_max_connections = ${original.db_ingress_max_connections},
        db_ingress_rate_per_second = ${original.db_ingress_rate_per_second},
        db_ingress_rate_burst = ${original.db_ingress_rate_burst}
      WHERE id = 'default'
    `;
  }
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  await rm(scratch, { recursive: true, force: true });
});

describe("database ingress limits API", () => {
  test("every role reads the §3.11 defaults", async () => {
    for (const role of ["owner", "operator", "viewer"] as const) {
      const response = await call(actors[role], "/api/settings/db-ingress");
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        maxConnectionsPerSource: 128,
        newConnectionsPerSecond: 30,
        newConnectionBurst: 60,
        defaults: { maxConnectionsPerSource: 128, newConnectionsPerSecond: 30, newConnectionBurst: 60 },
        ipv6Grouping: "/64",
        port: 5432,
      });
    }
  });

  test("operators and viewers get 403; owners need MFA and a grant bound to the request", async () => {
    const request = { maxConnectionsPerSource: 64, newConnectionsPerSecond: 10, newConnectionBurst: 20 };
    await stepUp(actors.operator, request);
    for (const role of ["operator", "viewer"] as const) {
      const response = await putLimits(actors[role], request);
      expect(response.status).toBe(403);
      expect(((await response.json()) as { error: string }).error).toBe("Owner access is required.");
    }
    const noMfa = await putLimits(actors.ownerWithoutMfa, request);
    expect(noMfa.status).toBe(403);
    expect(((await noMfa.json()) as { error: string }).error).toMatch(/MFA/);
    expect((await putLimits(actors.owner, request)).status).toBe(403);
    await stepUp(actors.owner, { ...request, maxConnectionsPerSource: 65 });
    expect((await putLimits(actors.owner, request)).status).toBe(403);
    const [row] = await sql`SELECT db_ingress_max_connections FROM platform_settings WHERE id = 'default'`;
    expect(row?.db_ingress_max_connections).toBe(128);
  });

  test("validation happens before the grant is consumed", async () => {
    const request = { maxConnectionsPerSource: 64, newConnectionsPerSecond: 10, newConnectionBurst: 20 };
    await stepUp(actors.owner, request);
    for (const body of [
      { ...request, maxConnectionsPerSource: 0 },
      { ...request, maxConnectionsPerSource: 65_536 },
      { ...request, newConnectionsPerSecond: 10_001 },
      { ...request, newConnectionBurst: 5 },
      { ...request, newConnectionBurst: 2.5 },
      { maxConnectionsPerSource: 64, newConnectionsPerSecond: 10 },
      { ...request, port: 6432 },
    ]) {
      expect((await putLimits(actors.owner, body)).status, JSON.stringify(body)).toBe(422);
    }
    const accepted = await putLimits(actors.owner, request);
    expect(accepted.status).toBe(200);
    const body = (await accepted.json()) as { operationId: string; maxConnectionsPerSource: number };
    operationIds.push(body.operationId);
    expect(body.maxConnectionsPerSource).toBe(64);
  });

  test("a change is stored, audited, and rendered into ark_db_ingress by pgbouncer.reload", async () => {
    const request = { maxConnectionsPerSource: 16, newConnectionsPerSecond: 4, newConnectionBurst: 8 };
    await stepUp(actors.owner, request);
    const response = await putLimits(actors.owner, request);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { operationId: string };
    operationIds.push(body.operationId);
    expect(body).toMatchObject(request);

    const [row] = await sql`
      SELECT db_ingress_max_connections, db_ingress_rate_per_second, db_ingress_rate_burst
      FROM platform_settings WHERE id = 'default'
    `;
    expect(row).toEqual({
      db_ingress_max_connections: 16,
      db_ingress_rate_per_second: 4,
      db_ingress_rate_burst: 8,
    });
    const [event] = await sql`
      SELECT action, resource_id, operation_id, detail FROM audit_events
      WHERE actor_id = ${actors.owner.userId} AND action = 'settings.db_ingress'
      ORDER BY created_at DESC LIMIT 1
    `;
    expect(event).toMatchObject({
      action: "settings.db_ingress",
      resource_id: "platform",
      operation_id: body.operationId,
      detail: {
        ...request,
        previous: { maxConnectionsPerSource: 64, newConnectionsPerSecond: 10, newConnectionBurst: 20 },
      },
    });
    // The grant was single use.
    expect((await putLimits(actors.owner, request)).status).toBe(403);

    const [operation] = await db.select().from(operations).where(eq(operations.id, body.operationId));
    expect(operation).toMatchObject({ kind: "pgbouncer.reload", targetIds: ["platform"] });
    await runOperation("pgbouncer.reload", operation!);
    const rules = await readFile(join(scratch, "pgbouncer", "allowlist.nft"), "utf8");
    expect(rules).toContain("ip saddr ct count over 16 }");
    expect(rules).toContain("ip6 saddr and ffff:ffff:ffff:ffff:: ct count over 16 }");
    expect(rules).toContain("ip saddr limit rate over 4/second burst 8 packets }");
    expect(rules).toContain("type filter hook input priority -1");
    expect(rules).toContain("ct status dnat tcp dport 5432 jump ark_db_limits");
  });
});

describe("nft drop counters on /api/metrics/prometheus", () => {
  test("a missing snapshot reports absent and no drop series", async () => {
    const response = await metrics();
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain('ark_nft_counters_present{table="ark_db_ingress"} 0');
    expect(text).not.toContain("ark_nft_drop_packets_total{");
  });

  test("the reconciler's snapshot is exported by table, chain, reason and family", async () => {
    await Bun.write(
      join(scratch, "metrics", "counters.json"),
      JSON.stringify({
        table: "ark_db_ingress",
        observedAt: new Date(Date.now() - 20_000).toISOString(),
        counters: [
          { name: "drop_conn4", packets: 12, bytes: 720 },
          { name: "drop_conn6", packets: 0, bytes: 0 },
          { name: "drop_rate4", packets: 3, bytes: 180 },
          { name: "drop_rate6", packets: 7, bytes: 560 },
        ],
      }),
    );
    const text = await (await metrics()).text();
    expect(text).toContain('ark_nft_counters_present{table="ark_db_ingress"} 1');
    expect(text).toMatch(/ark_nft_counters_age_seconds\{table="ark_db_ingress"\} (19|20|21)\n/);
    expect(text).toContain("# TYPE ark_nft_drop_packets_total counter");
    expect(text).toContain(
      'ark_nft_drop_packets_total{table="ark_db_ingress",chain="ark_db_limits",reason="concurrent",family="ipv4"} 12',
    );
    expect(text).toContain(
      'ark_nft_drop_packets_total{table="ark_db_ingress",chain="ark_db_limits",reason="rate",family="ipv6"} 7',
    );
    // The existing series are still there.
    expect(text).toContain("# TYPE ark_operations gauge");
  });

  test("a corrupt snapshot is reported absent rather than failing the scrape", async () => {
    await writeFile(join(scratch, "metrics", "counters.json"), "{not json");
    const response = await metrics();
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('ark_nft_counters_present{table="ark_db_ingress"} 0');
  });

  test("the counters still require the metrics token", async () => {
    const response = await app.request("/api/metrics/prometheus");
    expect(response.status).toBe(401);
  });
});
