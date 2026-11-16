// `GET /api/front/tailnet` and `POST /api/front/tailnet/observe` through the real app and Better
// Auth sessions (front door §3.3, FD-06): owner-only (403 for operators and viewers). Also the
// watchdog's internal endpoints: the lease is readable only with the watchdog token, the token
// opens nothing else, and a failed withdrawal raises a critical alert.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";

import { createId, parseEnvFile, type Role } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}
// Read per request, so it applies even when another test file imported the app first.
process.env.ARK_EDGE_WATCHDOG_TOKEN ||= "test-edge-watchdog-token";
const watchdogToken = process.env.ARK_EDGE_WATCHDOG_TOKEN;

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { sql } = await import("./db.ts");

const origin = new URL(process.env.BETTER_AUTH_URL ?? "http://localhost:3000").origin;

type Actor = { userId: string; cookie: string };
const actors = {} as Record<Role, Actor>;
const operationIds: string[] = [];

async function signUp(role: Role): Promise<Actor> {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `Tailnet ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
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

function call(actor: Actor, method: "GET" | "POST", path: string) {
  return app.request(path, {
    method,
    headers: {
      cookie: actor.cookie,
      origin,
      ...(method === "POST" ? { "content-type": "application/json" } : {}),
    },
    ...(method === "POST" ? { body: "{}" } : {}),
  });
}

function internal(token: string | null, path: string, init: RequestInit = {}) {
  return app.request(path, {
    ...init,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), "content-type": "application/json" },
  });
}

beforeAll(async () => {
  for (const role of ["owner", "operator", "viewer"] as const) actors[role] = await signUp(role);
});

afterAll(async () => {
  if (operationIds.length) await sql`DELETE FROM operations WHERE id IN ${sql(operationIds)}`;
  await sql`DELETE FROM alerts WHERE dedup_key = 'edge-withdrawal'`;
  await sql`DELETE FROM audit_events WHERE action LIKE 'edge.watchdog.%' OR action = 'front.tailnet.observe'`;
  const ids = Object.values(actors).map((actor) => actor.userId);
  if (ids.length) await sql`DELETE FROM "user" WHERE id IN ${sql(ids)}`;
});

describe("tailnet API", () => {
  test("operators and viewers get 403 from both endpoints", async () => {
    for (const role of ["operator", "viewer"] as const) {
      const read = await call(actors[role], "GET", "/api/front/tailnet");
      const observe = await call(actors[role], "POST", "/api/front/tailnet/observe");
      expect([role, read.status, observe.status]).toEqual([role, 403, 403]);
    }
    expect((await app.request("/api/front/tailnet")).status).toBe(401);
  });

  test("the owner reads the latest generation and route identity states", async () => {
    const response = await call(actors.owner, "GET", "/api/front/tailnet");
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(body).toSorted()).toEqual(
      ["generation", "lastObservation", "peers", "routes", "self", "tailnetSuffix"].toSorted(),
    );
  });

  test("the owner enqueues edge.observe; a queued one is reused", async () => {
    const first = await call(actors.owner, "POST", "/api/front/tailnet/observe");
    expect(first.status).toBe(202);
    const { operation } = (await first.json()) as {
      operation: { id: string; kind: string; targetIds: string[] };
    };
    operationIds.push(operation.id);
    expect(operation.kind).toBe("edge.observe");
    expect(operation.targetIds).toEqual(["tailnet:edge"]);
    const second = (await (await call(actors.owner, "POST", "/api/front/tailnet/observe")).json()) as {
      operation: { id: string };
    };
    expect(second.operation.id).toBe(operation.id);
  });
});

describe("edge watchdog endpoints", () => {
  test("the lease needs the watchdog token; worker tokens and no token are refused", async () => {
    expect((await internal(null, "/api/internal/edge/lease")).status).toBe(401);
    expect((await internal("not-a-token", "/api/internal/edge/lease")).status).toBe(401);
    const workerToken = process.env.ARK_DOMAIN_WORKER_TOKEN ?? process.env.ARK_INTERNAL_TOKEN ?? "";
    expect((await internal(workerToken, "/api/internal/edge/lease")).status).toBe(403);
    const response = await internal(watchdogToken, "/api/internal/edge/lease");
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = (await response.json()) as { now: string; lease: unknown; routes: unknown[] };
    expect(Number.isFinite(Date.parse(body.now))).toBe(true);
    expect(Array.isArray(body.routes)).toBe(true);
  });

  test("the watchdog token cannot heartbeat, claim or complete operations", async () => {
    const heartbeat = await internal(watchdogToken, "/api/internal/heartbeat", {
      method: "POST",
      body: JSON.stringify({ version: "x" }),
    });
    const jobs = await app.request("/api/internal/jobs", {
      headers: { authorization: `Bearer ${watchdogToken}`, "x-ark-worker-kinds": "edge." },
    });
    expect([heartbeat.status, jobs.status]).toEqual([403, 403]);
  });

  test("a failed withdrawal raises a critical alert; a successful one is audited and re-rendered", async () => {
    const withdrawn = await internal(watchdogToken, "/api/internal/edge/watchdog-event", {
      method: "POST",
      body: JSON.stringify({ event: "withdrawn", proxy: "caddy", detail: "withdrew 100.101.102.103:3000" }),
    });
    expect(withdrawn.status).toBe(200);
    expect(
      await sql`SELECT 1 FROM alerts WHERE dedup_key = 'edge-withdrawal' AND resolved_at IS NULL`,
    ).toHaveLength(0);
    // The rendered files are brought back in line with the policy by a durable edge.apply.
    const applies = await sql`SELECT id FROM operations WHERE kind = 'edge.apply' AND status = 'queued'`;
    expect(applies.length).toBeGreaterThanOrEqual(1);
    operationIds.push(...applies.map((row) => String(row.id)));
    const stopped = await internal(watchdogToken, "/api/internal/edge/watchdog-event", {
      method: "POST",
      body: JSON.stringify({ event: "proxy_stopped", proxy: "caddy", detail: "stopped caddy" }),
    });
    expect(stopped.status).toBe(200);
    const [alert] = await sql`SELECT severity, title FROM alerts WHERE dedup_key = 'edge-withdrawal'`;
    expect(alert).toMatchObject({ severity: "critical" });
    expect(String(alert?.title)).toMatch(/stopped caddy/);
  });
});
