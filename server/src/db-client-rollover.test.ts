// Database client certificate rollover on an injected clock (front door §3.10.4, FD-28).
//
// The real database worker code runs here: the daily `database.client_rollover` operation, the
// successor issuance under the per-client lock, the one-time successor reveal and the delivery
// confirmation (module and API), the rollover alerts, and the retirement task with its watchdog.
// The clock is injected into every rollover decision, so whole 90-day cycles run in
// milliseconds. PgBouncer itself is not running (ARK_PGBOUNCER_RELOAD=0): the worker writes the
// files it would RELOAD, and this suite reads the rendered CA bundle. The PgBouncer side of
// retirement (fence, drain, pre-auth races, the +5 s deadline) is injected here and runs for real
// in scripts/test-pgbouncer-public.ts.

import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";
import { createPrivateKey, generateKeyPairSync, X509Certificate } from "node:crypto";
import { buildCsr } from "./modules/csr-test-kit.ts";
import { existsSync } from "node:fs";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createId,
  parseEnvFile,
  PGBOUNCER_FILES,
  POOLER_ALLOWLIST_FILE,
  renderEdgeL4Generation,
  ROLLOVER_ALERT_PREFIX,
  VERCEL_ENV_NAMES,
  type Role,
} from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";
import postgres from "postgres";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { sql } = await import("./db.ts");
const { withPgbouncerLock } = await import("./modules/pgbouncer-lock.ts");
const clients = await import("./modules/db-clients.ts");
const rollover = await import("./modules/db-client-rollover.ts");
const coordinator = await import("./coordinator.ts");
const { evaluateAlerts, raiseAlert } = await import("./modules/alerts.ts");
const vercel = await import("./modules/vercel-integrations.ts");
const { vercelConnectBinding } = await import("./modules/vercel-api.ts");
const { loadPoolerPolicy, poolerEdgeInput } = await import("./modules/pooler-policy.ts");
import type { VercelTransport } from "./modules/vercel-api.ts";
const { RetirementError, retireGeneration } = await import("./modules/pgbouncer.ts");

const DAY = 86_400_000;
const authUrl = process.env.BETTER_AUTH_URL ?? "http://localhost:3000";
const origin = new URL(authUrl).origin;
const password = "Rollover-Test-Password-123!";
const appUrl = process.env.DATABASE_APP_URL ?? "";
const suffix = createId("x")
  .slice(-8)
  .toLowerCase()
  .replace(/[^a-z0-9]/g, "0");
const dbName = `fd28_${suffix}`;
const databaseId = createId("mdb");
const clusterId = createId("dcl");
const endpointId = createId("end");
const hostname = `db-${suffix}.example.com`;
const saved: Record<string, string | undefined> = {};
let work = "";
const vercelExpiryKeys = new Set<string>();

type Actor = { userId: string; cookie: string };
const actors = {} as Record<Role | "ownerWithoutMfa", Actor>;

// ---- Injected clock ------------------------------------------------------------------------------

// Each simulated timeline lies in the past, so certificates issued on it never collide with the
// real-time clients of the API test, and scenarios run one after the other.
const midnight = (value: number) => new Date(Math.floor(value / DAY) * DAY);
let clock = new Date();
const at = (base: Date, days: number, ms = 0) => new Date(base.getTime() + days * DAY + ms);

type RetireInput = Parameters<typeof retireGeneration>[0];
const drains: Array<{ role: string; database: string; at: Date; deadline: Date }> = [];
const failRoles = new Set<string>();
/** PgBouncer's side of retirement (fence, reload, drain, reopen), with timings on the clock. */
async function fakeRetire(input: RetireInput) {
  const fencedAt = clock.getTime();
  await input.apply();
  const reloadedAt = clock.getTime();
  if (failRoles.has(input.role))
    throw new RetirementError(`KILL_CLIENT failed for ${input.role}`, { fencedAt, reloadedAt });
  drains.push({ role: input.role, database: input.database, at: clock, deadline: input.deadline });
  const drainedAt = clock.getTime() + 120;
  return {
    startedAt: fencedAt,
    fencedAt,
    reloadedAt,
    drainedAt,
    reopenedAt: drainedAt + 5,
    killedRoleClients: 1,
    preAuthWaited: 0,
    iterations: 1,
    deadline: input.deadline.getTime(),
    withinDeadline: drainedAt <= input.deadline.getTime(),
  };
}
const watchdogCalls: string[] = [];
const runtime = {
  now: () => clock,
  reloadRequired: () => true,
  retire: fakeRetire as never,
  watchdog: {
    fence: async (database: string) => {
      watchdogCalls.push(`fence:${database}`);
    },
    stop: async () => {
      watchdogCalls.push("stop");
    },
    fenceListener: async () => {
      watchdogCalls.push("fenceListener");
    },
  },
};

// ---- Helpers -------------------------------------------------------------------------------------

async function signUp(role: Role, mfa: boolean): Promise<Actor> {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `Rollover ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
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

function call(actor: Actor, path: string, init: { method?: string; body?: unknown } = {}) {
  return app.request(`${origin}${path}`, {
    method: init.method ?? "GET",
    headers: {
      cookie: actor.cookie,
      origin,
      ...(init.method && init.method !== "GET" ? { "content-type": "application/json" } : {}),
    },
    body:
      init.body === undefined
        ? init.method && init.method !== "GET"
          ? "{}"
          : undefined
        : JSON.stringify(init.body),
  });
}

async function stepUp(actor: Actor, action: string, request: Record<string, unknown>) {
  const response = await call(actor, "/api/step-up", { method: "POST", body: { password, action, request } });
  expect(response.status).toBe(200);
}

function operationRow(row: Record<string, unknown>) {
  return {
    id: String(row.id),
    kind: String(row.kind),
    status: "running",
    actorId: (row.actor_id as string | null) ?? null,
    idempotencyKey: String(row.idempotency_key),
    planHash: String(row.plan_hash),
    targetIds: row.target_ids as string[],
    payload: row.payload as Record<string, unknown>,
    claimToken: String(row.claim_token),
    heartbeatAt: new Date(),
    error: null,
    createdAt: row.created_at as Date,
    updatedAt: row.updated_at as Date,
  };
}

/** Claim and execute exactly this queued operation, as the database worker does. */
async function runQueued(
  operationId: string,
  overrides: Parameters<typeof coordinator.runOperation>[2] = runtime,
) {
  const [row] = await sql`
    UPDATE operations SET status = 'running', claim_token = ${createId("claim")}, heartbeat_at = now()
    WHERE id = ${operationId} AND status = 'queued' RETURNING *
  `;
  expect(row).toBeDefined();
  try {
    const evidence = await coordinator.runOperation(row!.kind as never, operationRow(row!), overrides);
    await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${operationId}`;
    return evidence as Record<string, unknown>;
  } catch (error) {
    await sql`UPDATE operations SET status = 'failed', error = ${String(error)} WHERE id = ${operationId}`;
    throw error;
  }
}

/**
 * The daily job on the injected clock. `queueDailyRollover` queues at most one job per UTC day;
 * `retry` adds another run on the same day, as a worker retry or a second scheduler would.
 */
async function dailyJob(options: { retry?: boolean } = {}) {
  const queued = await coordinator.queueDailyRollover(clock);
  if (queued) return runQueued(queued.id);
  if (!options.retry) return null;
  const [row] = await sql`
    INSERT INTO operations (id, kind, target_ids, payload, idempotency_key, plan_hash, status)
    VALUES (${createId("op")}, 'database.client_rollover', '[]'::jsonb, '{}'::jsonb,
      ${`${coordinator.dailyRolloverKey(clock)}:retry:${createId("r")}`}, 'retry', 'queued')
    RETURNING id
  `;
  return runQueued(String(row!.id));
}

/** Issue a client on the injected clock, as database.client_issue does, and complete it. */
async function issueClient(name: string, environment = "production") {
  const result = await clients.issueDatabaseClient({
    clientId: createId("dbc"),
    databaseId,
    name,
    environment,
    roleKind: environment === "production" ? "runtime" : "readonly",
    now: clock,
  });
  await sql`UPDATE database_clients SET issued_at = ${clock.toISOString()} WHERE id = ${result.client.id}`;
  return { clientId: result.client.id, role: result.role, first: result.certificate! };
}

async function chain(clientId: string) {
  const [client] = await sql`SELECT ca_id FROM database_clients WHERE id = ${clientId}`;
  return clients.linkedCertificates({ caId: String(client!.ca_id) });
}

const bundleFile = () => readFile(join(work, "pgbouncer", PGBOUNCER_FILES.caBundle), "utf8");
async function caPem(caId: string) {
  const [row] = await sql`SELECT cert_pem FROM private_cas WHERE id = ${caId}`;
  return String(row!.cert_pem).trim();
}

/** Reveal the pending successor's bundle (module path: the API test covers the endpoint). */
async function revealSuccessor(clientId: string) {
  return rollover.revealRolloverSuccessor({
    databaseId,
    clientId,
    actorId: actors.owner.userId,
    actorRole: "owner",
    now: clock,
  });
}

async function openAlert(key: string) {
  const [row] = await sql`SELECT severity, title, resolved_at FROM alerts WHERE dedup_key = ${key}`;
  return row as { severity: string; title: string; resolved_at: Date | null } | undefined;
}

/** End a scenario: its clients leave every later rollover, alert and retirement decision. */
async function park(...clientIds: string[]) {
  for (const id of clientIds)
    await sql`UPDATE database_clients SET status = 'revoked', revoked_at = now(), revocation_completed_at = now() WHERE id = ${id}`;
}

const cluster = () => postgres(appUrl, { max: 1, onnotice: () => undefined });

beforeAll(async () => {
  work = await mkdtemp(join(tmpdir(), "ark-rollover-"));
  const overrides: Record<string, string> = {
    ARK_PGBOUNCER_DIR: join(work, "pgbouncer"),
    ARK_CERT_DIR: join(work, "certs"),
    ARK_APPLY_NFT: "0",
    ARK_EMBEDDED_WORKERS: "1",
    ARK_PGBOUNCER_RELOAD: "0",
  };
  for (const [name, value] of Object.entries(overrides)) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  await sql`INSERT INTO endpoints (id, kind, hostname, exposure, status) VALUES (${endpointId}, 'database', ${hostname}, 'public', 'verified')`;
  await sql`INSERT INTO database_clusters (id, name, endpoint_id, status) VALUES (${clusterId}, ${`fd28-${suffix}`}, ${endpointId}, 'ready')`;
  await sql`INSERT INTO managed_databases (id, cluster_id, name, exposure, status) VALUES (${databaseId}, ${clusterId}, ${dbName}, 'public', 'ready')`;
  const admin = cluster();
  try {
    await admin.unsafe(`CREATE ROLE "${dbName}_runtime" NOLOGIN`);
    await admin.unsafe(`CREATE ROLE "${dbName}_readonly" NOLOGIN`);
  } finally {
    await admin.end();
  }
  actors.owner = await signUp("owner", true);
  actors.operator = await signUp("operator", true);
  actors.viewer = await signUp("viewer", true);
  actors.ownerWithoutMfa = await signUp("owner", false);
});

afterAll(async () => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  const clientRows = await sql`SELECT id FROM database_clients WHERE database_id = ${databaseId}`;
  const clientIds = clientRows.map((row) => String(row.id));
  const roles = await sql`SELECT name FROM database_roles WHERE database_id = ${databaseId}`;
  const cas = await sql`
    SELECT DISTINCT ca_id AS id FROM client_certificates WHERE subject_cn LIKE ${`${dbName}_%`}
    UNION SELECT ca_id AS id FROM database_clients WHERE database_id = ${databaseId}
  `;
  const caIds = cas.map((row) => String(row.id));
  const alertKeys = [
    ...vercelExpiryKeys,
    ...clientIds.map(rollover.vercelPushAlertKey),
    ...clientIds.map((id) => `${ROLLOVER_ALERT_PREFIX}${id}`),
    ...(caIds.length
      ? (await sql`SELECT id FROM client_certificates WHERE ca_id IN ${sql(caIds)}`).map(
          (row) => `db-client-retire:${row.id}`,
        )
      : []),
  ];
  await sql`DELETE FROM operations WHERE target_ids ? ${databaseId} OR (kind = 'integration.vercel_push' AND payload->>'databaseId' = ${databaseId})`;
  await sql`DELETE FROM operations WHERE kind IN ('database.client_rollover', 'database.client_retire')`;
  if (clientIds.length)
    await sql`DELETE FROM client_certificate_retirements WHERE client_id IN ${sql(clientIds)}`;
  await sql`DELETE FROM database_clients WHERE database_id = ${databaseId}`;
  await sql`DELETE FROM database_roles WHERE database_id = ${databaseId}`;
  if (caIds.length) {
    await sql`UPDATE client_certificates SET superseded_by = NULL WHERE ca_id IN ${sql(caIds)}`;
    await sql`DELETE FROM client_certificates WHERE ca_id IN ${sql(caIds)}`;
    await sql`DELETE FROM private_cas WHERE id IN ${sql(caIds)}`;
    await sql`DELETE FROM secrets WHERE resource_id IN ${sql(caIds)}`;
  }
  if (alertKeys.length) await sql`DELETE FROM alerts WHERE dedup_key IN ${sql(alertKeys)}`;
  await sql`DELETE FROM secrets WHERE resource_id = ${databaseId}`;
  await sql`DELETE FROM managed_databases WHERE id = ${databaseId}`;
  await sql`DELETE FROM database_clusters WHERE id = ${clusterId}`;
  await sql`DELETE FROM endpoints WHERE id = ${endpointId}`;
  const admin = cluster();
  try {
    for (const role of [...roles.map((row) => String(row.name)), `${dbName}_runtime`, `${dbName}_readonly`])
      await admin.unsafe(`DROP ROLE IF EXISTS "${role}"`);
  } finally {
    await admin.end();
  }
  const ids = Object.values(actors).map((actor) => actor.userId);
  if (ids.length) {
    await sql`DELETE FROM audit_events WHERE actor_id IN ${sql(ids)}`;
    await sql`DELETE FROM step_up_grants WHERE user_id IN ${sql(ids)}`;
    await sql`UPDATE operations SET actor_id = NULL WHERE actor_id IN ${sql(ids)}`;
    await sql`DELETE FROM "user" WHERE id IN ${sql(ids)}`;
  }
  await sql`DELETE FROM audit_events WHERE resource_id = ${databaseId}`;
  if (work) await rm(work, { recursive: true, force: true });
});

// ---- Two complete cycles -------------------------------------------------------------------------

describe("two complete rollover cycles on an injected clock", () => {
  const T0 = midnight(Date.now() - 1_000 * DAY);
  const day = (n: number, ms = 0) => at(T0, n, ms);
  const timeline: string[] = [];
  const log = (line: string) => {
    timeline.push(`day ${((clock.getTime() - T0.getTime()) / DAY).toFixed(2).padStart(6)}: ${line}`);
  };
  let a: Awaited<ReturnType<typeof issueClient>>;
  let other: Awaited<ReturnType<typeof issueClient>>;
  const ids: Record<string, string> = {};
  /** Successors the job issued for client A (the unrelated client rolls over on its own dates). */
  const issuedForA = async (evidence: Record<string, unknown> | null) => {
    const mine = new Set((await chain(a.clientId)).map((row) => row.id));
    return ((evidence?.issued as string[]) ?? []).filter((id) => mine.has(id));
  };

  test("day 0 issues N; days 59 and 60: only day 60 issues N+1, from a fresh CA, exactly once", async () => {
    clock = day(0);
    a = await issueClient("shop");
    ids.N = a.first.id;
    log(
      `issued N ${a.first.serial.slice(0, 12)}… (CA ${a.first.caId}), not_after ${a.first.notAfter.toISOString()}`,
    );
    clock = day(10);
    other = await issueClient("other");

    clock = day(59);
    const early = await dailyJob();
    expect(await issuedForA(early)).toEqual([]);
    log("daily job: no successor (31 days before not_after)");

    clock = day(60);
    const issued = await dailyJob();
    expect((await issuedForA(issued)).length).toBe(1);
    const certs = await chain(a.clientId);
    expect(certs.map((row) => row.rolloverState)).toEqual(["current", "pending"]);
    const [n, n1] = certs as [(typeof certs)[0], (typeof certs)[0]];
    expect(n.supersededBy).toBe(n1.id);
    expect(n1.caId).not.toBe(n.caId);
    expect(n1.notBefore.getTime()).toBe(day(60).getTime());
    expect(n1.notAfter.getTime()).toBe(day(150).getTime());
    ids.N1 = n1.id;
    log(`daily job: issued N+1 ${n1.serial.slice(0, 12)}… (pending, fresh CA ${n1.caId}), not_after day 150`);
  });

  test("retries and repeated runs on day 60 create no extra successor", async () => {
    expect(await dailyJob()).toBeNull(); // the scheduler queues one job per day
    const retry = await dailyJob({ retry: true });
    expect(await issuedForA(retry)).toEqual([]);
    // Concurrent workers racing on the same client: the lock and the unique index allow one.
    const raced = await Promise.all(
      [1, 2, 3].map(() => rollover.issueSuccessor({ clientId: a.clientId, now: clock, reason: "scheduled" })),
    );
    expect(raced.map((item) => item.outcome)).toEqual(["exists", "exists", "exists"]);
    const early = await rollover.issueSuccessor({ clientId: a.clientId, now: clock, reason: "early" });
    expect(early.outcome).toBe("exists");
    expect(early.successor?.id).toBe(ids.N1);
    const certs = await chain(a.clientId);
    expect(certs.length).toBe(2);
    const [count] = await sql`
      SELECT count(*)::int AS n FROM client_certificates WHERE subject_cn = ${a.role}
    `;
    expect(count!.n).toBe(2);
    log("retry, second run and 3 concurrent issuers: no extra successor (2 certificates)");
  });

  test("CA rotation: the reload trusts both generations during the overlap", async () => {
    const [n, n1] = await chain(a.clientId);
    const bundle = await bundleFile();
    expect(bundle).toContain(await caPem(n!.caId));
    expect(bundle).toContain(await caPem(n1!.caId));
    expect(bundle).toContain(await caPem(other.first.caId));
    log("bundle: N and N+1 generation CAs both trusted (plus the unrelated client's)");
  });

  test("day 61: reveal and confirm promote N+1 to current and supersede N", async () => {
    clock = day(61);
    const revealed = await revealSuccessor(a.clientId);
    expect(revealed.certificate.id).toBe(ids.N1);
    expect(revealed.privateKey).toContain("BEGIN PRIVATE KEY");
    expect(revealed.guide.commands).toContain(
      "vercel env add ARK_DB_CLIENT_CERT_B64 production --sensitive --force",
    );
    await expect(revealSuccessor(a.clientId)).rejects.toThrow(/already revealed/);
    const confirmed = await rollover.confirmRolloverDelivery({
      databaseId,
      clientId: a.clientId,
      certificateId: ids.N1!,
      actorId: actors.owner.userId,
      now: clock,
    });
    expect(confirmed.successor.rolloverState).toBe("current");
    expect(confirmed.predecessor.rolloverState).toBe("superseded");
    const again = await rollover.confirmRolloverDelivery({
      databaseId,
      clientId: a.clientId,
      certificateId: ids.N1!,
      now: day(62),
    });
    expect(again.alreadyDelivered).toBe(true);
    expect(again.successor.deliveredAt?.getTime()).toBe(day(61).getTime());
    const [client] = await sql`SELECT ca_id FROM database_clients WHERE id = ${a.clientId}`;
    const n1 = (await chain(a.clientId)).find((row) => row.id === ids.N1)!;
    expect(client!.ca_id).toBe(n1.caId);
    expect(await issuedForA(await dailyJob())).toEqual([]);
    log(
      "confirmed: N+1 current (delivered_at day 61), N superseded, client CA pointer moved; job issues nothing",
    );
  });

  test("day 90: N's generation is removed and its role drained by not_after + 5 s", async () => {
    const n = (await chain(a.clientId)).find((row) => row.id === ids.N)!;
    clock = new Date(n.notAfter.getTime() - 1);
    await coordinator.rolloverTick(runtime);
    expect(drains.filter((item) => item.role === a.role)).toEqual([]);
    clock = n.notAfter;
    await coordinator.rolloverTick(runtime);
    const drained = drains.filter((item) => item.role === a.role);
    expect(drained.length).toBe(1);
    expect(drained[0]!.deadline.getTime()).toBe(n.notAfter.getTime() + 5_000);
    const certs = await chain(a.clientId);
    const retired = certs.find((row) => row.id === ids.N)!;
    expect(retired).toMatchObject({ status: "expired", rolloverState: "retired" });
    expect(retired.retiredAt?.getTime()).toBe(n.notAfter.getTime());
    const [task] = await sql`SELECT * FROM client_certificate_retirements WHERE certificate_id = ${ids.N}`;
    expect(task!.completed_at).toBeTruthy();
    expect(task!.deadline_missed).toBe(false);
    expect(new Date(task!.drained_at).getTime()).toBeLessThanOrEqual(n.notAfter.getTime() + 5_000);
    const [ca] = await sql`SELECT status FROM private_cas WHERE id = ${n.caId}`;
    expect(ca!.status).toBe("retired");
    const bundle = await bundleFile();
    expect(bundle).not.toContain(await caPem(n.caId));
    expect(bundle).toContain(await caPem(certs.find((row) => row.id === ids.N1)!.caId));
    // A second tick finds nothing left to retire.
    await coordinator.rolloverTick(runtime);
    expect(drains.filter((item) => item.role === a.role).length).toBe(1);
    log(
      `retired N at not_after: CA ${n.caId} removed from the bundle, role drained ${new Date(task!.drained_at).getTime() - n.notAfter.getTime()} ms after not_after (deadline +5000 ms)`,
    );
  });

  test("day 120 issues N+2 from N+1 (the unsuperseded current), delivered on day 121", async () => {
    clock = day(119);
    expect(await issuedForA(await dailyJob())).toEqual([]);
    clock = day(120);
    const issued = await dailyJob();
    expect((await issuedForA(issued)).length).toBe(1);
    const certs = await chain(a.clientId);
    const n2 = certs.find((row) => row.rolloverState === "pending")!;
    const n1 = certs.find((row) => row.id === ids.N1)!;
    expect(n1.supersededBy).toBe(n2.id);
    expect(certs.find((row) => row.id === ids.N)!.supersededBy).toBe(ids.N1);
    expect(new Set(certs.map((row) => row.caId)).size).toBe(3);
    ids.N2 = n2.id;
    expect(await issuedForA(await dailyJob({ retry: true }))).toEqual([]);
    log(
      `daily job: issued N+2 ${n2.serial.slice(0, 12)}… from N+1 (third CA generation); retry issued nothing`,
    );
    clock = day(121);
    await revealSuccessor(a.clientId);
    await rollover.confirmRolloverDelivery({
      databaseId,
      clientId: a.clientId,
      certificateId: n2.id,
      actorId: actors.owner.userId,
      now: clock,
    });
    log("confirmed N+2 (delivered_at day 121); N+1 superseded");
  });

  test("day 150 retires N+1; after day 150 the system keeps working and the cycle continues", async () => {
    const n1 = (await chain(a.clientId)).find((row) => row.id === ids.N1)!;
    clock = n1.notAfter;
    await coordinator.rolloverTick(runtime);
    expect(drains.filter((item) => item.role === a.role).length).toBe(2);
    log("retired N+1 at not_after (day 150), role drained");

    clock = day(151);
    expect(await issuedForA(await dailyJob())).toEqual([]);
    const plan = await bundleFile();
    const certs = await chain(a.clientId);
    const n2 = certs.find((row) => row.id === ids.N2)!;
    expect(plan).toContain(await caPem(n2.caId));
    expect(plan).not.toContain(await caPem(n1.caId));
    const ini = await readFile(join(work, "pgbouncer", PGBOUNCER_FILES.config), "utf8");
    expect(ini).toContain(`${a.role} = pool_mode=transaction`);
    log("day 151: only N+2 trusted, the role is still admitted, job issues nothing");

    clock = day(180);
    const next = await dailyJob();
    expect((await issuedForA(next)).length).toBe(1);
    const after = await chain(a.clientId);
    expect(after.map((row) => row.rolloverState)).toEqual(["retired", "retired", "current", "pending"]);
    log("day 180: the third cycle starts (N+3 pending)");

    // delivered_at history survives promotion, supersession and retirement.
    const history = Object.fromEntries(after.map((row) => [row.id, row.deliveredAt?.getTime() ?? null]));
    expect(history[ids.N1!]).toBe(day(61).getTime());
    expect(history[ids.N2!]).toBe(day(121).getTime());
    expect(history[ids.N!]).toBeNull();
    // A linear chain: every certificate has at most one successor.
    const successors = after.map((row) => row.supersededBy).filter(Boolean);
    expect(new Set(successors).size).toBe(successors.length);
    expect(successors.length).toBe(3);

    const status = await rollover.rolloverStatus({ databaseId, clientId: a.clientId, now: clock });
    expect(status.status).toBe("pending");
    expect(status.history.map((row) => row.deliveredAt?.getTime() ?? null)).toEqual([
      null,
      day(61).getTime(),
      day(121).getTime(),
      null,
    ]);
    log("delivered_at history: N+1 day 61, N+2 day 121 (kept after retirement)");
    console.log(`\n---- FD-28 two-cycle timeline ----\n${timeline.join("\n")}\n`);
    await park(a.clientId, other.clientId);
  });
});

// ---- Alerts --------------------------------------------------------------------------------------

describe("rollover alerts", () => {
  const T0 = midnight(Date.now() - 700 * DAY);
  const day = (n: number) => at(T0, n);

  test("pending at T−30, warning at T−14, critical at T−7; confirming clears it and supersedes N", async () => {
    clock = day(0);
    const c = await issueClient("alerts");
    const key = `${ROLLOVER_ALERT_PREFIX}${c.clientId}`;
    const results: string[] = [];
    clock = day(59);
    await rollover.evaluateRolloverAlerts(clock);
    expect(await openAlert(key)).toBeUndefined();
    results.push("T−31 (day 59): no alert");

    clock = day(60);
    await dailyJob(); // issues the successor and evaluates alerts
    let alert = await openAlert(key);
    expect(alert).toMatchObject({ severity: "info", resolved_at: null });
    expect(alert!.title).toMatch(/rollover pending; the current certificate expires in 30 day/);
    results.push(`T−30 (day 60): ${alert!.severity} — ${alert!.title}`);

    clock = day(75);
    await rollover.evaluateRolloverAlerts(clock);
    expect((await openAlert(key))!.severity).toBe("info");
    clock = day(76);
    await rollover.evaluateRolloverAlerts(clock);
    alert = await openAlert(key);
    expect(alert!.severity).toBe("warning");
    results.push(`T−14 (day 76): ${alert!.severity} — ${alert!.title}`);

    clock = day(82);
    await rollover.evaluateRolloverAlerts(clock);
    expect((await openAlert(key))!.severity).toBe("warning");
    clock = day(83);
    await rollover.evaluateRolloverAlerts(clock);
    alert = await openAlert(key);
    expect(alert!.severity).toBe("critical");
    results.push(`T−7 (day 83): ${alert!.severity} — ${alert!.title}`);
    const [count] = await sql`SELECT count(*)::int AS n FROM alerts WHERE dedup_key = ${key}`;
    expect(count!.n).toBe(1); // one alert, escalated in place

    // Confirming without revealing the generated key is refused: it cannot have been deployed.
    const pending = (await chain(c.clientId)).find((row) => row.rolloverState === "pending")!;
    await expect(
      rollover.confirmRolloverDelivery({
        databaseId,
        clientId: c.clientId,
        certificateId: pending.id,
        now: clock,
      }),
    ).rejects.toThrow(/Reveal the successor/);
    await revealSuccessor(c.clientId);
    await rollover.confirmRolloverDelivery({
      databaseId,
      clientId: c.clientId,
      certificateId: pending.id,
      now: clock,
    });
    alert = await openAlert(key);
    expect(alert!.resolved_at).toBeTruthy();
    const predecessor = (await chain(c.clientId)).find((row) => row.id === c.first.id)!;
    expect(predecessor.rolloverState).toBe("superseded");
    await rollover.evaluateRolloverAlerts(day(84));
    expect((await openAlert(key))!.resolved_at).toBeTruthy();
    results.push(
      "confirmed on day 83: alert resolved, predecessor superseded; re-evaluation keeps it resolved",
    );
    console.log(`\n---- FD-28 alert escalation ----\n${results.join("\n")}\n`);
    await park(c.clientId);
  });

  test("an undelivered successor keeps the alert critical after expiry, and retirement still happens", async () => {
    clock = day(200);
    const d = await issueClient("late");
    clock = day(260);
    await dailyJob();
    const key = `${ROLLOVER_ALERT_PREFIX}${d.clientId}`;
    clock = d.first.notAfter;
    await coordinator.rolloverTick(runtime);
    const certs = await chain(d.clientId);
    expect(certs.map((row) => row.rolloverState)).toEqual(["retired", "pending"]);
    await rollover.evaluateRolloverAlerts(at(d.first.notAfter, 1));
    const alert = await openAlert(key);
    expect(alert!.severity).toBe("critical");
    expect(alert!.title).toMatch(/expired .* before its successor was delivered/);
    // The successor can still be delivered after the predecessor retired.
    await revealSuccessor(d.clientId);
    await rollover.confirmRolloverDelivery({
      databaseId,
      clientId: d.clientId,
      certificateId: certs[1]!.id,
      now: at(d.first.notAfter, 1),
    });
    expect((await chain(d.clientId)).map((row) => row.rolloverState)).toEqual(["retired", "current"]);
    expect((await openAlert(key))!.resolved_at).toBeTruthy();
    await park(d.clientId);
  });
});

// ---- Retirement failures -------------------------------------------------------------------------

describe("retirement failures", () => {
  const T0 = midnight(Date.now() - 400 * DAY);
  const day = (n: number) => at(T0, n);

  test("a drain failure raises a critical alert and is retried; the watchdog fences and stops at the deadline", async () => {
    clock = day(0);
    const e = await issueClient("drainfail");
    clock = day(60);
    await dailyJob();
    clock = day(61);
    await revealSuccessor(e.clientId);
    const pending = (await chain(e.clientId)).find((row) => row.rolloverState === "pending")!;
    await rollover.confirmRolloverDelivery({
      databaseId,
      clientId: e.clientId,
      certificateId: pending.id,
      now: clock,
    });
    const notAfter = e.first.notAfter;
    const key = `db-client-retire:${e.first.id}`;
    const results: string[] = [];

    failRoles.add(e.role);
    clock = notAfter;
    await coordinator.rolloverTick(runtime);
    let [task] = await sql`SELECT * FROM client_certificate_retirements WHERE certificate_id = ${e.first.id}`;
    expect(task).toMatchObject({ attempts: 1, completed_at: null, deadline_missed: false });
    expect(task!.last_error).toMatch(/KILL_CLIENT failed/);
    let alert = await openAlert(key);
    expect(alert).toMatchObject({ severity: "critical", resolved_at: null });
    expect(alert!.title).toMatch(/draining the retiring certificate .* failed; retrying/);
    // The generation already left the bundle before the drain failed.
    expect(await bundleFile()).not.toContain(await caPem(e.first.caId));
    results.push(`T+0 s: drain failed → critical "${alert!.title}"`);
    const [failedOp] = await sql`
      SELECT status FROM operations WHERE kind = 'database.client_retire' AND payload->>'certificateId' = ${e.first.id}
    `;
    expect(failedOp!.status).toBe("failed");

    clock = new Date(notAfter.getTime() + 2_000);
    await coordinator.rolloverTick(runtime);
    [task] = await sql`SELECT * FROM client_certificate_retirements WHERE certificate_id = ${e.first.id}`;
    expect(task!.attempts).toBe(2);
    expect(watchdogCalls).toEqual([]);
    results.push("T+2 s: retried, failed again (no watchdog before the deadline)");

    clock = new Date(notAfter.getTime() + 6_000);
    await coordinator.rolloverTick(runtime);
    [task] = await sql`SELECT * FROM client_certificate_retirements WHERE certificate_id = ${e.first.id}`;
    expect(task!.deadline_missed).toBe(true);
    expect(task!.watchdog_at).toBeTruthy();
    expect(watchdogCalls).toEqual([`fence:${dbName}`, "stop"]);
    alert = await openAlert(key);
    expect(alert!.severity).toBe("critical");
    expect(alert!.title).toMatch(/deadline/);
    results.push(`T+6 s: deadline missed → watchdog ${watchdogCalls.join(", ")}; "${alert!.title}"`);

    // The watchdog acts once; retries continue until the drain succeeds.
    clock = new Date(notAfter.getTime() + 15_000);
    failRoles.delete(e.role);
    // Use production retireGeneration on recovery, rather than a fake late-success timeline.
    await coordinator.rolloverTick({
      ...runtime,
      retire: (input) => retireGeneration({ ...input, admin: async () => [] }),
    });
    expect(watchdogCalls.length).toBe(2);
    [task] = await sql`SELECT * FROM client_certificate_retirements WHERE certificate_id = ${e.first.id}`;
    expect(task!.completed_at).toBeTruthy();
    expect(task!.deadline_missed).toBe(true);
    expect(
      (await rollover.dueRetirements({ now: clock })).some((item) => item.certificate.id === e.first.id),
    ).toBe(false);
    const retired = (await chain(e.clientId)).find((row) => row.id === e.first.id)!;
    expect(retired.retiredAt).toBeTruthy();
    // Expiry without a timely drain is a failure: the alert stays open, naming the lateness.
    alert = await openAlert(key);
    expect(alert).toMatchObject({ severity: "critical", resolved_at: null });
    expect(alert!.title).toMatch(/drained \d+ s after its retirement deadline/);
    results.push(
      `T+15 s: retry drained the role; task complete with deadline_missed=true, alert stays: "${alert!.title}"`,
    );
    console.log(`\n---- FD-28 drain failure ----\n${results.join("\n")}\n`);
    await park(e.clientId);
  });

  test("without an admin socket the watchdog only alerts", async () => {
    clock = day(200);
    const f = await issueClient("nosocket");
    failRoles.add(f.role);
    clock = f.first.notAfter;
    await coordinator.rolloverTick(runtime);
    const before = watchdogCalls.length;
    clock = new Date(f.first.notAfter.getTime() + 10_000);
    const actions = await coordinator.runRetirementWatchdog({ ...runtime, reloadRequired: () => false });
    expect(actions.find((item) => item.certificateId === f.first.id)).toMatchObject({
      certificateId: f.first.id,
      skipped: "no admin socket",
    });
    expect(watchdogCalls.length).toBe(before);
    failRoles.delete(f.role);
    await park(f.clientId);
  });
});

// ---- API: early rollover, reveal, confirm ------------------------------------------------------

describe("rollover API", () => {
  const path = (clientId: string, tail = "") =>
    `/api/databases/${databaseId}/clients/${clientId}/rollover${tail}`;
  let client: Awaited<ReturnType<typeof issueClient>>;

  test("early rollover is owner-only with MFA step-up: 403 for operators and viewers", async () => {
    clock = new Date();
    client = await issueClient("api");
    await stepUp(actors.operator, "credential.rotate", {
      databaseId,
      clientId: client.clientId,
      rollover: true,
    });
    for (const role of ["operator", "viewer"] as const) {
      for (const [method, url] of [
        ["GET", path(client.clientId)],
        ["POST", path(client.clientId)],
        ["POST", path(client.clientId, "/reveal")],
        ["POST", path(client.clientId, "/confirm")],
      ] as const) {
        const response = await call(actors[role], url, {
          method,
          body: url.endsWith("/confirm") ? { certificateId: "ccert_x" } : undefined,
        });
        expect(response.status, `${role} ${method} ${url}`).toBe(403);
        expect(((await response.json()) as { error: string }).error).toBe("Owner access is required.");
      }
    }
    const noMfa = await call(actors.ownerWithoutMfa, path(client.clientId), { method: "POST" });
    expect(noMfa.status).toBe(403);
    expect(((await noMfa.json()) as { error: string }).error).toMatch(/MFA/);
    const noGrant = await call(actors.owner, path(client.clientId), { method: "POST" });
    expect(noGrant.status).toBe(403);
    expect(((await noGrant.json()) as { error: string }).error).toMatch(/credential.rotate/);
    const [queued] = await sql`
      SELECT count(*)::int AS n FROM operations WHERE kind = 'database.client_rollover' AND payload->>'clientId' = ${client.clientId}
    `;
    expect(queued!.n).toBe(0);
  });

  test("the owner's early rollover issues one successor; a second request is refused (one-successor rule)", async () => {
    await stepUp(actors.owner, "credential.rotate", {
      databaseId,
      clientId: client.clientId,
      rollover: true,
    });
    const response = await call(actors.owner, path(client.clientId), { method: "POST" });
    expect(response.status).toBe(202);
    const { operationId } = (await response.json()) as { operationId: string };
    // Queued but not run yet: a concurrent request is refused as in flight.
    await stepUp(actors.owner, "credential.rotate", {
      databaseId,
      clientId: client.clientId,
      rollover: true,
    });
    const inflight = await call(actors.owner, path(client.clientId), { method: "POST" });
    expect(inflight.status).toBe(409);
    clock = new Date();
    const evidence = await runQueued(operationId);
    expect((evidence.issued as string[]).length).toBe(1);
    const certs = await chain(client.clientId);
    expect(certs.map((row) => row.rolloverState)).toEqual(["current", "pending"]);
    expect(await bundleFile()).toContain(await caPem(certs[1]!.caId));

    await stepUp(actors.owner, "credential.rotate", {
      databaseId,
      clientId: client.clientId,
      rollover: true,
    });
    const second = await call(actors.owner, path(client.clientId), { method: "POST" });
    expect(second.status).toBe(409);
    expect(((await second.json()) as { error: string }).error).toMatch(
      /successor certificate already exists/,
    );
    // Even an early request that slipped past the API (a direct module call) cannot add one.
    const direct = await rollover.issueSuccessor({
      clientId: client.clientId,
      now: new Date(),
      reason: "early",
    });
    expect(direct.outcome).toBe("exists");
    expect((await chain(client.clientId)).length).toBe(2);
    const [audit] = await sql`
      SELECT detail FROM audit_events WHERE action = 'database.client_rollover_issued' AND operation_id = ${operationId}
    `;
    expect(JSON.stringify(audit!.detail)).not.toContain("BEGIN");
  });

  test("status, one-time successor reveal (secret.reveal) and confirm through the API", async () => {
    const status = await call(actors.owner, path(client.clientId));
    expect(status.status).toBe(200);
    const body = (await status.json()) as { status: string; successor: { id: string; revealed: boolean } };
    expect(body.status).toBe("pending");
    expect(body.successor.revealed).toBe(false);
    expect(JSON.stringify(body)).not.toContain("BEGIN");

    const noGrant = await call(actors.owner, path(client.clientId, "/reveal"), { method: "POST" });
    expect(noGrant.status).toBe(403);
    await stepUp(actors.owner, "secret.reveal", { databaseId, clientId: client.clientId, rollover: true });
    const revealed = await call(actors.owner, path(client.clientId, "/reveal"), { method: "POST" });
    expect(revealed.status).toBe(200);
    expect(revealed.headers.get("cache-control")).toBe("no-store");
    const bundle = (await revealed.json()) as {
      certificate: { id: string; pem: string };
      privateKey: string;
      confirm: { path: string; body: { certificateId: string } };
      guide: { env: Array<{ name: string; value: string }> };
    };
    expect(bundle.certificate.id).toBe(body.successor.id);
    expect(bundle.privateKey).toContain("BEGIN PRIVATE KEY");
    expect(bundle.guide.env.map((item) => item.name)).toEqual([
      "ARK_DB_CLIENT_CERT_B64",
      "ARK_DB_CLIENT_KEY_B64",
    ]);
    const [keySecret] =
      await sql`SELECT key_secret_id, revealed_at FROM client_certificates WHERE id = ${bundle.certificate.id}`;
    expect(keySecret!.key_secret_id).toBeNull();
    expect(keySecret!.revealed_at).toBeTruthy();
    await stepUp(actors.owner, "secret.reveal", { databaseId, clientId: client.clientId, rollover: true });
    const again = await call(actors.owner, path(client.clientId, "/reveal"), { method: "POST" });
    expect(again.status).toBe(409);

    const noMfa = await call(actors.ownerWithoutMfa, bundle.confirm.path, {
      method: "POST",
      body: bundle.confirm.body,
    });
    expect(noMfa.status).toBe(403);
    const confirmed = await call(actors.owner, bundle.confirm.path, {
      method: "POST",
      body: bundle.confirm.body,
    });
    expect(confirmed.status).toBe(200);
    const result = (await confirmed.json()) as {
      successor: { rolloverState: string };
      predecessor: { rolloverState: string };
    };
    expect(result.successor.rolloverState).toBe("current");
    expect(result.predecessor.rolloverState).toBe("superseded");
    const after = (await (await call(actors.owner, path(client.clientId))).json()) as { status: string };
    expect(after.status).toBe("delivered");

    // With the successor delivered, the next early rollover is allowed again (from N+1).
    await stepUp(actors.owner, "credential.rotate", {
      databaseId,
      clientId: client.clientId,
      rollover: true,
    });
    const next = await call(actors.owner, path(client.clientId), { method: "POST" });
    expect(next.status).toBe(202);
    await park(client.clientId);
  });
});

const until = async (ready: () => boolean) => {
  for (let i = 0; i < 300 && !ready(); i++) await Bun.sleep(5);
  expect(ready()).toBe(true);
};

// Recovery regressions use the real coordinator and database, with barriers only at I/O.
describe("rollover recovery and concurrency", () => {
  const base = midnight(Date.now() - 1_000 * DAY);
  let scenario = 0;
  const next = () => (clock = at(base, scenario++ * 200));
  async function op(clientId?: string) {
    const id = createId("op");
    const payload = clientId ? { clientId, early: true } : {};
    const [row] =
      await sql`INSERT INTO operations (id, kind, target_ids, payload, idempotency_key, plan_hash, status)
      VALUES (${id}, 'database.client_rollover', ${JSON.stringify([databaseId])}::jsonb, ${JSON.stringify(payload)}::jsonb, ${id}, 'test', 'running') RETURNING *`;
    return operationRow(row!);
  }

  test("fresh concurrent issuers commit exactly one successor and one new CA", async () => {
    next();
    const c = await issueClient("freshrace");
    clock = at(clock, 60);
    const results = await Promise.all(
      Array.from({ length: 4 }, () =>
        rollover.issueSuccessor({ clientId: c.clientId, now: clock, reason: "scheduled" }),
      ),
    );
    expect(results.filter((row) => row.outcome === "issued")).toHaveLength(1);
    expect(new Set(results.map((row) => row.successor?.id)).size).toBe(1);
    expect(await chain(c.clientId)).toHaveLength(2);
    const [cas] =
      await sql`SELECT count(DISTINCT ca_id)::int AS n FROM client_certificates WHERE subject_cn = ${c.role}`;
    expect(cas!.n).toBe(2);
    await park(c.clientId);
  });

  test("early retry and daily reconciliation apply the same committed successor after reload failure", async () => {
    for (const daily of [false, true]) {
      next();
      const c = await issueClient(`reload${daily}`);
      clock = at(clock, 60);
      const operation = await op(c.clientId);
      await expect(
        coordinator.runOperation("database.client_rollover", operation, {
          ...runtime,
          reload: async () => {
            throw new Error("reload unavailable");
          },
        }),
      ).rejects.toThrow("reload unavailable");
      const successor = (await chain(c.clientId))[1]!;
      const [unapplied] =
        await sql`SELECT trust_applied_at FROM client_certificates WHERE id = ${successor.id}`;
      expect(unapplied!.trust_applied_at).toBeNull();
      const savedReload = process.env.ARK_PGBOUNCER_RELOAD;
      process.env.ARK_PGBOUNCER_RELOAD = "1";
      try {
        await expect(revealSuccessor(c.clientId)).rejects.toThrow(/awaiting a successful PgBouncer reload/);
      } finally {
        process.env.ARK_PGBOUNCER_RELOAD = savedReload;
      }
      await coordinator.runOperation("database.client_rollover", daily ? await op() : operation, runtime);
      expect(await chain(c.clientId)).toHaveLength(2);
      expect(await bundleFile()).toContain(await caPem(successor.caId));
      const [applied] =
        await sql`SELECT trust_applied_at FROM client_certificates WHERE id = ${successor.id}`;
      expect(applied!.trust_applied_at).toBeTruthy();
      await park(c.clientId);
    }
  });

  test("historical confirmation leaves a later pending cycle's alert open", async () => {
    next();
    const c = await issueClient("oldconfirm");
    const first = await rollover.issueSuccessor({
      clientId: c.clientId,
      now: at(clock, 60),
      reason: "early",
    });
    clock = at(clock, 61);
    await revealSuccessor(c.clientId);
    await rollover.confirmRolloverDelivery({
      databaseId,
      clientId: c.clientId,
      certificateId: first.successor!.id,
      now: clock,
    });
    clock = at(clock, 65);
    await rollover.issueSuccessor({ clientId: c.clientId, now: clock, reason: "early" });
    await rollover.evaluateRolloverAlerts(clock);
    const key = `${ROLLOVER_ALERT_PREFIX}${c.clientId}`;
    expect((await openAlert(key))!.resolved_at).toBeNull();
    await rollover.confirmRolloverDelivery({
      databaseId,
      clientId: c.clientId,
      certificateId: first.successor!.id,
      now: clock,
    });
    expect((await openAlert(key))!.resolved_at).toBeNull();
    await park(c.clientId);
  });

  test("CSR automatic/early rollover and reveal state; missing successor stays critical after retirement", async () => {
    next();
    const key = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    const csrPem = buildCsr({ key }).pem;
    const issued = await clients.issueDatabaseClient({
      clientId: createId("dbc"),
      databaseId,
      name: "csrrecovery",
      environment: "production",
      roleKind: "runtime",
      now: clock,
      csrPem,
    });
    const id = issued.client.id;
    await sql`UPDATE database_clients SET issued_at = ${clock.toISOString()} WHERE id = ${id}`;
    const initial = clock;
    clock = at(clock, 60);
    const scheduled = await rollover.runScheduledRollover({ now: clock });
    expect(scheduled.find((row) => row.clientId === id)?.outcome).toBe("needs_csr");
    await expect(
      rollover.queueEarlyRollover({ databaseId, clientId: id, actorId: actors.owner.userId }),
    ).rejects.toThrow(/submit a CSR/);
    const early = await rollover.queueEarlyRollover({
      databaseId,
      clientId: id,
      actorId: actors.owner.userId,
      csrPem,
    });
    await runQueued(early.operation.id);
    let status = await rollover.rolloverStatus({ databaseId, clientId: id, now: clock });
    expect(status.successor?.revealed).toBe(false);
    const revealed = await revealSuccessor(id);
    expect(revealed.privateKey).toBeNull();
    status = await rollover.rolloverStatus({ databaseId, clientId: id, now: clock });
    expect(status.successor?.revealed).toBe(true);
    await rollover.confirmRolloverDelivery({
      databaseId,
      clientId: id,
      certificateId: revealed.certificate.id,
      now: clock,
    });
    await park(id);

    // A different CSR client never supplies the successor CSR.
    clock = initial;
    const missing = await clients.issueDatabaseClient({
      clientId: createId("dbc"),
      databaseId,
      name: "csrmissing",
      environment: "production",
      roleKind: "runtime",
      now: clock,
      csrPem,
    });
    await sql`UPDATE database_clients SET issued_at = ${clock.toISOString()} WHERE id = ${missing.client.id}`;
    clock = missing.certificate!.notAfter;
    await coordinator.rolloverTick(runtime);
    await rollover.evaluateRolloverAlerts(clock);
    expect(await openAlert(`${ROLLOVER_ALERT_PREFIX}${missing.client.id}`)).toMatchObject({
      severity: "critical",
      resolved_at: null,
    });
    await park(missing.client.id);
  });

  test("acknowledged warning escalates to critical and sends a fresh notification", async () => {
    next();
    const c = await issueClient("renotify");
    const initial = clock;
    const received: string[] = [];
    const server = Bun.serve({
      port: 0,
      fetch: async (request) => {
        received.push(await request.text());
        return new Response("ok");
      },
    });
    const previous = process.env.ARK_ALERT_WEBHOOK;
    process.env.ARK_ALERT_WEBHOOK = `http://localhost:${server.port}`;
    try {
      clock = at(initial, 76);
      await rollover.evaluateRolloverAlerts(clock);
      const key = `${ROLLOVER_ALERT_PREFIX}${c.clientId}`;
      await sql`UPDATE alerts SET acknowledged = true, notification_attempts = 5, last_notified_at = now() WHERE dedup_key = ${key}`;
      clock = at(initial, 83);
      await rollover.evaluateRolloverAlerts(clock);
      const [alert] =
        await sql`SELECT acknowledged, notification_attempts, severity FROM alerts WHERE dedup_key = ${key}`;
      expect(alert).toMatchObject({ acknowledged: false, notification_attempts: 1, severity: "critical" });
      expect(received.filter((body) => body.includes(c.role))).toHaveLength(2);
    } finally {
      if (previous === undefined) delete process.env.ARK_ALERT_WEBHOOK;
      else process.env.ARK_ALERT_WEBHOOK = previous;
      await server.stop(true);
      await park(c.clientId);
    }
  });

  test("failed escalation retries; retirement operations and op-failed alerts stay bounded", async () => {
    next();
    const c = await issueClient("backoff");
    clock = c.first.notAfter;
    failRoles.add(c.role);
    await coordinator.rolloverTick(runtime);
    const T = clock.getTime();
    for (let i = 1; i <= 12; i++) {
      clock = new Date(T + i * 1_000);
      await coordinator.rolloverTick({
        ...runtime,
        watchdog: {
          fence: async () => {
            throw Error("no socket");
          },
          stop: async () => {
            throw Error("no socket");
          },
          fenceListener: async () => {
            throw Error("no listener");
          },
        },
      });
    }
    const [task] =
      await sql`SELECT * FROM client_certificate_retirements WHERE certificate_id = ${c.first.id}`;
    expect(task!.attempts).toBeLessThanOrEqual(3);
    expect(task!.watchdog_at).toBeNull();
    const [count] =
      await sql`SELECT count(*)::int AS n FROM operations WHERE payload->>'certificateId' = ${c.first.id}`;
    expect(count!.n).toBe(1);
    await evaluateAlerts();
    const [alertCount] =
      await sql`SELECT count(*)::int AS n FROM alerts WHERE dedup_key IN (SELECT 'op-failed:' || id FROM operations WHERE payload->>'certificateId' = ${c.first.id})`;
    expect(alertCount!.n).toBe(1);
    const actions = await coordinator.runRetirementWatchdog(runtime);
    expect(actions.find((item) => item.certificateId === c.first.id)?.stop).toBe("ok");
    const [recovered] =
      await sql`SELECT watchdog_at FROM client_certificate_retirements WHERE certificate_id = ${c.first.id}`;
    expect(recovered!.watchdog_at).toBeTruthy();
    failRoles.delete(c.role);
    clock = new Date(T + 30_000);
    await coordinator.rolloverTick(runtime);
    await park(c.clientId);
  });

  test("revoked clients finish open retirements; completed revocation cancels without watchdog fencing", async () => {
    for (const alreadyDrained of [false, true]) {
      next();
      const c = await issueClient(`revoke${alreadyDrained}`);
      clock = c.first.notAfter;
      const item = (await rollover.dueRetirements({ now: clock })).find(
        (row) => row.certificate.id === c.first.id,
      )!;
      await rollover.ensureRetirement(item);
      await sql`UPDATE database_clients SET status = 'revoked', revoked_at = now(), revocation_completed_at = ${alreadyDrained ? new Date().toISOString() : null}::timestamptz WHERE id = ${c.clientId}`;
      await sql`UPDATE client_certificates SET status = 'revoked' WHERE id = ${c.first.id}`;
      const before = drains.length;
      await coordinator.rolloverTick(runtime);
      const [task] =
        await sql`SELECT completed_at FROM client_certificate_retirements WHERE certificate_id = ${c.first.id}`;
      expect(task!.completed_at).toBeTruthy();
      expect(drains.length - before).toBe(alreadyDrained ? 0 : 1);
      clock = new Date(clock.getTime() + 6_000);
      expect(
        (await coordinator.runRetirementWatchdog(runtime)).some((row) => row.certificateId === c.first.id),
      ).toBe(false);
      await park(c.clientId);
    }
  });

  test("scheduler watchdog runs while a retirement's apply is unresolved", async () => {
    next();
    const c = await issueClient("hungapply");
    clock = c.first.notAfter;
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    let applying = false;
    let completed = false;
    const calls: string[] = [];
    const stop = coordinator.startRolloverScheduler(10, {
      ...runtime,
      reload: async () => {
        applying = true;
        await barrier;
      },
      retire: async (input) => {
        try {
          return await retireGeneration({ ...input, admin: async () => [] });
        } finally {
          completed = true;
        }
      },
      watchdog: {
        fence: async () => {
          calls.push("fence");
        },
        stop: async () => {
          calls.push("stop");
        },
        fenceListener: async () => {
          calls.push("listener");
        },
      },
    });
    try {
      await until(() => applying);
      for (let tick = 0; tick < 3; tick++) await coordinator.rolloverTick(runtime);
      const [count] =
        await sql`SELECT count(*)::int AS n FROM operations WHERE payload->>'certificateId' = ${c.first.id}`;
      expect(count!.n).toBe(1);
      clock = new Date(clock.getTime() + 6_000);
      await until(() => calls.includes("stop"));
      expect(completed).toBe(false);
    } finally {
      stop();
      release();
      await until(() => completed);
      // Wait for the writer lock and durable completion before fixture cleanup.
      await withPgbouncerLock(async () => undefined);
      await park(c.clientId);
    }
  });

  test("the configuration lock excludes another database connection and releases after an error", async () => {
    let release!: () => void;
    let locked = false;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const external = sql.begin(async (connection) => {
      await connection`SELECT pg_advisory_xact_lock(hashtextextended('ark:pgbouncer-config', 0))`;
      locked = true;
      await barrier;
    });
    await until(() => locked);
    let entered = false;
    const writer = withPgbouncerLock(async () => {
      entered = true;
      throw Error("writer failed");
    }).catch((error: unknown) => error);
    try {
      await Bun.sleep(30);
      expect(entered).toBe(false);
    } finally {
      release();
      await external;
    }
    expect(await writer).toBeInstanceOf(Error);
    expect(await withPgbouncerLock(async () => "recovered")).toBe("recovered");
  });

  test("two expiry timers and an older regular reload share the complete writer/fence lock", async () => {
    next();
    const a = await issueClient("timera");
    const b = await issueClient("timerb");
    await coordinator.runOperation("pgbouncer.reload", await op(), runtime);
    expect(await bundleFile()).toContain(await caPem(a.first.caId));
    const T = a.first.notAfter.getTime();
    clock = new Date(T - 30);
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    let snapshotTaken = false;
    const stale = withPgbouncerLock(async () => {
      const snapshot = await bundleFile();
      snapshotTaken = true;
      await barrier;
      await Bun.write(join(work, "pgbouncer", PGBOUNCER_FILES.caBundle), snapshot);
    });
    await until(() => snapshotTaken);
    const commands: string[] = [];
    let disabled = false;
    const simultaneous = {
      ...runtime,
      retire: (input: RetireInput) =>
        retireGeneration({
          ...input,
          admin: async (command: string) => {
            if (command.startsWith("DISABLE")) {
              expect(disabled).toBe(false);
              disabled = true;
            }
            if (command.startsWith("ENABLE")) {
              expect(disabled).toBe(true);
              disabled = false;
            }
            commands.push(command);
            return [];
          },
        }),
    };
    const state = { timers: new Map<string, ReturnType<typeof setTimeout>>(), tickMs: 50 };
    await coordinator.rolloverTick(simultaneous, state);
    clock = new Date(T);
    await Bun.sleep(60); // both expiry timers are now queued behind the old writer
    expect(commands).toEqual([]);
    const regular = coordinator.runOperation("pgbouncer.reload", await op(), runtime);
    release();
    await stale;
    await regular;
    await until(() => state.timers.size === 0);
    await coordinator.rolloverTick(simultaneous);
    expect(commands.filter((command) => command.startsWith("DISABLE"))).toHaveLength(2);
    expect(commands.filter((command) => command.startsWith("ENABLE"))).toHaveLength(2);
    const bundle = await bundleFile();
    expect(bundle).not.toContain(await caPem(a.first.caId));
    expect(bundle).not.toContain(await caPem(b.first.caId));
    for (const c of [a, b]) {
      const [task] =
        await sql`SELECT completed_at FROM client_certificate_retirements WHERE certificate_id = ${c.first.id}`;
      expect(task!.completed_at).toBeTruthy();
    }
    await park(a.clientId, b.clientId);
  });
});

describe("FD-29 Vercel delivery", () => {
  const projectId = "prj_SelectedFD29";
  const teamId = "team_FD29";
  const otherProjectId = "prj_ComparatorFD29";
  const deployHook = `https://api.vercel.com/v1/integrations/deploy/${projectId}/hookSecretFD29`;
  const jobId = "VercelHookJobFD29001";
  const deploymentId = "dpl_NewFD29";
  const proof = {
    evidence: "mock-only",
    listDenialCode: "project_scope_resource_denied",
    otherProjectDenialCode: "project_scope_project_denied",
  };
  const actorRef = (clientId: string) => ({
    databaseId,
    clientId,
    actorId: actors.owner.userId,
    actorRole: "owner",
  });
  const inputFor = (name: string, target: "production" | "preview" = "production") => ({
    projectId,
    teamId,
    otherProjectId,
    deployHook,
    target,
    token: `vcp_RefusalSentinel_FD29_${name}`,
    ...(target === "preview" ? { gitBranch: "fd29-preview" } : {}),
  });
  const endpoint = (clientId: string) =>
    `/api/databases/${databaseId}/clients/${clientId}/vercel-integration`;
  const expectedProbes = [
    "/v5/user/tokens/current",
    `/v9/projects/${projectId}?teamId=${teamId}`,
    `/v9/projects?teamId=${teamId}`,
    `/v9/projects/${otherProjectId}?teamId=${teamId}`,
  ].toSorted();

  type Refusal =
    | "team"
    | "account"
    | "crossProject"
    | "expired"
    | "noExpiry"
    | "network"
    | "ambiguous"
    | "genericDenial"
    | "otherProjectVisible"
    | "listVisible"
    | "wrongTeam"
    | "invalidToken";
  type Options = {
    refusal?: Refusal;
    push?:
      | "ready"
      | "error"
      | "partial"
      | "partialOnce"
      | "unknownReceipt"
      | "timeout"
      | "upsertRejected"
      | "upsertUnsettled";
    beforeEnv?: () => Promise<void>;
    beforeHook?: () => Promise<void>;
    environment?: Map<string, string>;
    previewOverrides?: Map<string, Map<string, string>>;
    onPoll?: (poll: number, url: URL) => Promise<void | Response>;
    beforeProbe?: () => Promise<void>;
    expiresAt?: Date;
  };
  function mockApi(input: ReturnType<typeof inputFor>, options: Options = {}) {
    const calls: Array<{
      method: string;
      path: string;
      body?: Record<string, unknown>[];
      authenticated: boolean;
    }> = [];
    let polls = 0;
    let writes = 0;
    const branch = input.gitBranch ?? (input.target === "preview" ? "fd29-preview" : "main");
    const transport: VercelTransport = async (url, init) => {
      const method = init.method ?? "GET";
      const headers = new Headers(init.headers);
      const authenticated = headers.get("authorization") === `Bearer ${input.token}`;
      const path = url.pathname + url.search;
      const body = init.body ? (JSON.parse(String(init.body)) as Record<string, unknown>[]) : undefined;
      calls.push({ method, path, body, authenticated });
      if (
        method === "GET" &&
        (url.pathname.startsWith("/v9/projects") || url.pathname === "/v5/user/tokens/current")
      ) {
        await options.beforeProbe?.();
        if (!authenticated) return Response.json({}, { status: 401 });
      }
      if (url.pathname === "/v5/user/tokens/current") {
        const expiresAt = options.expiresAt ?? at(clock, 60);
        const scope = { type: "project", teamId, projectId, createdAt: clock.getTime() };
        if (options.refusal === "team") scope.type = "team";
        if (options.refusal === "account") scope.type = "user";
        if (options.refusal === "crossProject") scope.projectId = otherProjectId;
        if (options.refusal === "wrongTeam") scope.teamId = "team_Other";
        return Response.json({
          token: {
            expiresAt:
              options.refusal === "noExpiry"
                ? undefined
                : options.refusal === "expired"
                  ? clock.getTime() - 1
                  : expiresAt.getTime(),
            scopes: options.refusal === "ambiguous" ? [scope, { type: "user" }] : [scope],
            name: input.token, // Provider bodies may echo secret values.
          },
        });
      }
      if (url.pathname === `/v9/projects/${projectId}`) {
        return Response.json({
          id: projectId,
          accountId: teamId,
          link: { productionBranch: "main", deployHooks: [{ url: deployHook, ref: branch }] },
        });
      }
      if (url.pathname === "/v9/projects") {
        if (options.refusal === "network") throw new Error(`Network failure: ${input.token}`);
        if (options.refusal === "listVisible") return Response.json({ projects: [{ id: otherProjectId }] });
        return Response.json(
          {
            error: {
              code: options.refusal === "genericDenial" ? "forbidden" : proof.listDenialCode,
              invalidToken: options.refusal === "invalidToken" ? true : undefined,
              message: input.token,
            },
          },
          { status: 403 },
        );
      }
      if (url.pathname === `/v9/projects/${otherProjectId}`) {
        if (options.refusal === "otherProjectVisible") return Response.json({ id: otherProjectId });
        return Response.json(
          { error: { code: proof.otherProjectDenialCode, message: input.token } },
          { status: 403 },
        );
      }
      if (url.pathname === `/v10/projects/${projectId}/env`) {
        await options.beforeEnv?.();
        writes++;
        if (options.push === "upsertRejected") return Response.json({}, { status: 429 });
        if (options.push === "upsertUnsettled") throw new Error("The provider outcome is unknown");
        if (!Array.isArray(body)) return Response.json({}, { status: 400 });
        // Vercel may accept one entry and refuse the other. Existing deployments keep their env.
        const partial = options.push === "partial" || (options.push === "partialOnce" && writes === 1);
        const accepted = partial ? body.slice(0, 1) : body;
        for (const entry of accepted) {
          const environment =
            entry.gitBranch && options.previewOverrides
              ? options.previewOverrides.get(String(entry.gitBranch))
              : options.environment;
          environment?.set(String(entry.key), String(entry.value));
        }
        return Response.json(
          {
            created: accepted.map(({ key, type, target, gitBranch }) => ({ key, type, target, gitBranch })),
            failed: partial ? [{ error: { message: input.token } }] : [],
          },
          { status: 201 },
        );
      }
      if (url.pathname === new URL(deployHook).pathname) {
        await options.beforeHook?.();
        if (options.push === "unknownReceipt")
          throw new Error(`Provider request may have been sent to ${deployHook}`);
        return Response.json({ job: { id: jobId, state: "PENDING" } }, { status: 201 });
      }
      if (url.pathname === "/v7/deployments") {
        const response = await options.onPoll?.(++polls, url);
        if (response) return response;
        const readyState =
          options.push === "error"
            ? "ERROR"
            : options.push === "timeout" || (options.onPoll && polls <= 1)
              ? "BUILDING"
              : "READY";
        const expected = {
          source: "git-deploy-hook",
          projectId,
          target: input.target,
        };
        return Response.json({
          deployments: [
            { ...expected, uid: "dpl_UnrelatedFD29", readyState: "READY" },
            { ...expected, uid: deploymentId, meta: { deployHookJobId: jobId }, readyState },
          ],
        });
      }
      return Response.json({}, { status: 500 });
    };
    return { calls, transport, now: () => clock, proof };
  }

  async function noConnection(clientId: string) {
    expect(await sql`SELECT id FROM vercel_integrations WHERE database_client_id = ${clientId}`).toHaveLength(
      0,
    );
    expect(await sql`SELECT id FROM secrets WHERE resource_type = 'vercel_integration'`).toHaveLength(0);
    expect(
      await sql`SELECT id FROM operations WHERE kind = 'integration.vercel_push' AND payload->>'clientId' = ${clientId}`,
    ).toHaveLength(0);
  }

  async function assertNoCopies(token: string) {
    const rows = await sql`
      SELECT detail FROM audit_events WHERE resource_id = ${databaseId} AND action LIKE 'integration.vercel_%'
    `;
    for (const value of [token, deployHook]) {
      expect(JSON.stringify(rows).includes(value)).toBe(false);
      for (const file of await readdir(work, { recursive: true, withFileTypes: true })) {
        if (file.isFile())
          expect((await readFile(join(file.parentPath, file.name))).includes(value)).toBe(false);
      }
    }
  }

  async function issueEarly(clientId: string) {
    const { operation } = await rollover.queueEarlyRollover({
      databaseId,
      clientId,
      actorId: actors.owner.userId,
    });
    await runQueued(operation.id);
    return (await chain(clientId)).find((row) => row.rolloverState === "pending")!;
  }

  async function queuedPushId(clientId: string) {
    const queued =
      await sql`SELECT id FROM operations WHERE kind = 'integration.vercel_push' AND payload->>'clientId' = ${clientId}`;
    expect(queued).toHaveLength(1);
    return String(queued[0]!.id);
  }

  const refusals: Refusal[] = [
    "team",
    "account",
    "crossProject",
    "expired",
    "noExpiry",
    "network",
    "ambiguous",
    "genericDenial",
    "otherProjectVisible",
    "listVisible",
    "wrongTeam",
    "invalidToken",
  ];
  test("refuses every unproven token without writing secrets, integrations, jobs, disk copies, logs or Vercel mutations", async () => {
    clock = new Date();
    const { clientId } = await issueClient("vercelscope");
    await issueEarly(clientId); // A pass would queue a push immediately.
    const spies = [spyOn(console, "error"), spyOn(console, "warn"), spyOn(console, "log")];
    try {
      for (const refusal of refusals) {
        const input = inputFor(refusal);
        const mock = mockApi(input, { refusal, beforeProbe: () => noConnection(clientId) });
        await expect(vercel.connectVercel(actorRef(clientId), input, mock)).rejects.toThrow(
          /sole project scope/,
        );
        expect(mock.calls.map((request) => request.path).toSorted(), refusal).toEqual(expectedProbes);
        expect(
          mock.calls.every((request) => request.method === "GET" && request.authenticated),
          refusal,
        ).toBe(true);
        await noConnection(clientId);
        await assertNoCopies(input.token);
        const logged = spies
          .flatMap((spy) => spy.mock.calls.flat())
          .map(String)
          .join("\n");
        expect(logged.includes(input.token) || logged.includes(deployHook), refusal).toBe(false);
      }
    } finally {
      for (const spy of spies) spy.mockRestore();
      await park(clientId);
    }
  });

  test("applies owner, MFA and single-use step-up to every endpoint and preserves manual rollover with connect disabled", async () => {
    clock = new Date();
    const { clientId, first } = await issueClient("vercelgated");
    const ref = { databaseId, clientId };
    const input = inputFor("gate");
    const path = endpoint(clientId);
    expect(await (await call(actors.owner, path)).json()).toMatchObject({
      connectEnabled: false,
      eligible: true,
      integration: null,
    });
    for (const [method, tail, intent] of [
      ["PUT", "", "connect"],
      ["POST", "/test", "test"],
      ["DELETE", "", "disconnect"],
    ] as const) {
      const request = { method, ...(intent === "connect" ? { body: input } : {}) };
      for (const actor of [actors.operator, actors.viewer, actors.ownerWithoutMfa, actors.owner])
        expect((await call(actor, path + tail, request)).status, `${actor.userId} ${intent}`).toBe(403);
      const binding = intent === "connect" ? vercelConnectBinding(input) : {};
      await stepUp(actors.owner, "credential.rotate", { ...ref, vercelIntegration: intent, ...binding });
      const response = await call(actors.owner, path + tail, request);
      expect(response.status).toBe(intent === "disconnect" ? 200 : 409);
      const body = await response.text();
      expect(body.includes(input.token) || body.includes(deployHook)).toBe(false);
      expect((await call(actors.owner, path + tail, request)).status).toBe(403);
    }
    await noConnection(clientId);
    const pending = await issueEarly(clientId);
    await stepUp(actors.owner, "secret.reveal", { ...ref, rollover: true });
    const rolloverPath = `/api/databases/${databaseId}/clients/${clientId}/rollover`;
    expect((await call(actors.owner, `${rolloverPath}/reveal`, { method: "POST" })).status).toBe(200);
    expect(
      (
        await call(actors.owner, `${rolloverPath}/confirm`, {
          method: "POST",
          body: { certificateId: pending.id },
        })
      ).status,
    ).toBe(200);
    const certificates = await chain(clientId);
    expect(certificates.find((row) => row.id === first.id)?.rolloverState).toBe("superseded");
    expect(certificates.find((row) => row.id === pending.id)?.rolloverState).toBe("current");
    await noConnection(clientId);
    await park(clientId);
  });

  test("seals only a project-verified token and hook, queues after trust reload, delivers only after READY and cleans up on disconnect", async () => {
    clock = new Date();
    const { clientId, first } = await issueClient("vercelready", "preview");
    const input = { ...inputFor("verified", "preview"), gitBranch: undefined };
    const hookBranch = "fd29-preview";
    const ref = actorRef(clientId);
    const mock = mockApi(input, {
      beforeProbe: () => noConnection(clientId),
      expiresAt: at(clock, 30),
    });
    const connected = await vercel.connectVercel(ref, input, mock);
    expect(connected).toMatchObject({
      projectId,
      target: "preview",
      gitBranch: hookBranch,
      tokenExpiresAt: at(clock, 30),
    });
    expect(mock.calls.map(({ path }) => path).toSorted()).toEqual(expectedProbes);
    const [record] = await sql`
      SELECT id, token_secret_id, deploy_hook_secret_id, scope_verified_at FROM vercel_integrations
      WHERE database_client_id = ${clientId}
    `;
    expect(record?.scope_verified_at).toBeTruthy();
    const secretIds = [String(record?.token_secret_id), String(record?.deploy_hook_secret_id)];
    const stored = await sql`SELECT * FROM secrets WHERE id IN ${sql(secretIds)}`;
    expect(stored.map((row) => row.sensitivity)).toEqual(["provider", "provider"]);
    expect(JSON.stringify(stored).includes(input.token) || JSON.stringify(stored).includes(deployHook)).toBe(
      false,
    );
    const expiryKey = `vercel-token-expiry:${record!.id}`;
    vercelExpiryKeys.add(expiryKey);
    expect(await openAlert(expiryKey)).toMatchObject({ severity: "warning", resolved_at: null });
    await vercel.evaluateVercelTokenAlerts(at(clock, 30));
    expect(await openAlert(expiryKey)).toMatchObject({ severity: "critical", resolved_at: null });
    const probe = mockApi(input);
    expect(await vercel.testVercelConnection(ref, probe)).toMatchObject({ ok: true });
    expect(probe.calls.map((request) => request.path).toSorted()).toEqual(expectedProbes);
    expect(probe.calls.every((request) => request.method === "GET")).toBe(true);

    const pending = await issueEarly(clientId);
    expect(pending.trustAppliedAt).toBeTruthy();
    expect(await bundleFile()).toContain(await caPem(first.caId));
    expect(await bundleFile()).toContain(await caPem(pending.caId));
    const pushId = await queuedPushId(clientId);
    await vercel.queueVercelPush(ref, pending.id, clock);
    expect(await queuedPushId(clientId)).toBe(pushId);
    const workerRequest = (token: string) =>
      app.request(`${origin}/api/internal/jobs`, {
        headers: { authorization: `Bearer ${token}`, "x-ark-worker-kinds": "integration." },
      });
    expect((await workerRequest(process.env.ARK_DATABASE_WORKER_TOKEN!)).status).toBe(403);
    const claim = await workerRequest(process.env.ARK_DOMAIN_WORKER_TOKEN!);
    expect(claim.status).toBe(200);
    expect(await claim.json()).toMatchObject({ jobs: [{ id: pushId, kind: "integration.vercel_push" }] });
    const [op] = await sql`SELECT * FROM operations WHERE id = ${pushId}`;

    const defaults = new Map([[VERCEL_ENV_NAMES.key, "default-key"]]);
    const overrides = new Map([
      [VERCEL_ENV_NAMES.cert, "old-cert"],
      [VERCEL_ENV_NAMES.key, "old-key"],
    ]);
    const push = mockApi(input, {
      push: "ready",
      environment: defaults,
      previewOverrides: new Map([[hookBranch, overrides]]),
      onPoll: async () => {
        const pem = Buffer.from(overrides.get(VERCEL_ENV_NAMES.cert)!, "base64").toString();
        const key = Buffer.from(overrides.get(VERCEL_ENV_NAMES.key)!, "base64");
        expect(pem).toBe(pending.certPem!);
        expect(new X509Certificate(pem).checkPrivateKey(createPrivateKey(key))).toBe(true);
        expect(defaults.get(VERCEL_ENV_NAMES.key)).toBe("default-key");
        const certificates = await chain(clientId);
        expect(certificates.find((row) => row.id === first.id)?.rolloverState).toBe("current");
        expect(certificates.find((row) => row.id === pending.id)).toMatchObject({
          rolloverState: "pending",
          deliveredAt: null,
        });
        expect((await vercel.vercelIntegrationStatus(ref)).integration).toMatchObject({
          lastPushStatus: "pushing",
          lastDeploymentId: null,
        });
      },
    });
    const outcome = await coordinator.runOperation("integration.vercel_push", operationRow(op!), {
      vercelPush: (operation) => vercel.pushVercelRollover(operation, { ...push, sleep: async () => {} }),
    });
    expect(outcome).toMatchObject({
      certificateId: pending.id,
      deploymentId,
      deliveredAt: clock.toISOString(),
    });
    const mutations = push.calls.filter((request) => request.method === "POST");
    expect(mutations.map(({ path, authenticated }) => ({ path, authenticated }))).toEqual([
      { path: `/v10/projects/${projectId}/env?teamId=${teamId}&upsert=true`, authenticated: true },
      { path: new URL(deployHook).pathname, authenticated: false },
    ]);
    const target = {
      type: "sensitive",
      target: ["preview"],
      gitBranch: hookBranch,
    };
    const env = mutations[0]!.body!;
    expect(env).toEqual([
      { ...target, key: VERCEL_ENV_NAMES.cert, value: Buffer.from(pending.certPem!).toString("base64") },
      { ...target, key: VERCEL_ENV_NAMES.key, value: expect.any(String) },
    ]);
    const key = Buffer.from(String(env[1]!.value), "base64");
    expect(new X509Certificate(pending.certPem!).checkPrivateKey(createPrivateKey(key))).toBe(true);
    expect(push.calls.filter(({ path }) => path.startsWith("/v7/deployments"))).toHaveLength(2);
    const certificates = await chain(clientId);
    const original = certificates.find((row) => row.id === first.id);
    const successor = certificates.find((row) => row.id === pending.id);
    expect(original).toMatchObject({ status: "issued", rolloverState: "superseded" });
    expect(successor).toMatchObject({
      id: pending.id,
      rolloverState: "current",
      deliveredAt: clock,
      keySecretId: null,
    });
    expect(await sql`SELECT id FROM secrets WHERE id = ${pending.keySecretId!}`).toHaveLength(0);
    expect((await vercel.vercelIntegrationStatus(ref)).integration).toMatchObject({
      lastPushStatus: "delivered",
      lastDeploymentId: deploymentId,
    });
    expect(await vercel.pushVercelRollover(operationRow(op!), push)).toEqual({ skipped: true });
    expect(push.calls.filter((request) => request.method === "POST")).toHaveLength(2);

    for (const id of secretIds) {
      const response = await call(actors.owner, `/api/secrets/${id}/reveal`, { method: "POST" });
      expect(response.status).toBe(403);
    }
    await stepUp(actors.owner, "credential.rotate", {
      databaseId,
      clientId,
      vercelIntegration: "disconnect",
    });
    expect(await (await call(actors.owner, endpoint(clientId), { method: "DELETE" })).json()).toEqual({
      disconnected: true,
    });
    expect(await sql`SELECT id FROM secrets WHERE id IN ${sql(secretIds)}`).toHaveLength(0);
    expect(await sql`SELECT id FROM vercel_integrations WHERE id = ${record!.id}`).toHaveLength(0);
    expect((await openAlert(expiryKey))?.resolved_at).toBeTruthy();
    const [audit] = await sql`
      SELECT count(*)::int AS count FROM audit_events WHERE operation_id = ${pushId}
        AND action = 'integration.vercel_call' AND detail ?& ARRAY['endpoint', 'projectId', 'target', 'status']
    `;
    expect(audit!.count).toBe(push.calls.length);
    await assertNoCopies(input.token);
    await park(clientId);
  });

  test("a reclaimed push resumes the recorded hook job without sending another deployment", async () => {
    clock = new Date();
    const { clientId } = await issueClient("vercelresume");
    const ref = actorRef(clientId);
    const input = inputFor("resume");
    const pending = await issueEarly(clientId);
    await vercel.connectVercel(ref, input, mockApi(input));
    const pushId = await queuedPushId(clientId);
    const originalClaim = createId("claim");
    const nextClaim = createId("claim");
    const [op] = await sql`
      UPDATE operations SET status = 'running', claim_token = ${originalClaim}, heartbeat_at = now()
      WHERE id = ${pushId} RETURNING *
    `;
    const mock = mockApi(input, {
      onPoll: async (poll) => {
        if (poll === 1) await sql`UPDATE operations SET claim_token = ${nextClaim} WHERE id = ${pushId}`;
      },
    });
    const pushRuntime = { ...mock, sleep: async () => {} };
    expect(await vercel.pushVercelRollover(operationRow(op!), pushRuntime)).toEqual({ skipped: true });
    expect((await chain(clientId)).find((row) => row.id === pending.id)?.deliveredAt).toBeNull();
    expect(
      await vercel.pushVercelRollover({ ...operationRow(op!), claimToken: nextClaim }, pushRuntime),
    ).toMatchObject({ certificateId: pending.id, deploymentId });
    expect(mock.calls.filter((request) => request.method === "POST").map((request) => request.path)).toEqual([
      `/v10/projects/${projectId}/env?teamId=${teamId}&upsert=true`,
      new URL(deployHook).pathname,
    ]);
    await vercel.disconnectVercel(ref);
    await park(clientId);
  });

  test("verified enrollment and legacy removal preserve the published pooler policy", async () => {
    clock = new Date();
    const policyCidrs = ["198.51.100.0/24"];
    const sourceCidrs = ["203.0.113.0/24"];
    const [original] =
      await sql`SELECT pooler_source_cidrs, pooler_allow_internet, pooler_internet_confirmed_at,
      pooler_policy_reviewed_at, pooler_policy_reviewed_requests, pooler_fenced_at, pooler_fence_reason
      FROM platform_settings WHERE id = 'default'`;
    const [database] = await sql`SELECT source_cidrs FROM managed_databases WHERE id = ${databaseId}`;
    const verifiedClient = await issueClient("vercelrestricted");
    const legacyClients = [await issueClient("vercellegacy"), await issueClient("vercellegacyrevoke")];
    const ref = actorRef(verifiedClient.clientId);
    async function reviewCurrent() {
      const current = await loadPoolerPolicy();
      await sql`UPDATE platform_settings SET pooler_policy_reviewed_at = now(),
        pooler_policy_reviewed_requests = ${current.requestsFingerprint} WHERE id = 'default'`;
    }
    async function edgeFiles() {
      const { pooler } = await poolerEdgeInput();
      return renderEdgeL4Generation(coordinator.edgeL4Input({ certificates: [] }, {}, [], pooler)).files;
    }
    try {
      await sql`UPDATE managed_databases SET source_cidrs = ${JSON.stringify(sourceCidrs)}::jsonb WHERE id = ${databaseId}`;
      await sql`UPDATE platform_settings SET pooler_source_cidrs = ${JSON.stringify(policyCidrs)}::jsonb,
        pooler_allow_internet = false, pooler_fenced_at = NULL WHERE id = 'default'`;
      await reviewCurrent();
      const originalEdge = await poolerEdgeInput();
      expect(originalEdge.pooler).toMatchObject({ sourceCidrs: policyCidrs, allowInternet: false });
      const published = await edgeFiles();
      expect(published[POOLER_ALLOWLIST_FILE]).toBe(policyCidrs.join("\n") + "\n");
      expect(published["haproxy.cfg"]).toContain("use_backend be_pgbouncer if pg_ssl_request");

      const input = inputFor("restricted");
      await vercel.connectVercel(ref, input, mockApi(input));
      expect(await edgeFiles()).toEqual(published);
      expect((await loadPoolerPolicy()).requestsFingerprint).toBe(
        originalEdge.evaluation.requestsFingerprint,
      );
      await vercel.disconnectVercel(ref);
      expect(await edgeFiles()).toEqual(published);

      async function insertLegacy(clientId: string) {
        const secretId = createId("sec");
        await sql`INSERT INTO secrets (id, kind, resource_type, resource_id, ciphertext, iv, auth_tag, key_id, sensitivity)
          VALUES (${secretId}, 'legacy', 'vercel_integration', ${clientId}, 'test', 'test', 'test', 'test', 'provider')`;
        await sql`INSERT INTO vercel_integrations
          (id, database_client_id, vercel_project_id, token_secret_id, env_target)
          VALUES (${createId("vci")}, ${clientId}, 'prj_LegacyFixture', ${secretId}, 'production')`;
      }
      await insertLegacy(legacyClients[0]!.clientId);
      expect((await poolerEdgeInput()).pooler).toBeNull();
      await reviewCurrent();
      expect(await edgeFiles()).toEqual(published);
      await vercel.disconnectVercel(actorRef(legacyClients[0]!.clientId));
      expect(await edgeFiles()).toEqual(published);

      await insertLegacy(legacyClients[1]!.clientId);
      expect((await poolerEdgeInput()).pooler).toBeNull();
      await reviewCurrent();
      await clients.queueClientRevocation(actorRef(legacyClients[1]!.clientId));
      const after = await poolerEdgeInput();
      expect(after.pooler).toEqual(originalEdge.pooler);
      expect(after.evaluation).toMatchObject({ reviewed: true, distinctRequests: sourceCidrs });

      await sql`UPDATE managed_databases SET source_cidrs = '["192.0.2.0/24"]' WHERE id = ${databaseId}`;
      expect((await edgeFiles())["haproxy.cfg"]).not.toContain("use_backend be_pgbouncer");
    } finally {
      for (const item of [verifiedClient, ...legacyClients]) {
        await vercel.disconnectVercel(actorRef(item.clientId));
        await park(item.clientId);
      }
      await sql`UPDATE managed_databases SET source_cidrs = ${JSON.stringify(database!.source_cidrs)}::jsonb WHERE id = ${databaseId}`;
      await sql`UPDATE platform_settings SET
        pooler_source_cidrs = ${JSON.stringify(original!.pooler_source_cidrs)}::jsonb,
        pooler_allow_internet = ${original!.pooler_allow_internet},
        pooler_policy_reviewed_at = ${original!.pooler_policy_reviewed_at?.toISOString() ?? null}::timestamptz,
        pooler_policy_reviewed_requests = ${original!.pooler_policy_reviewed_requests},
        pooler_fenced_at = ${original!.pooler_fenced_at?.toISOString() ?? null}::timestamptz,
        pooler_fence_reason = ${original!.pooler_fence_reason} WHERE id = 'default'`;
    }
  });

  test("the hourly token alert can wait while the scheduler retires another client's certificate", async () => {
    clock = new Date();
    const retiring = await issueClient("verceltickretiring");
    clock = at(retiring.first.notAfter, -2);
    const recipient = await issueClient("vercelticktoken");
    const ref = actorRef(recipient.clientId);
    const input = inputFor("alert");
    const integration = await vercel.connectVercel(
      ref,
      input,
      mockApi(input, { expiresAt: at(retiring.first.notAfter, 30, 1) }),
    );
    expect(integration.tokenExpiryStatus).toBe("valid");
    const [row] =
      await sql`SELECT id FROM vercel_integrations WHERE database_client_id = ${recipient.clientId}`;
    const expiryKey = `vercel-token-expiry:${row!.id}`;
    vercelExpiryKeys.add(expiryKey);
    const release = Promise.withResolvers<void>();
    const watchdogRan = Promise.withResolvers<void>();
    let notifications = 0;
    const webhook = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(request) {
        const notification = (await request.json()) as { title: string };
        if (notification.title.startsWith(`Vercel token for ${projectId}`)) {
          notifications++;
          await release.promise;
        }
        return new Response(null, { status: 204 });
      },
    });
    const savedWebhook = process.env.ARK_ALERT_WEBHOOK;
    let pendingTick: ReturnType<typeof coordinator.rolloverTick> | undefined;
    const state: NonNullable<Parameters<typeof coordinator.rolloverTick>[1]> = {};
    try {
      process.env.ARK_ALERT_WEBHOOK = webhook.url.href;
      clock = new Date(retiring.first.notAfter.getTime() - 3_600_000);
      await coordinator.rolloverTick(runtime, state);
      await state.alertTask;
      expect(notifications).toBe(0);
      expect(await openAlert(expiryKey)).toBeUndefined();

      clock = at(retiring.first.notAfter, 0, 6_000);
      const item = (await rollover.dueRetirements({ now: clock })).find(
        ({ certificate }) => certificate.id === retiring.first.id,
      );
      await rollover.ensureRetirement(item!);
      pendingTick = coordinator.rolloverTick(
        {
          ...runtime,
          retire: (async (retirement: RetireInput) => {
            await watchdogRan.promise;
            return fakeRetire(retirement);
          }) as typeof runtime.retire,
          watchdog: {
            ...runtime.watchdog,
            stop: async () => {
              watchdogRan.resolve();
            },
          },
        },
        state,
      );
      await until(() => notifications === 1);
      let finished = false;
      void pendingTick.then(
        () => {
          finished = true;
        },
        () => {
          finished = true;
        },
      );
      try {
        await until(() => finished);
      } finally {
        watchdogRan.resolve();
      }
      expect(await pendingTick).toMatchObject({
        retired: [expect.objectContaining({ certificateId: retiring.first.id })],
        watchdog: [expect.objectContaining({ certificateId: retiring.first.id, stop: "ok" })],
      });
      expect(await openAlert(expiryKey)).toMatchObject({ severity: "warning", resolved_at: null });
      const [task] = await sql`SELECT completed_at FROM client_certificate_retirements
        WHERE certificate_id = ${retiring.first.id}`;
      expect(task?.completed_at).toBeTruthy();
      await coordinator.rolloverTick(runtime, state);
      expect(notifications).toBe(1);
    } finally {
      release.resolve();
      watchdogRan.resolve();
      await pendingTick;
      await state.alertTask;
      if (savedWebhook === undefined) delete process.env.ARK_ALERT_WEBHOOK;
      else process.env.ARK_ALERT_WEBHOOK = savedWebhook;
      webhook.stop(true);
      await vercel.disconnectVercel(ref);
      await park(retiring.clientId, recipient.clientId);
    }
  });

  test("the daily worker queues a trusted successor and retries a transient failure with one new attempt", async () => {
    clock = new Date();
    const { clientId, first } = await issueClient("verceldailyretry");
    const ref = actorRef(clientId);
    const input = inputFor("retry");
    const mock = mockApi(input, { push: "upsertRejected", expiresAt: at(clock, 120) });
    await vercel.connectVercel(ref, input, mock);
    try {
      clock = at(first.notAfter, -29);
      const daily = await coordinator.rolloverTick(runtime);
      expect(daily.queued).toBeTruthy();
      await runQueued(daily.queued!);
      const pending = (await chain(clientId)).find((certificate) => certificate.rolloverState === "pending")!;
      expect(pending.trustAppliedAt).toBeTruthy();
      const initial = await queuedPushId(clientId);
      await expect(
        runQueued(initial, {
          ...runtime,
          vercelPush: (operation) => vercel.pushVercelRollover(operation, mock),
        }),
      ).rejects.toThrow(/Manual rollover is available/);
      const genericKey = `op-failed:${initial}`;
      await evaluateAlerts();
      expect(await openAlert(genericKey)).toBeUndefined();
      await raiseAlert({
        dedupKey: genericKey,
        title: "Operation integration.vercel_push failed",
        severity: "warning",
      });

      clock = at(clock, 1);
      const retryDay = await coordinator.rolloverTick(runtime);
      await runQueued(retryDay.queued!);
      await Promise.all([
        vercel.queueVercelPush(ref, pending.id, clock),
        vercel.queueVercelPush(ref, pending.id, clock),
      ]);
      const attempts = await sql`SELECT id, status FROM operations
        WHERE kind = 'integration.vercel_push' AND payload->>'clientId' = ${clientId} ORDER BY created_at`;
      expect([...attempts]).toEqual([
        { id: initial, status: "failed" },
        { id: expect.any(String), status: "queued" },
      ]);
      const recovered = mockApi(input);
      await expect(
        runQueued(String(attempts[1]!.id), {
          ...runtime,
          vercelPush: (operation) => vercel.pushVercelRollover(operation, recovered),
        }),
      ).resolves.toMatchObject({ certificateId: pending.id, deploymentId });
      expect((await openAlert(rollover.vercelPushAlertKey(clientId)))?.resolved_at).toBeTruthy();
      await evaluateAlerts();
      expect((await openAlert(genericKey))?.resolved_at).toBeTruthy();
      await sql`DELETE FROM alerts WHERE dedup_key = ${genericKey}`;
    } finally {
      await vercel.disconnectVercel(ref);
      await park(clientId);
    }
  });

  test("a timed-out delivery can check its known receipt on a later retry without another hook", async () => {
    clock = new Date();
    const { clientId } = await issueClient("vercelretryreceipt");
    const ref = actorRef(clientId);
    const input = inputFor("retryreceipt");
    try {
      const pending = await issueEarly(clientId);
      const requestedAt = clock;
      const slow = mockApi(input, { push: "timeout" });
      await vercel.connectVercel(ref, input, slow);
      const initial = await queuedPushId(clientId);
      await expect(
        runQueued(initial, {
          ...runtime,
          vercelPush: (operation) =>
            vercel.pushVercelRollover(operation, {
              ...slow,
              sleep: async () => {
                clock = at(clock, 0, 30 * 60_000);
              },
            }),
        }),
      ).rejects.toThrow(/Manual rollover is available/);

      clock = at(clock, 1);
      await vercel.queueVercelPush(ref, pending.id, clock);
      const [retry] = await sql`SELECT id FROM operations WHERE kind = 'integration.vercel_push'
        AND payload->>'clientId' = ${clientId} AND status = 'queued'`;
      expect(retry?.id).toBeDefined();
      const firstCursor = requestedAt.getTime() + 1_000;
      const crowded = mockApi(input, {
        onPoll: async (_poll, url) => {
          const cursor = Number(url.searchParams.get("until") ?? firstCursor);
          return Response.json({
            deployments: [{ uid: "dpl_UnrelatedFD29", source: "git-deploy-hook", readyState: "READY" }],
            pagination: { next: cursor - 1 },
          });
        },
      });
      await expect(
        runQueued(String(retry?.id), {
          ...runtime,
          vercelPush: (operation) => vercel.pushVercelRollover(operation, crowded),
        }),
      ).rejects.toThrow(/Manual rollover is available/);
      expect(crowded.calls).toHaveLength(5);

      clock = at(clock, 1);
      await vercel.queueVercelPush(ref, pending.id, clock);
      const [lastRetry] = await sql`SELECT id FROM operations WHERE kind = 'integration.vercel_push'
        AND payload->>'clientId' = ${clientId} AND status = 'queued'`;
      const ready = mockApi(input, {
        onPoll: async (_poll, url) => {
          expect(url.searchParams.get("until")).toBe(String(firstCursor - 5));
          return Response.json({
            deployments: [
              {
                uid: deploymentId,
                source: "git-deploy-hook",
                projectId,
                target: "production",
                meta: { deployHookJobId: jobId },
                readyState: "READY",
              },
            ],
          });
        },
      });
      await expect(
        runQueued(String(lastRetry?.id), {
          ...runtime,
          vercelPush: (operation) => vercel.pushVercelRollover(operation, ready),
        }),
      ).resolves.toMatchObject({ certificateId: pending.id, deploymentId });
      expect(ready.calls.map(({ method, path }) => [method, path])).toEqual([
        ["GET", expect.stringMatching(/^\/v7\/deployments\?/)],
      ]);
    } finally {
      await vercel.disconnectVercel(ref);
      await park(clientId);
    }
  });

  test("an alert sweep retries a database rejection independently of retirement and the other sweep", async () => {
    clock = new Date();
    const retiring = await issueClient("vercelalertretiring");
    clock = at(retiring.first.notAfter, -2);
    const recipient = await issueClient("vercelalertretry");
    const ref = actorRef(recipient.clientId);
    const input = inputFor("alert-retry");
    await vercel.connectVercel(ref, input, mockApi(input, { expiresAt: at(clock, 45) }));
    const [integration] =
      await sql`SELECT id FROM vercel_integrations WHERE database_client_id = ${ref.clientId}`;
    const expiryKey = `vercel-token-expiry:${integration!.id}`;
    vercelExpiryKeys.add(expiryKey);
    const trigger = sql(`fd29_alert_failure_${suffix}`);
    const state: NonNullable<Parameters<typeof coordinator.rolloverTick>[1]> = {};
    try {
      await sql.unsafe(`CREATE FUNCTION fd29_alert_failure_${suffix}() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Vercel alert test rejection'; END; $$`);
      await sql`CREATE TRIGGER ${trigger} BEFORE INSERT ON alerts FOR EACH ROW
        WHEN (NEW.dedup_key LIKE 'vercel-token-expiry:%') EXECUTE FUNCTION ${trigger}()`;
      clock = at(retiring.first.notAfter, 0, 1);
      await sql`UPDATE vercel_integrations SET token_expires_at = ${at(clock, 10).toISOString()}::timestamptz
        WHERE id = ${integration!.id}`;
      const tick = await coordinator.rolloverTick(runtime, state);
      await state.alertTask;
      expect(tick.retired).toContainEqual(expect.objectContaining({ certificateId: retiring.first.id }));
      expect(await openAlert(expiryKey)).toBeUndefined();
      const nextSweepTimes = state.alertSweeps?.map(({ nextAt }) => nextAt);
      expect(nextSweepTimes).toEqual([clock.getTime() + 3_600_000, clock.getTime() + 5_000]);

      await sql`DROP TRIGGER ${trigger} ON alerts`;
      clock = at(clock, 0, 5_000);
      await coordinator.rolloverTick(runtime, state);
      await state.alertTask;
      expect(await openAlert(expiryKey)).toMatchObject({ severity: "warning", resolved_at: null });
      expect(state.alertSweeps?.[0]?.nextAt).toBe(nextSweepTimes?.[0]);
    } finally {
      await sql`DROP TRIGGER IF EXISTS ${trigger} ON alerts`;
      await sql`DROP FUNCTION IF EXISTS ${trigger}()`;
      await vercel.disconnectVercel(ref);
      await park(retiring.clientId, recipient.clientId);
    }
  });

  for (const readyOn of ["last response", "final lookup"] as const) {
    test(`delivers READY from the ${readyOn} at the polling deadline`, async () => {
      clock = new Date();
      const { clientId } = await issueClient(
        readyOn === "last response" ? "vercelboundary1" : "vercelboundary2",
      );
      const ref = actorRef(clientId);
      const input = inputFor(readyOn.replace(" ", "_"));
      try {
        const pending = await issueEarly(clientId);
        const deadline = at(clock, 0, 30 * 60_000);
        const mock = mockApi(input, {
          onPoll: async (poll) => {
            if (poll === 2 && readyOn === "last response") clock = deadline;
            if (poll === 2 && readyOn === "final lookup") expect(clock).toEqual(deadline);
          },
        });
        await vercel.connectVercel(ref, input, mock);
        const job = await queuedPushId(clientId);
        await expect(
          runQueued(job, {
            ...runtime,
            vercelPush: (operation) =>
              vercel.pushVercelRollover(operation, {
                ...mock,
                sleep: async () => {
                  clock = at(deadline, 0, readyOn === "last response" ? -1 : 0);
                },
              }),
          }),
        ).resolves.toMatchObject({ certificateId: pending.id, deploymentId });
        expect(mock.calls.filter(({ path }) => path.startsWith("/v7/deployments"))).toHaveLength(2);
        expect(await openAlert(rollover.vercelPushAlertKey(clientId))).toBeUndefined();
      } finally {
        await vercel.disconnectVercel(ref);
        await park(clientId);
      }
    });
  }

  test("repairs an incomplete pair before the hook and backs off with Retry-After while polling", async () => {
    clock = new Date();
    const { clientId } = await issueClient("vercelpartialrepair");
    const ref = actorRef(clientId);
    const input = inputFor("partial_repair");
    const environment = new Map([
      [VERCEL_ENV_NAMES.cert, "old-cert"],
      [VERCEL_ENV_NAMES.key, "old-key"],
    ]);
    const delays: number[] = [];
    try {
      const pending = await issueEarly(clientId);
      const mock = mockApi(input, {
        push: "partialOnce",
        environment,
        beforeHook: async () => {
          const cert = Buffer.from(environment.get(VERCEL_ENV_NAMES.cert)!, "base64").toString();
          const key = Buffer.from(environment.get(VERCEL_ENV_NAMES.key)!, "base64");
          expect(cert).toBe(pending.certPem!);
          expect(new X509Certificate(cert).checkPrivateKey(createPrivateKey(key))).toBe(true);
        },
        onPoll: async (poll) => {
          if (poll === 1 || poll === 3) return Response.json({}, { status: 429 });
          if (poll === 2) return Response.json({}, { status: 503, headers: { "Retry-After": "25" } });
        },
      });
      await vercel.connectVercel(ref, input, mock);
      const job = await queuedPushId(clientId);
      await expect(
        runQueued(job, {
          ...runtime,
          vercelPush: (operation) =>
            vercel.pushVercelRollover(operation, {
              ...mock,
              sleep: async (delay) => {
                delays.push(delay);
                clock = at(clock, 0, delay);
              },
            }),
        }),
      ).resolves.toMatchObject({ certificateId: pending.id, deploymentId });
      expect(mock.calls.filter(({ path }) => path.startsWith("/v10/"))).toHaveLength(2);
      expect(mock.calls.filter(({ path }) => path.startsWith("/v1/"))).toHaveLength(1);
      expect(mock.calls.filter(({ path }) => path.startsWith("/v7/"))).toHaveLength(4);
      expect(delays).toHaveLength(3);
      expect(delays[0]).toBeGreaterThanOrEqual(10_000);
      expect(delays[1]).toBe(25_000);
      expect(delays[2]).toBeGreaterThanOrEqual(40_000);
      expect(await openAlert(rollover.vercelPushAlertKey(clientId))).toBeUndefined();
    } finally {
      await vercel.disconnectVercel(ref);
      await park(clientId);
    }
  });

  for (const outcome of ["settled", "unsettled"] as const) {
    test(`defers a replacement push while the disconnected integration's write is ${outcome === "settled" ? "running" : "unconfirmed"}`, async () => {
      clock = new Date();
      const oldClient = await issueClient(outcome === "settled" ? "vercelold" : "vercelambiguous");
      const replacement = await issueClient(outcome === "settled" ? "vercelreplacement" : "verceldeferred");
      const oldRef = actorRef(oldClient.clientId);
      const nextRef = actorRef(replacement.clientId);
      const input = inputFor("old");
      const nextInput = inputFor("replacement");
      const entered = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      const environment = new Map<string, string>();
      const old = mockApi(input, {
        environment,
        push: outcome === "unsettled" ? "upsertUnsettled" : undefined,
        beforeEnv: async () => {
          entered.resolve();
          await release.promise;
        },
      });
      const next = mockApi(nextInput, { environment });
      await issueEarly(oldClient.clientId);
      const pending = await issueEarly(replacement.clientId);
      await vercel.connectVercel(oldRef, input, old);
      const oldJob = await queuedPushId(oldClient.clientId);
      const pushing = runQueued(oldJob, {
        ...runtime,
        vercelPush: (operation) => vercel.pushVercelRollover(operation, old),
      });
      try {
        await Promise.race([entered.promise, pushing]);
        await vercel.disconnectVercel(oldRef);
        expect((await vercel.vercelIntegrationStatus(oldRef)).integration).toBeNull();
        expect(await sql`SELECT id FROM secrets WHERE resource_type = 'vercel_integration'`).toHaveLength(0);
        await vercel.connectVercel(nextRef, nextInput, next);
        const nextJob = await queuedPushId(replacement.clientId);
        const nextRuntime = {
          ...runtime,
          vercelPush: (operation: Parameters<typeof vercel.pushVercelRollover>[0]) =>
            vercel.pushVercelRollover(operation, next),
        };
        await expect(runQueued(nextJob, nextRuntime)).rejects.toThrow(/Manual rollover is available/);
        expect(next.calls.some(({ method }) => method === "POST")).toBe(false);
        expect(await openAlert(rollover.vercelPushAlertKey(replacement.clientId))).toMatchObject({
          title: expect.stringContaining("environment write is unsettled"),
        });

        release.resolve();
        expect(await pushing).toEqual({ skipped: true });
        clock = at(clock, 1);
        await vercel.queueVercelPush(nextRef, pending.id, clock);
        const [retry] = await sql`SELECT id FROM operations WHERE kind = 'integration.vercel_push'
          AND payload->>'clientId' = ${replacement.clientId} AND status = 'queued'`;
        if (outcome === "unsettled") {
          await expect(runQueued(String(retry!.id), nextRuntime)).rejects.toThrow(
            /Manual rollover is available/,
          );
          expect(next.calls.some(({ method }) => method === "POST")).toBe(false);
        } else {
          await expect(runQueued(String(retry!.id), nextRuntime)).resolves.toMatchObject({
            certificateId: pending.id,
          });
          const cert = Buffer.from(environment.get(VERCEL_ENV_NAMES.cert)!, "base64").toString();
          const key = Buffer.from(environment.get(VERCEL_ENV_NAMES.key)!, "base64");
          expect(cert).toBe(pending.certPem!);
          expect(new X509Certificate(cert).checkPrivateKey(createPrivateKey(key))).toBe(true);
        }
      } finally {
        release.resolve();
        await pushing.catch(() => {});
        await sql`DELETE FROM vercel_env_writes WHERE operation_id = ${oldJob}`;
        await vercel.disconnectVercel(oldRef);
        await vercel.disconnectVercel(nextRef);
        await park(oldClient.clientId, replacement.clientId);
      }
    }, 15_000);
  }

  for (const phase of ["probe", "environment", "hook", "poll"] as const) {
    test(`local recovery proceeds during an in-flight Vercel ${phase} request`, async () => {
      clock = new Date();
      const { clientId } = await issueClient(`vercelrace${phase}`);
      const ref = actorRef(clientId);
      const input = inputFor(phase);
      const pending = await issueEarly(clientId);
      await vercel.connectVercel(ref, input, mockApi(input));
      const job = await queuedPushId(clientId);
      let entered = false;
      const blocked = Promise.withResolvers<void>();
      const pause = async () => {
        entered = true;
        await blocked.promise;
      };
      const mock = mockApi(input, {
        beforeProbe: phase === "probe" ? pause : undefined,
        beforeEnv: phase === "environment" ? pause : undefined,
        beforeHook: phase === "hook" ? pause : undefined,
        onPoll: phase === "poll" ? pause : undefined,
      });
      const pushing = runQueued(job, {
        ...runtime,
        vercelPush: (operation) => vercel.pushVercelRollover(operation, { ...mock, sleep: async () => {} }),
      });
      try {
        await until(() => entered);
        let finished = false;
        const local = (async () => {
          if (phase === "probe" || phase === "hook") {
            await clients.queueClientRevocation(ref);
            const [row] = await sql`SELECT revoked_at FROM database_clients WHERE id = ${clientId}`;
            expect(row?.revoked_at).toBeTruthy();
          } else if (phase === "environment") {
            await revealSuccessor(clientId);
            await rollover.confirmRolloverDelivery({ ...ref, certificateId: pending.id, now: clock });
            expect((await vercel.vercelIntegrationStatus(ref)).integration?.lastPushStatus).toBe("cancelled");
          } else {
            expect(await vercel.disconnectVercel(ref)).toEqual({ disconnected: true });
          }
        })().finally(() => {
          finished = true;
        });
        try {
          await until(() => finished);
        } finally {
          blocked.resolve();
          await local;
        }
        expect(await pushing).toEqual({ skipped: true });
        const calls = mock.calls.filter(({ method }) => method === "POST");
        expect(calls).toHaveLength(phase === "probe" ? 0 : phase === "environment" ? 1 : 2);
        expect(mock.calls.filter(({ path }) => path.startsWith("/v7/deployments"))).toHaveLength(
          phase === "poll" ? 1 : 0,
        );
      } finally {
        blocked.resolve();
        await pushing;
        await vercel.disconnectVercel(ref);
        await park(clientId);
      }
    });
  }

  for (const mode of ["partial", "error", "timeout", "unknownReceipt"] as const) {
    test(`leaves the old certificate usable after a ${mode} delivery failure`, async () => {
      clock = new Date();
      const target = mode === "partial" ? "preview" : "production";
      const { clientId, first } = await issueClient(`vercel${mode.toLowerCase()}`, target);
      const ref = actorRef(clientId);
      const input = inputFor(mode, target);
      const pending = await issueEarly(clientId);
      const current = await clients.revealDatabaseClient(ref);
      const oldKey = Buffer.from(current.privateKey!).toString("base64");
      const environment = new Map([
        [VERCEL_ENV_NAMES.cert, Buffer.from(current.certificate.pem!).toString("base64")],
        [VERCEL_ENV_NAMES.key, oldKey],
      ]);
      const mock = mockApi(input, { push: mode, environment });
      await vercel.connectVercel(ref, input, mock);
      const job = await queuedPushId(clientId);
      const pushRuntime = {
        ...runtime,
        vercelPush: (operation: Parameters<typeof vercel.pushVercelRollover>[0]) =>
          vercel.pushVercelRollover(operation, {
            ...mock,
            sleep: async () => {
              clock = new Date(clock.getTime() + 30 * 60_000);
            },
          }),
      };
      await expect(runQueued(job, pushRuntime)).rejects.toThrow(/Manual rollover is available/);
      if (mode === "unknownReceipt") {
        await vercel.queueVercelPush(ref, pending.id, clock);
        expect(await queuedPushId(clientId)).toBe(job);
        await sql`UPDATE operations SET status = 'queued' WHERE id = ${job}`;
        await expect(runQueued(job, pushRuntime)).rejects.toThrow(/Manual rollover is available/);
      }
      expect(
        mock.calls.filter(({ method, path }) => method === "POST" && path.startsWith("/v1/")),
      ).toHaveLength(mode === "partial" ? 0 : 1);
      expect((await vercel.vercelIntegrationStatus(ref)).integration?.lastPushStatus).toBe("failed");
      const certificates = await chain(clientId);
      const old = certificates.find((row) => row.id === first.id);
      const next = certificates.find((row) => row.id === pending.id);
      expect(old).toMatchObject({ status: "issued", rolloverState: "current" });
      expect(next).toMatchObject({
        id: pending.id,
        rolloverState: "pending",
        deliveredAt: null,
        keySecretId: pending.keySecretId,
      });
      if (mode === "partial") {
        expect(environment.get(VERCEL_ENV_NAMES.cert)).toBe(Buffer.from(next!.certPem!).toString("base64"));
        expect(environment.get(VERCEL_ENV_NAMES.key) === oldKey).toBe(true);
        expect(mock.calls.some(({ path }) => path.startsWith("/v7/deployments"))).toBe(false);
        expect(mock.calls.filter(({ path }) => path.startsWith("/v10/"))).toHaveLength(2);
        expect((await openAlert(rollover.vercelPushAlertKey(clientId)))?.title).toContain(
          `mismatched certificate and key for ${projectId} (preview · fd29-preview)`,
        );
      }
      const oldCa = await caPem(first.caId);
      expect(await bundleFile()).toContain(oldCa);
      const oldLeaf = new X509Certificate(old!.certPem!);
      expect(oldLeaf.verify(new X509Certificate(oldCa).publicKey)).toBe(true);
      expect(oldLeaf.checkPrivateKey(createPrivateKey(current.privateKey!))).toBe(true);
      expect(old!.notAfter > clock).toBe(true);
      expect(await openAlert(rollover.vercelPushAlertKey(clientId))).toMatchObject({
        severity: mode === "partial" ? "critical" : "warning",
        resolved_at: null,
      });
      await assertNoCopies(input.token);
      const status = await rollover.rolloverStatus({ ...ref, now: clock });
      const revealed = await revealSuccessor(clientId);
      if (mode === "partial") {
        for (const guide of [status.guide, revealed.guide]) {
          expect(guide.commands).toContain(projectId);
          expect(guide.commands.match(/--git-branch='fd29-preview'/g)).toHaveLength(2);
          expect(guide.commands).toContain('Redeploy Preview branch "fd29-preview"');
        }
      }
      await rollover.confirmRolloverDelivery({ databaseId, clientId, certificateId: pending.id, now: clock });
      expect((await openAlert(rollover.vercelPushAlertKey(clientId)))?.resolved_at).toBeTruthy();
      expect((await vercel.vercelIntegrationStatus(ref)).integration?.lastPushStatus).toBe("cancelled");
      await vercel.disconnectVercel(ref);
      await park(clientId);
    }, 15_000);
  }
});
