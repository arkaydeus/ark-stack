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

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createId, parseEnvFile, PGBOUNCER_FILES, ROLLOVER_ALERT_PREFIX, type Role } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";
import postgres from "postgres";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { sql } = await import("./db.ts");
const clients = await import("./modules/db-clients.ts");
const rollover = await import("./modules/db-client-rollover.ts");
const coordinator = await import("./coordinator.ts");
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
  return app.request(path, {
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
async function runQueued(operationId: string) {
  const [row] = await sql`
    UPDATE operations SET status = 'running', claim_token = ${createId("claim")}, heartbeat_at = now()
    WHERE id = ${operationId} AND status = 'queued' RETURNING *
  `;
  expect(row).toBeDefined();
  try {
    const evidence = await coordinator.runOperation(row!.kind as never, operationRow(row!), runtime);
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
    await sql`UPDATE database_clients SET status = 'revoked', revoked_at = now() WHERE id = ${id}`;
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
    ...clientIds.map((id) => `${ROLLOVER_ALERT_PREFIX}${id}`),
    ...(caIds.length
      ? (await sql`SELECT id FROM client_certificates WHERE ca_id IN ${sql(caIds)}`).map(
          (row) => `db-client-retire:${row.id}`,
        )
      : []),
  ];
  await sql`DELETE FROM operations WHERE target_ids ? ${databaseId}`;
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
    expect(alert!.title).toMatch(
      /retirement deadline .* missed; the watchdog fenced admission and stopped PgBouncer/,
    );
    results.push(`T+6 s: deadline missed → watchdog ${watchdogCalls.join(", ")}; "${alert!.title}"`);

    // The watchdog acts once; retries continue until the drain succeeds.
    clock = new Date(notAfter.getTime() + 7_000);
    failRoles.delete(e.role);
    await coordinator.rolloverTick(runtime);
    expect(watchdogCalls.length).toBe(2);
    [task] = await sql`SELECT * FROM client_certificate_retirements WHERE certificate_id = ${e.first.id}`;
    expect(task!.completed_at).toBeTruthy();
    expect(task!.deadline_missed).toBe(true);
    const retired = (await chain(e.clientId)).find((row) => row.id === e.first.id)!;
    expect(retired.retiredAt).toBeTruthy();
    // Expiry without a timely drain is a failure: the alert stays open, naming the lateness.
    alert = await openAlert(key);
    expect(alert).toMatchObject({ severity: "critical", resolved_at: null });
    expect(alert!.title).toMatch(/drained \d+ s after its retirement deadline/);
    results.push(
      `T+7 s: retry drained the role; task complete with deadline_missed=true, alert stays: "${alert!.title}"`,
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
    expect(actions[0]).toMatchObject({ certificateId: f.first.id, skipped: "no admin socket" });
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
