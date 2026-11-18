// FD-12 (docs/design/front-door.md §3.9.6): gate users against the real API on a real listener, run
// only by `gate-users.test.ts` in its own process and database.
//
// Requests go over TCP so the API sees a real transport peer: 127.0.0.1 is the recorded edge peer
// and carries the edge token on login-origin requests, as Caddy does. Route-host requests are made
// exactly as the rendered Caddyfile makes them (forward_auth to /api/gate/check and the callback
// rewrite with X-Ark-Route). A fake Caddy admin API stands in for the edge's forced reloads.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";

import { createId, privilegedRequestHash } from "@ark-stack/shared";
import postgres from "postgres";

const { app } = await import("./app.ts");
const { auth, authCookieName } = await import("./auth.ts");
const { sql } = await import("./db.ts");
const { refreshLoginHost } = await import("./origin-hosts.ts");
const { runOperation } = await import("./coordinator.ts");

const adminHost = new URL(process.env.BETTER_AUTH_URL!).host;
const zone = "gate12.example.com";
const loginHost = `login.${zone}`;
const appHost = `app.${zone}`;
const edgeToken = process.env.ARK_EDGE_GATE_TOKEN!;
const ownerPassword = "Gate-Users-Owner-Password-123!";

const server = Bun.serve({ hostname: "::", port: 0, fetch: app.fetch });

// ---- Fake Caddy admin API: records forced reloads -------------------------------------------------------
const caddy = { loads: [] as Array<{ cacheControl: string | null }> };
const caddyAdmin = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname === "/config/") return Response.json({}, { headers: { etag: '"1"' } });
    if (pathname === "/adapt") return Response.json({ result: { apps: {} } });
    if (pathname === "/load") {
      caddy.loads.push({ cacheControl: request.headers.get("cache-control") });
      return new Response(null, { status: 200 });
    }
    if (pathname === "/stop") return new Response(null, { status: 200 });
    return new Response("not found", { status: 404 });
  },
});

type Call = {
  host: string;
  path: string;
  method?: string;
  body?: unknown;
  cookie?: string;
  edge?: { client: string } | false;
  headers?: Record<string, string>;
};

async function call(input: Call) {
  const method = input.method ?? (input.body === undefined ? "GET" : "POST");
  const headers = new Headers({ host: input.host, ...input.headers });
  if (input.cookie) headers.set("cookie", input.cookie);
  if (input.body !== undefined) headers.set("content-type", "application/json");
  if (method !== "GET" && method !== "HEAD" && !headers.has("origin"))
    headers.set("origin", `https://${input.host}`);
  if (input.edge) {
    headers.set("x-forwarded-for", input.edge.client);
    headers.set("x-ark-edge-token", edgeToken);
  }
  return fetch(`http://127.0.0.1:${server.port}${input.path}`, {
    method,
    headers,
    body: input.body === undefined ? undefined : JSON.stringify(input.body),
    redirect: "manual",
  });
}

/** A browser's cookie jar for one host. */
class Jar {
  cookies = new Map<string, string>();
  get header() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
  take(response: Response) {
    for (const header of response.headers.getSetCookie()) {
      const pair = header.split(";")[0]!;
      const separator = pair.indexOf("=");
      const [name, value] = [pair.slice(0, separator), pair.slice(separator + 1)];
      if (value === "" || /max-age=0/i.test(header)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return response;
  }
}

let clientCounter = 10;
/** A browser with its own client address (separate rate-limit buckets) and per-host jars. */
class Browser {
  readonly client = `198.51.100.${clientCounter++}`;
  readonly jars = new Map<string, Jar>();
  jar(host: string) {
    let jar = this.jars.get(host);
    if (!jar) this.jars.set(host, (jar = new Jar()));
    return jar;
  }
  /** A login-origin request as the edge forwards it, or a direct admin-origin request. */
  async send(path: string, body?: unknown, host = loginHost, extra: Partial<Call> = {}) {
    const jar = this.jar(host);
    return jar.take(
      await call({
        host,
        path,
        body,
        cookie: jar.header,
        edge: host === loginHost ? { client: this.client } : false,
        ...extra,
      }),
    );
  }
  async check(routeId: string, accept = "text/html") {
    const jar = this.jar(appHost);
    return jar.take(
      await call({
        host: appHost,
        path: `/api/gate/check?route=${routeId}`,
        cookie: jar.header,
        edge: { client: this.client },
        headers: { "x-forwarded-method": "GET", "x-forwarded-uri": "/", accept },
      }),
    );
  }
  async callback(routeId: string, search: string) {
    const jar = this.jar(appHost);
    return jar.take(
      await call({
        host: appHost,
        path: `/api/gate/callback${search}`,
        cookie: jar.header,
        edge: { client: this.client },
        headers: { "x-ark-route": routeId },
      }),
    );
  }
}

// RFC 4648 Base32 decoding and RFC 6238 SHA-1 TOTP, independent of Better Auth's generator.
function totpGenerator(secret: string) {
  const bits = [...secret.toUpperCase().replace(/=+$/, "")]
    .map((char) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char).toString(2).padStart(5, "0"))
    .join("");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((byte) => Number.parseInt(byte, 2)));
  return () => {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
    const digest = createHmac("sha1", key).update(counter).digest();
    const offset = digest[digest.length - 1]! & 15;
    return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
  };
}

type Admin = { id: string; email: string; cookie: string };

/** An administrator with assured MFA and an admin-origin session minted with explicit provenance. */
async function createAdmin(label: string, role: "owner" | "operator" | "viewer"): Promise<Admin> {
  const ctx = await auth.$context;
  const email = `${label}-${createId("usr").slice(4, 12)}@example.test`;
  const created = await ctx.internalAdapter.createUser(
    { name: label, email, emailVerified: true },
    { method: "email-password" },
  );
  await ctx.internalAdapter.linkAccount({
    userId: created.id,
    providerId: "credential",
    accountId: created.id,
    password: await ctx.password.hash(ownerPassword),
  });
  await sql`INSERT INTO platform_access (user_id, role) VALUES (${created.id}, ${role})`;
  await sql`UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${created.id}`;
  return { id: created.id, email, cookie: await adminCookie(created.id) };
}

async function adminCookie(userId: string) {
  const ctx = await auth.$context;
  const session = await ctx.internalAdapter.createSession(userId, false, { origin: "admin" });
  const { makeSignature } = await import("better-auth/crypto");
  return `${authCookieName("session_token")}=${encodeURIComponent(`${session.token}.${await makeSignature(session.token, ctx.secret)}`)}`;
}

/** The admin API, as the admin SPA calls it. */
function adminApi(admin: Admin, path: string, method = "GET", body?: unknown) {
  return call({
    host: adminHost,
    path,
    method,
    body: body ?? (method === "GET" ? undefined : {}),
    cookie: admin.cookie,
  });
}

/** The real step-up endpoint: password, MFA assurance and a request binding. */
async function stepUp(
  admin: Admin,
  action: "role.grant" | "secret.reveal",
  request: Record<string, unknown>,
) {
  return adminApi(admin, "/api/step-up", "POST", { password: ownerPassword, action, request });
}

async function createGateUser(email: string) {
  const request = { email };
  expect((await stepUp(owner, "role.grant", { ...request, gateUsers: "create" })).status).toBe(200);
  const response = await adminApi(owner, "/api/gate/users", "POST", request);
  expect(response.status).toBe(201);
  return ((await response.json()) as { user: { id: string; email: string } }).user;
}

async function revealPassword(userId: string) {
  expect((await stepUp(owner, "secret.reveal", { gateUserTemporaryPassword: userId })).status).toBe(200);
  return adminApi(owner, `/api/gate/users/${userId}/temporary-password`, "POST");
}

async function addRoute(label: string) {
  const endpointId = createId("end");
  const routeId = `rt_${createId("x").slice(2, 14)}`;
  const hostname = `${label}.${zone}`;
  await sql`INSERT INTO endpoints (id, kind, hostname, exposure) VALUES (${endpointId}, 'route', ${hostname}, 'public')`;
  await sql`
    INSERT INTO front_routes (id, kind, endpoint_id, listen_port, target_input, target_node_stable_id,
      target_ip, target_port, access_mode, status, enabled)
    VALUES (${routeId}, 'http', ${endpointId}, 443, 'home.tail1234.ts.net', 'nHOME', '100.101.102.103', 3000,
      'sso', 'ready', true)
  `;
  return { id: routeId, hostname };
}

/** Runs every queued gate-revocation drain like the domain worker, against the fake Caddy admin. */
async function runDrains() {
  process.env.ARK_EDGE_RELOAD_URL = `http://127.0.0.1:${caddyAdmin.port}`;
  try {
    for (const row of await sql`SELECT * FROM operations WHERE kind = 'edge.drain' AND status = 'queued' AND payload ->> 'reason' = 'gate_revocation'`) {
      await sql`UPDATE operations SET status = 'running' WHERE id = ${row.id}`;
      const operation = {
        ...row,
        targetIds: row.target_ids,
        payload: row.payload,
      } as unknown as Parameters<typeof runOperation>[1];
      await runOperation("edge.drain", operation);
      await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${row.id}`;
    }
  } finally {
    process.env.ARK_EDGE_RELOAD_URL = "";
  }
}

/** The error message a statement fails with (postgres.js queries are lazy thenables). */
async function failure(query: PromiseLike<unknown>) {
  try {
    await query;
    return "";
  } catch (error) {
    return (error as Error).message;
  }
}

async function pendingRevocations() {
  return sql`SELECT route_id, reason FROM gate_revocations WHERE applied_at IS NULL ORDER BY route_id`;
}

let owner: Admin;
let operator: Admin;
let viewer: Admin;
let route: { id: string; hostname: string };

beforeAll(async () => {
  await sql`
    UPDATE platform_settings
    SET gate_login_mode = 'public', gate_login_hostname = ${loginHost}, public_ipv4 = '203.0.113.10'
    WHERE id = 'default'
  `;
  await refreshLoginHost(true);
  route = await addRoute("app");
  expect(route.hostname).toBe(appHost);
  owner = await createAdmin("owner", "owner");
  operator = await createAdmin("operator", "operator");
  viewer = await createAdmin("viewer", "viewer");
});

afterAll(() => {
  server.stop(true);
  caddyAdmin.stop(true);
});

describe("/api/gate/users authorization", () => {
  test("operators and viewers get 403 on every gate-user endpoint", async () => {
    const target = await createGateUser(`authz-${createId("x").slice(2, 10)}@example.test`);
    for (const admin of [operator, viewer]) {
      expect((await adminApi(admin, "/api/gate/users")).status).toBe(403);
      expect((await adminApi(admin, "/api/gate/users", "POST", { email: "x@example.test" })).status).toBe(
        403,
      );
      expect((await adminApi(admin, `/api/gate/users/${target.id}/temporary-password`, "POST")).status).toBe(
        403,
      );
      expect((await adminApi(admin, `/api/gate/users/${target.id}`, "DELETE")).status).toBe(403);
      // Even a step-up grant of their own does not let them in.
      expect((await stepUp(admin, "role.grant", { gateUsers: "delete", userId: target.id })).status).toBe(
        admin === operator ? 200 : 403,
      );
      expect((await adminApi(admin, `/api/gate/users/${target.id}`, "DELETE")).status).toBe(403);
    }
    const [row] = await sql`SELECT 1 FROM gate_users WHERE user_id = ${target.id}`;
    expect(row).toBeTruthy();
  });

  test("an owner without a fresh, exactly bound role.grant step-up is refused and nothing changes", async () => {
    const email = `nostepup-${createId("x").slice(2, 10)}@example.test`;
    expect((await adminApi(owner, "/api/gate/users", "POST", { email })).status).toBe(403);
    // A grant bound to another request (or another action) does not authorize this one.
    expect(
      (await stepUp(owner, "role.grant", { email: "other@example.test", gateUsers: "create" })).status,
    ).toBe(200);
    expect((await adminApi(owner, "/api/gate/users", "POST", { email })).status).toBe(403);
    expect((await stepUp(owner, "secret.reveal", { email, gateUsers: "create" })).status).toBe(200);
    expect((await adminApi(owner, "/api/gate/users", "POST", { email })).status).toBe(403);
    // An expired grant is refused too.
    expect((await stepUp(owner, "role.grant", { email, gateUsers: "create" })).status).toBe(200);
    await sql`UPDATE step_up_grants SET expires_at = now() - interval '1 second' WHERE user_id = ${owner.id} AND consumed_at IS NULL`;
    expect((await adminApi(owner, "/api/gate/users", "POST", { email })).status).toBe(403);
    expect(await sql`SELECT 1 FROM "user" WHERE email = ${email}`).toHaveLength(0);

    const target = await createGateUser(email);
    expect((await adminApi(owner, `/api/gate/users/${target.id}`, "DELETE")).status).toBe(403);
    // A grant for deleting a different user does not delete this one.
    expect((await stepUp(owner, "role.grant", { gateUsers: "delete", userId: "usr_other" })).status).toBe(
      200,
    );
    expect((await adminApi(owner, `/api/gate/users/${target.id}`, "DELETE")).status).toBe(403);
    expect((await adminApi(owner, `/api/gate/users/${target.id}/temporary-password`, "POST")).status).toBe(
      403,
    );
    expect(await sql`SELECT 1 FROM gate_users WHERE user_id = ${target.id}`).toHaveLength(1);
    expect(
      (await sql`SELECT revealed_at FROM secrets WHERE resource_id = ${target.id}`).map(
        (row) => row.revealed_at,
      ),
    ).toEqual([null]);
  });

  test("an owner without MFA assurance is refused", async () => {
    const unassured = await createAdmin("unassured", "owner");
    await sql`UPDATE "user" SET mfa_enrolled_at = now() + interval '1 minute' WHERE id = ${unassured.id}`;
    expect((await adminApi(unassured, "/api/gate/users", "POST", { email: "mfa@example.test" })).status).toBe(
      403,
    );
  });

  test("the login origin answers 404 for the gate-user API, and the edge token grants nothing", async () => {
    const browser = new Browser();
    expect((await browser.send("/api/gate/users")).status).toBe(404);
    const viaToken = await call({
      host: adminHost,
      path: "/api/gate/users",
      headers: { "x-ark-edge-token": edgeToken },
    });
    expect(viaToken.status).toBe(401);
  });

  test("an administrator cannot be deleted or revealed through the gate-user API", async () => {
    expect((await stepUp(owner, "role.grant", { gateUsers: "delete", userId: operator.id })).status).toBe(
      200,
    );
    expect((await adminApi(owner, `/api/gate/users/${operator.id}`, "DELETE")).status).toBe(404);
    expect(await sql`SELECT 1 FROM "user" WHERE id = ${operator.id}`).toHaveLength(1);
    expect((await adminApi(owner, `/api/gate/users/${operator.id}/temporary-password`, "POST")).status).toBe(
      404,
    );
  });
});

describe("creation and the one-time temporary password", () => {
  test("the user has no platform_access row, no session and an unrevealed one-time secret", async () => {
    const email = `create-${createId("x").slice(2, 10)}@example.test`;
    const user = await createGateUser(email);
    expect(user.email).toBe(email);
    expect(await sql`SELECT 1 FROM platform_access WHERE user_id = ${user.id}`).toHaveLength(0);
    expect(await sql`SELECT 1 FROM session WHERE user_id = ${user.id}`).toHaveLength(0);
    const [secret] = await sql`
      SELECT s.once, s.revealed_at, s.kind FROM gate_users g JOIN secrets s ON s.id = g.temporary_password_secret_id
      WHERE g.user_id = ${user.id}
    `;
    expect(secret).toMatchObject({ once: true, revealed_at: null, kind: "gate-user.temporary-password" });
    const list = (await (await adminApi(owner, "/api/gate/users")).json()) as {
      users: Array<{ id: string; temporaryPassword: string; mfaEnrolled: boolean }>;
    };
    expect(list.users.find((item) => item.id === user.id)).toMatchObject({
      temporaryPassword: "unrevealed",
      mfaEnrolled: false,
    });
    // The two tables stay exclusive for every writer, not just this API.
    expect(
      await failure(sql`INSERT INTO platform_access (user_id, role) VALUES (${user.id}, 'viewer')`),
    ).toMatch(/gate user/);
    expect(await failure(sql`INSERT INTO gate_users (user_id) VALUES (${operator.id})`)).toMatch(
      /administration access/,
    );
  });

  test("a taken email address is refused with 409 and does not burn the step-up grant", async () => {
    const request = { email: operator.email };
    expect((await stepUp(owner, "role.grant", { ...request, gateUsers: "create" })).status).toBe(200);
    expect((await adminApi(owner, "/api/gate/users", "POST", request)).status).toBe(409);
    const [grant] = await sql`
      SELECT consumed_at FROM step_up_grants
      WHERE user_id = ${owner.id} AND plan_hash = ${privilegedRequestHash("role.grant", { ...request, gateUsers: "create" })}
    `;
    expect(grant?.consumed_at).toBeNull();
  });

  test("the temporary password is revealed exactly once", async () => {
    const user = await createGateUser(`reveal-${createId("x").slice(2, 10)}@example.test`);
    const first = await revealPassword(user.id);
    expect(first.status).toBe(200);
    expect(first.headers.get("cache-control")).toBe("no-store");
    const { password } = (await first.json()) as { password: string };
    expect(password.length).toBeGreaterThanOrEqual(12);
    // A second reveal fails even with a fresh, correctly bound step-up.
    const second = await revealPassword(user.id);
    expect(second.status).toBe(409);
    expect(JSON.stringify(await second.json())).not.toContain(password);
    // The generic secret endpoint never reveals it either.
    const [row] =
      await sql`SELECT temporary_password_secret_id AS id FROM gate_users WHERE user_id = ${user.id}`;
    expect((await stepUp(owner, "secret.reveal", { secretId: row!.id })).status).toBe(200);
    expect((await adminApi(owner, `/api/secrets/${row!.id}/reveal`, "POST")).status).toBe(403);
    // The password works on the login origin.
    const browser = new Browser();
    expect((await browser.send("/api/auth/sign-in/email", { email: user.email, password })).status).toBe(200);
  });
});

// Inject database errors at the real write boundaries, not mocked auth methods. These triggers
// exist only in this suite's disposable database and are always removed before retrying.
describe("creation failure recovery", () => {
  for (const table of ["account", "session", "secrets", "gate_users", "audit_events"]) {
    test(`${table} insertion failure leaves no partial account and the email can be retried`, async () => {
      const email = `failure-${table}@example.test`;
      const counts = async () =>
        (
          await sql`
        SELECT (SELECT count(*)::int FROM "user") AS users,
          (SELECT count(*)::int FROM account) AS accounts,
          (SELECT count(*)::int FROM session) AS sessions,
          (SELECT count(*)::int FROM gate_users) AS gate_users,
          (SELECT count(*)::int FROM secrets) AS secrets
      `
        )[0];
      const before = await counts();
      await sql.unsafe(`
        CREATE FUNCTION gate12_fail_insert() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE target_id text;
        BEGIN
          target_id := coalesce(to_jsonb(NEW)->>'user_id', to_jsonb(NEW)->>'resource_id');
          IF EXISTS (SELECT 1 FROM "user" WHERE id = target_id AND email = '${email}') THEN
            RAISE EXCEPTION 'gate12 injected ${table} failure';
          END IF;
          RETURN NEW;
        END $$
      `);
      try {
        await sql.unsafe(`CREATE TRIGGER gate12_failure BEFORE INSERT ON ${table}
          FOR EACH ROW EXECUTE FUNCTION gate12_fail_insert()`);
        expect((await stepUp(owner, "role.grant", { email, gateUsers: "create" })).status).toBe(200);
        const failed = await adminApi(owner, "/api/gate/users", "POST", { email });
        expect(failed.status).toBeGreaterThanOrEqual(400);
        expect(await sql`SELECT 1 FROM "user" WHERE email = ${email}`).toHaveLength(0);
        expect(await counts()).toEqual(before);
      } finally {
        await sql.unsafe(`DROP TRIGGER IF EXISTS gate12_failure ON ${table}`);
        await sql`DROP FUNCTION gate12_fail_insert()`;
      }
      const retry = await createGateUser(email);
      expect(await sql`SELECT 1 FROM account WHERE user_id = ${retry.id}`).toHaveLength(1);
      expect(await sql`SELECT 1 FROM session WHERE user_id = ${retry.id}`).toHaveLength(0);
      expect(await sql`SELECT 1 FROM gate_users WHERE user_id = ${retry.id}`).toHaveLength(1);
      expect(await sql`SELECT 1 FROM secrets WHERE resource_id = ${retry.id}`).toHaveLength(1);
    });
  }
});

describe("concurrent mutations", () => {
  for (const firstTable of ["gate_users", "platform_access"]) {
    test(`${firstTable} wins while the competing insert waits on another connection`, async () => {
      const first = postgres(process.env.DATABASE_URL!, { max: 1, connection: { statement_timeout: 5000 } });
      const second = postgres(process.env.DATABASE_URL!, { max: 1, connection: { statement_timeout: 5000 } });
      const ctx = await auth.$context;
      const target = await ctx.internalAdapter.createUser(
        {
          email: `race-${firstTable}@example.test`,
          name: "race",
          emailVerified: true,
        },
        { method: "email-password" },
      );
      const insert = (table: string) =>
        table === "gate_users"
          ? `INSERT INTO gate_users (user_id) VALUES ('${target.id}')`
          : `INSERT INTO platform_access (user_id, role) VALUES ('${target.id}', 'viewer')`;
      let release!: () => void;
      const hold = new Promise<void>((resolve) => {
        release = resolve;
      });
      let inserted!: () => void;
      const ready = new Promise<void>((resolve) => {
        inserted = resolve;
      });
      let writes: PromiseSettledResult<unknown>[] = [];
      try {
        const [firstPid] = await first`SELECT pg_backend_pid() AS pid`;
        const [secondPid] = await second`SELECT pg_backend_pid() AS pid`;
        const winner = first.begin(async (tx) => {
          try {
            await tx.unsafe(insert(firstTable));
          } finally {
            inserted();
          }
          await hold;
        });
        // Attach handlers immediately so a failed transaction cannot be an unhandled rejection.
        const winnerResult = Promise.allSettled([winner]);
        await ready;
        const loserResult = Promise.allSettled([
          second.begin(async (tx) => {
            await tx.unsafe(insert(firstTable === "gate_users" ? "platform_access" : "gate_users"));
          }),
        ]);
        try {
          let blocked = false;
          for (let attempt = 0; attempt < 200; attempt++) {
            const [row] =
              await sql`SELECT ${firstPid!.pid}::int = ANY(pg_blocking_pids(${secondPid!.pid}::int)) AS blocked`;
            if (row!.blocked) {
              blocked = true;
              break;
            }
            await Bun.sleep(10);
          }
          expect(blocked, "the competing connection must actually wait on the winner's lock").toBe(true);
        } finally {
          release();
          writes = [...(await winnerResult), ...(await loserResult)];
        }
        expect(writes[0]!.status).toBe("fulfilled");
        expect(writes[1]!.status).toBe("rejected");
        const error = writes[1] as PromiseRejectedResult;
        expect(error.reason.code).toBe("23514");
        expect(await sql`SELECT 1 FROM gate_users WHERE user_id = ${target.id}`).toHaveLength(
          firstTable === "gate_users" ? 1 : 0,
        );
        expect(await sql`SELECT 1 FROM platform_access WHERE user_id = ${target.id}`).toHaveLength(
          firstTable === "platform_access" ? 1 : 0,
        );
      } finally {
        release();
        await Promise.all([first.end(), second.end()]);
        await sql`DELETE FROM "user" WHERE id = ${target.id}`;
      }
    });
  }

  test("simultaneous reveals with independent valid grants return one password and one 409", async () => {
    const target = await createGateUser("reveal-race@example.test");
    const otherOwner = await createAdmin("reveal-racer", "owner");
    const binding = { gateUserTemporaryPassword: target.id };
    for (const admin of [owner, otherOwner]) {
      expect((await stepUp(admin, "secret.reveal", binding)).status).toBe(200);
    }
    const responses = await Promise.all(
      [owner, otherOwner].map((admin) =>
        adminApi(admin, `/api/gate/users/${target.id}/temporary-password`, "POST"),
      ),
    );
    expect(responses.map((r) => r.status).toSorted()).toEqual([200, 409]);
    const winner = responses.findIndex((r) => r.status === 200);
    const password = ((await responses[winner]!.json()) as { password: string }).password;
    expect(password).toHaveLength(24);
    expect(JSON.stringify(await responses[1 - winner]!.json())).not.toContain(password);
    expect(
      await sql`SELECT 1 FROM audit_events WHERE resource_id = ${target.id} AND action = 'secret.reveal'`,
    ).toHaveLength(1);
    const grants = await sql`SELECT user_id, consumed_at FROM step_up_grants
      WHERE user_id IN (${owner.id}, ${otherOwner.id}) AND action = 'secret.reveal'
        AND plan_hash = ${privilegedRequestHash("secret.reveal", binding)}`;
    expect(grants).toHaveLength(2);
    expect(grants.filter((g) => g.consumed_at !== null)).toHaveLength(1);
    expect(grants.find((g) => g.consumed_at !== null)!.user_id).toBe([owner, otherOwner][winner]!.id);
  });
});

describe("first login: login origin only, TOTP enrollment before any route", () => {
  test("sign-in works only on the login origin, enrollment is forced, then the route is reachable", async () => {
    const email = `first-${createId("x").slice(2, 10)}@example.test`;
    const user = await createGateUser(email);
    const { password } = (await (await revealPassword(user.id)).json()) as { password: string };
    await sql`INSERT INTO front_route_access (route_id, user_id, granted_by) VALUES (${route.id}, ${user.id}, ${owner.id})`;

    // The admin origin refuses the account outright: no admin-origin session is minted.
    const adminBrowser = new Browser();
    const refused = await adminBrowser.send("/api/auth/sign-in/email", { email, password }, adminHost);
    expect(refused.status).toBe(403);
    expect(await sql`SELECT 1 FROM session WHERE user_id = ${user.id}`).toHaveLength(0);

    // The browser arrives at the route and is sent to the login origin.
    const browser = new Browser();
    const check = await browser.check(route.id);
    expect(check.status).toBe(302);
    const authorize = new URL(check.headers.get("location")!);
    const authorizePath = `${authorize.pathname}${authorize.search}`;

    // Password only: no TOTP challenge yet, a login-origin session, and nothing else.
    const signedIn = await browser.send("/api/auth/sign-in/email", { email, password });
    expect(signedIn.status).toBe(200);
    expect(((await signedIn.json()) as { twoFactorRedirect?: boolean }).twoFactorRedirect).toBeUndefined();
    expect(
      (await sql`SELECT origin FROM session WHERE user_id = ${user.id}`).map((row) => row.origin),
    ).toEqual(["gate"]);
    expect(await sql`SELECT 1 FROM platform_access WHERE user_id = ${user.id}`).toHaveLength(0);
    // The login origin serves nothing of the admin API.
    expect((await browser.send("/api/me")).status).toBe(404);

    // Authorize and the login page send an unenrolled user to enrollment, carrying `next`.
    const toEnroll = await browser.send(authorizePath);
    expect(toEnroll.status).toBe(303);
    const enrollLocation = toEnroll.headers.get("location")!;
    expect(enrollLocation).toBe(`/gate/enroll?next=${encodeURIComponent(authorizePath)}`);
    expect(await sql`SELECT 1 FROM gate_handoffs WHERE user_id = ${user.id}`).toHaveLength(0);
    const loginPage = await browser.send(`/gate/login?next=${encodeURIComponent(authorizePath)}`);
    expect(loginPage.status).toBe(303);
    expect(loginPage.headers.get("location")).toBe(enrollLocation);
    const plainLogin = await browser.send("/gate/login");
    expect(plainLogin.headers.get("location")).toBe("/gate/enroll");
    // No route session, so the route itself stays closed.
    expect((await browser.check(route.id, "application/json")).status).toBe(401);

    const enrollPage = await browser.send(enrollLocation);
    expect(enrollPage.status).toBe(200);
    expect(enrollPage.headers.get("content-security-policy")).toContain("script-src 'nonce-");
    const html = await enrollPage.text();
    expect(html).toContain("Set up two-factor authentication");
    expect(html).toContain(`data-next="${authorizePath.replaceAll("&", "&amp;")}"`);
    // Only the login host serves the page.
    expect((await adminBrowser.send("/gate/enroll", undefined, adminHost)).status).toBe(404);

    // Enroll exactly as the page script does, through the login-origin allowlist.
    const enabled = await browser.send("/api/auth/two-factor/enable", { password });
    expect(enabled.status).toBe(200);
    const totpURI = ((await enabled.json()) as { totpURI: string }).totpURI;
    const totp = totpGenerator(new URL(totpURI).searchParams.get("secret")!);
    expect((await browser.send("/api/auth/two-factor/verify-totp", { code: totp() })).status).toBe(200);

    // Enrolled: the page is no longer offered, and re-enrollment on the login origin is refused.
    const after = await browser.send(enrollLocation);
    expect(after.status).toBe(303);
    expect(after.headers.get("location")).toBe(authorizePath);
    expect((await browser.send("/api/auth/two-factor/enable", { password })).status).toBe(403);

    // The rotated session carries MFA assurance with no other help: the handshake completes.
    const authorized = await browser.send(authorizePath);
    expect(authorized.status).toBe(303);
    const callback = new URL(authorized.headers.get("location")!);
    expect(callback.host).toBe(appHost);
    expect((await browser.callback(route.id, callback.search)).status).toBe(303);
    const allowed = await browser.check(route.id);
    expect(allowed.status).toBe(204);
    expect(allowed.headers.get("x-ark-user")).toBe(user.id);

    // Even with TOTP the admin origin still refuses the account.
    expect((await adminBrowser.send("/api/auth/sign-in/email", { email, password }, adminHost)).status).toBe(
      403,
    );
  });
});

describe("deletion", () => {
  test("removes sessions and route access, and journals the forced reload that closes open sockets", async () => {
    const email = `delete-${createId("x").slice(2, 10)}@example.test`;
    const user = await createGateUser(email);
    await sql`INSERT INTO front_route_access (route_id, user_id, granted_by) VALUES (${route.id}, ${user.id}, ${owner.id})`;
    // A live, assured login session and route session, like a browser holding an open WebSocket.
    await sql`UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${user.id}`;
    const ctx = await auth.$context;
    const parent = await ctx.internalAdapter.createSession(user.id, false, { origin: "gate" });
    const browser = new Browser();
    const { makeSignature } = await import("better-auth/crypto");
    browser
      .jar(loginHost)
      .cookies.set(
        authCookieName("session_token"),
        encodeURIComponent(`${parent.token}.${await makeSignature(parent.token, ctx.secret)}`),
      );
    const check = await browser.check(route.id);
    const authorize = new URL(check.headers.get("location")!);
    const authorized = await browser.send(`${authorize.pathname}${authorize.search}`);
    expect(authorized.status).toBe(303);
    expect(
      (await browser.callback(route.id, new URL(authorized.headers.get("location")!).search)).status,
    ).toBe(303);
    expect((await browser.check(route.id)).status).toBe(204);
    await sql`UPDATE gate_revocations SET applied_at = now(), applied_by = 'test-reset' WHERE applied_at IS NULL`;
    await sql`UPDATE operations SET status = 'failed' WHERE kind = 'edge.drain' AND status IN ('queued', 'running')`;

    expect((await stepUp(owner, "role.grant", { gateUsers: "delete", userId: user.id })).status).toBe(200);
    const deleted = await adminApi(owner, `/api/gate/users/${user.id}`, "DELETE");
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({
      id: user.id,
      sessionsRemoved: 1,
      routeAccessRemoved: 1,
      revokedRouteIds: [route.id],
    });

    expect(await sql`SELECT 1 FROM "user" WHERE id = ${user.id}`).toHaveLength(0);
    expect(await sql`SELECT 1 FROM session WHERE user_id = ${user.id}`).toHaveLength(0);
    expect(await sql`SELECT 1 FROM gate_sessions WHERE user_id = ${user.id}`).toHaveLength(0);
    expect(await sql`SELECT 1 FROM front_route_access WHERE user_id = ${user.id}`).toHaveLength(0);
    expect(await sql`SELECT 1 FROM secrets WHERE resource_id = ${user.id}`).toHaveLength(0);
    // The next request is denied, and the revocation journal holds the route with a queued drain.
    expect((await browser.check(route.id, "application/json")).status).toBe(401);
    expect((await pendingRevocations()).map((row) => ({ ...row }))).toEqual([
      { route_id: route.id, reason: "gate_user_deleted" },
    ]);
    const drains =
      await sql`SELECT 1 FROM operations WHERE kind = 'edge.drain' AND status = 'queued' AND payload ->> 'reason' = 'gate_revocation'`;
    expect(drains).toHaveLength(1);
    // The drain forces a reload even though nothing else changed; the old handler then closes the
    // route's upgraded connections within its stream_close_delay (FD-11's 305 s bound).
    const loads = caddy.loads.length;
    await runDrains();
    expect(caddy.loads.length).toBe(loads + 1);
    expect(caddy.loads.at(-1)!.cacheControl).toBe("must-revalidate");
    expect(await pendingRevocations()).toHaveLength(0);
    const [audit] =
      await sql`SELECT detail FROM audit_events WHERE action = 'gate_user.delete' AND resource_id = ${user.id}`;
    expect(audit?.detail).toMatchObject({ email, revokedRouteIds: [route.id] });
    // Deleting again is a 404.
    expect((await stepUp(owner, "role.grant", { gateUsers: "delete", userId: user.id })).status).toBe(200);
    expect((await adminApi(owner, `/api/gate/users/${user.id}`, "DELETE")).status).toBe(404);
  });
});
