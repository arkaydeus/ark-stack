// FD-11 (docs/design/front-door.md §3.9.2-§3.9.5): the gate handshake against the real API on a
// real listener, run only by `gate-handshake.test.ts` in its own process and database.
//
// Requests go over TCP so the API sees a real transport peer: 127.0.0.1 is the recorded edge peer
// and carries the edge token like Caddy does; ::1 stands in for any other container. Route-host
// requests are made exactly as the rendered Caddyfile makes them (forward_auth to /api/gate/check,
// the callback and logout rewrites with X-Ark-Route); the literal Caddyfile itself is exercised
// through Caddy by scripts/test-edge-gate.ts. A fake Caddy admin API stands in for the edge's
// forced reloads.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { join, resolve } from "node:path";

import {
  GATE_COOKIE,
  gateStateCookieName,
  createId,
  privilegedRequestHash,
  sha256Hex,
} from "@ark-stack/shared";

const { app } = await import("./app.ts");
const { auth, authCookieName } = await import("./auth.ts");
const { sql } = await import("./db.ts");
const { refreshLoginHost } = await import("./origin-hosts.ts");
const { claimQueued, enqueue, runOperation } = await import("./coordinator.ts");
const { commitTailnetGeneration } = await import("./modules/tailnet-snapshot.ts");

const root = resolve(import.meta.dir, "../..");
const adminHost = new URL(process.env.BETTER_AUTH_URL!).host;
const zone = "gate11.example.com";
const loginHost = `login.${zone}`;
const appHost = `app.${zone}`;
const siblingHost = `sibling.${zone}`;
const edgeToken = process.env.ARK_EDGE_GATE_TOKEN!;
const password = "Gate-Handshake-Test-Password-123!";

const server = Bun.serve({ hostname: "::", port: 0, fetch: app.fetch });

// ---- Fake Caddy admin API: records forced reloads -----------------------------------------------------------
const caddy = { loads: [] as Array<{ cacheControl: string | null }>, failLoad: false };
const caddyAdmin = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname === "/config/") return Response.json({}, { headers: { etag: '"1"' } });
    if (pathname === "/adapt") return Response.json({ result: { apps: {} } });
    if (pathname === "/load") {
      if (caddy.failLoad) return new Response("rejected", { status: 500 });
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
  peer?: "edge" | "other";
  /** Sent as the edge sends it (token and client address). `false` for a direct client. */
  edge?: { client: string; token?: string } | false;
  headers?: Record<string, string>;
};

async function call(input: Call) {
  const base = input.peer === "other" ? `http://[::1]:${server.port}` : `http://127.0.0.1:${server.port}`;
  const method = input.method ?? (input.body === undefined ? "GET" : "POST");
  const headers = new Headers({ host: input.host, ...input.headers });
  if (input.cookie) headers.set("cookie", input.cookie);
  if (input.body !== undefined) headers.set("content-type", "application/json");
  if (method !== "GET" && method !== "HEAD" && !headers.has("origin"))
    headers.set("origin", `https://${input.host}`);
  if (input.edge) {
    headers.set("x-forwarded-for", input.edge.client);
    headers.set("x-ark-edge-token", input.edge.token ?? edgeToken);
  }
  return fetch(`${base}${input.path}`, {
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
  /** A login-origin or admin-origin request, as the edge forwards it. */
  async login(path: string, body?: unknown, host = loginHost, extra: Partial<Call> = {}) {
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
  /** What Caddy's forward_auth sends to /api/gate/check for a request to a route host. */
  async check(
    host: string,
    routeId: string,
    request: { method?: string; uri?: string; accept?: string; origin?: string; upgrade?: string } = {},
  ) {
    const headers: Record<string, string> = {
      "x-forwarded-method": request.method ?? "GET",
      "x-forwarded-uri": request.uri ?? "/",
      accept: request.accept ?? "text/html,application/xhtml+xml",
    };
    if (request.origin) headers.origin = request.origin;
    if (request.upgrade) headers["x-ark-upgrade"] = request.upgrade;
    const jar = this.jar(host);
    return jar.take(
      await call({
        host,
        path: `/api/gate/check?route=${routeId}`,
        cookie: jar.header,
        edge: { client: this.client },
        headers,
      }),
    );
  }
  /** `GET /.ark/gate/callback?…` as Caddy rewrites it (query unchanged, X-Ark-Route added). */
  async callback(host: string, routeId: string, search: string) {
    const jar = this.jar(host);
    return jar.take(
      await call({
        host,
        path: `/api/gate/callback${search}`,
        cookie: jar.header,
        edge: { client: this.client },
        headers: { "x-ark-route": routeId },
      }),
    );
  }
  async logoutRoute(host: string, routeId: string, origin = `https://${host}`) {
    const jar = this.jar(host);
    return jar.take(
      await call({
        host,
        path: "/api/gate/logout-route",
        method: "POST",
        cookie: jar.header,
        edge: { client: this.client },
        headers: { "x-ark-route": routeId, origin },
      }),
    );
  }
}

// RFC 4648 Base32 decoding and RFC 6238 SHA-1 TOTP, independent of Better Auth's generator.
function totpGenerator(uri: string) {
  const secret = new URL(uri).searchParams.get("secret")!;
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

type User = { id: string; email: string; totp: () => string };

async function createUser(label: string, role?: "owner"): Promise<Omit<User, "totp">> {
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
    password: await ctx.password.hash(password),
  });
  if (role) await sql`INSERT INTO platform_access (user_id, role) VALUES (${created.id}, ${role})`;
  return { id: created.id, email };
}

/** First enrollment on the login origin (allowed for a gate session without TOTP), then sign out. */
async function enrollOnLogin(user: Omit<User, "totp">): Promise<User> {
  const browser = new Browser();
  expect((await browser.login("/api/auth/sign-in/email", { email: user.email, password })).status).toBe(200);
  const enabled = await browser.login("/api/auth/two-factor/enable", { password });
  expect(enabled.status).toBe(200);
  const totp = totpGenerator(((await enabled.json()) as { totpURI: string }).totpURI);
  expect((await browser.login("/api/auth/two-factor/verify-totp", { code: totp() })).status).toBe(200);
  // MFA assurance needs a session created after enrollment.
  await sql`UPDATE "user" SET mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${user.id}`;
  await browser.login("/api/auth/sign-out", {});
  return { ...user, totp };
}

/** Password and TOTP on the login origin, exactly as the /gate/login page script does it. */
async function signIn(browser: Browser, user: User) {
  const first = await browser.login("/api/auth/sign-in/email", { email: user.email, password });
  expect(first.status).toBe(200);
  expect(((await first.json()) as { twoFactorRedirect?: boolean }).twoFactorRedirect).toBe(true);
  const second = await browser.login("/api/auth/two-factor/verify-totp", { code: user.totp() });
  expect(second.status).toBe(200);
}

/** The whole handshake from an unauthenticated navigation to a route session; returns the landing URL. */
async function handshake(browser: Browser, host: string, routeId: string, uri = "/dashboard?tab=1") {
  const check = await browser.check(host, routeId, { uri });
  expect(check.status).toBe(302);
  const authorize = new URL(check.headers.get("location")!);
  expect(authorize.host).toBe(loginHost);
  const authorized = await browser.login(`${authorize.pathname}${authorize.search}`);
  expect(authorized.status).toBe(303);
  const callback = new URL(authorized.headers.get("location")!);
  expect(`${callback.protocol}//${callback.host}${callback.pathname}`).toBe(
    `https://${host}/.ark/gate/callback`,
  );
  const landed = await browser.callback(host, routeId, callback.search);
  expect(landed.status).toBe(303);
  return { landed, callback };
}

async function addRoute(label: string, opts: { bypassPaths?: string[]; allowedOrigins?: string[] } = {}) {
  const endpointId = createId("end");
  const routeId = `rt_${createId("x").slice(2, 14)}`;
  const hostname = `${label}.${zone}`;
  await sql`INSERT INTO endpoints (id, kind, hostname, exposure) VALUES (${endpointId}, 'route', ${hostname}, 'public')`;
  await sql`
    INSERT INTO front_routes (id, kind, endpoint_id, listen_port, target_input, target_node_stable_id,
      target_ip, target_port, access_mode, bypass_paths, http_options, status, enabled)
    VALUES (${routeId}, 'http', ${endpointId}, 443, 'home.tail1234.ts.net', 'nHOME', '100.101.102.103', 3000,
      'sso', ${JSON.stringify(opts.bypassPaths ?? [])}::jsonb,
      ${JSON.stringify(opts.allowedOrigins ? { allowedOrigins: opts.allowedOrigins } : {})}::jsonb, 'ready', true)
  `;
  return { id: routeId, hostname };
}

async function grant(routeId: string, userId: string) {
  await sql`INSERT INTO front_route_access (route_id, user_id) VALUES (${routeId}, ${userId}) ON CONFLICT DO NOTHING`;
}

async function pendingRevocations(routeId?: string) {
  const rows = routeId
    ? await sql`SELECT * FROM gate_revocations WHERE applied_at IS NULL AND route_id = ${routeId}`
    : await sql`SELECT * FROM gate_revocations WHERE applied_at IS NULL`;
  return rows;
}

async function queuedRevocationDrains() {
  return sql`SELECT id, status FROM operations WHERE kind = 'edge.drain' AND payload ->> 'reason' = 'gate_revocation' AND status IN ('queued', 'running')`;
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
      try {
        await runOperation("edge.drain", operation);
        await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${row.id}`;
      } catch (error) {
        await sql`UPDATE operations SET status = 'failed', updated_at = now(), error = ${(error as Error).message} WHERE id = ${row.id}`;
        throw error;
      }
    }
  } finally {
    process.env.ARK_EDGE_RELOAD_URL = "";
  }
}

/** Clears earlier revocations so each case observes only its own. */
async function settleRevocations() {
  await sql`UPDATE gate_revocations SET applied_at = now(), applied_by = 'test-reset' WHERE applied_at IS NULL`;
  await sql`UPDATE operations SET status = 'failed' WHERE kind = 'edge.drain' AND status IN ('queued', 'running')`;
}

let owner: User;
let alice: User;
let route: { id: string; hostname: string };
let sibling: { id: string; hostname: string };
let ownerAdminCookie: string;

beforeAll(async () => {
  await sql`
    UPDATE platform_settings
    SET gate_login_mode = 'public', gate_login_hostname = ${loginHost}, public_ipv4 = '203.0.113.10'
    WHERE id = 'default'
  `;
  await refreshLoginHost(true);
  route = await addRoute("app", { bypassPaths: ["/webhooks/*"] });
  sibling = await addRoute("sibling");
  expect(route.hostname).toBe(appHost);
  expect(sibling.hostname).toBe(siblingHost);
  owner = await enrollOnLogin(await createUser("owner", "owner"));
  alice = await enrollOnLogin(await createUser("alice"));
  await grant(route.id, alice.id);
  await grant(sibling.id, alice.id);
  // An admin-origin session for the owner, minted server-side with explicit provenance.
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createSession(owner.id, false, { origin: "admin" });
  const { makeSignature } = await import("better-auth/crypto");
  ownerAdminCookie = `${authCookieName("session_token")}=${encodeURIComponent(`${created.token}.${await makeSignature(created.token, ctx.secret)}`)}`;
  await settleRevocations();
});

afterAll(() => {
  server.stop(true);
  caddyAdmin.stop(true);
});

describe("edge-only endpoints and the edge token (§3.9.4)", () => {
  test("/api/gate/check without the edge token, with a wrong one or from another peer is 401", async () => {
    for (const edge of [false, { client: "198.51.100.1", token: "wrong-token" }] as const) {
      const response = await call({ host: appHost, path: `/api/gate/check?route=${route.id}`, edge });
      expect(response.status).toBe(401);
    }
    const otherPeer = await call({
      host: appHost,
      path: `/api/gate/check?route=${route.id}`,
      peer: "other",
      edge: { client: "198.51.100.1" },
    });
    expect(otherPeer.status).toBe(401);
    for (const path of ["/api/gate/callback?code=x&state=y", "/api/gate/bypass-check?route=x"])
      expect((await call({ host: appHost, path, edge: false })).status).toBe(401);
    expect(
      (await call({ host: appHost, path: "/api/gate/logout-route", method: "POST", edge: false })).status,
    ).toBe(401);
  });

  test("the login origin answers 404 for every edge handler", async () => {
    for (const path of ["/api/gate/check", "/api/gate/callback", "/api/gate/bypass-check", "/api/gate/users"])
      expect((await call({ host: loginHost, path, edge: { client: "198.51.100.1" } })).status).toBe(404);
  });

  test("the edge token grants no admin access", async () => {
    for (const path of ["/api/state", "/api/front/routes", "/api/gate/users", "/api/settings/gate"]) {
      const response = await call({ host: adminHost, path, edge: { client: "198.51.100.1" } });
      expect([401, 404]).toContain(response.status);
    }
    // A route host is not an admin origin, token or not.
    expect((await call({ host: appHost, path: "/api/state", edge: { client: "198.51.100.1" } })).status).toBe(
      421,
    );
  });

  test("wrong methods on the edge handlers are 405", async () => {
    const response = await call({
      host: appHost,
      path: "/api/gate/callback",
      method: "POST",
      edge: { client: "198.51.100.1" },
    });
    expect(response.status).toBe(405);
  });
});

describe("handshake (§3.9.2)", () => {
  test("an unauthenticated HTML GET redirects to the login origin and sets the state cookie", async () => {
    const browser = new Browser();
    const response = await browser.check(appHost, route.id, { uri: "/dashboard?tab=1" });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.origin).toBe(`https://${loginHost}`);
    expect(location.pathname).toBe("/gate/authorize");
    expect(location.searchParams.get("route")).toBe(route.id);
    expect(location.searchParams.get("rd")).toBe("/dashboard?tab=1");
    const state = location.searchParams.get("state")!;
    const cookie = response.headers
      .getSetCookie()
      .find((item) => item.startsWith(`${gateStateCookieName(state)}=`))!;
    expect(cookie).toBe(
      `${gateStateCookieName(state)}=${state}; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax`,
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  test("concurrent sign-ins keep independent cookies and both callbacks succeed", async () => {
    const browser = new Browser();
    await signIn(browser, alice);
    const checks = await Promise.all([browser.check(appHost, route.id), browser.check(appHost, route.id)]);
    const callbacks: URL[] = [];
    for (const check of checks) {
      const url = new URL(check.headers.get("location")!);
      const authorized = await browser.login(`${url.pathname}${url.search}`);
      callbacks.push(new URL(authorized.headers.get("location")!));
    }
    expect(callbacks[0]!.searchParams.get("state")).not.toBe(callbacks[1]!.searchParams.get("state"));
    for (const callback of callbacks)
      expect((await browser.callback(appHost, route.id, callback.search)).status).toBe(303);
  });

  test("an XHR (Accept: application/json), an unsafe method or an upgrade without a session gets 401", async () => {
    const browser = new Browser();
    for (const request of [
      { accept: "application/json" },
      { method: "POST", accept: "text/html" },
      { upgrade: "websocket", origin: `https://${appHost}` },
    ]) {
      const response = await browser.check(appHost, route.id, request);
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toBe("Ark-Gate");
      expect(response.headers.get("location")).toBeNull();
    }
  });

  test("authorize without a login session sends the browser to the login page with a relative next", async () => {
    const browser = new Browser();
    const check = await browser.check(appHost, route.id);
    const authorize = new URL(check.headers.get("location")!);
    const response = await browser.login(`${authorize.pathname}${authorize.search}`);
    expect(response.status).toBe(303);
    const location = response.headers.get("location")!;
    expect(location.startsWith("/gate/login?next=")).toBe(true);
    const next = new URL(location, `https://${loginHost}`).searchParams.get("next")!;
    expect(next).toBe(`/gate/authorize${authorize.search}`);
    const page = await browser.login(location);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-security-policy")).toContain("script-src 'nonce-");
    expect(await page.text()).toContain(`data-next="${next.replaceAll("&", "&amp;")}"`);
  });

  test("password + TOTP, authorize, callback: the route cookie is __Host-, Secure, HttpOnly, Lax, no Domain", async () => {
    const browser = new Browser();
    await signIn(browser, alice);
    const { landed, callback } = await handshake(browser, appHost, route.id);
    expect(landed.headers.get("location")).toBe(`https://${appHost}/dashboard?tab=1`);
    expect(landed.headers.get("referrer-policy")).toBe("no-referrer");
    const cookie = landed.headers.getSetCookie().find((item) => item.startsWith(`${GATE_COOKIE}=`))!;
    expect(cookie).toMatch(
      /^__Host-ark_gate=[A-Za-z0-9_-]{43}; Max-Age=\d+; Path=\/; Secure; HttpOnly; SameSite=Lax$/,
    );
    expect(cookie.toLowerCase()).not.toContain("domain=");
    expect(
      landed.headers
        .getSetCookie()
        .some((item) => item.startsWith(`${gateStateCookieName(callback.searchParams.get("state")!)}=;`)),
    ).toBe(true);
    const ok = await browser.check(appHost, route.id, { uri: "/dashboard?tab=1" });
    expect(ok.status).toBe(204);
    expect(ok.headers.get("x-ark-user")).toBe(alice.id);
    expect(ok.headers.get("x-ark-email")).toBe(alice.email);
    expect(ok.headers.get("cache-control")).toBe("no-store");
    // The route session is bound to its route.
    const jar = browser.jar(appHost);
    const otherJar = browser.jar(siblingHost);
    otherJar.cookies.set(GATE_COOKIE, jar.cookies.get(GATE_COOKIE)!);
    expect((await browser.check(siblingHost, sibling.id)).status).toBe(302);
  });

  test("a used code, an expired code, another route's hostname and a missing state cookie all fail", async () => {
    const browser = new Browser();
    await signIn(browser, alice);
    const { callback } = await handshake(browser, appHost, route.id);
    // Replay.
    const replayBrowser = new Browser();
    replayBrowser
      .jar(appHost)
      .cookies.set(
        gateStateCookieName(callback.searchParams.get("state")!),
        callback.searchParams.get("state")!,
      );
    const replay = await replayBrowser.callback(appHost, route.id, callback.search);
    expect(replay.status).toBe(400);
    expect(replay.headers.getSetCookie().some((item) => item.startsWith(`${GATE_COOKIE}=`))).toBe(false);

    const fresh = async () => {
      browser.jar(appHost).cookies.delete(GATE_COOKIE);
      const check = await browser.check(appHost, route.id);
      const authorize = new URL(check.headers.get("location")!);
      const authorized = await browser.login(`${authorize.pathname}${authorize.search}`);
      return new URL(authorized.headers.get("location")!);
    };
    // Older than 60 s.
    const expired = await fresh();
    await sql`UPDATE gate_handoffs SET expires_at = now() - interval '1 second' WHERE code_hash = ${sha256Hex(expired.searchParams.get("code")!)}`;
    expect((await browser.callback(appHost, route.id, expired.search)).status).toBe(400);
    // Presented on another route's hostname (the edge sets that route's X-Ark-Route).
    const moved = await fresh();
    browser
      .jar(siblingHost)
      .cookies.set(gateStateCookieName(moved.searchParams.get("state")!), moved.searchParams.get("state")!);
    const onSibling = await browser.callback(siblingHost, sibling.id, moved.search);
    expect(onSibling.status).toBe(400);
    expect(onSibling.headers.getSetCookie().some((item) => item.startsWith(`${GATE_COOKIE}=`))).toBe(false);
    // Without the matching state cookie (login CSRF / code injection).
    const noState = await fresh();
    browser.jar(appHost).cookies.delete(gateStateCookieName(noState.searchParams.get("state")!));
    expect((await browser.callback(appHost, route.id, noState.search)).status).toBe(400);
    const wrongState = await fresh();
    browser
      .jar(appHost)
      .cookies.set(gateStateCookieName(wrongState.searchParams.get("state")!), "A".repeat(22));
    expect((await browser.callback(appHost, route.id, wrongState.search)).status).toBe(400);
  });

  test("rd values that leave the route host are rejected and mint no code", async () => {
    const browser = new Browser();
    await signIn(browser, alice);
    const before = (await sql`SELECT count(*)::int AS n FROM gate_handoffs`)[0]!.n as number;
    for (const rd of ["//evil.com", "https://evil.com", "/\\evil.com", "/ok\r\nSet-Cookie: x=1", "/ok\nx"]) {
      const search = new URLSearchParams({ route: route.id, state: "S".repeat(22), rd });
      const response = await browser.login(`/gate/authorize?${search}`);
      expect([rd, response.status]).toEqual([rd, 400]);
      expect(response.headers.get("location")).toBeNull();
    }
    expect((await sql`SELECT count(*)::int AS n FROM gate_handoffs`)[0]!.n).toBe(before);
    // The check never builds a redirect to an off-host rd either: it falls back to "/".
    const check = await new Browser().check(appHost, route.id, { uri: "//evil.com/x" });
    expect(new URL(check.headers.get("location")!).searchParams.get("rd")).toBe("/");
  });

  test("a user who is not on the access list is refused at authorize", async () => {
    const bob = await enrollOnLogin(await createUser("bob"));
    const browser = new Browser();
    await signIn(browser, bob);
    const check = await browser.check(appHost, route.id);
    const authorize = new URL(check.headers.get("location")!);
    const response = await browser.login(`${authorize.pathname}${authorize.search}`);
    expect(response.status).toBe(403);
    expect(await response.text()).toContain("does not have access");
  });

  test("an admin-origin session is not accepted by the login origin's authorize", async () => {
    const browser = new Browser();
    const check = await browser.check(appHost, route.id);
    const authorize = new URL(check.headers.get("location")!);
    const response = await call({
      host: loginHost,
      path: `${authorize.pathname}${authorize.search}`,
      cookie: ownerAdminCookie,
    });
    // Better Auth's before hook (FD-10) or authorize itself refuses it; either way no code is minted.
    expect(response.headers.get("location") ?? "").not.toContain("/.ark/gate/callback");
  });
});

describe("Origin and CSRF contract (§3.9.4)", () => {
  let browser: Browser;
  beforeAll(async () => {
    browser = new Browser();
    await signIn(browser, alice);
    await handshake(browser, appHost, route.id);
  });

  test("a sibling route's page cannot open an authenticated WebSocket; the route itself can", async () => {
    expect(
      (await browser.check(appHost, route.id, { upgrade: "websocket", origin: `https://${siblingHost}` }))
        .status,
    ).toBe(403);
    expect(
      (await browser.check(appHost, route.id, { upgrade: "websocket", origin: `https://${appHost}` })).status,
    ).toBe(204);
    for (const origin of [undefined, "null", `https://evil.${appHost}`, `http://${appHost}`])
      expect((await browser.check(appHost, route.id, { upgrade: "websocket", origin })).status).toBe(403);
  });

  test("unsafe methods with the cookie need the route's Origin", async () => {
    for (const method of ["POST", "PUT", "DELETE"]) {
      expect((await browser.check(appHost, route.id, { method })).status).toBe(403);
      expect(
        (await browser.check(appHost, route.id, { method, origin: `https://${siblingHost}` })).status,
      ).toBe(403);
      expect((await browser.check(appHost, route.id, { method, origin: `https://${appHost}` })).status).toBe(
        204,
      );
    }
  });

  test("an explicit owner-approved origin exception works", async () => {
    await sql`UPDATE front_routes SET http_options = ${JSON.stringify({ allowedOrigins: [`https://${siblingHost}`] })}::jsonb WHERE id = ${route.id}`;
    try {
      expect(
        (await browser.check(appHost, route.id, { upgrade: "websocket", origin: `https://${siblingHost}` }))
          .status,
      ).toBe(204);
      expect(
        (await browser.check(appHost, route.id, { method: "POST", origin: `https://${siblingHost}` })).status,
      ).toBe(204);
    } finally {
      await sql`UPDATE front_routes SET http_options = '{}'::jsonb WHERE id = ${route.id}`;
    }
  });
});

describe("bypass precheck (§3.9.5)", () => {
  const bypass = (uri: string, host = appHost, routeId = route.id) =>
    call({
      host,
      path: `/api/gate/bypass-check?route=${routeId}`,
      edge: { client: "198.51.100.1" },
      headers: { "x-ark-original-uri": uri },
    });

  test("only unambiguous paths under a configured bypass pass", async () => {
    expect((await bypass("/webhooks/github")).status).toBe(204);
    expect((await bypass("/webhooks/github?x=1")).status).toBe(204);
    for (const uri of [
      "/webhooks/..;/admin",
      "/webhooks/..%3b/admin",
      "/webhooks/..%3B/admin",
      "/webhooks/../admin",
      "/webhooks\\..\\admin",
      "/webhooks/%2e%2e/admin",
      "/webhooks/%2fadmin",
      "/webhooks/%5cadmin",
      "/webhooks/%252e%252e/admin",
      "/webhooks/%zz",
      "/WEBHOOKS/x",
      "/admin",
    ])
      expect([uri, (await bypass(uri)).status]).toEqual([uri, 400]);
    // Another route's hostname, or a route without that bypass, never passes.
    expect((await bypass("/webhooks/github", siblingHost)).status).toBe(400);
    expect((await bypass("/webhooks/github", siblingHost, sibling.id)).status).toBe(400);
  });
});

describe("access lists (PUT /api/front/routes/:id/access)", () => {
  const putAccess = (routeId: string, userIds: string[], cookie = ownerAdminCookie) =>
    call({
      host: adminHost,
      path: `/api/front/routes/${routeId}/access`,
      method: "PUT",
      body: { userIds },
      cookie,
    });
  const stepUp = async (routeId: string, userIds: string[]) => {
    const request = { userIds };
    const ctx = await auth.$context;
    void ctx;
    await sql`
      INSERT INTO step_up_grants (id, user_id, session_id, action, plan_hash, expires_at)
      SELECT ${createId("sug")}, ${owner.id}, s.id, 'role.grant',
        ${privilegedRequestHash("role.grant", { routeId, ...request })}, now() + interval '5 minutes'
      FROM session s WHERE s.user_id = ${owner.id} AND s.origin = 'admin'
    `;
  };

  test("owner only, with MFA and a role.grant step-up bound to the exact list; unknown users refused", async () => {
    expect((await putAccess(route.id, [alice.id])).status).toBe(403);
    await stepUp(route.id, ["usr_missing"]);
    expect((await putAccess(route.id, ["usr_missing"])).status).toBe(422);
    const list = await call({
      host: adminHost,
      path: `/api/front/routes/${route.id}/access`,
      cookie: ownerAdminCookie,
    });
    expect(list.status).toBe(200);
    expect(
      ((await list.json()) as { users: Array<{ userId: string }> }).users.map((item) => item.userId),
    ).toEqual([alice.id]);
  });

  test("removing the user denies the next request and enqueues the revocation drain atomically", async () => {
    await settleRevocations();
    const browser = new Browser();
    await signIn(browser, alice);
    await handshake(browser, appHost, route.id);
    expect((await browser.check(appHost, route.id)).status).toBe(204);
    await stepUp(route.id, []);
    const removed = await putAccess(route.id, []);
    expect(removed.status).toBe(200);
    expect(((await removed.json()) as { removed: string[] }).removed).toEqual([alice.id]);
    // The next request, well within 10 s.
    expect((await browser.check(appHost, route.id, { accept: "application/json" })).status).toBe(401);
    const revocations = await pendingRevocations(route.id);
    expect(revocations.map((row) => row.reason)).toEqual(["access_removed"]);
    expect(await queuedRevocationDrains()).toHaveLength(1);
    await grant(route.id, alice.id);
  });
});

describe("revocation closes sockets: every event journals a forced reload (§3.9.3)", () => {
  /** A user with live route sessions on both routes. */
  async function liveUser(label: string, role?: "owner") {
    const user = await enrollOnLogin(await createUser(label, role));
    await grant(route.id, user.id);
    await grant(sibling.id, user.id);
    const browser = new Browser();
    await signIn(browser, user);
    await handshake(browser, appHost, route.id);
    await handshake(browser, siblingHost, sibling.id);
    expect((await browser.check(appHost, route.id)).status).toBe(204);
    return { user, browser };
  }

  async function expectRevoked(routeIds: string[], browser: Browser) {
    for (const id of routeIds) expect((await pendingRevocations(id)).length).toBeGreaterThan(0);
    expect((await queuedRevocationDrains()).length).toBeGreaterThan(0);
    expect((await browser.check(appHost, route.id, { accept: "application/json" })).status).toBe(401);
    // The drain forces a reload even though the configuration did not change.
    const loads = caddy.loads.length;
    await runDrains();
    expect(caddy.loads.length).toBe(loads + 1);
    expect(caddy.loads.at(-1)!.cacheControl).toBe("must-revalidate");
    expect(await pendingRevocations()).toHaveLength(0);
  }

  test("route logout (Origin must be the route)", async () => {
    await settleRevocations();
    const { browser } = await liveUser("routelogout");
    expect((await browser.logoutRoute(appHost, route.id, `https://${siblingHost}`)).status).toBe(403);
    expect((await browser.check(appHost, route.id)).status).toBe(204);
    const out = await browser.logoutRoute(appHost, route.id);
    expect(out.status).toBe(200);
    expect(out.headers.getSetCookie()).toContain(
      `${GATE_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`,
    );
    expect((await pendingRevocations(route.id)).map((row) => row.reason)).toEqual(["route_logout"]);
    // The other route's session is untouched by a route logout.
    expect((await browser.check(siblingHost, sibling.id)).status).toBe(204);
    await expectRevoked([route.id], browser);
  });

  test("signing out on the login origin invalidates every route session", async () => {
    await settleRevocations();
    const { browser } = await liveUser("signout");
    const response = await browser.login("/gate/logout", undefined, loginHost, {
      method: "POST",
      headers: { origin: `https://${loginHost}` },
    });
    expect(response.status).toBe(303);
    expect((await browser.check(siblingHost, sibling.id, { accept: "application/json" })).status).toBe(401);
    await expectRevoked([route.id, sibling.id], browser);
  });

  test("Better Auth's own sign-out on the login origin", async () => {
    await settleRevocations();
    const { browser } = await liveUser("authsignout");
    expect((await browser.login("/api/auth/sign-out", {})).status).toBe(200);
    await expectRevoked([route.id, sibling.id], browser);
  });

  test("session deletion", async () => {
    await settleRevocations();
    const { user, browser } = await liveUser("sessiondelete");
    await sql`DELETE FROM session WHERE user_id = ${user.id} AND origin = 'gate'`;
    await expectRevoked([route.id, sibling.id], browser);
  });

  test("logout everywhere (Better Auth revoke-sessions on the admin origin)", async () => {
    await settleRevocations();
    const { user, browser } = await liveUser("everywhere", "owner");
    const ctx = await auth.$context;
    const created = await ctx.internalAdapter.createSession(user.id, false, { origin: "admin" });
    const { makeSignature } = await import("better-auth/crypto");
    const cookie = `${authCookieName("session_token")}=${encodeURIComponent(`${created.token}.${await makeSignature(created.token, ctx.secret)}`)}`;
    const response = await call({ host: adminHost, path: "/api/auth/revoke-sessions", body: {}, cookie });
    expect(response.status).toBe(200);
    await expectRevoked([route.id, sibling.id], browser);
  });

  test("MFA reset (scripts/recover-mfa.ts)", async () => {
    await settleRevocations();
    const { user, browser } = await liveUser("mfareset", "owner");
    const child = Bun.spawn(
      [
        "bun",
        "scripts/recover-mfa.ts",
        user.email,
        `RESET:${user.email}`,
        process.env.ARK_MFA_RECOVERY_TOKEN!,
      ],
      { cwd: root, env: process.env, stdout: "pipe", stderr: "pipe" },
    );
    expect(await child.exited).toBe(0);
    await expectRevoked([route.id, sibling.id], browser);
  });

  test("user deletion", async () => {
    await settleRevocations();
    const { user, browser } = await liveUser("deleted");
    await sql`DELETE FROM "user" WHERE id = ${user.id}`;
    await expectRevoked([route.id, sibling.id], browser);
  });

  test("access removal", async () => {
    await settleRevocations();
    const { user, browser } = await liveUser("accessremoved");
    await sql`DELETE FROM front_route_access WHERE route_id = ${route.id} AND user_id = ${user.id}`;
    expect((await pendingRevocations(sibling.id)).length).toBe(0);
    await expectRevoked([route.id], browser);
  });

  test("route access mode change (public -> sso) and admin mode change", async () => {
    await settleRevocations();
    const { browser } = await liveUser("modechange");
    process.env.ARK_TAILNET_AUTH_ORIGIN = `https://${adminHost}`;
    const operation = await enqueue({
      kind: "admin.mode_change",
      targetIds: ["platform"],
      payload: { adminMode: "tailnet", nonce: crypto.randomUUID() },
    });
    await runOperation("admin.mode_change", operation!);
    await expectRevoked([route.id, sibling.id], browser);
    // Re-create the owner's admin session for later cases.
    const ctx = await auth.$context;
    const created = await ctx.internalAdapter.createSession(owner.id, false, { origin: "admin" });
    const { makeSignature } = await import("better-auth/crypto");
    ownerAdminCookie = `${authCookieName("session_token")}=${encodeURIComponent(`${created.token}.${await makeSignature(created.token, ctx.secret)}`)}`;
  });

  test("admin-origin MFA disable revokes separate gate parents", async () => {
    await settleRevocations();
    const { user, browser } = await liveUser("mfadisable", "owner");
    const admin = new Browser();
    expect(
      (await admin.login("/api/auth/sign-in/email", { email: user.email, password }, adminHost)).status,
    ).toBe(200);
    expect(
      (await admin.login("/api/auth/two-factor/verify-totp", { code: user.totp() }, adminHost)).status,
    ).toBe(200);
    expect((await admin.login("/api/auth/two-factor/disable", { password }, adminHost)).status).toBe(200);
    await expectRevoked([route.id, sibling.id], browser);
  });

  test("MFA enrollment assurance changes revoke existing route sessions", async () => {
    await settleRevocations();
    const { user, browser } = await liveUser("mfareenroll");
    await sql`UPDATE "user" SET mfa_enrolled_at = now() WHERE id = ${user.id}`;
    await expectRevoked([route.id, sibling.id], browser);
  });

  test("expired sessions still journal a drain; already revoked sessions do not journal twice", async () => {
    await settleRevocations();
    const { user } = await liveUser("expired");
    await sql`UPDATE gate_sessions SET expires_at = now() - interval '1 second' WHERE user_id = ${user.id}`;
    await sql`DELETE FROM gate_sessions WHERE user_id = ${user.id}`;
    expect(await pendingRevocations()).toHaveLength(2);
    await runDrains();
    const { user: revoked } = await liveUser("alreadyrevoked");
    await sql`UPDATE gate_sessions SET revoked_at = now() WHERE user_id = ${revoked.id}`;
    await runDrains();
    await sql`DELETE FROM gate_sessions WHERE user_id = ${revoked.id}`;
    expect(await pendingRevocations()).toHaveLength(0);
  });
});

/** An edge tailnet node for the lease snapshot. */
const node = (stableId: string, name: string, ipv4: string, isSelf: boolean) => ({
  source: "edge" as const,
  generation: "g-fd11",
  stableId,
  dnsName: `${name}.tail1234.ts.net.`,
  hostName: name,
  ipv4,
  ipv6: null,
  tags: isSelf ? ["tag:ark-edge"] : [],
  isSelf,
  online: true,
});

describe("durable retry and fail closed (§3.9.3)", () => {
  async function seedLease() {
    const now = new Date();
    await commitTailnetGeneration("edge", {
      generation: "g-fd11",
      self: node("nEDGE", "ark-edge", "100.64.0.1", true),
      peers: [node("nHOME", "home", "100.101.102.103", false)],
      completedAt: now,
      validUntil: new Date(now.getTime() + 6 * 60_000),
    });
  }
  const lease = async () => {
    const response = await call({
      host: "api:3000",
      path: "/api/internal/edge/lease",
      peer: "other",
      headers: { authorization: `Bearer ${process.env.ARK_EDGE_WATCHDOG_TOKEN}` },
    });
    expect(response.status).toBe(200);
    return (await response.json()) as {
      routes: Array<{ id: string }>;
      revocations: Array<{ routeId: string; overdue: boolean }>;
    };
  };

  test("a rejected apply keeps the revocation pending; after 5 s the lease withdraws the route and alerts; retry applies it", async () => {
    await settleRevocations();
    await seedLease();
    expect((await lease()).routes.map((item) => item.id).toSorted()).toEqual(
      [route.id, sibling.id].toSorted(),
    );
    await sql`SELECT ark_gate_revoke(${route.id}, 'test')`;
    // Within the deadline nothing is withdrawn.
    let document = await lease();
    expect(document.routes.map((item) => item.id)).toContain(route.id);
    expect(document.revocations).toEqual([expect.objectContaining({ routeId: route.id, overdue: false })]);
    // The edge rejects the reload: the drain fails and the revocation stays pending.
    caddy.failLoad = true;
    await expect(runDrains()).rejects.toThrow(/Caddy reload failed: 500/);
    caddy.failLoad = false;
    expect(await pendingRevocations(route.id)).toHaveLength(1);
    // 5 s later the watchdog's lease leaves the route out (fail closed), and a critical alert is raised.
    await sql`UPDATE gate_revocations SET created_at = now() - interval '6 seconds' WHERE applied_at IS NULL`;
    document = await lease();
    expect(document.routes.map((item) => item.id)).not.toContain(route.id);
    expect(document.routes.map((item) => item.id)).toContain(sibling.id);
    expect(document.revocations).toEqual([expect.objectContaining({ routeId: route.id, overdue: true })]);
    const [alert] =
      await sql`SELECT severity, resolved_at FROM alerts WHERE dedup_key = 'gate-revocation-overdue'`;
    expect(alert?.severity).toBe("critical");
    // Immediate retries are suppressed; retry after the first 10 s backoff.
    expect(await queuedRevocationDrains()).toHaveLength(0);
    await claimQueued({ limit: 0 });
    expect(await queuedRevocationDrains()).toHaveLength(0);
    await sql`UPDATE operations SET updated_at = now() - interval '11 seconds' WHERE status = 'failed' AND payload ->> 'reason' = 'gate_revocation'`;
    await claimQueued({ limit: 0 });
    expect(await queuedRevocationDrains()).toHaveLength(1);
    await runDrains();
    expect(await pendingRevocations()).toHaveLength(0);
    expect((await lease()).routes.map((item) => item.id)).toContain(route.id);
  });

  test("concurrent revocations coalesce; a newer event cannot be acknowledged by an older reload", async () => {
    await settleRevocations();
    await Promise.all([
      sql.begin(async (tx) => {
        await tx`SELECT ark_gate_revoke(${route.id}, 'first')`;
        await tx`SELECT pg_sleep(0.1)`;
      }),
      sql.begin(async (tx) => {
        await tx`SELECT ark_gate_revoke(${route.id}, 'second')`;
      }),
      claimQueued({ limit: 0 }),
    ]);
    expect(await pendingRevocations(route.id)).toHaveLength(1);
    expect(await queuedRevocationDrains()).toHaveLength(1);
    const [snapshot] = await pendingRevocations(route.id);
    await sql`SELECT ark_gate_revoke(${route.id}, 'during_reload')`;
    const { markGateRevocationsApplied } = await import("./modules/gate-revocations.ts");
    expect(await markGateRevocationsApplied([String(snapshot!.id)], "old-reload")).toBe(0);
    expect(await pendingRevocations(route.id)).toHaveLength(1);
    await runDrains();
    expect(await pendingRevocations()).toHaveLength(0);
  });

  test("persistent reload failures create only one failed operation during the backoff window", async () => {
    await settleRevocations();
    await sql`SELECT ark_gate_revoke(${route.id}, 'outage')`;
    const [before] = await sql`SELECT count(*)::int AS n FROM operations WHERE kind = 'edge.drain'`;
    caddy.failLoad = true;
    try {
      await expect(runDrains()).rejects.toThrow(/Caddy reload failed/);
      for (let n = 0; n < 5; n++) {
        await claimQueued({ limit: 0 });
        await sql`SELECT ark_gate_revoke(${route.id}, 'another_during_outage')`;
        await runDrains();
      }
      const [after] = await sql`SELECT count(*)::int AS n FROM operations WHERE kind = 'edge.drain'`;
      expect(after!.n).toBe(before!.n);
      expect(await queuedRevocationDrains()).toHaveLength(0);
    } finally {
      caddy.failLoad = false;
    }
  });

  test("retry delay grows after repeated failures instead of resetting on a new revocation", async () => {
    await settleRevocations();
    await sql`SELECT ark_gate_revoke(${route.id}, 'backoff')`;
    await sql`UPDATE operations SET updated_at = now() - interval '1 day' WHERE status = 'failed' AND payload ->> 'reason' = 'gate_revocation'`;
    // Keep all simulated failure timestamps inside the current outage.
    await sql`UPDATE gate_revocations SET created_at = now() - interval '10 minutes' WHERE applied_at IS NULL`;
    caddy.failLoad = true;
    try {
      await expect(runDrains()).rejects.toThrow(/Caddy reload failed/);
      const [first] =
        await sql`SELECT id FROM operations WHERE status = 'failed' AND payload ->> 'reason' = 'gate_revocation' ORDER BY updated_at DESC LIMIT 1`;
      await sql`UPDATE operations SET updated_at = now() - interval '11 seconds' WHERE id = ${first!.id}`;
      await claimQueued({ limit: 0 });
      expect(await queuedRevocationDrains()).toHaveLength(1);
      await expect(runDrains()).rejects.toThrow(/Caddy reload failed/);
      // Eleven seconds was enough for attempt one, but attempt two requires twenty.
      const [second] =
        await sql`SELECT id FROM operations WHERE status = 'failed' AND payload ->> 'reason' = 'gate_revocation' ORDER BY updated_at DESC LIMIT 1`;
      await sql`UPDATE operations SET updated_at = now() - interval '11 seconds' WHERE id = ${second!.id}`;
      await sql`SELECT ark_gate_revoke(${route.id}, 'new_event_same_outage')`;
      await claimQueued({ limit: 0 });
      expect(await queuedRevocationDrains()).toHaveLength(0);
      await sql`UPDATE operations SET updated_at = now() - interval '21 seconds' WHERE id IN (${first!.id}, ${second!.id})`;
      await claimQueued({ limit: 0 });
      expect(await queuedRevocationDrains()).toHaveLength(1);
    } finally {
      caddy.failLoad = false;
    }
  });

  test("a drain lost with its worker is reclaimed and retried; the revocation is never reported applied before", async () => {
    await settleRevocations();
    await sql`SELECT ark_gate_revoke(${sibling.id}, 'test')`;
    const [drain] = await queuedRevocationDrains();
    // The worker claimed it and died: running, with a stale heartbeat.
    await sql`UPDATE operations SET status = 'running', heartbeat_at = now() - interval '10 minutes' WHERE id = ${drain!.id}`;
    expect(await pendingRevocations(sibling.id)).toHaveLength(1);
    await claimQueued({ limit: 0 });
    const [reclaimed] = await sql`SELECT status FROM operations WHERE id = ${drain!.id}`;
    expect(reclaimed?.status).toBe("queued");
    await runDrains();
    expect(await pendingRevocations()).toHaveLength(0);
  });
});

describe("lifetime", () => {
  test("idle for more than 2 h, or past its parent session, a route session is dead", async () => {
    const browser = new Browser();
    await signIn(browser, alice);
    await handshake(browser, appHost, route.id);
    expect((await browser.check(appHost, route.id)).status).toBe(204);
    const token = browser.jar(appHost).cookies.get(GATE_COOKIE)!;
    await sql`UPDATE gate_sessions SET last_seen_at = now() - interval '3 hours' WHERE token_hash = ${sha256Hex(token)}`;
    expect((await browser.check(appHost, route.id, { accept: "application/json" })).status).toBe(401);
    await sql`UPDATE gate_sessions SET last_seen_at = now() WHERE token_hash = ${sha256Hex(token)}`;
    expect((await browser.check(appHost, route.id)).status).toBe(204);
    await sql`UPDATE session SET expires_at = now() - interval '1 second' WHERE id = (SELECT auth_session_id FROM gate_sessions WHERE token_hash = ${sha256Hex(token)})`;
    expect((await browser.check(appHost, route.id, { accept: "application/json" })).status).toBe(401);
  });

  test("route sessions never outlive their parent session", async () => {
    const [row] = await sql`
      SELECT bool_and(gs.expires_at <= s.expires_at) AS ok
      FROM gate_sessions gs JOIN session s ON s.id = gs.auth_session_id
      WHERE s.expires_at > now()
    `;
    expect(row?.ok ?? true).toBe(true);
  });
});

void join;
