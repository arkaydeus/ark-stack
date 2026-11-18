// FD-10 (docs/design/front-door.md §3.5, §3.9.1, §3.9.3): the gate login origin and session
// separation, against the real API on a real listener. Run only by `gate-login.test.ts`, in its own
// process and database, because the API here is configured for HTTPS origins with a login host, a
// genuine edge token and one recorded edge peer, and a mode change revokes every session.
//
// Requests go over TCP so the API sees a real transport peer: 127.0.0.1 is the recorded edge peer,
// and ::1 stands in for any other container on the admin bridge.
// Admin proxy cases also require Docker and run the pinned Caddy configuration with two clients.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { GATE_EDGE_API_PATHS, createId, privilegedRequestHash, renderCaddyfile } from "@ark-stack/shared";
import { createAuthEndpoint } from "better-auth/api";
import { makeSignature } from "better-auth/crypto";
import { betterAuth } from "better-auth/minimal";

const { app } = await import("./app.ts");
const { auth, authBaseURL, authCookieName, AUTH_COOKIE_KEYS } = await import("./auth.ts");
const { sql } = await import("./db.ts");
const { refreshLoginHost } = await import("./origin-hosts.ts");
const { enqueue, runOperation } = await import("./coordinator.ts");
const { prepareGateSettings, commitGateSettings, enqueueGateOperation } =
  await import("./modules/gate-settings.ts");

const adminHost = new URL(process.env.BETTER_AUTH_URL!).host;
const loginHost = "login.gate.example.com";
const movedLoginHost = "signin.gate.example.com";
const zone = "gate.example.com";
const edgeToken = process.env.ARK_EDGE_GATE_TOKEN!;
const password = "Gate-Login-Test-Password-123!";

const server = Bun.serve({ hostname: "::", port: 0, fetch: app.fetch });

type Peer = "edge" | "other";
type Call = {
  host: string;
  path: string;
  method?: string;
  body?: unknown;
  cookie?: string;
  /** 127.0.0.1 (the recorded edge peer, the default) or ::1 (another bridge peer). */
  peer?: Peer;
  /** What the edge adds on allowlisted login API requests; `token` overrides the genuine one. */
  edge?: { client: string; token?: string };
  headers?: Record<string, string>;
};

/** Every Set-Cookie the API sent, for the attribute checks. */
const setCookies: string[] = [];

async function call(input: Call) {
  const base = input.peer === "other" ? `http://[::1]:${server.port}` : `http://127.0.0.1:${server.port}`;
  const method = input.method ?? (input.body === undefined ? "GET" : "POST");
  const headers = new Headers({ host: input.host, ...input.headers });
  if (input.cookie) headers.set("cookie", input.cookie);
  if (input.body !== undefined) headers.set("content-type", "application/json");
  if (method !== "GET" && !headers.has("origin")) headers.set("origin", `https://${input.host}`);
  if (input.edge) {
    headers.set("x-forwarded-for", input.edge.client);
    headers.set("x-ark-edge-token", input.edge.token ?? edgeToken);
  }
  const response = await fetch(`${base}${input.path}`, {
    method,
    headers,
    body: input.body === undefined ? undefined : JSON.stringify(input.body),
    redirect: "manual",
  });
  setCookies.push(...response.headers.getSetCookie());
  return response;
}

/** A tiny cookie jar per browser. */
class Browser {
  cookies = new Map<string, string>();
  constructor(
    readonly host: string,
    readonly client: string,
  ) {}
  get cookie() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
  async send(path: string, body?: unknown, extra: Partial<Call> = {}) {
    const response = await call({
      host: this.host,
      path,
      body,
      cookie: this.cookie,
      // Login-origin API requests arrive from the edge with the token and the client address.
      edge: this.host === adminHost ? undefined : { client: this.client },
      ...extra,
    });
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

// RFC 4648 Base32 decoding and RFC 6238 SHA-1 TOTP, independent of Better Auth's generator.
function totp(uri: string) {
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

// Routes that take no browser session: worker, metrics, health, setup status, Better Auth itself, and
// the gate's edge handlers (FD-11), which answer 401 to anything without the edge token.
const sessionFree = (path: string) =>
  path.startsWith("/api/internal/") ||
  path.startsWith("/api/auth/") ||
  (GATE_EDGE_API_PATHS as readonly string[]).includes(path) ||
  ["/api/health", "/api/setup/status", "/api/metrics/prometheus", "/api/*"].includes(path);

type User = { id: string; email: string };

async function createUser(label: string, role?: "owner" | "operator" | "viewer"): Promise<User> {
  const ctx = await auth.$context;
  const email = `${label}-${createId("usr")}@example.test`;
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

/** A signed session cookie minted server-side with an explicit origin (positive provenance). */
async function sessionCookie(userId: string, origin: "admin" | "gate") {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createSession(userId, false, { origin });
  const signed = `${created.token}.${await makeSignature(created.token, ctx.secret)}`;
  return { token: created.token, cookie: `${authCookieName("session_token")}=${encodeURIComponent(signed)}` };
}

async function countSessions() {
  const [row] = await sql`SELECT count(*)::int AS count FROM session`;
  return row!.count as number;
}

let owner: User;
let ownerTotp: () => string;
let ownerAdmin: { token: string; cookie: string };

beforeAll(async () => {
  await sql`
    UPDATE platform_settings
    SET gate_login_mode = 'public', gate_login_hostname = ${loginHost}, public_ipv4 = '203.0.113.10'
    WHERE id = 'default'
  `;
  await sql`
    INSERT INTO domain_claims (id, name, ownership_token, status) VALUES (${createId("dom")}, ${zone}, 'tok', 'verified')
  `;
  await refreshLoginHost(true);

  // The owner enrolls TOTP for real on the admin origin (one admin-host sign-in from the edge peer).
  owner = await createUser("owner", "owner");
  const browser = new Browser(adminHost, "unused");
  expect((await browser.send("/api/auth/sign-in/email", { email: owner.email, password })).status).toBe(200);
  const enabled = await browser.send("/api/auth/two-factor/enable", { password });
  expect(enabled.status).toBe(200);
  ownerTotp = totp((await enabled.json()).totpURI);
  expect((await browser.send("/api/auth/two-factor/verify-totp", { code: ownerTotp() })).status).toBe(200);
  await sql`UPDATE "user" SET mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${owner.id}`;
  ownerAdmin = await sessionCookie(owner.id, "admin");
});

afterAll(() => server.stop(true));

describe("Better Auth 1.7.25 dynamic base URL", () => {
  // The same `baseURL` object the API passes to Better Auth, in an instance with one probe endpoint.
  const probe = betterAuth({
    baseURL: authBaseURL,
    secret: "gate-login-probe-secret-0123456789abcdef",
    plugins: [
      {
        id: "ark-base-url-probe",
        endpoints: {
          probe: createAuthEndpoint("/ark-base-url", { method: "GET" }, async (ctx) =>
            ctx.json({ baseURL: ctx.context.baseURL, trusted: ctx.context.trustedOrigins }),
          ),
        },
      },
    ],
  });
  const ask = (host: string, headers: Record<string, string> = {}) =>
    probe.handler(new Request(`http://${host}/api/auth/ark-base-url`, { headers: { host, ...headers } }));

  test("builds a per-request base URL for the admin host and for the login host", async () => {
    expect((await (await ask(adminHost)).json()).baseURL).toBe(`https://${adminHost}/api/auth`);
    const login = await (await ask(loginHost)).json();
    expect(login.baseURL).toBe(`https://${loginHost}/api/auth`);
    expect(login.trusted).toContain(`https://${loginHost}`);
  });

  test("ignores X-Forwarded-Host and X-Forwarded-Proto (no trustedProxyHeaders)", async () => {
    const forwarded = await ask(adminHost, { "x-forwarded-host": loginHost, "x-forwarded-proto": "http" });
    expect((await forwarded.json()).baseURL).toBe(`https://${adminHost}/api/auth`);
  });

  test("rejects a third host with no fallback, in the probe and in the API's own instance", async () => {
    await expect(ask("www.example.com")).rejects.toThrow(/not in the allowed hosts list/);
    await expect(
      auth.handler(
        new Request("http://www.example.com/api/auth/get-session", { headers: { host: "www.example.com" } }),
      ),
    ).rejects.toThrow(/not in the allowed hosts list/);
  });
});

describe("unknown and malformed hosts", () => {
  test("sign-in with Host www.example.com is refused before Better Auth and inserts no session", async () => {
    const user = await createUser("unknown-host");
    const before = await countSessions();
    for (const host of ["www.example.com", "example.com", `${loginHost}.evil.test`]) {
      const response = await call({
        host,
        path: "/api/auth/sign-in/email",
        body: { email: user.email, password },
        edge: { client: "192.0.2.10" },
      });
      expect(response.status, host).toBe(421);
      expect(response.headers.getSetCookie(), host).toEqual([]);
    }
    expect(await countSessions()).toBe(before);
    const [rows] = await sql`SELECT count(*)::int AS count FROM session WHERE user_id = ${user.id}`;
    expect(rows!.count).toBe(0);
  });

  test("a Host that contradicts the request URL is refused (in-process request)", async () => {
    const response = await app.request(
      new Request(`https://${adminHost}/api/auth/get-session`, { headers: { host: loginHost } }),
    );
    expect(response.status).toBe(421);
  });

  test("server-side calls need an explicit origin, and the database refuses an insert without one", async () => {
    const user = await createUser("server-side");
    await expect(
      auth.api.signInEmail({
        body: { email: user.email, password },
        headers: new Headers({ host: adminHost, origin: `https://${adminHost}` }),
      }),
    ).rejects.toThrow(/without a request or an explicit origin/);
    await expect(
      sql`
        INSERT INTO session (id, user_id, token, expires_at, created_at, updated_at)
        VALUES (${createId("ses")}, ${user.id}, ${createId("tok")}, now() + interval '1 hour', now(), now())
      `.then((rows) => rows),
    ).rejects.toThrow(/null value in column "origin"/);
    const [rows] = await sql`SELECT count(*)::int AS count FROM session WHERE user_id = ${user.id}`;
    expect(rows!.count).toBe(0);
  });
});

describe("session separation", () => {
  let gate: Browser;
  let gateUser: User;

  beforeAll(async () => {
    gateUser = await createUser("gate-user");
    gate = new Browser(loginHost, "198.51.100.21");
  });

  test("signing in on the login origin creates an origin = 'gate' session with __Host- cookies", async () => {
    const response = await gate.send("/api/auth/sign-in/email", { email: gateUser.email, password });
    expect(response.status).toBe(200);
    const { token } = await response.json();
    const [row] = await sql`SELECT origin, ip_address FROM session WHERE token = ${token}`;
    expect(row?.origin).toBe("gate");
    // The real client address the edge forwarded, not the edge's own peer address.
    expect(row?.ip_address).toBe("198.51.100.21");
    const setCookie = response.headers
      .getSetCookie()
      .find((header) => header.startsWith(`${authCookieName("session_token")}=`));
    expect(setCookie).toBeDefined();
    expect(authCookieName("session_token")).toBe("__Host-ark_stack.session_token");
    expect(setCookie).toMatch(/; Secure/i);
    expect(setCookie).toMatch(/; Path=\/(;|$)/i);
    expect(setCookie).not.toMatch(/domain=/i);
  });

  test("the gate session gets 403 on every /api/* admin route", async () => {
    const routes = [
      ...new Map(
        app.routes
          .filter(
            (route) => route.path.startsWith("/api/") && !sessionFree(route.path) && route.method !== "ALL",
          )
          .map((route) => [`${route.method} ${route.path}`, route]),
      ).values(),
    ];
    expect(routes.length).toBeGreaterThan(60);
    for (const route of routes) {
      const path = route.path.replaceAll(/:[A-Za-z]+/g, "x");
      const response = await call({
        host: adminHost,
        path,
        method: route.method,
        cookie: gate.cookie,
        body: route.method === "GET" ? undefined : {},
      });
      expect(response.status, `${route.method} ${path}`).toBe(403);
    }
  });

  test("Better Auth refuses the gate session on the admin origin, and serves it on the login origin", async () => {
    const onAdmin = await call({ host: adminHost, path: "/api/auth/get-session", cookie: gate.cookie });
    expect(onAdmin.status).toBe(403);
    const onLogin = await gate.send("/api/auth/get-session");
    expect(onLogin.status).toBe(200);
    expect((await onLogin.json())?.session?.origin).toBe("gate");
  });

  test("an admin session is not accepted on the login origin", async () => {
    const response = await call({
      host: loginHost,
      path: "/api/auth/get-session",
      cookie: ownerAdmin.cookie,
      edge: { client: "198.51.100.22" },
    });
    expect(response.status).toBe(403);
  });

  test("a user with no platform_access row gets 403 from /api/state, not viewer data", async () => {
    const user = await createUser("no-access");
    const { cookie } = await sessionCookie(user.id, "admin");
    const response = await call({ host: adminHost, path: "/api/state", cookie });
    expect(response.status).toBe(403);
    expect(JSON.stringify(await response.json())).not.toContain("projects");
  });

  test("an admin session on the admin origin is unaffected", async () => {
    for (const path of ["/api/state", "/api/me", "/api/settings/gate"]) {
      const response = await call({ host: adminHost, path, cookie: ownerAdmin.cookie });
      expect(response.status, path).toBe(200);
    }
  });
});

describe("login origin path allowlist", () => {
  test("every path outside the allowlist is 404 on the login host, whatever credential is sent", async () => {
    const worker = `Bearer ${process.env.ARK_DOMAIN_WORKER_TOKEN}`;
    const metrics = `Bearer ${process.env.ARK_METRICS_TOKEN}`;
    const cases: Array<[string, string, Record<string, string>?]> = [
      ["GET", "/api/state"],
      ["GET", "/api/me"],
      ["GET", "/api/internal/jobs", { authorization: worker }],
      ["GET", "/api/internal/edge/lease", { authorization: worker }],
      ["GET", "/api/gate/check?route=rt_x"],
      ["GET", "/api/gate/users"],
      ["GET", "/api/health"],
      ["GET", "/api/metrics/prometheus", { authorization: metrics }],
      ["GET", "/api/setup/status"],
      ["POST", "/api/auth/sign-up/email"],
      ["POST", "/api/auth/two-factor/disable"],
      ["POST", "/api/auth/two-factor/generate-backup-codes"],
      ["GET", "/api/auth/list-sessions"],
      ["POST", "/api/auth/sign-in/email/"],
      ["POST", "/api/auth/sign-in%2Femail"],
      ["GET", "/"],
      ["GET", "/index.html"],
      ["GET", "/.well-known/acme-challenge/x"],
    ];
    for (const [method, path, headers] of cases) {
      const response = await call({
        host: loginHost,
        path,
        method,
        headers,
        cookie: ownerAdmin.cookie,
        body: method === "GET" ? undefined : {},
        edge: { client: "198.51.100.30" },
      });
      expect(response.status, `${method} ${path}`).toBe(404);
    }
  });

  test("the allowlisted login API paths reach Better Auth", async () => {
    const response = await call({
      host: loginHost,
      path: "/api/auth/get-session",
      edge: { client: "198.51.100.31" },
    });
    expect(response.status).toBe(200);
  });

  test("cross-origin mutations on the login origin are refused", async () => {
    const response = await call({
      host: loginHost,
      path: "/api/auth/sign-in/email",
      body: { email: owner.email, password },
      headers: { origin: `https://${adminHost}` },
      edge: { client: "198.51.100.32" },
    });
    expect(response.status).toBe(403);
  });
});

describe("enrollment guard on the login origin", () => {
  test("an already-enrolled admin gets 403 for enable and get-totp-uri; secret and backup codes unchanged", async () => {
    const [before] = await sql`SELECT secret, backup_codes FROM two_factor WHERE user_id = ${owner.id}`;
    expect(before).toBeDefined();
    const browser = new Browser(loginHost, "198.51.100.41");
    const signIn = await browser.send("/api/auth/sign-in/email", {
      email: owner.email,
      password,
      rememberMe: false,
    });
    expect(signIn.status).toBe(200);
    expect((await signIn.json()).twoFactorRedirect).toBe(true);
    // Without a session yet (only the two_factor cookie), enrollment is not even considered.
    expect((await browser.send("/api/auth/two-factor/enable", { password })).status).toBe(401);
    const verified = await browser.send("/api/auth/two-factor/verify-totp", {
      code: ownerTotp(),
      trustDevice: true,
    });
    expect(verified.status).toBe(200);
    const [session] = await sql`SELECT origin FROM session WHERE token = ${(await verified.json()).token}`;
    expect(session?.origin).toBe("gate");
    expect((await browser.send("/api/auth/two-factor/enable", { password })).status).toBe(403);
    expect((await browser.send("/api/auth/two-factor/get-totp-uri", { password })).status).toBe(403);
    const [after] = await sql`SELECT secret, backup_codes FROM two_factor WHERE user_id = ${owner.id}`;
    expect(after).toEqual(before!);
    const [user] = await sql`SELECT two_factor_enabled FROM "user" WHERE id = ${owner.id}`;
    expect(user?.two_factor_enabled).toBe(true);
  });

  test("re-enrollment material stays available to an admin session on the admin origin", async () => {
    const response = await call({
      host: adminHost,
      path: "/api/auth/two-factor/get-totp-uri",
      body: { password },
      cookie: ownerAdmin.cookie,
    });
    expect(response.status).toBe(200);
  });

  test("a new gate user completes first enrollment once, and cannot repeat it after verification", async () => {
    const user = await createUser("enrolling");
    const browser = new Browser(loginHost, "198.51.100.42");
    expect((await browser.send("/api/auth/sign-in/email", { email: user.email, password })).status).toBe(200);
    const enabled = await browser.send("/api/auth/two-factor/enable", { password });
    expect(enabled.status).toBe(200);
    const body = await enabled.json();
    expect(body.backupCodes.length).toBeGreaterThan(0);
    expect((await browser.send("/api/auth/two-factor/get-totp-uri", { password })).status).toBe(200);
    const code = totp(body.totpURI);
    const verified = await browser.send("/api/auth/two-factor/verify-totp", { code: code() });
    expect(verified.status).toBe(200);
    // Enrollment replaces the session; every session of this user is a gate session.
    const sessions = await sql`SELECT origin FROM session WHERE user_id = ${user.id}`;
    expect(sessions.map((row) => row.origin)).toEqual(["gate"]);
    const [row] = await sql`SELECT two_factor_enabled FROM "user" WHERE id = ${user.id}`;
    expect(row?.two_factor_enabled).toBe(true);
    const [secret] = await sql`SELECT secret, backup_codes FROM two_factor WHERE user_id = ${user.id}`;
    expect((await browser.send("/api/auth/two-factor/enable", { password })).status).toBe(403);
    expect((await browser.send("/api/auth/two-factor/get-totp-uri", { password })).status).toBe(403);
    const [unchanged] = await sql`SELECT secret, backup_codes FROM two_factor WHERE user_id = ${user.id}`;
    expect(unchanged).toEqual(secret!);
  });
});

describe("cookie tossing", () => {
  test("an attacker session planted under a sibling-settable name is not honoured on the login origin", async () => {
    const attacker = await createUser("attacker");
    const planted = await sessionCookie(attacker.id, "gate");
    const signed = decodeURIComponent(planted.cookie.split("=").slice(1).join("="));
    const value = encodeURIComponent(signed);
    // What JavaScript on a sibling route can set with Domain=<parent>; Path=/gate: any name except a
    // __Host- one, which the browser refuses with a Domain attribute.
    for (const name of [
      "__Secure-ark_stack.session_token",
      "ark_stack.session_token",
      "better-auth.session_token",
      "__Secure-better-auth.session_token",
    ]) {
      const response = await call({
        host: loginHost,
        path: "/api/auth/get-session",
        cookie: `${name}=${value}`,
        edge: { client: "198.51.100.51" },
      });
      expect(response.status, name).toBe(200);
      expect(await response.json(), name).toBeNull();
    }
    // FD-11's /gate/authorize does not honor it either: the browser is treated as signed out and
    // sent to the sign-in page, and no handoff code is minted.
    const authorize = await call({
      host: loginHost,
      path: "/gate/authorize?route=rt_x",
      cookie: `__Secure-ark_stack.session_token=${value}`,
    });
    expect(authorize.status).toBe(303);
    expect(authorize.headers.get("location")).toStartWith("/gate/login?next=");
    expect((await sql`SELECT count(*)::int AS n FROM gate_handoffs`)[0]!.n).toBe(0);
  });

  test("a duplicated authentication cookie name is refused", async () => {
    const attacker = await createUser("duplicate");
    const first = await sessionCookie(attacker.id, "gate");
    const second = await sessionCookie(attacker.id, "gate");
    const response = await call({
      host: loginHost,
      path: "/api/auth/get-session",
      cookie: `${first.cookie}; ${second.cookie}`,
      edge: { client: "198.51.100.52" },
    });
    expect(response.status).toBe(400);
  });

  test("every authentication and two-factor cookie carries enforced __Host- attributes", async () => {
    const ctx = await auth.$context;
    for (const cookie of Object.values(ctx.authCookies)) expect(cookie.name.startsWith("__Host-")).toBe(true);
    for (const key of AUTH_COOKIE_KEYS) {
      const created = ctx.createAuthCookie(key);
      expect(created.name, key).toBe(`__Host-ark_stack.${key}`);
      expect(created.attributes.secure, key).toBe(true);
      expect(created.attributes.path, key).toBe("/");
      expect(created.attributes.domain, key).toBeUndefined();
    }
    const emitted = setCookies.filter((header) => /ark_stack\./.test(header.split("=")[0]!));
    const names = new Set(emitted.map((header) => header.split("=")[0]!));
    // Sign-in, remember-me off, the two-factor challenge and a trusted device were all exercised.
    for (const key of ["session_token", "dont_remember", "two_factor", "trust_device"] as const) {
      expect(names.has(authCookieName(key)), key).toBe(true);
    }
    for (const header of emitted) {
      expect(header.startsWith("__Host-ark_stack."), header).toBe(true);
      expect(header, header).toMatch(/; Secure/i);
      expect(header, header).toMatch(/; Path=\/(;|$)/i);
      expect(header, header).not.toMatch(/domain=/i);
    }
  });
});

async function proxyDocker(...args: string[]) {
  const child = Bun.spawn(["docker", ...args], { stdout: "pipe", stderr: "pipe" });
  const [code, out, err] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) throw new Error(`docker ${args[0]}: ${err || out}`);
  return out.trim();
}

describe("trusted client address and sign-in rate limit", () => {
  // Keep subnets allocated until both proxy modes have run: Docker otherwise reuses the first
  // client's address immediately, carrying its deliberately exhausted in-memory rate bucket over.
  const proxyNetworks: string[] = [];
  afterAll(async () => {
    for (const network of proxyNetworks) await proxyDocker("network", "rm", network);
  });
  for (const mode of ["public", "tailnet"] as const) {
    test(`${mode} admin Caddy keeps two clients' sign-in and MFA buckets and session addresses separate`, async () => {
      const directory = await mkdtemp(join(tmpdir(), "ark-admin-proxy-"));
      const network = `ark-admin-proxy-${crypto.randomUUID()}`;
      const containers: string[] = [];
      // A byte-preserving HTTP relay makes the Caddy->API transport peer the recorded loopback
      // address on both Docker Desktop and Linux. Only Caddy supplies the authentication headers.
      const relay = Bun.serve({
        hostname: "0.0.0.0",
        port: 0,
        fetch: (request) =>
          fetch(new Request(`http://127.0.0.1:${server.port}${new URL(request.url).pathname}`, request)),
      });
      try {
        const rendered = renderCaddyfile({
          adminMode: "public",
          adminHostname: adminHost,
          apiUpstream: `host.docker.internal:${relay.port}`,
          challengeDir: "/unused",
          certificates: [{ hostname: adminHost, status: "issued", fullchain: "/unused", privkey: "/unused" }],
        });
        const start = rendered.indexOf(`${adminHost} {\n`) + `${adminHost} {\n`.length;
        const siteBody = rendered
          .slice(start, rendered.indexOf("\n}\n", start))
          .replace(/^  (bind|tls) .*\n/gm, "");
        const publicConfig = `{\n  admin off\n  auto_https off\n}\n:8080 {\n${siteBody}\n}\n`;
        // Stand in for Tailscale Serve in the gateway's loopback namespace. The outer proxy
        // overwrites forged forwarding headers, as Serve does, and the shipped gateway resolves
        // its strict chain before writing a single authenticated address to the API.
        const tailnetConfig = (
          await Bun.file(join(import.meta.dir, "../../infra/platform/TailnetCaddyfile")).text()
        )
          .replaceAll("api:3000", `host.docker.internal:${relay.port}`)
          .concat("\n:8081 {\n  reverse_proxy 127.0.0.1:8080\n}\n");
        await Bun.write(join(directory, "Caddyfile"), mode === "public" ? publicConfig : tailnetConfig);
        const compose = Bun.YAML.parse(
          await Bun.file(join(import.meta.dir, "../../infra/platform/docker-compose.yml")).text(),
        ) as { services: { edge: { image: string } } };
        await proxyDocker("network", "create", network);
        proxyNetworks.push(network);
        const proxy = `${network}-caddy`;
        containers.push(proxy);
        await proxyDocker(
          "run",
          "-d",
          "--name",
          proxy,
          "--network",
          network,
          "--network-alias",
          "proxy",
          "--add-host",
          "host.docker.internal:host-gateway",
          "-e",
          `ARK_EDGE_GATE_TOKEN=${edgeToken}`,
          "-v",
          `${directory}/Caddyfile:/etc/caddy/Caddyfile:ro`,
          compose.services.edge.image,
        );
        for (const label of ["a", "b"]) {
          const name = `${network}-${label}`;
          containers.push(name);
          await proxyDocker(
            "run",
            "-d",
            "--name",
            name,
            "--network",
            network,
            "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61",
            "bun",
            "-e",
            "setInterval(() => {}, 1000)",
          );
        }
        const request = async (client: string, path: string, body?: unknown, cookie?: string) =>
          JSON.parse(
            await proxyDocker(
              "exec",
              `${network}-${client}`,
              "bun",
              "-e",
              `const i=JSON.parse(process.argv[1]); const r=await fetch('http://proxy:'+i.port+i.path,{method:i.body===undefined?'GET':'POST',headers:{host:i.host,origin:'https://'+i.host,'content-type':'application/json','x-forwarded-for':'6.6.6.6','x-ark-edge-token':'forged','x-ark-client-ip':'6.6.6.6',...(i.cookie?{cookie:i.cookie}:{})},body:i.body===undefined?undefined:JSON.stringify(i.body)});console.log(JSON.stringify({status:r.status,body:await r.text(),cookies:r.headers.getSetCookie()}));`,
              JSON.stringify({ host: adminHost, path, body, cookie, port: mode === "public" ? 8080 : 8081 }),
            ),
          ) as { status: number; body: string; cookies: string[] };
        // Wait for the proxy using a session lookup, which does not touch sign-in/MFA limits.
        for (let i = 0; ; i++) {
          try {
            expect((await request("b", "/api/auth/get-session")).status).toBe(200);
            break;
          } catch (error) {
            if (i === 30) throw error;
            await Bun.sleep(100);
          }
        }
        const user = await createUser("admin-proxy", "viewer");
        for (let i = 0; i < 6; i++)
          expect(
            (await request("a", "/api/auth/sign-in/email", { email: user.email, password: "wrong" })).status,
          ).toBe(i === 5 ? 429 : 401);
        const signed = await request("b", "/api/auth/sign-in/email", { email: user.email, password });
        expect(signed.status).toBe(200);
        const address = await proxyDocker(
          "inspect",
          "-f",
          `{{(index .NetworkSettings.Networks "${network}").IPAddress}}`,
          `${network}-b`,
        );
        const [record] =
          await sql`SELECT ip_address FROM session WHERE token = ${JSON.parse(signed.body).token}`;
        expect(record?.ip_address).toBe(address);
        // MFA management uses the same authenticated address channel.
        const cookie = signed.cookies.map((value) => value.split(";")[0]).join("; ");
        const existing = await sessionCookie(user.id, "admin");
        for (let i = 0; i < 6; i++)
          expect(
            (await request("a", "/api/auth/two-factor/enable", { password: "wrong" }, existing.cookie))
              .status,
          ).toBe(i === 5 ? 429 : 400);
        expect((await request("b", "/api/auth/two-factor/enable", { password }, cookie)).status).toBe(200);
      } finally {
        for (const name of containers.toReversed()) await proxyDocker("rm", "-f", name);
        relay.stop(true);
        await rm(directory, { recursive: true, force: true });
      }
    }, 120_000);
  }

  const failedSignIn = (input: Partial<Call>) =>
    call({
      host: loginHost,
      path: "/api/auth/sign-in/email",
      body: { email: owner.email, password: "wrong-password-for-the-limiter" },
      ...input,
    });

  test("more than 5 failed sign-ins per minute from one client address are rate-limited (429)", async () => {
    const statuses = [];
    for (let attempt = 0; attempt < 6; attempt++) {
      statuses.push((await failedSignIn({ edge: { client: "203.0.113.50" } })).status);
    }
    expect(statuses).toEqual([401, 401, 401, 401, 401, 429]);
    // Another real client behind the same edge is unaffected.
    expect((await failedSignIn({ edge: { client: "203.0.113.51" } })).status).toBe(401);
  });

  test("a non-edge bridge peer with a forged XFF and a forged edge token is keyed on its own address", async () => {
    const statuses = [];
    for (let attempt = 0; attempt < 6; attempt++) {
      statuses.push(
        (
          await failedSignIn({
            peer: "other",
            edge: { client: `198.18.0.${attempt + 1}`, token: `forged-${attempt}` },
          })
        ).status,
      );
    }
    expect(statuses).toEqual([401, 401, 401, 401, 401, 429]);
    // The genuine token from a peer that is not the recorded edge peer is not trusted either.
    expect((await failedSignIn({ peer: "other", edge: { client: "198.18.1.1" } })).status).toBe(429);
    // A genuine token from an unpinned peer is refused on the admin origin too.
    expect(
      (
        await call({
          host: adminHost,
          peer: "other",
          path: "/api/auth/sign-in/email",
          body: { email: owner.email, password: "wrong" },
          headers: { "x-forwarded-for": "198.18.2.1", "x-ark-edge-token": edgeToken },
        })
      ).status,
    ).toBe(429);
  });

  test("a session created through the edge records the client address, otherwise the transport peer", async () => {
    const user = await createUser("addresses");
    const viaEdge = await call({
      host: loginHost,
      path: "/api/auth/sign-in/email",
      body: { email: user.email, password },
      edge: { client: "2001:db8::77" },
    });
    expect(viaEdge.status).toBe(200);
    const [edgeRow] = await sql`SELECT ip_address FROM session WHERE token = ${(await viaEdge.json()).token}`;
    // Better Auth groups IPv6 clients by /64 for rate limiting and records the normalized form.
    expect(String(edgeRow?.ip_address)).toMatch(/^2001:0?db8:/);
    const forged = await call({
      host: loginHost,
      path: "/api/auth/sign-in/email",
      body: { email: user.email, password },
      edge: { client: "203.0.113.99", token: "forged" },
    });
    expect(forged.status).toBe(200);
    const [peerRow] = await sql`SELECT ip_address FROM session WHERE token = ${(await forged.json()).token}`;
    expect(peerRow?.ip_address).toBe("127.0.0.1");
  });
});

describe("PUT /api/settings/gate", () => {
  let operator: { cookie: string };

  beforeAll(async () => {
    const user = await createUser("operator", "operator");
    await sql`
      UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${user.id}
    `;
    operator = await sessionCookie(user.id, "admin");
  });

  const put = (body: unknown, cookie = ownerAdmin.cookie) =>
    call({ host: adminHost, path: "/api/settings/gate", method: "PUT", body, cookie });
  const stepUp = async (request: Record<string, unknown>) => {
    const response = await call({
      host: adminHost,
      path: "/api/step-up",
      body: { password, action: "exposure.public", request },
      cookie: ownerAdmin.cookie,
    });
    expect(response.status).toBe(200);
  };

  const gateState = async () => ({
    settings: [...(await sql`SELECT * FROM platform_settings ORDER BY id`)],
    sessions: [...(await sql`SELECT * FROM session ORDER BY id`)],
    dns: [...(await sql`SELECT * FROM dns_records ORDER BY id`)],
    audit: [...(await sql`SELECT * FROM audit_events ORDER BY id`)],
    grants: [...(await sql`SELECT * FROM step_up_grants ORDER BY id`)],
    gates: [...(await sql`SELECT * FROM endpoints WHERE kind = 'gate' ORDER BY id`)],
  });

  test("commit rejects a hostname reserved after prepare, including a gate endpoint owned by another domain, without writes", async () => {
    for (const kind of ["route", "gate"]) {
      const hostname = `collision-${kind}.${zone}`;
      const plan = await prepareGateSettings({ mode: "public", hostname });
      const id = createId("ep");
      // A gate with no matching domain ownership must also be refused.
      await sql`INSERT INTO endpoints (id, kind, hostname, domain_id) VALUES (${id}, ${kind}, ${hostname}, ${kind === "route" ? plan.domain!.id : null})`;
      const before = await gateState();
      const queued: unknown[] = [];
      try {
        await expect(
          commitGateSettings(
            plan,
            { userId: owner.id, role: "owner" },
            async (input) => {
              queued.push(input);
              return { id: "unexpected" };
            },
            async (tx) => {
              // Stand-in for transactional authorization consumption: this must roll back too.
              await tx.delete((await import("./schema.ts")).session);
            },
          ),
        ).rejects.toMatchObject({ status: 409 });
        expect(await gateState()).toEqual(before);
        expect(queued).toEqual([]);
        expect((await sql`SELECT kind FROM endpoints WHERE id = ${id}`)[0]?.kind).toBe(kind);
      } finally {
        await sql`DELETE FROM endpoints WHERE id = ${id}`;
      }
    }
  });

  test("a concurrent route reservation wins the unique-hostname race and rolls gate commit back with 409", async () => {
    const hostname = `concurrent.${zone}`;
    const plan = await prepareGateSettings({ mode: "public", hostname });
    const before = await gateState();
    let reserved!: () => void;
    let release!: () => void;
    const inserted = new Promise<void>((resolve) => {
      reserved = resolve;
    });
    const proceed = new Promise<void>((resolve) => {
      release = resolve;
    });
    const id = createId("ep");
    const route = sql.begin(async (tx) => {
      await tx`INSERT INTO endpoints (id, kind, hostname, domain_id) VALUES (${id}, 'route', ${hostname}, ${plan.domain!.id})`;
      reserved();
      await proceed;
    });
    await inserted;
    const gate = commitGateSettings(plan, { userId: owner.id, role: "owner" }, async () => {
      throw new Error("must not enqueue on conflict");
    }).then(
      () => ({ status: 200 }),
      (error: unknown) => error,
    );
    try {
      // The route insert is still invisible to the SELECT. Wait until the gate INSERT is blocked
      // on its unique index, then commit the route, exercising the insert-race conflict branch.
      let waiting = false;
      for (let attempt = 0; attempt < 100; attempt++) {
        const rows =
          await sql`SELECT pid FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE '%insert into "endpoints"%'`;
        if (rows.length) {
          waiting = true;
          break;
        }
        await Bun.sleep(20);
      }
      expect(waiting).toBe(true);
      release();
      await route;
      expect(await gate).toMatchObject({ status: 409 });
      expect(await gateState()).toEqual(before);
      expect((await sql`SELECT kind FROM endpoints WHERE id = ${id}`)[0]?.kind).toBe("route");
    } finally {
      release();
      await route;
      await gate;
      await sql`DELETE FROM endpoints WHERE id = ${id}`;
    }
  });

  test("either durable enqueue failure rolls back settings, grants, sessions and all jobs", async () => {
    for (const failAt of [1, 2]) {
      const plan = await prepareGateSettings({ mode: "public", hostname: `rollback-${failAt}.${zone}` });
      const before = await gateState();
      const jobs = [...(await sql`SELECT * FROM operations ORDER BY id`)];
      let inserted = 0;
      await expect(
        commitGateSettings(
          plan,
          { userId: owner.id, role: "owner" },
          async (input, tx) => {
            const job = await enqueueGateOperation(input, tx);
            if (++inserted === failAt) throw new Error("injected enqueue failure");
            return job;
          },
          async (tx) => {
            await tx.delete((await import("./schema.ts")).session);
          },
        ),
      ).rejects.toThrow("injected enqueue failure");
      expect(await gateState()).toEqual(before);
      expect([...(await sql`SELECT * FROM operations ORDER BY id`)]).toEqual(jobs);
    }
  });

  test("enable, move and disable keep durable work after a post-commit refresh failure", async () => {
    const original = await prepareGateSettings({ mode: "public", hostname: loginHost });
    try {
      for (const input of [
        { mode: "public" as const, hostname: `recover.${zone}` },
        { mode: "public" as const, hostname: `moved-recover.${zone}` },
        { mode: "disabled" as const },
      ]) {
        const plan = await prepareGateSettings(input);
        const ids: string[] = [];
        await expect(
          commitGateSettings(
            plan,
            { userId: owner.id, role: "owner" },
            async (job, tx) => {
              const result = await enqueueGateOperation(job, tx);
              ids.push(result.id);
              return result;
            },
            undefined,
            async () => {
              throw new Error("crash immediately after commit");
            },
          ),
        ).rejects.toThrow("crash immediately after commit");
        // A new connection sees the committed jobs without another PUT or authorization grant.
        const { default: postgres } = await import("postgres");
        const restarted = postgres(process.env.DATABASE_URL!, { max: 1 });
        try {
          const rows = await restarted`SELECT kind, status FROM operations WHERE id IN ${restarted(ids)}`;
          expect(rows.map((r) => r.kind).toSorted()).toEqual(
            input.mode === "public" ? ["domain.verify", "edge.apply"] : ["edge.apply"],
          );
          expect(rows.every((r) => r.status === "queued")).toBe(true);
          const [settings] =
            await restarted`SELECT gate_login_mode, gate_login_hostname FROM platform_settings WHERE id = 'default'`;
          expect(settings).toMatchObject({ gate_login_mode: input.mode, gate_login_hostname: plan.hostname });
        } finally {
          await restarted.end();
        }
        await refreshLoginHost(true);
        expect((await import("./origin-hosts.ts")).currentLoginHost()).toBe(plan.hostname);
      }
    } finally {
      await commitGateSettings(original, { userId: owner.id, role: "owner" });
    }
  });

  test("only public or disabled (R1), owner only, and public needs an exposure.public step-up", async () => {
    expect((await put({ mode: "tailnet", hostname: movedLoginHost })).status).toBe(422);
    expect((await put({ mode: "public" })).status).toBe(422);
    expect((await put({ mode: "public", hostname: movedLoginHost }, operator.cookie)).status).toBe(403);
    const missingGrant = await put({ mode: "public", hostname: movedLoginHost });
    expect(missingGrant.status).toBe(403);
    expect((await missingGrant.json()).error).toMatch(/exposure\.public/);
    expect((await put({ mode: "public", hostname: adminHost })).status).toBe(409);
    expect((await put({ mode: "public", hostname: "login.elsewhere.test" })).status).toBe(422);
  });

  test("moving the login origin creates the gate endpoint and records, revokes gate sessions and re-registers hosts", async () => {
    const gateUser = await createUser("moved");
    await sessionCookie(gateUser.id, "gate");
    expect(
      privilegedRequestHash("exposure.public", { mode: "public", hostname: movedLoginHost }),
    ).toBeTruthy();
    await stepUp({ mode: "public", hostname: movedLoginHost });
    const response = await put({ mode: "public", hostname: movedLoginHost });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.mode).toBe("public");
    expect(body.hostname).toBe(movedLoginHost);
    expect(body.revokedSessions).toBeGreaterThan(0);
    const [settings] = await sql`SELECT gate_login_mode, gate_login_hostname FROM platform_settings`;
    expect(settings).toEqual({ gate_login_mode: "public", gate_login_hostname: movedLoginHost });
    const [endpoint] =
      await sql`SELECT kind, exposure, status FROM endpoints WHERE hostname = ${movedLoginHost}`;
    expect(endpoint).toEqual({ kind: "gate", exposure: "public", status: "awaiting_dns" });
    const records = await sql`SELECT type, expected_value FROM dns_records WHERE name = ${movedLoginHost}`;
    expect([...records]).toEqual([{ type: "A", expected_value: "203.0.113.10" }]);
    const queued = await sql`SELECT kind FROM operations WHERE id IN ${sql(body.operationIds)} ORDER BY kind`;
    expect(queued.map((row) => row.kind)).toEqual(["domain.verify", "edge.apply"]);
    expect((await sql`SELECT id FROM session WHERE origin = 'gate'`).length).toBe(0);
    // The old login host is now an unknown host; the new one serves the login allowlist only.
    expect((await call({ host: loginHost, path: "/api/auth/get-session" })).status).toBe(421);
    expect((await call({ host: movedLoginHost, path: "/api/auth/get-session" })).status).toBe(200);
    expect((await call({ host: movedLoginHost, path: "/api/state" })).status).toBe(404);
    const [audit] =
      await sql`SELECT detail FROM audit_events WHERE action = 'settings.gate' ORDER BY created_at DESC LIMIT 1`;
    expect(audit?.detail.hostname).toBe(movedLoginHost);
  });

  test("disabling needs no step-up, removes the endpoint, retires its DNS and revokes gate sessions", async () => {
    const gateUser = await createUser("disabled");
    await sessionCookie(gateUser.id, "gate");
    const response = await put({ mode: "disabled" });
    expect(response.status).toBe(200);
    expect((await sql`SELECT id FROM endpoints WHERE kind = 'gate'`).length).toBe(0);
    const records =
      await sql`SELECT type, status, withdrawal_reason FROM dns_records WHERE name = ${movedLoginHost}`;
    expect([...records]).toEqual([
      { type: "A", status: "withdrawal_pending", withdrawal_reason: "endpoint_deleted" },
    ]);
    expect((await sql`SELECT id FROM session WHERE origin = 'gate'`).length).toBe(0);
    expect((await call({ host: movedLoginHost, path: "/api/auth/get-session" })).status).toBe(421);
    // Restore the login origin for the mode-change checks.
    await sql`UPDATE platform_settings SET gate_login_mode = 'public', gate_login_hostname = ${loginHost}`;
    await refreshLoginHost(true);
  });
});

describe("admin mode changes", () => {
  const modeChange = async () => {
    const operation = await enqueue({
      kind: "admin.mode_change",
      targetIds: ["platform"],
      payload: { adminMode: "tailnet", nonce: crypto.randomUUID() },
    });
    return runOperation("admin.mode_change", operation);
  };

  test("the login origin can never become the admin origin", async () => {
    const before = await countSessions();
    process.env.ARK_TAILNET_AUTH_ORIGIN = `https://${loginHost}`;
    await expect(modeChange()).rejects.toThrow(/admin hosts do not include/);
    process.env.ARK_TAILNET_AUTH_ORIGIN = `https://www.example.com`;
    await expect(modeChange()).rejects.toThrow(/admin hosts do not include/);
    expect(await countSessions()).toBe(before);
  });

  test("a mode change to a registered admin origin still revokes every session, gate sessions included", async () => {
    const gateUser = await createUser("mode");
    await sessionCookie(gateUser.id, "gate");
    expect(await countSessions()).toBeGreaterThan(1);
    process.env.ARK_TAILNET_AUTH_ORIGIN = `https://${adminHost}`;
    await modeChange();
    expect(await countSessions()).toBe(0);
    expect((await call({ host: adminHost, path: "/api/state", cookie: ownerAdmin.cookie })).status).toBe(401);
  });
});
