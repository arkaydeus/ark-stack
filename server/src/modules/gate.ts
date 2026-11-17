// Gate handshake for `access_mode: sso` HTTP routes (docs/design/front-door.md §3.9.2-§3.9.5, FD-11).
//
// The edge (Caddy) calls `/api/gate/check` with `forward_auth` before every request to an SSO route,
// and maps exactly `GET /.ark/gate/callback` and `POST /.ark/gate/logout` on the route host to
// `/api/gate/callback` and `/api/gate/logout-route`. Those four handlers require `X-Ark-Edge-Token`
// (app.ts) and are on no public or tailnet path allowlist. The login origin serves `/gate/authorize`,
// `/gate/login` and `/gate/logout` (gate-pages.ts).
//
// - Handoff codes are 256-bit, stored as SHA-256 only, live 60 s and are consumed atomically. Each is
//   bound to its route, user, parent login session and the state nonce whose cookie the check set
//   on the route host, so a code cannot be replayed, moved to another route or planted in another
//   browser.
// - Gate sessions are opaque 256-bit tokens in `__Host-ark_gate` (Secure, HttpOnly, SameSite=Lax,
//   Path=/, no Domain), stored as SHA-256. Every check re-reads the session, its parent login
//   session, the access list and MFA assurance, so a removal takes effect on the next request.
// - A WebSocket upgrade or unsafe method needs an Origin that is the route itself or an
//   owner-approved exception (`gateOriginDecision`).

import {
  GATE_COOKIE,
  GATE_HANDOFF_TTL_MS,
  GATE_LAST_SEEN_INTERVAL_MS,
  GATE_SESSION_ABSOLUTE_MS,
  GATE_SESSION_IDLE_MS,
  GATE_STATE_COOKIE,
  GATE_STATE_MAX_AGE_S,
  ROUTE_ID_PATTERN,
  bypassMatches,
  checkGateNonce,
  checkRawRequestUri,
  checkReturnPath,
  createId,
  createToken,
  gateOriginDecision,
  gateWantsRedirect,
  hasMfaAssurance,
  parseCookies,
  secureEqual,
  sha256Hex,
} from "@ark-stack/shared";

import { sql as statement } from "drizzle-orm";

import { db, sql, type DbTransaction } from "../db.ts";

export type GateRoute = {
  id: string;
  hostname: string;
  kind: string;
  enabled: boolean;
  status: string;
  accessMode: string;
  bypassPaths: string[];
  allowedOrigins: string[];
};

/** A response for app.ts to send: status, headers (Set-Cookie may repeat) and an optional body. */
export type GateResponse = {
  status: number;
  headers: Array<[string, string]>;
  body?: string;
  /** Why a request was refused, for tests and logs; never sent to the client. */
  reason?: string;
};

const NO_STORE: [string, string] = ["Cache-Control", "no-store"];

function respond(status: number, headers: Array<[string, string]> = [], reason?: string): GateResponse {
  return { status, headers: [NO_STORE, ...headers], reason };
}

/** A route that the gate serves: HTTP, `sso`, enabled. */
export async function loadGateRoute(routeId: string | null | undefined): Promise<GateRoute | null> {
  if (!routeId || !ROUTE_ID_PATTERN.test(routeId)) return null;
  const [row] = await sql`
    SELECT r.id, e.hostname, r.kind, r.enabled, r.status, r.access_mode, r.bypass_paths, r.http_options
    FROM front_routes r JOIN endpoints e ON e.id = r.endpoint_id
    WHERE r.id = ${routeId}
  `;
  if (!row) return null;
  const options = (row.http_options ?? {}) as Record<string, unknown>;
  return {
    id: String(row.id),
    hostname: String(row.hostname),
    kind: String(row.kind),
    enabled: Boolean(row.enabled),
    status: String(row.status),
    accessMode: String(row.access_mode),
    bypassPaths: Array.isArray(row.bypass_paths) ? (row.bypass_paths as string[]) : [],
    allowedOrigins: Array.isArray(options.allowedOrigins)
      ? (options.allowedOrigins as unknown[]).filter((item): item is string => typeof item === "string")
      : [],
  };
}

function servable(route: GateRoute | null, host: string | null | undefined): route is GateRoute {
  return Boolean(
    route && route.kind === "http" && route.accessMode === "sso" && route.enabled && route.hostname === host,
  );
}

/** The public login origin's hostname, or null when the gate is disabled. */
export async function gateLoginHostname() {
  const [row] = await sql`
    SELECT gate_login_mode, gate_login_hostname FROM platform_settings WHERE id = 'default'
  `;
  return row?.gate_login_mode === "public" && row.gate_login_hostname
    ? String(row.gate_login_hostname)
    : null;
}

/** Whether the user is on the route's access list (individual users only, R11). */
export async function userAllowedOnRoute(routeId: string, userId: string) {
  const [row] = await sql`
    SELECT 1 FROM front_route_access WHERE route_id = ${routeId} AND user_id = ${userId}
  `;
  return Boolean(row);
}

function cookie(name: string, value: string, maxAgeSeconds: number) {
  return `${name}=${value}; Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

export function clearCookie(name: string) {
  return `${name}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

type LiveSession = {
  id: string;
  userId: string;
  email: string;
  lastSeenAt: Date | null;
};

/**
 * The live gate session for a token on a route: not revoked, within its absolute and idle lifetime,
 * its parent login session alive and minted on the login origin, the user still on the access list
 * and with MFA assurance.
 */
async function liveSession(token: string, routeId: string): Promise<LiveSession | null> {
  const [row] = await sql`
    SELECT gs.id, gs.user_id, gs.last_seen_at, u.email, u.two_factor_enabled, u.mfa_enrolled_at,
      s.created_at AS session_created_at
    FROM gate_sessions gs
    JOIN session s ON s.id = gs.auth_session_id AND s.user_id = gs.user_id
    JOIN "user" u ON u.id = gs.user_id
    JOIN front_route_access a ON a.route_id = gs.route_id AND a.user_id = gs.user_id
    WHERE gs.token_hash = ${sha256Hex(token)}
      AND gs.route_id = ${routeId}
      AND gs.revoked_at IS NULL
      AND gs.expires_at > now()
      AND coalesce(gs.last_seen_at, gs.created_at) > now() - ${`${GATE_SESSION_IDLE_MS / 1000} seconds`}::interval
      AND s.expires_at > now()
      AND s.origin = 'gate'
  `;
  if (!row) return null;
  if (
    !hasMfaAssurance({
      twoFactorEnabled: Boolean(row.two_factor_enabled),
      mfaEnrolledAt: row.mfa_enrolled_at ? new Date(row.mfa_enrolled_at as string) : null,
      sessionCreatedAt: new Date(row.session_created_at as string),
    })
  )
    return null;
  return {
    id: String(row.id),
    userId: String(row.user_id),
    email: String(row.email),
    lastSeenAt: row.last_seen_at ? new Date(row.last_seen_at as string) : null,
  };
}

export type GateCheckInput = {
  routeId: string | null;
  host: string | null;
  cookie: string | null;
  /** `X-Forwarded-Method` and `X-Forwarded-Uri` from forward_auth. */
  method: string | null;
  uri: string | null;
  accept: string | null;
  origin: string | null;
  /** `X-Ark-Upgrade` (or `Upgrade`): the original request's upgrade token. */
  upgrade: string | null;
};

/**
 * `GET /api/gate/check` (§3.9.4): 204 with `X-Ark-User` and `X-Ark-Email` for a live session and an
 * acceptable Origin; 403 for a refused Origin or an unknown route; otherwise 302 to the login
 * origin (GET/HEAD for HTML only, with the state cookie) or 401 with `WWW-Authenticate: Ark-Gate`.
 */
export async function gateCheck(input: GateCheckInput): Promise<GateResponse> {
  const route = await loadGateRoute(input.routeId);
  if (!servable(route, input.host)) return respond(403, [], "route not served for this host");
  const method = (input.method ?? "GET").toUpperCase();
  const tokens = parseCookies(input.cookie).get(GATE_COOKIE) ?? [];
  if (tokens.length > 1) return respond(400, [], "duplicate gate cookie");
  const token = checkGateNonce(tokens[0], 40);
  const session = token ? await liveSession(token, route.id) : null;
  if (session) {
    const origin = gateOriginDecision({
      method,
      origin: input.origin,
      upgrade: input.upgrade,
      routeHost: route.hostname,
      allowedOrigins: route.allowedOrigins,
    });
    if (!origin.ok) return respond(403, [], origin.reason);
    if (!session.lastSeenAt || Date.now() - session.lastSeenAt.getTime() > GATE_LAST_SEEN_INTERVAL_MS) {
      await sql`UPDATE gate_sessions SET last_seen_at = now() WHERE id = ${session.id}`;
    }
    return respond(204, [
      ["X-Ark-User", session.userId],
      ["X-Ark-Email", session.email],
    ]);
  }
  const login = await gateLoginHostname();
  if (login && gateWantsRedirect({ method, accept: input.accept, upgrade: input.upgrade })) {
    const state = createToken(16);
    let rd = "/";
    try {
      rd = checkReturnPath(input.uri ?? "/");
    } catch {
      rd = "/";
    }
    const location = new URL(`https://${login}/gate/authorize`);
    location.searchParams.set("route", route.id);
    location.searchParams.set("state", state);
    location.searchParams.set("rd", rd);
    return respond(
      302,
      [
        ["Location", location.toString()],
        ["Set-Cookie", cookie(GATE_STATE_COOKIE, state, GATE_STATE_MAX_AGE_S)],
      ],
      "no session: redirect",
    );
  }
  return respond(401, [["WWW-Authenticate", "Ark-Gate"]], "no session");
}

/**
 * `GET /api/gate/bypass-check` (§3.9.5): 204 only when the unmodified original request target
 * (`X-Ark-Original-Uri`) passes the raw-URI guard and its path is under one of the route's bypass
 * paths, compared case-sensitively; otherwise 400. It grants no session or admin authority.
 */
export async function gateBypassCheck(input: {
  routeId: string | null;
  host: string | null;
  originalUri: string | null;
}): Promise<GateResponse> {
  const route = await loadGateRoute(input.routeId);
  if (!servable(route, input.host)) return respond(400, [], "route not served for this host");
  const checked = checkRawRequestUri(input.originalUri);
  if (!checked.ok) return respond(400, [], checked.reason);
  if (!bypassMatches(checked.path, route.bypassPaths)) return respond(400, [], "not a bypass path");
  return respond(204);
}

export type AuthorizeOutcome =
  | { kind: "redirect"; location: string }
  | { kind: "error"; status: number; message: string };

/**
 * `GET /gate/authorize` (§3.9.2), for a signed-in login-origin session with MFA: the route must be
 * an enabled SSO route and the user on its access list. Mints a handoff code bound to the route,
 * user, parent session and state, and answers with the route-host callback URL.
 */
export async function gateAuthorize(input: {
  routeId: string | null;
  state: string | null;
  rd: string | null;
  session: { id: string; userId: string; createdAt: Date };
  user: { twoFactorEnabled: boolean; mfaEnrolledAt: Date | null };
}): Promise<AuthorizeOutcome> {
  const state = checkGateNonce(input.state);
  if (!state) return { kind: "error", status: 400, message: "The sign-in request is malformed." };
  let rd: string;
  try {
    rd = checkReturnPath(input.rd ?? "/");
  } catch (error) {
    return { kind: "error", status: 400, message: (error as Error).message };
  }
  const route = await loadGateRoute(input.routeId);
  if (!route || route.kind !== "http" || route.accessMode !== "sso" || !route.enabled)
    return { kind: "error", status: 404, message: "This site is not available." };
  if (
    !hasMfaAssurance({
      twoFactorEnabled: input.user.twoFactorEnabled,
      mfaEnrolledAt: input.user.mfaEnrolledAt,
      sessionCreatedAt: input.session.createdAt,
    })
  )
    return {
      kind: "error",
      status: 403,
      message: "Two-factor authentication is required. Sign in again after enrolling an authenticator.",
    };
  if (!(await userAllowedOnRoute(route.id, input.session.userId)))
    return { kind: "error", status: 403, message: "Your account does not have access to this site." };
  const code = createToken(32);
  await sql`
    INSERT INTO gate_handoffs (id, code_hash, route_id, user_id, auth_session_id, state_hash, return_path, expires_at)
    VALUES (${createId("gho")}, ${sha256Hex(code)}, ${route.id}, ${input.session.userId}, ${input.session.id},
      ${sha256Hex(state)}, ${rd}, now() + ${`${GATE_HANDOFF_TTL_MS / 1000} seconds`}::interval)
  `;
  const location = new URL(`https://${route.hostname}/.ark/gate/callback`);
  location.searchParams.set("code", code);
  location.searchParams.set("state", state);
  return { kind: "redirect", location: location.toString() };
}

/**
 * `GET /api/gate/callback` (route host, §3.9.2): consumes the code atomically, then requires the
 * state to equal both the state cookie and the handoff's state, the route header and Host to name
 * the handoff's route, a live parent session, access and MFA. Sets `__Host-ark_gate` and answers
 * 303 to `https://<route host><rd>`. Any failure clears the state cookie and sets no session.
 */
export async function gateCallback(input: {
  host: string | null;
  routeHeader: string | null;
  code: string | null;
  state: string | null;
  cookie: string | null;
  ipAddress: string | null;
  userAgent: string | null;
}): Promise<GateResponse> {
  const fail = (status: number, reason: string) =>
    respond(
      status,
      [
        ["Set-Cookie", clearCookie(GATE_STATE_COOKIE)],
        ["Referrer-Policy", "no-referrer"],
      ],
      reason,
    );
  const code = checkGateNonce(input.code, 40);
  const state = checkGateNonce(input.state);
  if (!code || !state) return fail(400, "malformed code or state");
  const stateCookies = parseCookies(input.cookie).get(GATE_STATE_COOKIE) ?? [];
  if (stateCookies.length !== 1 || !secureEqual(stateCookies[0]!, state))
    return fail(400, "state cookie missing or different");
  const [handoff] = await sql`
    UPDATE gate_handoffs SET consumed_at = now()
    WHERE code_hash = ${sha256Hex(code)} AND consumed_at IS NULL AND expires_at > now()
    RETURNING route_id, user_id, auth_session_id, state_hash, return_path
  `;
  if (!handoff) return fail(400, "code unknown, used or expired");
  if (!secureEqual(String(handoff.state_hash), sha256Hex(state))) return fail(400, "state mismatch");
  const route = await loadGateRoute(String(handoff.route_id));
  if (input.routeHeader !== String(handoff.route_id) || !servable(route, input.host))
    return fail(400, "code presented on another route");
  const [parent] = await sql`
    SELECT s.id, s.expires_at, s.created_at, u.two_factor_enabled, u.mfa_enrolled_at
    FROM session s JOIN "user" u ON u.id = s.user_id
    WHERE s.id = ${String(handoff.auth_session_id)} AND s.user_id = ${String(handoff.user_id)}
      AND s.origin = 'gate' AND s.expires_at > now()
  `;
  if (!parent) return fail(403, "parent session ended");
  if (
    !hasMfaAssurance({
      twoFactorEnabled: Boolean(parent.two_factor_enabled),
      mfaEnrolledAt: parent.mfa_enrolled_at ? new Date(parent.mfa_enrolled_at as string) : null,
      sessionCreatedAt: new Date(parent.created_at as string),
    })
  )
    return fail(403, "no MFA assurance");
  if (!(await userAllowedOnRoute(route.id, String(handoff.user_id)))) return fail(403, "access removed");
  const token = createToken(32);
  const expiresAt = new Date(
    Math.min(Date.now() + GATE_SESSION_ABSOLUTE_MS, new Date(parent.expires_at as string).getTime()),
  );
  await sql`
    INSERT INTO gate_sessions (id, token_hash, route_id, user_id, auth_session_id, ip_address, user_agent, expires_at)
    VALUES (${createId("gss")}, ${sha256Hex(token)}, ${route.id}, ${String(handoff.user_id)},
      ${String(handoff.auth_session_id)}, ${input.ipAddress}, ${input.userAgent?.slice(0, 512) ?? null},
      ${expiresAt.toISOString()}::timestamptz)
  `;
  return respond(303, [
    ["Location", `https://${route.hostname}${checkReturnPath(String(handoff.return_path))}`],
    ["Set-Cookie", cookie(GATE_COOKIE, token, (expiresAt.getTime() - Date.now()) / 1000)],
    ["Set-Cookie", clearCookie(GATE_STATE_COOKIE)],
    ["Referrer-Policy", "no-referrer"],
  ]);
}

/**
 * `POST /api/gate/logout-route` (route host, §3.9.3): with an Origin exactly equal to the route
 * origin, revokes this browser's gate session for the route (the revocation trigger queues the
 * forced reload) and clears the cookie.
 */
export async function gateLogoutRoute(input: {
  host: string | null;
  routeHeader: string | null;
  origin: string | null;
  cookie: string | null;
}): Promise<GateResponse> {
  const route = await loadGateRoute(input.routeHeader);
  if (!route || route.hostname !== input.host || route.kind !== "http")
    return respond(400, [], "route not served for this host");
  if (input.origin !== `https://${route.hostname}`) return respond(403, [], "origin is not the route");
  const tokens = parseCookies(input.cookie).get(GATE_COOKIE) ?? [];
  for (const token of tokens) {
    if (!checkGateNonce(token, 40)) continue;
    await sql.begin(async (tx) => {
      await tx`SELECT set_config('ark.gate_revocation_reason', 'route_logout', true)`;
      await tx`
        UPDATE gate_sessions SET revoked_at = now()
        WHERE token_hash = ${sha256Hex(token)} AND route_id = ${route.id} AND revoked_at IS NULL
      `;
    });
  }
  return {
    ...respond(200, [
      ["Set-Cookie", clearCookie(GATE_COOKIE)],
      ["Content-Type", "text/html; charset=utf-8"],
    ]),
    body: "<!doctype html><title>Signed out</title><p>You are signed out of this site.</p>",
  };
}

// ---- Access lists (R11: individual users only) --------------------------------------------------------

export async function listRouteAccess(routeId: string) {
  const rows = await sql`
    SELECT a.user_id, u.email, u.name, a.granted_by, a.created_at
    FROM front_route_access a JOIN "user" u ON u.id = a.user_id
    WHERE a.route_id = ${routeId}
    ORDER BY u.email
  `;
  return rows.map((row) => ({
    userId: String(row.user_id),
    email: String(row.email),
    name: String(row.name),
    grantedBy: row.granted_by ? String(row.granted_by) : null,
    createdAt: new Date(row.created_at as string).toISOString(),
  }));
}

export class RouteAccessError extends Error {
  constructor(
    readonly status: 404 | 422,
    message: string,
  ) {
    super(message);
    this.name = "RouteAccessError";
  }
}

/**
 * Replaces a route's access list in one transaction. Removals revoke the users' gate sessions on the
 * route and queue the forced-reload drain atomically (migration 0026 triggers, §3.9.3).
 */
export async function replaceRouteAccess(
  routeId: string,
  userIds: string[],
  actor: { userId: string; role: string },
  authorize?: (tx: DbTransaction) => Promise<unknown>,
) {
  const wanted = [...new Set(userIds)];
  return db.transaction(async (tx) => {
    const [route] = await tx.execute(
      statement`SELECT id, kind FROM front_routes WHERE id = ${routeId} FOR UPDATE`,
    );
    if (!route) throw new RouteAccessError(404, "Route not found.");
    if (route.kind !== "http") throw new RouteAccessError(422, "Access lists apply to HTTP routes only.");
    if (wanted.length) {
      const found = await tx.execute(
        statement`SELECT id FROM "user" WHERE id IN (SELECT jsonb_array_elements_text(${JSON.stringify(wanted)}::jsonb))`,
      );
      const known = new Set(found.map((row) => String(row.id)));
      const missing = wanted.filter((id) => !known.has(id));
      if (missing.length) throw new RouteAccessError(422, `Unknown user(s): ${missing.join(", ")}.`);
    }
    await authorize?.(tx);
    const current = await tx.execute(
      statement`SELECT user_id FROM front_route_access WHERE route_id = ${routeId}`,
    );
    const before = current.map((row) => String(row.user_id));
    const removed = before.filter((id) => !wanted.includes(id));
    const added = wanted.filter((id) => !before.includes(id));
    if (removed.length) {
      await tx.execute(statement`SELECT set_config('ark.gate_revocation_reason', 'access_removed', true)`);
      await tx.execute(
        statement`DELETE FROM front_route_access WHERE route_id = ${routeId} AND user_id IN (SELECT jsonb_array_elements_text(${JSON.stringify(removed)}::jsonb))`,
      );
    }
    for (const userId of added) {
      await tx.execute(
        statement`INSERT INTO front_route_access (route_id, user_id, granted_by) VALUES (${routeId}, ${userId}, ${actor.userId})`,
      );
    }
    await tx.execute(statement`
      INSERT INTO audit_events (id, actor_id, role, action, resource_type, resource_id, detail)
      VALUES (${createId("aud")}, ${actor.userId}, ${actor.role}, 'front_route.access', 'front_route', ${routeId},
        ${JSON.stringify({ added, removed })}::jsonb)
    `);
    return { added, removed };
  });
}
