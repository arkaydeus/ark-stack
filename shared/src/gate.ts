// The login gate for `access_mode: sso` HTTP routes (docs/design/front-door.md §3.9, FD-11).
//
// Pure policy shared by the API, the edge renderer and the tests:
// - the names, paths and lifetimes of the handshake (§3.9.2, §3.9.3);
// - `rd` and `next` validation (no open redirect);
// - the raw-request-URI bypass guard and bypass-path validation (§3.9.5);
// - the browser WebSocket Origin and unsafe-method CSRF contract (§3.9.4);
// - the revocation deadline and the stream lifetime it bounds (§3.9.3).

import { z } from "zod";

import { ValidationError } from "./errors.ts";
import { normalizeHostname } from "./hostnames.ts";

/** The route-host gate session cookie (`__Host-`: Secure, Path=/, no Domain). */
export const GATE_COOKIE = "__Host-ark_gate";
/** Prefix for per-flow, one-time state cookies on the route host. */
export const GATE_STATE_COOKIE = "__Host-ark_gate_state";
export const gateStateCookieName = (state: string) => `${GATE_STATE_COOKIE}_${state}`;

/** Public route-host paths. Only these two reach the API; every other `/.ark/gate/*` is 404. */
export const GATE_CALLBACK_PATH = "/.ark/gate/callback";
export const GATE_LOGOUT_PATH = "/.ark/gate/logout";
export const GATE_RESERVED_PREFIX = "/.ark/gate/";

/**
 * The API handlers the edge calls with `X-Ark-Edge-Token`. They are on no public or tailnet path
 * allowlist; the exact route-host rewrites above are the only public exposure of the last two.
 */
export const GATE_CHECK_API = "/api/gate/check";
export const GATE_BYPASS_CHECK_API = "/api/gate/bypass-check";
export const GATE_CALLBACK_API = "/api/gate/callback";
export const GATE_LOGOUT_ROUTE_API = "/api/gate/logout-route";
export const GATE_EDGE_API_PATHS = [
  GATE_CHECK_API,
  GATE_BYPASS_CHECK_API,
  GATE_CALLBACK_API,
  GATE_LOGOUT_ROUTE_API,
] as const;

/** Login-origin pages (§3.3). */
export const GATE_LOGIN_PAGE = "/gate/login";
export const GATE_AUTHORIZE_PAGE = "/gate/authorize";
export const GATE_LOGOUT_PAGE = "/gate/logout";

/** Handoff codes live 60 s and are single-use (§3.9.3). */
export const GATE_HANDOFF_TTL_MS = 60_000;
/** The state cookie outlives a slow sign-in, not a day. */
export const GATE_STATE_MAX_AGE_S = 600;
/** Gate sessions: absolute 12 h, idle 2 h, never longer than the parent login session. */
export const GATE_SESSION_ABSOLUTE_MS = 12 * 3_600_000;
export const GATE_SESSION_IDLE_MS = 2 * 3_600_000;
/** `last_seen_at` is written at most once a minute. */
export const GATE_LAST_SEEN_INTERVAL_MS = 60_000;

/**
 * A revocation's forced Caddy reload must begin within 5 s of the event; after that the edge-local
 * watchdog withdraws the route (fail closed) and a critical alert is raised (§3.9.3).
 */
export const GATE_REVOCATION_DEADLINE_MS = 5_000;
/**
 * Upgraded connections close at most this long after the reload (the old handler's
 * `stream_close_delay`), so every open socket is gone by revocation + 305 s.
 */
export const GATE_MAX_STREAM_CLOSE_DELAY_MS = 300_000;

export const GATE_RD_MAX_BYTES = 2048;

/** Whether a string contains an ASCII control character (U+0000-U+001F or U+007F). */
const CONTROL = {
  test: (value: string) =>
    [...value].some((char) => char.charCodeAt(0) < 0x20 || char.charCodeAt(0) === 0x7f),
};

/**
 * Validates the `rd` return path (§3.9.3, "No open redirect"). The value is the query parameter as
 * decoded once by the URL parser and is never decoded again. It must be a path on the route host:
 * it starts with `/`, not `//` or `/\`, has no backslash or control character, and is at most 2048
 * bytes. The final redirect is `https://<route host><rd>`.
 */
export function checkReturnPath(rd: unknown): string {
  if (typeof rd !== "string" || !rd.startsWith("/"))
    throw new ValidationError("The return path must start with /.");
  if (rd.startsWith("//")) throw new ValidationError("The return path must not start with //.");
  if (rd.includes("\\")) throw new ValidationError("The return path must not contain a backslash.");
  if (CONTROL.test(rd)) throw new ValidationError("The return path must not contain control characters.");
  if (Buffer.byteLength(rd, "utf8") > GATE_RD_MAX_BYTES)
    throw new ValidationError(`The return path is longer than ${GATE_RD_MAX_BYTES} bytes.`);
  return rd;
}

/** The login page's `next`: only a relative `/gate/authorize?…` path, or nothing. */
export function checkLoginNext(next: unknown): string | null {
  if (typeof next !== "string") return null;
  if (!next.startsWith(`${GATE_AUTHORIZE_PAGE}?`)) return null;
  if (next.includes("\\") || CONTROL.test(next) || next.length > 4096) return null;
  return next;
}

/** A handshake state or code: base64url only, of the expected size. */
export function checkGateNonce(value: unknown, minChars = 22): string | null {
  return typeof value === "string" && value.length >= minChars && /^[A-Za-z0-9_-]{1,128}$/.test(value)
    ? value
    : null;
}

export const ROUTE_ID_PATTERN = /^rt_[a-z0-9]+$/;

// ---- Bypass paths (§3.9.5) ---------------------------------------------------------------------------------

const BYPASS_PATH = /^\/[A-Za-z0-9._~\-/]*\*?$/;
export const GATE_MAX_BYPASS_PATHS = 32;

/**
 * Validates a route's bypass paths: path prefixes (`/webhooks/*`) or exact paths (`/hook`) that
 * skip the gate. Refused: anything outside `^/[A-Za-z0-9._~\-/]*\*?$`, dot segments, `/` and `/*`
 * (that is what `access_mode: public` is for), and anything that could match a path under
 * `/.ark/gate/`, which the gate's own handlers own.
 */
export function checkBypassPaths(paths: unknown): string[] {
  if (!Array.isArray(paths)) throw new ValidationError("Bypass paths must be a list.");
  if (paths.length > GATE_MAX_BYPASS_PATHS)
    throw new ValidationError(`At most ${GATE_MAX_BYPASS_PATHS} bypass paths are allowed.`);
  const result: string[] = [];
  for (const path of paths) {
    if (typeof path !== "string" || path.length > 256 || !BYPASS_PATH.test(path))
      throw new ValidationError(`Bypass path ${JSON.stringify(path)} is invalid.`);
    const prefix = path.endsWith("*") ? path.slice(0, -1) : path;
    const segments = prefix.split("/");
    if (segments.includes("..") || segments.includes("."))
      throw new ValidationError(`Bypass path ${JSON.stringify(path)} has a dot segment.`);
    if (prefix === "/" || prefix === "")
      throw new ValidationError(
        `Bypass path ${JSON.stringify(path)} would bypass the whole site; use access mode "public" instead.`,
      );
    const wildcard = path.endsWith("*");
    const reserved = "/.ark/gate/";
    if (
      prefix.startsWith("/.ark") ||
      (wildcard && (reserved.startsWith(prefix) || `${reserved}callback`.startsWith(prefix)))
    )
      throw new ValidationError(`Bypass path ${JSON.stringify(path)} would shadow /.ark/gate/*.`);
    if (!result.includes(path)) result.push(path);
  }
  return result;
}

/** Whether a decoded request path is covered by a bypass path (case-sensitive prefix or exact). */
export function bypassMatches(path: string, bypassPaths: readonly string[]) {
  return bypassPaths.some((bypass) =>
    bypass.endsWith("*") ? path.startsWith(bypass.slice(0, -1)) : path === bypass,
  );
}

/**
 * The mandatory raw-request-URI guard (§3.9.5). It examines the original request target, not
 * Caddy's cleaned path, and refuses (400) anything an upstream could normalise differently:
 * dot segments, empty inner segments, semicolons, backslashes, percent-encoded dots, slashes and
 * backslashes (any case), nested encodings (`%25`), malformed encodings, and anything that is not
 * printable ASCII. The query string is passed through, but must be printable ASCII with well-formed
 * encodings. On success it returns the path decoded exactly once.
 */
export function checkRawRequestUri(uri: unknown): { ok: true; path: string } | { ok: false; reason: string } {
  if (typeof uri !== "string" || !uri.startsWith("/")) return { ok: false, reason: "not origin-form" };
  if (uri.length > 8192) return { ok: false, reason: "too long" };
  if (!/^[\x21-\x7e]*$/.test(uri)) return { ok: false, reason: "non-printable or non-ASCII character" };
  const queryAt = uri.indexOf("?");
  const rawPath = queryAt === -1 ? uri : uri.slice(0, queryAt);
  const query = queryAt === -1 ? "" : uri.slice(queryAt + 1);
  if (uri.includes("#")) return { ok: false, reason: "fragment in request target" };
  for (const [part, value] of [
    ["path", rawPath],
    ["query", query],
  ] as const) {
    for (let index = value.indexOf("%"); index !== -1; index = value.indexOf("%", index + 1)) {
      if (!/^[0-9a-f]{2}$/i.test(value.slice(index + 1, index + 3)))
        return { ok: false, reason: `malformed percent-encoding in the ${part}` };
    }
  }
  if (rawPath.includes("\\")) return { ok: false, reason: "backslash" };
  if (rawPath.includes(";")) return { ok: false, reason: "semicolon" };
  if (/%(?:2e|2f|5c|25)/i.test(rawPath))
    return { ok: false, reason: "encoded dot, slash, backslash or percent" };
  const segments = rawPath.split("/").slice(1);
  for (const [index, segment] of segments.entries()) {
    if (segment === "." || segment === "..") return { ok: false, reason: "dot segment" };
    if (segment === "" && index < segments.length - 1) return { ok: false, reason: "empty segment" };
  }
  let path: string;
  try {
    path = decodeURIComponent(rawPath);
  } catch {
    return { ok: false, reason: "undecodable path" };
  }
  if (path.includes(";")) return { ok: false, reason: "encoded semicolon" };
  if (CONTROL.test(path)) return { ok: false, reason: "encoded control character" };
  return { ok: true, path };
}

// ---- Origins and CSRF (§3.9.4) ---------------------------------------------------------------------------

export const GATE_MAX_ALLOWED_ORIGINS = 16;

/** Normalises one owner-approved origin exception: `https://host[:port]`, nothing else. */
export function normalizeGateOrigin(value: unknown): string {
  if (typeof value !== "string") throw new ValidationError("An allowed origin must be a string.");
  const match = /^https:\/\/([^/?#:@\s]+)(?::(\d{1,5}))?$/i.exec(value.trim());
  if (!match)
    throw new ValidationError(`Allowed origin ${JSON.stringify(value)} must be https://host[:port].`);
  let host: string;
  try {
    host = normalizeHostname(match[1]!);
  } catch (error) {
    throw new ValidationError(`Allowed origin ${JSON.stringify(value)}: ${(error as Error).message}`);
  }
  const port = match[2] ? Number(match[2]) : 443;
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new ValidationError(`Allowed origin ${JSON.stringify(value)} has an invalid port.`);
  return port === 443 ? `https://${host}` : `https://${host}:${port}`;
}

export function checkAllowedOrigins(origins: unknown): string[] {
  if (!Array.isArray(origins)) throw new ValidationError("Allowed origins must be a list.");
  if (origins.length > GATE_MAX_ALLOWED_ORIGINS)
    throw new ValidationError(`At most ${GATE_MAX_ALLOWED_ORIGINS} allowed origins are allowed.`);
  return [...new Set(origins.map(normalizeGateOrigin))];
}

/** Methods that must be read-only at the upstream; every other method is unsafe for CSRF purposes. */
export const SAFE_METHODS = ["GET", "HEAD", "OPTIONS"] as const;

export function isUpgradeRequest(upgrade: string | null | undefined) {
  return Boolean(upgrade && upgrade.trim() !== "");
}

/**
 * The browser contract for an authenticated request (§3.9.4). A cookie-authenticated WebSocket
 * upgrade or unsafe method needs an Origin that is exactly `https://<route hostname>` or one of the
 * owner-approved exceptions. Missing, `null`, suffix and sibling origins are refused; there is no
 * browser bypass for an absent Origin. Safe, non-upgrade requests need no Origin.
 */
export function gateOriginDecision(input: {
  method: string;
  origin: string | null | undefined;
  upgrade?: string | null;
  routeHost: string;
  allowedOrigins?: readonly string[];
}): { ok: true } | { ok: false; reason: string } {
  const method = input.method.toUpperCase();
  const upgrade = isUpgradeRequest(input.upgrade);
  if (!upgrade && (SAFE_METHODS as readonly string[]).includes(method)) return { ok: true };
  const what = upgrade ? "A WebSocket upgrade" : `A ${method} request`;
  const origin = input.origin?.trim();
  if (!origin) return { ok: false, reason: `${what} needs an Origin header.` };
  if (origin === "null") return { ok: false, reason: `${what} from an opaque (null) origin is refused.` };
  if (origin.toLowerCase() === `https://${input.routeHost}`) return { ok: true };
  if ((input.allowedOrigins ?? []).includes(origin.toLowerCase())) return { ok: true };
  return { ok: false, reason: `${what} from ${origin} is refused.` };
}

/** Whether an unauthenticated request should be redirected to sign in (GET/HEAD for HTML only). */
export function gateWantsRedirect(input: {
  method: string;
  accept: string | null | undefined;
  upgrade?: string | null;
}) {
  const method = input.method.toUpperCase();
  return (
    (method === "GET" || method === "HEAD") &&
    !isUpgradeRequest(input.upgrade) &&
    /(^|,)\s*text\/html\s*(;|,|$)/i.test(input.accept ?? "")
  );
}

/** Every value of every cookie in a Cookie header, so duplicates can be refused. */
export function parseCookies(header: string | null | undefined) {
  const cookies = new Map<string, string[]>();
  for (const pair of (header ?? "").split(";")) {
    const separator = pair.indexOf("=");
    if (separator === -1) continue;
    const name = pair.slice(0, separator).trim();
    const value = pair.slice(separator + 1).trim();
    if (!name) continue;
    cookies.set(name, [...(cookies.get(name) ?? []), value]);
  }
  return cookies;
}

/** `PUT /api/front/routes/:id/access`: the complete list of allowed users (individual users only, R11). */
export const routeAccessInput = z
  .object({
    userIds: z.array(z.string().min(1).max(200)).max(500),
  })
  .strict();

export type RouteAccessInput = z.infer<typeof routeAccessInput>;

/** One revocation still waiting for its forced reload, as the lease endpoint reports it. */
export type PendingGateRevocation = { id: string; routeId: string; createdAt: string };

/**
 * Applies pending revocations to the allowlist the edge watchdog enforces (§3.9.3). A route whose
 * revocation has not been confirmed by a forced reload within `GATE_REVOCATION_DEADLINE_MS` is
 * withdrawn (fail closed) until the reload succeeds. Within the deadline nothing changes.
 */
export function routesAfterRevocations<T extends { id: string }>(
  routes: readonly T[],
  pending: readonly PendingGateRevocation[],
  now: Date,
) {
  const overdue = new Set(
    pending
      .filter((item) => now.getTime() - Date.parse(item.createdAt) > GATE_REVOCATION_DEADLINE_MS)
      .map((item) => item.routeId),
  );
  return { routes: routes.filter((route) => !overdue.has(route.id)), overdue: [...overdue].toSorted() };
}
