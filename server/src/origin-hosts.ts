// Registered login origins (docs/design/front-door.md §3.9.1, FD-10).
//
// The API answers authentication and session-bearing requests only for hosts it can name:
//
// - **admin**: the host of `BETTER_AUTH_URL` and of every `BETTER_AUTH_TRUSTED_ORIGINS` entry (the
//   tailnet or public admin origin, plus the operator's local bootstrap and development origins);
// - **gate**: `platform_settings.gate_login_hostname` while `gate_login_mode = 'public'`.
//
// A request whose canonical Host is neither is refused before Better Auth sees it. There is no
// fallback to the admin origin: Better Auth's dynamic `baseURL` gets exactly these hosts as
// `allowedHosts` and no `fallback`, and session origin is derived only by a positive match.

import { eq } from "drizzle-orm";

import { db } from "./db.ts";
import { loadEnv } from "./env.ts";
import { platformSettings } from "./schema.ts";
import type { SessionOrigin } from "./session-origin.ts";

const env = loadEnv();

// A DNS name (letters, digits, hyphens), a dotted quad or a bracketed IPv6 literal, with an optional
// port. Anything else (spaces, userinfo, a trailing dot, percent-encoding) is malformed.
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const HOST = new RegExp(
  `^(?:${LABEL}(?:\\.${LABEL})*|\\d{1,3}(?:\\.\\d{1,3}){3}|\\[[0-9a-f:.]+\\])(?::(\\d{1,5}))?$`,
);

/** The lower-case `host[:port]`, or null when the value is not a well-formed authority. */
export function canonicalHost(value: string | null | undefined) {
  if (!value || value.length > 260) return null;
  const host = value.toLowerCase();
  const match = HOST.exec(host);
  if (!match) return null;
  if (match[1] !== undefined && (Number(match[1]) < 1 || Number(match[1]) > 65_535)) return null;
  return host;
}

/**
 * The canonical host of a request: the `Host` header, which must agree with the request URL's
 * authority. A malformed Host, or one that contradicts the URL, gives null. Without a Host header
 * (an in-process request) the URL authority is used.
 */
export function requestHost(request: Request) {
  let urlHost: string;
  try {
    urlHost = new URL(request.url).host;
  } catch {
    return null;
  }
  const fromUrl = canonicalHost(urlHost);
  const header = request.headers.get("host");
  if (header === null) return fromUrl;
  const fromHeader = canonicalHost(header);
  if (!fromHeader || fromHeader !== fromUrl) return null;
  return fromHeader;
}

function hostOf(origin: string) {
  try {
    return canonicalHost(new URL(origin).host);
  } catch {
    return null;
  }
}

const adminHosts = new Set(
  [env.authUrl, ...env.trustedOrigins].map(hostOf).filter((host): host is string => Boolean(host)),
);

const LOGIN_HOST_TTL_MS = 5_000;
let loginHost: string | null = null;
let loadedAt = 0;

/** Re-reads the login origin from `platform_settings` (at most every 5 s unless forced). */
export async function refreshLoginHost(force = false) {
  if (!force && Date.now() - loadedAt < LOGIN_HOST_TTL_MS) return loginHost;
  const [settings] = await db
    .select({ mode: platformSettings.gateLoginMode, hostname: platformSettings.gateLoginHostname })
    .from(platformSettings)
    .where(eq(platformSettings.id, "default"));
  const host = settings?.mode === "public" ? canonicalHost(settings.hostname) : null;
  // A host is never both origins. `PUT /api/settings/gate` refuses this; a hand-edited row too.
  loginHost = host && !adminHosts.has(host) ? host : null;
  loadedAt = Date.now();
  return loginHost;
}

/** The login host as last loaded; `refreshLoginHost` runs before every request that needs it. */
export function currentLoginHost() {
  return loginHost;
}

export function isAdminHost(host: string | null | undefined) {
  return Boolean(host && adminHosts.has(host));
}

/** Positive match only: the origin a canonical host belongs to, or null for any other host. */
export function originForHost(host: string | null | undefined): SessionOrigin | null {
  if (!host) return null;
  if (loginHost && host === loginHost) return "gate";
  if (adminHosts.has(host)) return "admin";
  return null;
}

/** The origin of a request, from its canonical host; null when malformed, contradictory or unknown. */
export function originForRequest(request: Request) {
  return originForHost(requestHost(request));
}

/** Better Auth's `allowedHosts`: every admin host and the current login host. */
export function registeredHosts() {
  return [...adminHosts, ...(loginHost ? [loginHost] : [])];
}
