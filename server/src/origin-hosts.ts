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

/** Serializes forced reads after in-flight reads; failed reads clear gate trust and are retriable. */
export function createLoginHostCache(load: () => Promise<string | null>, now = Date.now) {
  let host: string | null = null;
  let loadedAt: number | null = null;
  let pending: Promise<string | null> | null = null;
  return {
    current: () => host,
    refresh(force = false): Promise<string | null> {
      if (!force && pending) return pending;
      if (!force && loadedAt !== null && now() - loadedAt < 5_000) return Promise.resolve(host);
      const previous = pending;
      const read = async () => {
        // A forced refresh must read again after an older read, even if that read failed.
        await previous?.catch(() => undefined);
        try {
          const value = canonicalHost(await load());
          host = value && !adminHosts.has(value) ? value : null;
          loadedAt = now();
          return host;
        } catch (error) {
          host = null;
          loadedAt = null;
          throw error;
        }
      };
      const request = read().finally(() => {
        if (pending === request) pending = null;
      });
      pending = request;
      return request;
    },
  };
}

const loginHosts = createLoginHostCache(async () => {
  const [settings] = await db
    .select({ mode: platformSettings.gateLoginMode, hostname: platformSettings.gateLoginHostname })
    .from(platformSettings)
    .where(eq(platformSettings.id, "default"));
  return settings?.mode === "public" ? settings.hostname : null;
});

/** Re-reads the login origin (at most every 5 s unless forced); errors fail closed. */
export const refreshLoginHost = (force = false) => loginHosts.refresh(force);

/** The login host as last loaded; refreshed before requests that need it. */
export const currentLoginHost = () => loginHosts.current();

export function isAdminHost(host: string | null | undefined) {
  return Boolean(host && adminHosts.has(host));
}

/** Positive match only: the origin a canonical host belongs to, or null for any other host. */
export function originForHost(host: string | null | undefined): SessionOrigin | null {
  if (!host) return null;
  if (currentLoginHost() && host === currentLoginHost()) return "gate";
  if (adminHosts.has(host)) return "admin";
  return null;
}

/** The origin of a request, from its canonical host; null when malformed, contradictory or unknown. */
export function originForRequest(request: Request) {
  return originForHost(requestHost(request));
}

/** Better Auth's `allowedHosts`: every admin host and the current login host. */
export function registeredHosts() {
  return [...adminHosts, ...(currentLoginHost() ? [currentLoginHost()!] : [])];
}
