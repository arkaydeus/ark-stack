// `session.origin` (front door §3.1, §3.9.1) records which login origin minted a Better Auth
// session. The column has no SQL default, so every insert path must name the origin.

import { AsyncLocalStorage } from "node:async_hooks";

export const sessionOrigins = ["admin", "gate"] as const;
export type SessionOrigin = (typeof sessionOrigins)[number];

export function isSessionOrigin(value: unknown): value is SessionOrigin {
  return typeof value === "string" && (sessionOrigins as readonly string[]).includes(value);
}

const explicitOrigin = new AsyncLocalStorage<SessionOrigin>();

/**
 * Runs Ark's own server-side Better Auth call with an explicit session origin, for calls that have
 * no request to derive it from (for example FD-12's gate-user creation through `auth.api.*`).
 */
export function withSessionOrigin<T>(origin: SessionOrigin, work: () => Promise<T>) {
  if (!isSessionOrigin(origin)) throw new Error(`Unknown session origin ${JSON.stringify(origin)}.`);
  return explicitOrigin.run(origin, work);
}

/**
 * Decides the origin for a new session in the Better Auth `session.create.before` hook, from every
 * source of positive provenance:
 *
 * - an origin set by Ark's own server-side code (an internal-adapter override, or `withSessionOrigin`);
 * - the host of the HTTP request being served: the login host gives `gate`, an admin host `admin`.
 *   A request for any other host (or a malformed or contradictory one) is refused, never mapped to
 *   the admin origin.
 *
 * The sources must agree. With none (no request and no explicit origin) the creation is refused
 * rather than guessed from absent headers.
 */
export function resolveSessionOrigin(
  data: Record<string, unknown>,
  context: { request?: Request | null } | null | undefined,
  originOfRequest: (request: Request) => SessionOrigin | null,
): SessionOrigin {
  const found: SessionOrigin[] = [];
  if (data.origin !== undefined && data.origin !== null) {
    if (!isSessionOrigin(data.origin)) {
      throw new Error(`Refusing to create a session with unknown origin ${JSON.stringify(data.origin)}.`);
    }
    found.push(data.origin);
  }
  const scoped = explicitOrigin.getStore();
  if (scoped) found.push(scoped);
  if (context?.request) {
    const fromHost = originOfRequest(context.request);
    if (!fromHost) {
      throw new Error("Refusing to create a session for a host that is not a registered login origin.");
    }
    found.push(fromHost);
  }
  if (!found.length) {
    throw new Error("Refusing to create a session without a request or an explicit origin.");
  }
  if (found.some((origin) => origin !== found[0])) {
    throw new Error(`Refusing to create a session with contradictory origins (${found.join(", ")}).`);
  }
  return found[0]!;
}
