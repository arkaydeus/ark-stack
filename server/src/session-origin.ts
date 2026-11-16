// `session.origin` (front door §3.1, §3.9.1) records which login origin minted a Better Auth
// session. The column has no SQL default, so every insert path must name the origin.

export const sessionOrigins = ["admin", "gate"] as const;
export type SessionOrigin = (typeof sessionOrigins)[number];

export function isSessionOrigin(value: unknown): value is SessionOrigin {
  return typeof value === "string" && (sessionOrigins as readonly string[]).includes(value);
}

/**
 * Decides the origin for a new session in the Better Auth `session.create.before` hook.
 *
 * - An origin set by Ark's own server-side code (an internal-adapter override) is kept.
 * - A session minted while serving an HTTP request is an `admin` session: until the gate login
 *   origin exists (FD-10), every sign-in host is the admin origin.
 * - Anything else has no provenance (no request, no explicit origin) and is refused rather than
 *   guessed from absent headers.
 */
export function resolveSessionOrigin(
  data: Record<string, unknown>,
  context: { request?: Request | null } | null | undefined,
): SessionOrigin {
  if (data.origin !== undefined && data.origin !== null) {
    if (isSessionOrigin(data.origin)) return data.origin;
    throw new Error(`Refusing to create a session with unknown origin ${JSON.stringify(data.origin)}.`);
  }
  if (context?.request) return "admin";
  throw new Error("Refusing to create a session without a request or an explicit origin.");
}
