// The public gate login origin (docs/design/front-door.md §3.5, §3.9.1, FD-10).
//
// `https://login.<base-domain>` is served by the public edge behind the HAProxy SNI router. It exposes
// only the Better Auth sign-in, sign-out, get-session and two-factor endpoints listed here, plus the
// gate pages under `/gate/`. The edge renders exactly this list (`renderCaddyfile`), and the API
// refuses every other path on the login host with 404 as a second, independent layer.

import { z } from "zod";

/**
 * Better Auth endpoints the login origin forwards, as exact paths. The edge adds `X-Ark-Edge-Token`
 * only on these requests on the login origin. Admin paths are listed separately below.
 */
export const GATE_LOGIN_AUTH_PATHS = [
  "/api/auth/sign-in/email",
  "/api/auth/sign-out",
  "/api/auth/get-session",
  "/api/auth/two-factor/verify-totp",
  "/api/auth/two-factor/verify-backup-code",
  "/api/auth/two-factor/enable",
  "/api/auth/two-factor/get-totp-uri",
] as const;

/** Exact admin auth paths that receive a proxy-authenticated client address, including MFA management. */
export const ADMIN_CLIENT_IP_AUTH_PATHS = [
  ...GATE_LOGIN_AUTH_PATHS,
  "/api/auth/two-factor/disable",
  "/api/auth/two-factor/generate-backup-codes",
] as const;

/** Gate pages (`/gate/login`, `/gate/authorize`, `/gate/logout`, FD-11), forwarded without the token. */
export const GATE_LOGIN_PAGES_PREFIX = "/gate/";

/**
 * The enrollment-only endpoints (§3.9.1). On the login origin they are allowed only for a `gate`
 * session whose user has not enrolled TOTP yet; anything else gets 403 before Better Auth runs.
 * Paths are relative to Better Auth's `/api/auth` base path.
 */
export const GATE_ENROLLMENT_AUTH_PATHS = ["/two-factor/enable", "/two-factor/get-totp-uri"] as const;

export function isGateLoginAuthPath(path: string) {
  return (GATE_LOGIN_AUTH_PATHS as readonly string[]).includes(path);
}

/** Whether a raw request path is on the login-origin allowlist. Exact, case-sensitive comparison. */
export function isGateLoginPath(path: string) {
  // Same set as the edge's `path /gate/*` matcher, which also matches `/gate/` itself.
  return isGateLoginAuthPath(path) || path.startsWith(GATE_LOGIN_PAGES_PREFIX);
}

/** R1: the login origin is public or off. A tailnet-only login mode is not offered. */
export const gateLoginModes = ["disabled", "public"] as const;
export type GateLoginMode = (typeof gateLoginModes)[number];

/** `PUT /api/settings/gate`. The hostname is normalized and checked against domain claims server-side. */
export const gateSettingsInput = z
  .object({
    mode: z.enum(gateLoginModes),
    hostname: z.string().min(1).max(253).nullable().optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.mode === "public" && !value.hostname) {
      ctx.addIssue({
        code: "custom",
        path: ["hostname"],
        message: "A public login origin needs a hostname.",
      });
    }
    if (value.mode === "disabled" && value.hostname) {
      ctx.addIssue({
        code: "custom",
        path: ["hostname"],
        message: "Leave the hostname empty when the login origin is disabled.",
      });
    }
  });

export type GateSettingsInput = z.output<typeof gateSettingsInput>;
