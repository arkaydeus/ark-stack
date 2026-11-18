import { betterAuth } from "better-auth/minimal";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { twoFactor as twoFactorPlugin } from "better-auth/plugins";
import { eq } from "drizzle-orm";

import { GATE_ENROLLMENT_AUTH_PATHS } from "@ark-stack/shared";

import { CLIENT_IP_HEADER } from "./client-ip.ts";
import { db } from "./db.ts";
import { loadEnv } from "./env.ts";
import { originForRequest, registeredHosts } from "./origin-hosts.ts";
import { account, gateUsers, session, twoFactor, user, verification } from "./schema.ts";
import { resolveSessionOrigin } from "./session-origin.ts";

const env = loadEnv();
const secure = env.authUrl.startsWith("https://");

/**
 * Every Better Auth cookie Ark can emit: authentication, MFA and auxiliary (front door §3.9.1). Over
 * HTTPS each one is named `__Host-ark_stack.<name>`: the browser then enforces `Secure`, `Path=/` and
 * no `Domain`, so JavaScript on a sibling route can never plant one for the login origin with
 * `Domain=<parent>`. The legacy `__Secure-ark_stack.*` names (which may carry a Domain) are no longer
 * read anywhere. Plain-HTTP development keeps unprefixed names, which browsers refuse over HTTP.
 */
export const AUTH_COOKIE_KEYS = [
  "session_token",
  "session_data",
  "account_data",
  "dont_remember",
  "two_factor",
  "trust_device",
  "oauth_state",
] as const;
const COOKIE_PREFIX = secure ? "__Host-ark_stack" : "ark_stack";
export const authCookieName = (key: (typeof AUTH_COOKIE_KEYS)[number]) => `${COOKIE_PREFIX}.${key}`;
const cookies = Object.fromEntries(
  AUTH_COOKIE_KEYS.map((key) => [
    key,
    { name: authCookieName(key), attributes: { secure, path: "/", domain: undefined } },
  ]),
);

/**
 * Dynamic base URL (Better Auth 1.7.25, front door §3.9.1). `allowedHosts` is read on every request
 * and is exactly the registered admin hosts plus the current login host. There is no `fallback`, so
 * Better Auth itself refuses a third host; `trustedProxyHeaders` stays off, so `X-Forwarded-Host` and
 * `X-Forwarded-Proto` are ignored. The app refuses unknown hosts before Better Auth runs anyway.
 */
export const authBaseURL = {
  get allowedHosts() {
    return registeredHosts();
  },
  protocol: secure ? ("https" as const) : ("http" as const),
};

/** The two-factor rate-limit rule, also applied to sign-in: 5 attempts per minute per client IP. */
export const AUTH_ATTEMPT_LIMIT = { window: 60, max: 5 };

export const auth = betterAuth({
  appName: "Ark Stack",
  baseURL: authBaseURL,
  secret: env.authSecret,
  database: drizzleAdapter(db, {
    provider: "pg",
    schema: { user, session, account, verification, twoFactor },
  }),
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 12,
  },
  user: {
    additionalFields: {
      mfaEnrolledAt: {
        type: "date",
        required: false,
        input: false,
      },
    },
  },
  session: {
    additionalFields: {
      // Server-authored: browser payloads can never choose it (§3.1). No SQL default exists, so
      // the session create hook below must set it on every insert.
      origin: {
        type: "string",
        required: true,
        input: false,
      },
    },
  },
  hooks: {
    before: createAuthMiddleware(async (ctx) => {
      // Server-side `auth.api.*` calls have no request; their session origin is checked by the
      // create hook below, and they never pass through the public login origin.
      if (!ctx.request) return;
      const origin = originForRequest(ctx.request);
      if (!origin) {
        throw new APIError("FORBIDDEN", { message: "This host is not a registered login origin." });
      }
      const enrollment = (GATE_ENROLLMENT_AUTH_PATHS as readonly string[]).includes(ctx.path);
      // A session is only ever used on the origin that minted it: a gate session never manages an
      // admin account on the admin origin, and an admin session is not accepted on the login origin.
      const hasSessionCookie = (ctx.request.headers.get("cookie") ?? "").includes(
        authCookieName("session_token"),
      );
      const current = hasSessionCookie || enrollment ? await getSessionFromCtx(ctx) : null;
      const sessionOrigin = (current?.session as { origin?: string } | undefined)?.origin;
      if (current && sessionOrigin !== origin) {
        throw new APIError("FORBIDDEN", { message: "This session belongs to another origin." });
      }
      // Enrollment-only on the public login origin (§3.9.1): a gate session whose user has not
      // enrolled TOTP yet. Already-enrolled users get 403 and keep their secret and backup codes;
      // re-enrollment and every other MFA change need an admin session on the admin origin.
      if (origin === "gate" && enrollment) {
        if (!current) throw new APIError("UNAUTHORIZED", { message: "Sign in to continue." });
        const [row] = await db
          .select({ twoFactorEnabled: user.twoFactorEnabled })
          .from(user)
          .where(eq(user.id, current.user.id));
        if (!row || row.twoFactorEnabled) {
          throw new APIError("FORBIDDEN", {
            message: "Two-factor authentication is already enrolled. Manage it from the admin origin.",
          });
        }
      }
    }),
  },
  databaseHooks: {
    session: {
      create: {
        before: async (data, context) => {
          try {
            const origin = resolveSessionOrigin(data, context, originForRequest);
            // Gate users (FD-12, §3.9.6) sign in only on the login origin: an admin-origin session is
            // never minted for them, whichever path asks (password sign-in, TOTP rotation, recovery).
            if (origin === "admin" && typeof data.userId === "string") {
              const [gate] = await db
                .select({ userId: gateUsers.userId })
                .from(gateUsers)
                .where(eq(gateUsers.userId, data.userId));
              if (gate) throw new Error("This account can sign in only on the login origin.");
            }
            return { data: { ...data, origin } };
          } catch (error) {
            throw new APIError("FORBIDDEN", { message: (error as Error).message });
          }
        },
      },
    },
    user: {
      update: {
        before: async (data) => {
          if (data.twoFactorEnabled === true) return { data: { ...data, mfaEnrolledAt: new Date() } };
          if (data.twoFactorEnabled === false) return { data: { ...data, mfaEnrolledAt: null } };
        },
      },
    },
  },
  plugins: [twoFactorPlugin({ issuer: "Ark Stack" })],
  trustedOrigins: env.trustedOrigins,
  advanced: {
    // Names are set explicitly per cookie above; no `__Secure-` prefix is added on top.
    useSecureCookies: false,
    cookies,
    defaultCookieAttributes: {
      sameSite: "lax",
      httpOnly: true,
      secure,
      path: "/",
    },
    ipAddress: {
      // Set by the app from the transport peer, or from the edge's X-Forwarded-For only for genuine
      // edge-token login requests (client-ip.ts). No proxy subnet is trusted.
      ipAddressHeaders: [CLIENT_IP_HEADER],
    },
  },
  rateLimit: {
    enabled: true,
    window: 60,
    max: 60,
    customRules: {
      "/sign-in/email": AUTH_ATTEMPT_LIMIT,
      "/two-factor/*": AUTH_ATTEMPT_LIMIT,
    },
  },
});
