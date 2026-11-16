import { betterAuth } from "better-auth/minimal";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { APIError } from "better-auth/api";
import { twoFactor as twoFactorPlugin } from "better-auth/plugins";

import { db } from "./db.ts";
import { loadEnv } from "./env.ts";
import { account, session, twoFactor, user, verification } from "./schema.ts";
import { resolveSessionOrigin } from "./session-origin.ts";

const env = loadEnv();

export const auth = betterAuth({
  appName: "Ark Stack",
  baseURL: env.authUrl,
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
  databaseHooks: {
    session: {
      create: {
        before: async (data, context) => {
          try {
            return { data: { ...data, origin: resolveSessionOrigin(data, context) } };
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
    cookiePrefix: "ark_stack",
    useSecureCookies: env.authUrl.startsWith("https://"),
    defaultCookieAttributes: {
      sameSite: "lax",
      httpOnly: true,
    },
    ipAddress: {
      trustedProxies: env.trustedProxies,
    },
  },
  rateLimit: {
    enabled: true,
    window: 60,
    max: 60,
  },
});
