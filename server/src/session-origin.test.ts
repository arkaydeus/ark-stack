import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { createHmac } from "node:crypto";

import { createId, parseEnvFile } from "@ark-stack/shared";

import { resolveSessionOrigin, withSessionOrigin, type SessionOrigin } from "./session-origin.ts";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { auth } = await import("./auth.ts");
const { sql } = await import("./db.ts");

const adminRequest = new Request("https://admin.example.test/api/auth/sign-in/email");
const loginRequest = new Request("https://login.example.test/api/auth/sign-in/email");
const otherRequest = new Request("https://www.example.test/api/auth/sign-in/email");
// Positive match only, as origin-hosts.ts does: any other host has no origin.
const byHost = (request: Request): SessionOrigin | null =>
  (({ "admin.example.test": "admin", "login.example.test": "gate" })[new URL(request.url).host] as
    | SessionOrigin
    | undefined) ?? null;

describe("resolveSessionOrigin", () => {
  test("the request host decides: the login host mints gate sessions, an admin host admin ones", () => {
    expect(resolveSessionOrigin({}, { request: adminRequest }, byHost)).toBe("admin");
    expect(resolveSessionOrigin({}, { request: loginRequest }, byHost)).toBe("gate");
  });

  test("a request for any other host is refused, never mapped to the admin origin", () => {
    expect(() => resolveSessionOrigin({}, { request: otherRequest }, byHost)).toThrow(
      /not a registered login origin/,
    );
    expect(() => resolveSessionOrigin({ origin: "admin" }, { request: otherRequest }, byHost)).toThrow(
      /not a registered login origin/,
    );
  });

  test("an explicit server-side origin is kept, and must agree with the request host", () => {
    expect(resolveSessionOrigin({ origin: "gate" }, null, byHost)).toBe("gate");
    expect(resolveSessionOrigin({ origin: "admin" }, { request: adminRequest }, byHost)).toBe("admin");
    expect(() => resolveSessionOrigin({ origin: "admin" }, { request: loginRequest }, byHost)).toThrow(
      /contradictory origins/,
    );
  });

  test("withSessionOrigin supplies positive provenance to a context-free call", async () => {
    expect(await withSessionOrigin("gate", async () => resolveSessionOrigin({}, null, byHost))).toBe("gate");
    await expect(
      withSessionOrigin("gate", async () => resolveSessionOrigin({}, { request: adminRequest }, byHost)),
    ).rejects.toThrow(/contradictory origins/);
  });

  test("a context-free creation without an origin is refused, not guessed", () => {
    expect(() => resolveSessionOrigin({}, null, byHost)).toThrow(/without a request or an explicit origin/);
    expect(() => resolveSessionOrigin({}, {}, byHost)).toThrow(/without a request or an explicit origin/);
    expect(() => resolveSessionOrigin({ origin: "public" }, { request: adminRequest }, byHost)).toThrow(
      /unknown origin/,
    );
  });
});

describe("Better Auth session insert paths set origin", () => {
  const authUrl = process.env.BETTER_AUTH_URL ?? "http://127.0.0.1:3000";
  const email = `${createId("usr")}@example.com`;
  const password = "Origin-Test-Password-123!";
  const post = (path: string, body: unknown, cookie = "") =>
    auth.handler(
      new Request(`${authUrl}/api/auth/${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: authUrl, Cookie: cookie },
        body: JSON.stringify(body),
      }),
    );
  const sessionsFor = () => sql`
    SELECT s.origin FROM session s JOIN "user" u ON u.id = s.user_id WHERE u.email = ${email}
  `;

  test("sign-up and sign-in record origin = admin", async () => {
    const signUp = await post("sign-up/email", { name: "Origin test", email, password, origin: "gate" });
    expect(signUp.status).toBe(200);
    const signIn = await post("sign-in/email", { email, password, origin: "gate" });
    expect(signIn.status).toBe(200);
    const token = (await signIn.json()).token as string;
    const [session] = await sql`SELECT origin FROM session WHERE token = ${token}`;
    expect(session?.origin).toBe("admin");
    expect((await sessionsFor()).map((row) => row.origin)).toEqual(["admin", "admin"]);
  });

  test("TOTP enrollment replaces the session and TOTP login creates an admin session", async () => {
    const mfaEmail = `${createId("usr")}@example.com`;
    const cookies = new Map<string, string>();
    const browserPost = async (path: string, body: unknown) => {
      const response = await post(path, body, [...cookies].map(([k, v]) => `${k}=${v}`).join("; "));
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(";")[0]!;
        const separator = pair.indexOf("=");
        cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
      }
      expect(response.status).toBe(200);
      return response.json();
    };
    const rows = () => sql`
      SELECT s.id, s.origin FROM session s JOIN "user" u ON u.id = s.user_id WHERE u.email = ${mfaEmail}
    `;
    try {
      await browserPost("sign-up/email", { name: "MFA origin", email: mfaEmail, password, origin: "gate" });
      const [original] = await rows();
      expect(original?.origin).toBe("admin");
      const { totpURI } = await browserPost("two-factor/enable", { password, origin: "gate" });
      const secret = new URL(totpURI).searchParams.get("secret")!;
      // RFC 4648 Base32 decoding and RFC 6238 SHA-1 TOTP, independent of Better Auth's generator.
      const bits = [...secret.toUpperCase().replace(/=+$/, "")]
        .map((char) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char).toString(2).padStart(5, "0"))
        .join("");
      const key = Buffer.from(bits.match(/.{8}/g)!.map((byte) => Number.parseInt(byte, 2)));
      const code = () => {
        const counter = Buffer.alloc(8);
        counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
        const digest = createHmac("sha1", key).update(counter).digest();
        const offset = digest[digest.length - 1]! & 15;
        return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
      };
      await browserPost("two-factor/verify-totp", { code: code(), origin: "gate" });
      const enrolled = await rows();
      expect(enrolled).toHaveLength(1);
      expect(enrolled[0]?.origin).toBe("admin");
      expect(enrolled[0]?.id).not.toBe(original?.id);
      const [user] = await sql`SELECT two_factor_enabled FROM "user" WHERE email = ${mfaEmail}`;
      expect(user?.two_factor_enabled).toBe(true);

      await browserPost("sign-out", {});
      expect(await rows()).toHaveLength(0);
      cookies.clear();
      const login = await browserPost("sign-in/email", { email: mfaEmail, password, origin: "gate" });
      expect(login.twoFactorRedirect).toBe(true);
      expect(await rows()).toHaveLength(0);
      const verified = await browserPost("two-factor/verify-totp", { code: code(), origin: "gate" });
      const signedIn = await rows();
      expect(signedIn).toHaveLength(1);
      expect(signedIn[0]?.origin).toBe("admin");
      expect(signedIn[0]?.id).not.toBe(enrolled[0]?.id);
      const [persisted] = await sql`SELECT id, origin FROM session WHERE token = ${verified.token}`;
      expect(persisted).toEqual(signedIn[0]);
    } finally {
      await sql`DELETE FROM "user" WHERE email = ${mfaEmail}`;
    }
  });

  test("a server-side sign-in with no request context is refused and inserts nothing", async () => {
    const before = (await sessionsFor()).length;
    // No host at all: the dynamic base URL has no fallback, so nothing is resolved for the admin origin.
    await expect(auth.api.signInEmail({ body: { email, password } })).rejects.toThrow(
      /Dynamic baseURL could not be resolved/,
    );
    // A registered host but no request and no explicit origin: the session hook refuses.
    await expect(
      auth.api.signInEmail({
        body: { email, password },
        headers: new Headers({ Origin: authUrl, Host: new URL(authUrl).host }),
      }),
    ).rejects.toThrow(/without a request or an explicit origin/);
    expect((await sessionsFor()).length).toBe(before);
  });

  test("a literal session insert that omits origin fails at the database", async () => {
    const [owner] = await sql`SELECT id FROM "user" WHERE email = ${email}`;
    await expect(
      sql`
        INSERT INTO session (id, user_id, token, expires_at, created_at, updated_at)
        VALUES (${createId("ses")}, ${owner!.id}, ${createId("tok")}, now() + interval '1 hour', now(), now())
      `,
    ).rejects.toThrow(/null value in column "origin"/);
  });
});
