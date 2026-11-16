import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";

import { createId, parseEnvFile } from "@ark-stack/shared";

import { resolveSessionOrigin } from "./session-origin.ts";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { auth } = await import("./auth.ts");
const { sql } = await import("./db.ts");

const request = new Request("http://127.0.0.1:3000/api/auth/sign-in/email");

describe("resolveSessionOrigin", () => {
  test("a session minted while serving a request is an admin session", () => {
    expect(resolveSessionOrigin({}, { request })).toBe("admin");
  });

  test("an explicit server-side origin is kept", () => {
    expect(resolveSessionOrigin({ origin: "gate" }, null)).toBe("gate");
    expect(resolveSessionOrigin({ origin: "admin" }, { request })).toBe("admin");
  });

  test("a context-free creation without an origin is refused, not guessed", () => {
    expect(() => resolveSessionOrigin({}, null)).toThrow(/without a request or an explicit origin/);
    expect(() => resolveSessionOrigin({}, {})).toThrow(/without a request or an explicit origin/);
    expect(() => resolveSessionOrigin({ origin: "public" }, { request })).toThrow(/unknown origin/);
  });
});

describe("Better Auth session insert paths set origin", () => {
  const authUrl = process.env.BETTER_AUTH_URL ?? "http://127.0.0.1:3000";
  const email = `${createId("usr")}@example.com`;
  const password = "Origin-Test-Password-123!";
  const post = (path: string, body: unknown) =>
    auth.handler(
      new Request(`${authUrl}/api/auth/${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: authUrl },
        body: JSON.stringify(body),
      }),
    );
  const sessionsFor = () => sql`
    SELECT s.origin FROM session s JOIN "user" u ON u.id = s.user_id WHERE u.email = ${email}
  `;

  test("sign-up and sign-in record origin = admin", async () => {
    const signUp = await post("sign-up/email", { name: "Origin test", email, password });
    expect(signUp.status).toBe(200);
    const signIn = await post("sign-in/email", { email, password });
    expect(signIn.status).toBe(200);
    const token = (await signIn.json()).token as string;
    const [session] = await sql`SELECT origin FROM session WHERE token = ${token}`;
    expect(session?.origin).toBe("admin");
    expect((await sessionsFor()).map((row) => row.origin)).toEqual(["admin", "admin"]);
  });

  test("a server-side sign-in with no request context is refused and inserts nothing", async () => {
    const before = (await sessionsFor()).length;
    await expect(auth.api.signInEmail({ body: { email, password } })).rejects.toThrow(
      /without a request or an explicit origin/,
    );
    await expect(
      auth.api.signInEmail({ body: { email, password }, headers: new Headers({ Origin: authUrl }) }),
    ).rejects.toThrow(/without a request or an explicit origin/);
    expect((await sessionsFor()).length).toBe(before);
  });
});
