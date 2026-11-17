import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";

import { parseEnvFile } from "../../shared/src/install.ts";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app: server } = await import("../../server/src/app.ts");
// Requests go to the configured admin origin: the API refuses hosts that are not registered origins.
const origin = new URL(process.env.BETTER_AUTH_URL ?? "http://localhost:3000").origin;
const app = { request: (path: string, init?: RequestInit) => server.request(`${origin}${path}`, init) };

describe("high-risk HTTP flows", () => {
  test("setup status is public and state requires a session", async () => {
    const setup = await app.request("/api/setup/status");
    expect(setup.status).toBe(200);
    const state = await app.request("/api/state");
    expect(state.status).toBe(401);
    const metrics = await app.request("/api/metrics");
    expect(metrics.status).toBe(401);
    const publish = await app.request("/api/domains/x/publish", { method: "POST", body: "{}" });
    expect(publish.status).toBe(401);
  });

  test("signup without a setup token is closed", async () => {
    const response = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "x", email: "x@example.com", password: "not-a-real-password" }),
    });
    expect(response.status).toBe(403);
  });

  test("mailbox credential and privileged secrets require an authenticated MFA session", async () => {
    const mailbox = await app.request("/api/mailboxes/mbx_x/credential", { method: "POST", body: "{}" });
    expect(mailbox.status).toBe(401);
    const reveal = await app.request("/api/secrets/sec_x/reveal", { method: "POST", body: "{}" });
    expect(reveal.status).toBe(401);
  });

  test("external alias creation is denied without a session", async () => {
    const response = await app.request("/api/aliases", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domainId: "dom_x",
        localPart: "fwd",
        targets: ["outside@example.net"],
        allowExternal: true,
      }),
    });
    expect(response.status).toBe(401);
  });

  test("built UI contains the sign-in contract", async () => {
    expect(existsSync("web/dist/index.html")).toBe(true);
    const html = await Bun.file("web/dist/index.html").text();
    expect(html).toContain("Ark Stack");
  });
});
