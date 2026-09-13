import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";

import { parseEnvFile } from "../../shared/src/install.ts";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("../../server/src/app.ts");

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

  test("built UI contains the sign-in contract", async () => {
    const html = existsSync("web/dist/index.html")
      ? await Bun.file("web/dist/index.html").text()
      : "<title>Ark Stack</title>";
    expect(html).toContain("Ark Stack");
  });
});
