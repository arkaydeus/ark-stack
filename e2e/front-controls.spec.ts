import { realpathSync } from "node:fs";

import { expect, test } from "@playwright/test";
import { createServer } from "../web/node_modules/vite/dist/node/index.js";

test("HTTP controls save only edited fields and ask for a password after the API requests step-up", async ({
  page,
}) => {
  const vite = await createServer({
    root: new URL("../web", import.meta.url).pathname,
    server: {
      host: "127.0.0.1",
      port: 0,
      fs: {
        allow: [
          new URL("..", import.meta.url).pathname,
          ...[
            "@fontsource-variable/ibm-plex-sans",
            "@fontsource-variable/source-serif-4",
            "@fontsource/ibm-plex-mono",
          ].map((name) => realpathSync(new URL(`../web/node_modules/${name}`, import.meta.url))),
        ],
      },
    },
  });
  try {
    await vite.listen();
    const user = { id: "owner", name: "Owner", email: "owner@example.test", role: "owner" };
    await page.route("**/api/auth/get-session", (route) =>
      route.fulfill({ json: { user, session: { id: "test", expiresAt: "2099-01-01T00:00:00Z" } } }),
    );
    await page.route("**/api/state", (route) =>
      route.fulfill({
        json: {
          user,
          setup: { mfaAssured: true, mfaEnrolled: true, wizardCompleted: true },
          domains: [],
          endpoints: [],
          operations: [],
        },
      }),
    );
    await page.route("**/api/front/listeners", (route) =>
      route.fulfill({
        json: {
          sharedSniPorts: { available: [], enabled: [] },
          tcpPorts: { start: 20000, end: 20049 },
          reservedPorts: [],
        },
      }),
    );
    const routeState = {
      id: "rt_web",
      hostname: "app.example.com",
      kind: "http",
      listenPort: 443,
      accessMode: "public",
      enabled: true,
      status: "ready",
      version: "10",
      mtls: false,
      rateLimit: null as { requests: number; window: string } | null,
    };
    type Patch = { version: string; rateLimit?: typeof routeState.rateLimit; mtls?: boolean };
    const patches: Patch[] = [];
    const grants: unknown[] = [];
    await page.route("**/api/front/routes", (route) => route.fulfill({ json: { routes: [routeState] } }));
    await page.route("**/api/step-up", async (route) => {
      grants.push(route.request().postDataJSON());
      await route.fulfill({ json: {} });
    });
    await page.route("**/api/front/routes/rt_web", async (route) => {
      const patch = route.request().postDataJSON() as Patch;
      patches.push(patch);
      if (patch.version !== routeState.version) {
        await route.fulfill({ status: 409, json: { error: "The route changed state; reload and retry." } });
        return;
      }
      if (patch.rateLimit === null && !grants.length) {
        await route.fulfill({
          status: 403,
          json: { code: "exposure_step_up_required", error: "Verify password." },
        });
        return;
      }
      Object.assign(routeState, patch, { version: String(Number(routeState.version) + 1) });
      await route.fulfill({ json: { route: routeState } });
    });

    await page.goto(vite.resolvedUrls!.local[0]! + "#/front-routes");
    await page.getByRole("button", { name: "Controls" }).click();
    const limit = page.getByRole("checkbox", { name: /Limit requests/ });
    const mtls = page.getByRole("checkbox", { name: /Require a client certificate/ });
    const save = page.getByRole("button", { name: "Save controls" });
    const password = page.getByLabel("Verify your password to widen access");
    const saved = page.getByText("Saved. The edge applies the change within seconds.");
    await expect(password).toHaveCount(0);

    await limit.check();
    await save.click();
    await expect(saved).toBeVisible();
    expect(patches[0]).toEqual({ version: "10", rateLimit: { requests: 60, window: "1m" } });
    expect(grants).toHaveLength(0);

    await limit.uncheck();
    await save.click();
    await expect(password).toBeVisible();
    expect(grants).toHaveLength(0);
    await password.fill("test-password");
    await save.click();
    await expect(saved).toBeVisible();
    expect(grants).toEqual([
      {
        password: "test-password",
        action: "exposure.public",
        request: { routeId: "rt_web", version: "11", rateLimit: null },
      },
    ]);

    page.once("dialog", (dialog) => dialog.accept());
    await mtls.check();
    await save.click();
    await expect(saved).toBeVisible();
    expect(patches[3]).toEqual({ version: "12", mtls: true });
    expect(grants).toHaveLength(1);

    // Another owner edits the route after this panel's successful save.
    routeState.version = "14";
    await limit.check();
    await save.click();
    await expect(page.getByText("The route changed state; reload and retry.")).toBeVisible();
    expect(patches[4]).toEqual({ version: "13", rateLimit: { requests: 60, window: "1m" } });
    expect(routeState.mtls).toBe(true);
    await expect(password).toHaveCount(0);
  } finally {
    await vite.close();
  }
});
