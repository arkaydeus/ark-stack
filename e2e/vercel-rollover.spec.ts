import { realpathSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { createServer } from "../web/node_modules/vite/dist/node/index.js";
import { vercelConnectBinding } from "../server/src/modules/vercel-api.ts";

test("an owner can connect and disconnect Vercel on a private database with credential step-up", async ({
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
    const database = { id: "mdb_fixture", name: "fixture", roles: [], exposure: "private", status: "ready" };
    const client = { id: "dbc_fixture", name: "Fixture client", environment: "preview" };
    const credentials = {
      projectId: "prj_Fixture",
      teamId: "team_Fixture",
      otherProjectId: "prj_Other",
      target: "preview" as const,
      gitBranch: "fixture-preview",
      token: "vcp_FixtureToken",
      deployHook: "https://api.vercel.com/v1/integrations/deploy/prj_Fixture/FixtureHook",
    };
    const password = "Fixture password";
    const path = `**/api/databases/${database.id}/clients/${client.id}/vercel-integration`;
    const submissions: { kind: string; body: unknown }[] = [];
    let connected = false;
    let connectEnabled = true;
    await page.route("**/api/**", (route) => route.fulfill({ json: {} }));
    await page.route("**/api/auth/get-session", (route) =>
      route.fulfill({
        json: {
          session: { id: "test", expiresAt: "2099-01-01T00:00:00Z" },
          user: { id: "owner", name: "Owner", email: "owner@example.com" },
        },
      }),
    );
    await page.route("**/api/state", (route) =>
      route.fulfill({
        json: {
          user: { id: "owner", role: "owner" },
          setup: { mfaAssured: true, mfaEnrolled: true, wizardCompleted: true },
          databases: [database],
          operations: [],
        },
      }),
    );
    await page.route(`**/api/databases/${database.id}/clients`, (route) =>
      route.fulfill({ json: { clients: [client] } }),
    );
    await page.route("**/api/step-up", (route) => {
      submissions.push({ kind: "step-up", body: route.request().postDataJSON() });
      return route.fulfill({ json: { ok: true } });
    });
    await page.route(path, (route) => {
      if (route.request().method() === "GET") {
        return route.fulfill({
          json: {
            connectEnabled,
            eligible: true,
            requiresReconnect: false,
            integration: connected
              ? {
                  projectId: credentials.projectId,
                  target: "preview",
                  gitBranch: credentials.gitBranch,
                  tokenExpiresAt: "2099-01-01T00:00:00Z",
                  tokenExpiryStatus: "valid",
                }
              : null,
          },
        });
      }
      const kind = route.request().method();
      submissions.push({ kind, body: route.request().postData() ? route.request().postDataJSON() : null });
      if (kind === "DELETE") {
        connected = false;
        return route.fulfill({ json: { disconnected: true } });
      }
      if (submissions.length === 2) return route.fulfill({ status: 422, json: { error: "Fixture refusal" } });
      connected = true;
      connectEnabled = false;
      return route.fulfill({ json: { ok: true } });
    });
    await page.goto(vite.resolvedUrls!.local[0]! + "#/databases");
    await page.getByRole("button", { name: "Vercel rollover", exact: true }).click();
    const token = page.getByLabel("Project token", { exact: true });
    const hook = page.getByLabel("Deploy hook URL", { exact: true });
    const ownerPassword = page.getByLabel("Your Ark password", { exact: true });
    const submit = page.getByRole("button", { name: "Connect Vercel", exact: true });
    await page.getByLabel("Vercel project ID", { exact: true }).fill(credentials.projectId);
    await page.getByLabel("Vercel team ID", { exact: true }).fill(credentials.teamId);
    await page
      .getByLabel("Other project ID in the same team", { exact: true })
      .fill(credentials.otherProjectId);
    await page
      .getByLabel("Preview branch (defaults to the deploy hook branch)", { exact: true })
      .fill(credentials.gitBranch);
    for (const attempt of [0, 1]) {
      await token.fill(credentials.token);
      await hook.fill(credentials.deployHook);
      await ownerPassword.fill(password);
      await submit.click();
      if (attempt === 0) {
        await expect(page.getByRole("alert")).toHaveText("Fixture refusal");
        await expect(token).toHaveValue("");
        await expect(hook).toHaveValue("");
      } else {
        await expect(page.getByText("Vercel connected.")).toBeVisible();
        await expect(token).toHaveCount(0);
        await expect(hook).toHaveCount(0);
      }
      await expect(ownerPassword).toHaveValue("");
    }
    const attempt = [
      {
        kind: "step-up",
        body: {
          password,
          action: "credential.rotate",
          request: {
            databaseId: database.id,
            clientId: client.id,
            vercelIntegration: "connect",
            ...vercelConnectBinding(credentials),
          },
        },
      },
      { kind: "PUT", body: credentials },
    ];
    await expect(page.getByText("Token expiry", { exact: true })).toBeVisible();
    await expect(page.getByText(credentials.gitBranch, { exact: false })).toBeVisible();
    await ownerPassword.fill(password);
    await page.getByRole("button", { name: "Disconnect", exact: true }).click();
    await expect(page.getByText("Vercel disconnected. Continue with manual rollover.")).toBeVisible();
    await expect(page.getByText("Token expiry", { exact: true })).toHaveCount(0);
    await expect(ownerPassword).toHaveCount(0);
    expect(submissions).toEqual([
      ...attempt,
      ...attempt,
      {
        kind: "step-up",
        body: {
          password,
          action: "credential.rotate",
          request: { databaseId: database.id, clientId: client.id, vercelIntegration: "disconnect" },
        },
      },
      { kind: "DELETE", body: null },
    ]);
  } finally {
    await vite.close();
  }
});
