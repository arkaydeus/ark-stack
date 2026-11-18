// Real React page with deferred API responses. Vite serves current source so these regressions
// do not depend on a stale dist build or a database. The regular E2E harness also runs this spec.
import { realpathSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import { createServer, type ViteDevServer } from "../web/node_modules/vite/dist/node/index.js";

let vite: ViteDevServer;
let baseUrl: string;
test.beforeAll(async () => {
  vite = await createServer({
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
  await vite.listen();
  baseUrl = vite.resolvedUrls!.local[0]!;
});
test.afterAll(async () => {
  await vite?.close();
});

type GateUser = {
  id: string;
  email: string;
  name: string;
  createdAt: string;
  createdBy: string;
  mfaEnrolled: boolean;
  temporaryPassword: string;
  routes: unknown[];
  activeSessions: number;
};
const temporaryPassword = "Browser-Temporary-123456!";
const ownerPassword = "Browser-Owner-Password-123!";

async function open(page: Page, role = "owner") {
  const model = {
    users: [] as GateUser[],
    listRequests: 0,
    writes: [] as Array<{ method: string; path: string; body: Record<string, unknown> }>,
    denyAction: "",
    listError: false,
  };
  await page.route("**/api/auth/get-session", (route) =>
    route.fulfill({
      json: {
        session: { id: "test", expiresAt: "2099-01-01T00:00:00Z" },
        user: { id: "owner", name: "Gate tester", email: "owner@example.test" },
      },
    }),
  );
  await page.route("**/api/state", (route) =>
    route.fulfill({
      json: {
        user: { id: "owner", role },
        setup: { mfaAssured: true, mfaEnrolled: true, wizardCompleted: true },
        operations: [],
      },
    }),
  );
  await page.route("**/api/step-up", async (route) => {
    const body = route.request().postDataJSON();
    model.writes.push({ method: "POST", path: "/api/step-up", body });
    if (body.password !== ownerPassword || body.action === model.denyAction) {
      await route.fulfill({ status: 403, json: { error: "Password confirmation failed" } });
    } else await route.fulfill({ json: { ok: true } });
  });
  await page.route("**/api/gate/users**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "GET") {
      model.listRequests++;
      await route.fulfill(
        model.listError
          ? { status: 500, json: { error: "Gate users unavailable" } }
          : { json: { users: model.users } },
      );
      return;
    }
    model.writes.push({ method: request.method(), path, body: request.postDataJSON() });
    if (request.method() === "DELETE") {
      model.users = model.users.filter((user) => user.id !== path.split("/").at(-1));
      await route.fulfill({ json: { ok: true } });
    } else if (path.endsWith("/temporary-password")) {
      const user = model.users.find((item) => item.id === path.split("/").at(-2))!;
      expect(user.temporaryPassword).toBe("unrevealed");
      user.temporaryPassword = "revealed";
      await route.fulfill({ json: { password: temporaryPassword } });
    } else {
      const body = request.postDataJSON();
      const user = {
        id: `gate-${model.users.length}`,
        email: body.email,
        name: body.name ?? body.email,
        createdAt: "2026-11-18T00:00:00Z",
        createdBy: "owner",
        mfaEnrolled: false,
        temporaryPassword: "unrevealed",
        routes: [],
        activeSessions: 0,
      };
      model.users.push(user);
      await route.fulfill({ status: 201, json: { user } });
    }
  });
  await page.goto(`${baseUrl}#/gate-users`);
  return model;
}

async function create(page: Page, email = "guest@example.test") {
  await page.getByLabel("Your password (confirms each change)").fill(ownerPassword);
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Name (optional)").fill("Guest");
  await page.getByRole("button", { name: "Create", exact: true }).click();
}

test("owner creates, automatically reveals, hides and confirms deletion", async ({ page }) => {
  const model = await open(page);
  await expect(page.getByText("No gate users", { exact: true })).toBeVisible();
  await create(page);
  await expect(page.getByTestId("gate-temporary-password")).toHaveText(temporaryPassword);
  await expect(page.getByText("1 gate user", { exact: true })).toBeVisible();
  expect(model.writes).toEqual([
    {
      method: "POST",
      path: "/api/step-up",
      body: {
        password: ownerPassword,
        action: "role.grant",
        request: { email: "guest@example.test", name: "Guest", gateUsers: "create" },
      },
    },
    { method: "POST", path: "/api/gate/users", body: { email: "guest@example.test", name: "Guest" } },
    {
      method: "POST",
      path: "/api/step-up",
      body: {
        password: ownerPassword,
        action: "secret.reveal",
        request: { gateUserTemporaryPassword: "gate-0" },
      },
    },
    { method: "POST", path: "/api/gate/users/gate-0/temporary-password", body: {} },
  ]);
  await expect(page.getByRole("button", { name: "Reveal temporary password", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Done, hide it" }).click();
  await expect(page.getByTestId("gate-temporary-password")).toHaveCount(0);
  page.once("dialog", async (dialog) => {
    await dialog.dismiss();
  });
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  expect(model.writes).toHaveLength(4);
  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toContain("Delete guest@example.test?");
    await dialog.accept();
  });
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByText("No gate users", { exact: true })).toBeVisible();
  expect(model.writes.slice(-2)).toEqual([
    {
      method: "POST",
      path: "/api/step-up",
      body: {
        password: ownerPassword,
        action: "role.grant",
        request: { gateUsers: "delete", userId: "gate-0" },
      },
    },
    { method: "DELETE", path: "/api/gate/users/gate-0", body: {} },
  ]);
});

test("failed step-ups show errors, prevent writes and allow a later manual reveal", async ({ page }) => {
  const model = await open(page);
  model.denyAction = "role.grant";
  await create(page);
  await expect(page.getByText("Password confirmation failed", { exact: true })).toBeVisible();
  expect(model.users).toHaveLength(0);
  expect(model.writes).toHaveLength(1);
  model.denyAction = "secret.reveal";
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("button", { name: "Reveal temporary password", exact: true })).toBeVisible();
  await expect(page.getByText("Password confirmation failed", { exact: true })).toBeVisible();
  expect(model.users[0]!.temporaryPassword).toBe("unrevealed");
  await expect(page.getByTestId("gate-temporary-password")).toHaveCount(0);
  model.denyAction = "";
  await page.getByRole("button", { name: "Reveal temporary password", exact: true }).click();
  await expect(page.getByTestId("gate-temporary-password")).toHaveText(temporaryPassword);
  await expect(page.getByRole("button", { name: "Reveal temporary password", exact: true })).toHaveCount(0);
  await expect(page.getByText("Password confirmation failed", { exact: true })).toHaveCount(0);
});

test("app Refresh updates external enrollment, sessions and users while keeping the password visible", async ({
  page,
}) => {
  const model = await open(page);
  await create(page);
  await expect(page.getByTestId("gate-temporary-password")).toHaveText(temporaryPassword);
  await expect(page.getByText("authenticator pending", { exact: true })).toBeVisible();
  await expect(page.getByText("0 sessions", { exact: true })).toBeVisible();
  model.users[0]!.mfaEnrolled = true;
  model.users[0]!.activeSessions = 2;
  model.users.push({ ...model.users[0]!, id: "external", email: "external@example.test", activeSessions: 1 });
  const before = model.listRequests;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect.poll(() => model.listRequests).toBeGreaterThan(before);
  await expect(page.getByText("2 gate users", { exact: true })).toBeVisible();
  await expect(page.getByText("authenticator set up", { exact: true })).toHaveCount(2);
  await expect(page.getByText("2 sessions", { exact: true })).toBeVisible();
  await expect(page.getByText("external@example.test", { exact: true })).toBeVisible();
  await expect(page.getByTestId("gate-temporary-password")).toHaveText(temporaryPassword);
  await expect(page.getByLabel("Your password (confirms each change)")).toHaveValue(ownerPassword);
  model.users = model.users.filter((user) => user.id !== "external");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByText("external@example.test", { exact: true })).toHaveCount(0);
  model.listError = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Gate users unavailable");
  await expect(page.getByTestId("gate-temporary-password")).toHaveText(temporaryPassword);
  model.listError = false;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveCount(0);
});

for (const role of ["operator", "viewer"]) {
  test(`${role} cannot manage gate users or fetch the list`, async ({ page }) => {
    const model = await open(page, role);
    await expect(page.getByText("Only an owner can manage gate users.")).toBeVisible();
    expect(model.listRequests).toBe(0);
    expect(model.writes).toEqual([]);
  });
}
