// Real React page with deferred API responses. Vite serves current source so these regressions
// do not depend on a stale dist build or a database. The regular E2E harness also runs this spec.
import { realpathSync } from "node:fs";
import { expect, test, type Page, type Route } from "@playwright/test";
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

const routes = ["A", "B"].map((id) => ({
  id,
  kind: "http",
  hostname: `${id.toLowerCase()}.example.com`,
  listenPort: 443,
  status: "ready",
}));
function snippet(scope = "global") {
  return {
    scope: scope === "global" ? "global" : "route",
    routeId: scope === "global" ? null : scope,
    snippet: `POLICY ${scope}`,
    digest: `${scope}-digest`,
    tailnet: null,
    generatedAt: "2026-11-16T12:00:00Z",
    sshExample: "SSH example",
    omitted: [],
    routes,
    previous: { digest: "old-digest", generatedAt: "2026-11-15T12:00:00Z" },
    diff: [
      { op: "same", line: "context line" },
      { op: "remove", line: "old grant" },
      { op: "add", line: "new grant" },
    ],
  };
}
async function open(page: Page, role = "owner") {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      value: {
        writeText: async (value: string) => {
          (window as unknown as { copied: string }).copied = value;
        },
      },
    });
  });
  await page.route("**/api/auth/get-session", (route) =>
    route.fulfill({
      json: {
        session: { id: "test", expiresAt: "2099-01-01T00:00:00Z" },
        user: { id: "owner", name: "ACL tester", email: "acl@example.com" },
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
  await page.route("**/api/front/acl", (route) => route.fulfill({ json: snippet() }));
  await page.goto(`${baseUrl}#/front-acl`);
}

test("copy and diff show the selected snippet and accurate change counts", async ({ page }) => {
  await open(page);
  await expect(page.getByText("POLICY global", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Copy snippet", exact: true }).click();
  await expect
    .poll(() => page.evaluate(() => (window as unknown as { copied: string }).copied))
    .toBe("POLICY global");
  await expect(page.getByText("2 changed lines", { exact: true })).toBeVisible();
  await expect(page.getByText("context line", { exact: false })).toHaveCount(0);
  await page.getByRole("button", { name: "Show full diff" }).click();
  await expect(page.getByText("context line", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Show changes only" }).click();
  await expect(page.getByText("context line", { exact: false })).toHaveCount(0);
  await page.getByRole("button", { name: "Copy SSH example" }).click();
  await expect
    .poll(() => page.evaluate(() => (window as unknown as { copied: string }).copied))
    .toBe("SSH example");
  await page.screenshot({ path: "tmp/fd07-fixes/front-acl-desktop.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByLabel("Scope")).toBeVisible();
  await page.screenshot({ path: "tmp/fd07-fixes/front-acl-mobile.png", fullPage: true });
});

test("late responses cannot replace the selected scope and failed loads cannot be copied", async ({
  page,
}) => {
  const pending = new Map<string, Route>();
  await page.route("**/api/front/routes/*/acl", (route) => {
    pending.set(route.request().url().split("/").at(-2)!, route);
  });
  await open(page);
  await expect(page.getByRole("button", { name: "Copy snippet", exact: true })).toBeVisible();
  await page.getByLabel("Scope").selectOption("A");
  await expect.poll(() => pending.has("A")).toBe(true);
  await expect(page.getByRole("button", { name: "Copy snippet", exact: true })).toHaveCount(0);
  await page.getByLabel("Scope").selectOption("B");
  await expect.poll(() => pending.has("B")).toBe(true);
  await pending.get("B")!.fulfill({ json: snippet("B") });
  await expect(page.getByText("POLICY B", { exact: true })).toBeVisible();
  // Wait for the stale response to be processed, not an arbitrary time delay.
  const stale = page.waitForResponse((response) => response.url().includes("/routes/A/acl"));
  await pending.get("A")!.fulfill({ json: snippet("A") });
  await (await stale).finished();
  await page.getByRole("button", { name: "Copy snippet", exact: true }).click();
  await expect
    .poll(() => page.evaluate(() => (window as unknown as { copied: string }).copied))
    .toBe("POLICY B");
  await expect(page.getByLabel("Scope")).toHaveValue("B");
  pending.delete("A");
  await page.getByLabel("Scope").selectOption("A");
  await expect.poll(() => pending.has("A")).toBe(true);
  await pending.get("A")!.fulfill({ status: 500, json: { error: "Scope unavailable" } });
  await expect(page.getByRole("alert")).toContainText("Scope unavailable");
  await expect(page.getByRole("button", { name: "Copy snippet", exact: true })).toHaveCount(0);
  await expect(page.getByText("POLICY B", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Regenerate" })).toBeEnabled();
  await page.screenshot({ path: "tmp/fd07-fixes/front-acl-error.png", fullPage: true });
});

for (const role of ["operator", "viewer"]) {
  test(`${role} sees the non-owner fallback without fetching a snippet`, async ({ page }) => {
    let aclRequests = 0;
    page.on("request", (request) => {
      if (request.url().endsWith("/api/front/acl")) aclRequests++;
    });
    await open(page, role);
    await expect(page.getByText("Only an owner can view the tailnet policy snippet.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Copy snippet", exact: true })).toHaveCount(0);
    expect(aclRequests).toBe(0);
  });
}

test("copy failures are visible and regeneration rejects a mismatched scope", async ({ page }) => {
  await open(page);
  await page.evaluate(() => {
    Object.defineProperty(navigator.clipboard, "writeText", {
      value: async () => {
        throw new Error("Clipboard denied");
      },
    });
  });
  await page.getByRole("button", { name: "Copy snippet", exact: true }).click();
  await expect(page.getByRole("button", { name: "Copy failed: select the text" })).toBeVisible();
  await page.route("**/api/front/acl", (route) => route.fulfill({ json: snippet("A") }));
  await page.getByRole("button", { name: "Regenerate" }).click();
  await expect(page.getByRole("alert")).toContainText("different ACL scope");
  await expect(page.getByText("POLICY A", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Copy snippet", exact: true })).toHaveCount(0);
});
