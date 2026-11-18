import { realpathSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { createServer } from "../web/node_modules/vite/dist/node/index.js";

test("withdrawal consent follows the displayed plan and resets after a publish conflict", async ({
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
    const domain = { id: "dom_dns", name: "example.com", status: "verified", records: [] };
    await page.route("**/api/auth/get-session", (route) =>
      route.fulfill({
        json: {
          session: { id: "test", expiresAt: "2099-01-01T00:00:00Z" },
          user: { id: "owner", name: "DNS tester", email: "dns@example.com" },
        },
      }),
    );
    await page.route("**/api/state", (route) =>
      route.fulfill({
        json: {
          user: { id: "owner", role: "owner" },
          setup: { mfaAssured: true, mfaEnrolled: true, wizardCompleted: true },
          domains: [domain],
          endpoints: [],
          operations: [],
        },
      }),
    );
    let revision = 1;
    await page.route("**/api/domains/dom_dns/dns", (route) =>
      route.fulfill({
        json: {
          domainId: domain.id,
          zone: domain.name,
          provider: "cloudflare",
          aaaaEnabled: true,
          ipv6Status: "eligible",
          records: [],
          guides: [],
          cloudflare: {
            planHash: `plan-${revision}`,
            actions: Array.from({ length: revision }, (_, index) => ({
              recordId: `aaaa-${index}`,
              action: "create",
              before: null,
              after: {
                type: "AAAA",
                name: index ? "www.example.com" : domain.name,
                content: "2001:db8::1",
                ttl: 300,
              },
              canAuthorizeWithdrawal: true,
            })),
          },
        },
      }),
    );
    const submitted: unknown[] = [];
    await page.route("**/api/domains/dom_dns/publish", (route) => {
      submitted.push(route.request().postDataJSON());
      return submitted.length === 1
        ? route.fulfill({ status: 409, json: { error: "DNS plan changed" } })
        : route.fulfill({ json: { operationId: "op" } });
    });
    await page.goto(vite.resolvedUrls!.local[0]! + "#/domains");
    await page.getByRole("button", { name: "Review DNS", exact: true }).click();

    const consent = page.getByRole("checkbox", {
      name: "Allow Ark to withdraw its AAAA records",
      exact: false,
    });
    const reload = page.getByRole("button", { name: "Reload review" });
    const publish = page.getByRole("button", { name: "Publish reviewed DNS" });
    await consent.check();
    revision = 2;
    await reload.click();
    await expect(page.getByText("www.example.com", { exact: true })).toBeVisible();
    await expect(consent).not.toBeChecked();

    await consent.check();
    await publish.click();
    await expect(page.getByText("DNS plan changed", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Reload DNS review" }).click();
    await expect(consent).not.toBeChecked();
    await publish.click();
    await expect
      .poll(() => submitted)
      .toEqual([{ planHash: "plan-2", authorizeAAAAWithdrawal: true }, { planHash: "plan-2" }]);
  } finally {
    await vite.close();
  }
});
