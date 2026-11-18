import { realpathSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { createServer } from "../web/node_modules/vite/dist/node/index.js";

for (const view of ["domains", "front-routes"] as const) {
  test(`withdrawal consent follows the reviewed plan on ${view}`, async ({ page }) => {
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
      let operationCount = 1;
      let routeLoads = 0;
      await page.route("**/api/state", (route) =>
        route.fulfill({
          json: {
            user: { id: "owner", role: "owner" },
            setup: { mfaAssured: true, mfaEnrolled: true, wizardCompleted: true },
            domains: [domain],
            endpoints: [],
            operations: Array.from({ length: operationCount }, (_, id) => ({
              id: "op-" + id,
              kind: "domain.verify",
              status: "running",
              error: null,
            })),
          },
        }),
      );
      await page.route("**/api/front/routes", (route) => {
        routeLoads++;
        return route.fulfill({
          json: {
            routes: [
              {
                id: "route_dns",
                hostname: domain.name,
                kind: "https",
                listenPort: 443,
                enabled: true,
                status: "awaiting_dns",
                domain,
              },
            ],
          },
        });
      });
      await page.route("**/api/front/listeners", (route) =>
        route.fulfill({
          json: {
            sharedSniPorts: { available: [], enabled: [] },
            tcpPorts: { start: 3000, end: 4000 },
            reservedPorts: [],
          },
        }),
      );
      let revision = 1;
      const reviewPath = view === "domains" ? "/api/domains/dom_dns/dns" : "/api/front/routes/route_dns/dns";
      await page.route("**" + reviewPath, (route) =>
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
        if (submitted.length === 1)
          return route.fulfill({ status: 409, json: { error: "DNS plan changed" } });
        if (submitted.length === 2) return route.abort("timedout");
        return route.fulfill({ status: 202, json: { operationId: "op" } });
      });
      let finished = false;
      await page.route("**/api/domains/dom_dns/publish/op", (route) =>
        route.fulfill({
          json: { status: finished ? "succeeded" : "running", applied: 1, total: 2 },
        }),
      );
      await page.goto(vite.resolvedUrls!.local[0]! + "#/" + view);
      const opener = page.getByRole("button", {
        name: view === "domains" ? "Review DNS" : "DNS",
        exact: true,
      });
      await opener.click();

      const consent = page.getByRole("checkbox", {
        name: "Allow Ark to withdraw its AAAA records",
        exact: false,
      });
      const reload = page.getByRole("button", { name: "Reload review" });
      const publish = page.getByRole("button", { name: "Publish reviewed DNS" });
      await consent.check();
      if (view === "front-routes") {
        const before = routeLoads;
        operationCount++;
        await expect.poll(() => routeLoads).toBeGreaterThan(before);
        await expect(consent).toBeChecked();
      }
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
        .toEqual([
          { planHash: "plan-2", authorizeAAAAWithdrawal: true, requestId: expect.any(String) },
          { planHash: "plan-2", requestId: expect.any(String) },
          { planHash: "plan-2", requestId: expect.any(String) },
        ]);
      expect(submitted[2]).toEqual(submitted[1]);
      await expect(page.getByText("Checking Cloudflare records (1 of 2)…", { exact: true })).toBeVisible();
      if (view === "front-routes") {
        const before = routeLoads;
        operationCount++;
        await expect.poll(() => routeLoads).toBeGreaterThan(before);
        await expect(opener).toHaveAttribute("aria-expanded", "true");
      }
      finished = true;
      await expect(
        page.getByText("Cloudflare changes applied. Public DNS verification is queued."),
      ).toBeVisible();
    } finally {
      await vite.close();
    }
  });
}
