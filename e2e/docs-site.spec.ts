import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, test } from "@playwright/test";

let out: string;
let server: ChildProcess;
let site: string;

test.beforeAll(async () => {
  out = mkdtempSync(join(tmpdir(), "ark-docs-browser-"));
  server = spawn("bun", ["scripts/docs-site/build.ts", "serve", "--out", out, "--port", "0"], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  site = await new Promise<string>((resolve, reject) => {
    let output = "";
    server.once("error", reject);
    server.once("exit", (code) => reject(new Error(`Docs preview exited with status ${code}`)));
    server.stdout!.on("data", (chunk: Buffer) => {
      output += chunk.toString();
      const url = /docs site on (http:\/\/127\.0\.0\.1:\d+\/)/.exec(output)?.[1];
      if (url) resolve(url);
    });
  });
});

test.afterAll(async () => {
  if (server?.pid && server.exitCode === null && server.signalCode === null) {
    const exited = once(server, "exit");
    server.kill();
    await exited;
  }
  if (out) rmSync(out, { recursive: true, force: true });
});

test("search retries a failed index load and supports keyboard selection and dismissal", async ({ page }) => {
  const errors: Error[] = [];
  page.on("pageerror", (error) => errors.push(error));
  const indexRoute = "**/assets/search-index.js";
  await page.route(indexRoute, (route) => route.abort());

  await page.goto(site);
  const search = page.getByRole("searchbox");
  const results = page.getByRole("listbox");
  await search.fill("host:install");
  await expect(results).toHaveText("Search is unavailable. Edit your query to try again.");
  await expect(page.locator('script[src$="/search-index.js"]')).toHaveCount(0);

  await page.unroute(indexRoute);
  await search.fill("host:install --harden-vps");
  await expect(results.getByRole("option").first()).toBeVisible();
  await search.press("ArrowDown");
  await expect(results.getByRole("option").first()).toHaveAttribute("aria-selected", "true");
  await page.locator(".sidebar summary").first().click();
  await expect(results).toBeHidden();
  await search.focus();
  await search.press("Enter");
  await expect(page).toHaveURL(site);
  await expect(results).toBeHidden();

  await search.fill("setup");
  const links = results.getByRole("option");
  await expect(links.first()).toBeVisible();
  await search.press("ArrowUp");
  const last = links.last();
  await expect(last).toHaveAttribute("aria-selected", "true");
  const destination = await last.getAttribute("href");
  await search.press("Enter");
  await expect(page).toHaveURL(new URL(destination!, site).href);
  expect(errors).toEqual([]);
});

test("the mobile drawer opens, closes and follows a sidebar link", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(site);
  const menu = page.getByRole("button", { name: "Toggle navigation" });
  const navigation = page.getByRole("navigation", { name: "Documentation" });
  await expect(menu).toBeVisible();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await expect(page.locator("body")).not.toHaveClass(/nav-open/);
  await menu.click();
  await expect(menu).toHaveAttribute("aria-expanded", "true");
  await expect(navigation).toBeVisible();
  await menu.click();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await menu.click();
  await navigation.getByRole("link", { name: "Production install", exact: true }).click();
  await expect(page).toHaveURL(new URL("getting-started/production-install.html", site).href);
  await expect(menu).toHaveAttribute("aria-expanded", "false");
});

test("Mermaid loads only for diagrams and initializes with strict rendering", async ({ page }) => {
  const moduleUrl = "https://cdn.jsdelivr.net/npm/mermaid@11.16.1/dist/mermaid.esm.min.mjs";
  let loads = 0;
  await page.route(moduleUrl, async (route) => {
    loads += 1;
    await route.fulfill({
      contentType: "application/javascript",
      headers: { "access-control-allow-origin": "*" },
      body: `let config;
        export default {
          initialize(options) { config = options; },
          run({ querySelector }) {
            document.querySelector(querySelector).textContent = config.securityLevel;
          },
        };`,
    });
  });
  await page.goto(new URL("features/accounts-and-access.html", site).href);
  await expect(page.locator("body")).not.toHaveAttribute("data-mermaid", moduleUrl);
  expect(loads).toBe(0);

  await page.goto(new URL("getting-started/production-install.html", site).href);
  await expect(page.locator("pre.mermaid").first()).toHaveText("strict");
  expect(loads).toBe(1);
});

test("Mermaid source remains readable when the renderer is unavailable", async ({ page }) => {
  const errors: Error[] = [];
  page.on("pageerror", (error) => errors.push(error));
  await page.route("https://cdn.jsdelivr.net/npm/mermaid@*/dist/mermaid.esm.min.mjs", (route) =>
    route.abort(),
  );
  await page.goto(new URL("getting-started/production-install.html", site).href);
  await expect(page.locator("pre.mermaid").first()).toContainText("flowchart TD");
  expect(errors).toEqual([]);
});
