// FD-11 (docs/design/front-door.md §3.9.2): the login gate in a real browser, against the containerised
// edge, the real API and a fake upstream. Run by scripts/test-e2e-gate.ts, which starts all of them
// and points Chromium at the edge through a CONNECT proxy; skipped in the regular browser run.
import { expect, test } from "@playwright/test";

import { totpCode } from "./totp.ts";

const appUrl = process.env.ARK_E2E_GATE_APP_URL ?? "";
const loginHost = process.env.ARK_E2E_GATE_LOGIN_HOST ?? "";

test.skip(!appUrl, "Runs only through scripts/test-e2e-gate.ts (containerised edge).");
test.use({
  proxy: { server: process.env.ARK_E2E_GATE_PROXY ?? "http://127.0.0.1:9" },
  ignoreHTTPSErrors: true,
});

test("SSO route: login-origin redirect, password and TOTP, host-only route cookie, identity upstream", async ({
  page,
  context,
}) => {
  const appHost = new URL(appUrl).host;
  const original = `${appUrl}/dashboard?tab=1`;
  const navigations: string[] = [];
  page.on("request", (request) => {
    if (request.isNavigationRequest()) navigations.push(request.url());
  });

  // An unauthenticated GET is redirected to the login origin (authorize, then the sign-in page).
  await page.goto(original);
  await expect(page).toHaveURL(new RegExp(`^https://${loginHost.replaceAll(".", "\\.")}/gate/login\\?next=`));
  const authorize = navigations.map((url) => new URL(url)).find((url) => url.pathname === "/gate/authorize");
  expect(authorize?.host).toBe(loginHost);
  expect(authorize?.searchParams.get("rd")).toBe("/dashboard?tab=1");

  // Password, then TOTP.
  await page.getByLabel("Email").fill(process.env.ARK_E2E_GATE_EMAIL!);
  await page.getByLabel("Password").fill(process.env.ARK_E2E_GATE_PASSWORD!);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Authenticator code").fill(totpCode(process.env.ARK_E2E_GATE_TOTP_SECRET!));
  await page.getByRole("button", { name: "Verify" }).click();

  // The browser lands on the original path, through the route host's callback.
  await page.waitForURL(original);
  expect(navigations.some((url) => url.startsWith(`${appUrl}/.ark/gate/callback?code=`))).toBe(true);
  const cookie = (await context.cookies(appUrl)).find((item) => item.name === "__Host-ark_gate");
  expect(cookie).toMatchObject({ secure: true, httpOnly: true, sameSite: "Lax", path: "/", domain: appHost });
  // Host-only: no Domain attribute, so the cookie never reaches a sibling or parent domain.
  expect(cookie?.domain.startsWith(".")).toBe(false);
  expect(
    (await context.cookies(`https://login.${appHost.split(".").slice(1).join(".")}`)).some(
      (item) => item.name === "__Host-ark_gate",
    ),
  ).toBe(false);

  // The upstream sees X-Ark-User and never the gate cookie (its /headers echo).
  await page.goto(`${appUrl}/headers`);
  const seen = JSON.parse(await page.locator("body").innerText()) as Record<string, string>;
  expect(seen["x-ark-user"]).toBe(process.env.ARK_E2E_GATE_USER_ID);
  expect(seen["x-ark-email"]).toBe(process.env.ARK_E2E_GATE_EMAIL);
  expect(seen.cookie ?? "").not.toContain("ark_gate");
  expect(seen["x-ark-edge-token"]).toBeUndefined();
});
