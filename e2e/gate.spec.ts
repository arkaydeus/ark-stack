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

async function fixture(action: string) {
  const response = await fetch(`${process.env.ARK_E2E_GATE_CONTROL}/${action}`, { method: "POST" });
  const result = (await response.json()) as {
    error?: string;
    pending?: number;
    sessions?: number;
    cookies?: Record<string, string>;
  };
  expect(response.status, result.error).toBe(200);
  return result;
}

async function signIn(page: import("@playwright/test").Page) {
  // The first case above proves the real password + TOTP UI. Later independent socket cases
  // mint an assured parent to avoid exhausting the production five-attempt/IP/minute limiter.
  const { cookies } = await fixture("browser-session");
  await page.context().addCookies(
    Object.entries(cookies!).map(([name, value]) => ({
      name,
      value,
      url: `https://${loginHost}/`,
      secure: true,
      httpOnly: true,
      sameSite: "Lax" as const,
    })),
  );
  await page.goto(`${appUrl}/headers`);
  await page.waitForURL(`${appUrl}/headers`);
}

for (const source of ["signed-in", "access-denied"]) {
  test(`rendered sign-out works from the ${source} page and invalidates the route session`, async ({
    page,
  }) => {
    await fixture("prepare");
    await signIn(page);
    // Two route sessions under the same login parent must both end on global logout.
    await page.context().clearCookies({ name: "__Host-ark_gate" });
    await page.goto(`${appUrl}/headers`);
    expect((await fixture("status")).sessions).toBe(2);
    if (source === "access-denied") {
      // Keep the parent but remove its MFA assurance before visiting authorize.
      await fixture("mfa-assurance");
      await page.goto(
        `https://${loginHost}/gate/authorize?route=${process.env.ARK_E2E_GATE_ROUTE_ID}&state=${"A".repeat(22)}&rd=/`,
      );
      await expect(page.getByRole("heading", { name: "Access denied" })).toBeVisible();
    } else await page.goto(`https://${loginHost}/gate/login`);
    const logout = page.waitForResponse((response) => new URL(response.url()).pathname === "/gate/logout");
    await page.getByRole("button", { name: "Sign out everywhere" }).click();
    expect((await logout).status()).toBe(303);
    await expect(page.getByLabel("Email")).toBeVisible();
    expect((await fixture("status")).sessions).toBe(0);
    await page.goto(`${appUrl}/headers`);
    await expect(page.getByLabel("Email")).toBeVisible();
  });
}

// Each case starts an independently authenticated socket. Only the event's queued drain may run;
// failure cases leave it pending and let the shipped watchdog consume the real API lease.
for (const event of [
  "route-logout",
  "sign-out",
  "auth-sign-out",
  "logout-everywhere",
  "session",
  "access",
  "expired-access",
  "expired-session",
  "mfa-assurance",
  "mfa-disable",
  "mode",
  "worker-death",
  "rejected-apply",
  "mfa-reset",
  "user-delete",
]) {
  test(`real authenticated WebSocket closes after ${event}`, async ({ page }) => {
    test.setTimeout(60_000);
    await fixture("prepare");
    await signIn(page);
    await page.evaluate(
      async (url) => {
        const state = window as unknown as { gateSocket: WebSocket; gateSocketClosed: boolean };
        state.gateSocketClosed = false;
        state.gateSocket = new WebSocket(url);
        state.gateSocket.addEventListener("close", () => {
          state.gateSocketClosed = true;
        });
        await new Promise<void>((resolve, reject) => {
          state.gateSocket.addEventListener("open", () => resolve(), { once: true });
          state.gateSocket.addEventListener("error", () => reject(new Error("socket failed to open")), {
            once: true,
          });
        });
      },
      `${appUrl.replace("https:", "wss:")}/ws`,
    );
    const started = Date.now();
    if (event === "route-logout") {
      expect(
        await page.evaluate(async () => (await fetch("/.ark/gate/logout", { method: "POST" })).status),
      ).toBe(200);
    } else if (event === "sign-out" || event === "auth-sign-out") {
      // Keep the route page/socket alive; sign out through a second page on the login origin.
      const login = await page.context().newPage();
      await login.goto(`https://${loginHost}/gate/login`);
      expect(
        await login.evaluate(
          async (path) =>
            (
              await fetch(path, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: "{}",
              })
            ).status,
          event === "sign-out" ? "/gate/logout" : "/api/auth/sign-out",
        ),
      ).toBe(200);
      await login.close();
    } else await fixture(["worker-death", "rejected-apply"].includes(event) ? "access" : event);
    expect((await fixture("status")).pending).toBeGreaterThan(0);
    if (event === "worker-death") await fixture("lost-worker");
    else if (event === "rejected-apply") {
      await fixture("reject");
      const response = await fetch(`${process.env.ARK_E2E_GATE_CONTROL}/worker`, { method: "POST" });
      expect(response.status).toBe(500);
      expect(((await response.json()) as { error: string }).error).toContain("Caddy reload failed");
    } else {
      await fixture("worker");
      expect((await fixture("status")).pending).toBe(0);
    }
    // The DB change denies the very next request without any new browser sign-in.
    if (event !== "mode")
      expect(
        await page.evaluate(
          async () => (await fetch("/headers", { headers: { accept: "application/json" } })).status,
        ),
      ).toBe(401);
    await expect
      .poll(
        async () =>
          page.evaluate(() => (window as unknown as { gateSocketClosed: boolean }).gateSocketClosed),
        { timeout: 20_000 },
      )
      .toBe(true);
    expect(Date.now() - started).toBeLessThan(305_000);
  });
}
