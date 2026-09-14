import { createHmac } from "node:crypto";

import { expect, test } from "@playwright/test";

function totp(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of secret) bits += alphabet.indexOf(character).toString(2).padStart(5, "0");
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((byte) => Number.parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const hash = createHmac("sha1", key).update(counter).digest();
  const offset = hash.at(-1)! & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("fresh owner completes MFA acknowledgement and custom-domain onboarding", async ({ page }) => {
  const setupToken = process.env.ARK_E2E_SETUP_TOKEN;
  const password = process.env.ARK_E2E_OWNER_PASSWORD;
  const domain = process.env.ARK_E2E_DOMAIN;
  expect(setupToken, "The disposable E2E harness must provide a setup token").toBeTruthy();
  expect(password, "The disposable E2E harness must provide an owner password").toBeTruthy();
  expect(domain, "The disposable E2E harness must provide a non-production domain").toBeTruthy();

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Create the owner" })).toBeVisible();
  await page.getByLabel("Name").fill("Browser Acceptance Owner");
  await page.getByLabel("Email").fill("browser-acceptance@example.test");
  await page.getByLabel("Password").fill(password!);
  await page.getByLabel("Setup token").fill(setupToken!);
  await page.getByRole("button", { name: "Create administrator" }).click();

  await expect(page.getByRole("heading", { name: "Secure the owner account" })).toBeVisible();
  const blocked = await page.evaluate(async () => {
    const response = await fetch("/api/projects", {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Must fail", slug: "must-fail" }),
    });
    return response.status;
  });
  expect(blocked).toBe(403);

  await page.getByLabel("Confirm your password").fill(password!);
  await page.getByRole("button", { name: "Create TOTP enrollment" }).click();
  const secret = (await page.locator("code").textContent())!.trim();
  const recoveryCode = (await page.locator("li").first().textContent())!.trim();
  await page.getByLabel("Six-digit verification code").fill("000000");
  await page.getByRole("button", { name: "Verify TOTP" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await page.getByLabel("Six-digit verification code").fill(totp(secret));
  await page.getByRole("button", { name: "Verify TOTP" }).click();

  const continueButton = page.getByRole("button", { name: "Continue to domain setup" });
  await expect(continueButton).toBeDisabled();
  await page.getByLabel("I saved the recovery codes outside this browser.").check();
  await continueButton.click();

  await page.getByLabel("Base domain").fill(domain!);
  await page.getByLabel("Public IPv4").fill("203.0.113.10");
  await page.getByLabel("Public IPv6 (optional)").fill("2001:db8::10");
  await page.getByLabel("Admin hostname (optional)").fill(`desk.${domain}`);
  await page.getByLabel("Database hostname (optional)").fill(`postgres.${domain}`);
  await page.getByLabel("Mail hostname (optional)").fill(`mx.${domain}`);
  await page.getByLabel("First database name").fill("orders");
  await page.getByLabel("First mailbox local part").fill("hello");
  await page.getByRole("button", { name: "Generate DNS plan and continue" }).click();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await expect(page.getByText(domain!, { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByLabel("Email").fill("browser-acceptance@example.test");
  await page.getByLabel("Password").fill(password!);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByLabel("Verification code").fill(recoveryCode);
  await page.getByLabel("Use a recovery code").check();
  await page.getByRole("button", { name: "Verify and sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByLabel("Email").fill("browser-acceptance@example.test");
  await page.getByLabel("Password").fill(password!);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByLabel("Verification code").fill(recoveryCode);
  await page.getByLabel("Use a recovery code").check();
  await page.getByRole("button", { name: "Verify and sign in" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Verify your sign-in" })).toBeVisible();
});
