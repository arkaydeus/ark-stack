import { createHmac } from "node:crypto";

import { expect, test } from "@playwright/test";
import postgres from "postgres";

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

test("fresh owner completes MFA, custom-domain onboarding and region settings", async ({ page }) => {
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

  await test.step("owner saves the region through step-up and sees persisted suggestions", async () => {
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    const form = page.locator("form").filter({ has: page.getByLabel("VPS region label (optional)") });
    await form.getByLabel("Region", { exact: true }).selectOption("eu-west");
    await form.getByLabel("VPS region label (optional)").fill("  DO lon1  ");
    await form.getByLabel("Current password").fill(password!);

    const stepUp = page.waitForResponse(
      (response) => response.url().endsWith("/api/step-up") && response.request().method() === "POST",
    );
    const put = page.waitForResponse(
      (response) => response.url().endsWith("/api/settings/region") && response.request().method() === "PUT",
    );
    await form.getByRole("button", { name: "Save", exact: true }).click();
    const granted = await stepUp;
    expect(granted.status()).toBe(200);
    expect(granted.request().postDataJSON()).toMatchObject({
      action: "platform.update",
      request: { region: "eu-west", vpsRegionLabel: "DO lon1" },
    });
    const saved = await put;
    expect(saved.status()).toBe(200);
    expect(saved.request().postDataJSON()).toEqual({ region: "eu-west", vpsRegionLabel: "DO lon1" });
    await expect(form.getByText("Region saved: EU West, Vercel dub1.", { exact: true })).toBeVisible();

    await page.reload();
    await expect(form.getByLabel("Region", { exact: true })).toHaveValue("eu-west");
    await expect(form.getByLabel("VPS region label (optional)")).toHaveValue("DO lon1");
    await expect(form.locator("code")).toHaveText('{"regions":["dub1"]}');
    await expect(form.getByText("eu-west-1", { exact: false })).toBeVisible();
  });

  await test.step("failed password and validation saves preserve edits and stored values", async () => {
    const form = page.locator("form").filter({ has: page.getByLabel("VPS region label (optional)") });
    await form.getByLabel("Region", { exact: true }).selectOption("us-west");
    await form.getByLabel("VPS region label (optional)").fill("Pending location");
    await form.getByLabel("Current password").fill("Incorrect-Password-123!");
    const denied = page.waitForResponse((response) => response.url().endsWith("/api/step-up"));
    const writes: string[] = [];
    const recordWrite = (request: import("@playwright/test").Request) => {
      if (request.url().endsWith("/api/settings/region") && request.method() === "PUT") {
        writes.push(request.postData() ?? "");
      }
    };
    page.on("request", recordWrite);
    try {
      await form.getByRole("button", { name: "Save", exact: true }).click();
      const rejected = await denied;
      expect(rejected.ok()).toBe(false);
      const passwordError = (await rejected.json()) as { error: string };
      expect(passwordError.error).toBeTruthy();
      await expect(form.getByRole("alert")).toHaveText(passwordError.error);
      await expect(form.getByLabel("Region", { exact: true })).toHaveValue("us-west");
      await expect(form.getByLabel("VPS region label (optional)")).toHaveValue("Pending location");
      expect(writes).toEqual([]);

      await form.getByLabel("Current password").fill(password!);
      await form.getByLabel("VPS region label (optional)").fill("<b>invalid</b>");
      const invalid = page.waitForResponse(
        (response) =>
          response.url().endsWith("/api/settings/region") && response.request().method() === "PUT",
      );
      await form.getByRole("button", { name: "Save", exact: true }).click();
      expect((await invalid).status()).toBe(422);
      await expect(form.getByRole("alert")).toBeVisible();
      await expect(form.getByLabel("Region", { exact: true })).toHaveValue("us-west");
      await expect(form.getByLabel("VPS region label (optional)")).toHaveValue("<b>invalid</b>");
      const stored = await page.request.get("/api/settings/region");
      expect(await stored.json()).toMatchObject({ region: "eu-west", vpsRegionLabel: "DO lon1" });
      await page.reload();
      await expect(form.getByLabel("Region", { exact: true })).toHaveValue("eu-west");
      await expect(form.getByLabel("VPS region label (optional)")).toHaveValue("DO lon1");
    } finally {
      page.off("request", recordWrite);
    }
  });

  await test.step("operators and viewers see persisted region details without edit controls", async () => {
    // Change this session's role only in the harness's disposable database, then restore it.
    // The UI and /api/state both use the real role lookup; no API responses are mocked.
    const databaseUrl = new URL(process.env.DATABASE_URL!);
    expect(["127.0.0.1", "localhost", "::1"]).toContain(databaseUrl.hostname);
    expect(databaseUrl.pathname).toMatch(/^\/ark_e2e_[a-f0-9]{12}$/);
    const sql = postgres(databaseUrl.toString(), { max: 1 });
    const me = await page.request.get("/api/me");
    const { user } = (await me.json()) as { user: { id: string } };
    try {
      for (const role of ["operator", "viewer"]) {
        await sql`UPDATE platform_access SET role = ${role} WHERE user_id = ${user.id}`;
        await page.reload();
        const card = page.locator("div.rounded-xl").filter({
          has: page.getByRole("heading", { name: "Region", exact: true }),
        });
        await expect(card.getByText("Only an owner can change the region.")).toBeVisible();
        await expect(card.getByText("DO lon1", { exact: true })).toBeVisible();
        await expect(card.locator("code")).toHaveText('{"regions":["dub1"]}');
        await expect(card.getByText("eu-west-1", { exact: false })).toBeVisible();
        await expect(card.locator("input, select, button, form")).toHaveCount(0);
      }
    } finally {
      await sql`UPDATE platform_access SET role = 'owner' WHERE user_id = ${user.id}`;
      await sql.end();
    }
    await page.reload();
    await expect(page.getByLabel("VPS region label (optional)")).toBeVisible();
    await page.getByRole("button", { name: "Overview", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  });

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
