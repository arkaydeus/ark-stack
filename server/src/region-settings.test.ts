// `GET/PUT /api/settings/region` through the real app, Better Auth sessions and step-up grants
// (front door §3.15, FD-03).

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";

import { createId, parseEnvFile, type Role } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { sql } = await import("./db.ts");
const { reconcileSes } = await import("./modules/providers.ts");

const authUrl = process.env.BETTER_AUTH_URL ?? "http://localhost:3000";
const origin = new URL(authUrl).origin;
const password = "Region-Test-Password-123!";

type Actor = { userId: string; cookie: string };
const actors = {} as Record<Role | "ownerWithoutMfa", Actor>;
let original: { region: string; vps_region_label: string | null } | undefined;

// Users, credential accounts and sessions go through Better Auth's own adapter rather than the
// HTTP sign-up route, whose per-path rate limit is shared with other test files in this process.
async function signUp(role: Role, mfa: boolean): Promise<Actor> {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `Region ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
    { method: "email-password" },
  );
  await ctx.internalAdapter.linkAccount({
    userId: created.id,
    providerId: "credential",
    accountId: created.id,
    password: await ctx.password.hash(password),
  });
  await sql`INSERT INTO platform_access (user_id, role) VALUES (${created.id}, ${role})`;
  if (mfa) {
    // Enrolled before the session below is created, so that session carries MFA assurance.
    await sql`
      UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute'
      WHERE id = ${created.id}
    `;
  }
  const session = await ctx.internalAdapter.createSession(created.id, false, { origin: "admin" });
  const signed = `${session.token}.${await makeSignature(session.token, ctx.secret)}`;
  return {
    userId: created.id,
    cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(signed)}`,
  };
}

function call(actor: Actor, path: string, init: { method?: string; body?: unknown } = {}) {
  return app.request(path, {
    method: init.method ?? "GET",
    headers: {
      cookie: actor.cookie,
      origin,
      ...(init.body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

const putRegion = (actor: Actor, body: unknown) =>
  call(actor, "/api/settings/region", { method: "PUT", body });

async function stepUp(actor: Actor, request: Record<string, unknown>) {
  const response = await call(actor, "/api/step-up", {
    method: "POST",
    body: { password, action: "platform.update", request },
  });
  expect(response.status).toBe(200);
}

beforeAll(async () => {
  [original] = await sql`SELECT region, vps_region_label FROM platform_settings WHERE id = 'default'`;
  await sql`
    INSERT INTO platform_settings (id, region, vps_region_label) VALUES ('default', 'us-east', NULL)
    ON CONFLICT (id) DO UPDATE SET region = 'us-east', vps_region_label = NULL
  `;
  actors.owner = await signUp("owner", true);
  actors.operator = await signUp("operator", true);
  actors.viewer = await signUp("viewer", true);
  actors.ownerWithoutMfa = await signUp("owner", false);
});

afterAll(async () => {
  const ids = Object.values(actors).map((actor) => actor.userId);
  if (ids.length) {
    await sql`DELETE FROM audit_events WHERE actor_id IN ${sql(ids)}`;
    await sql`DELETE FROM step_up_grants WHERE user_id IN ${sql(ids)}`;
    await sql`DELETE FROM "user" WHERE id IN ${sql(ids)}`;
  }
  if (original) {
    await sql`
      UPDATE platform_settings SET region = ${original.region}, vps_region_label = ${original.vps_region_label}
      WHERE id = 'default'
    `;
  }
});

describe("region setting API", () => {
  test("the default install reports us-east and a Vercel snippet with iad1 to every role", async () => {
    for (const role of ["owner", "operator", "viewer"] as const) {
      const response = await call(actors[role], "/api/settings/region");
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        region: "us-east",
        vercelRegion: "iad1",
        vercelConfig: { regions: ["iad1"] },
        vercelSnippet: '{"regions":["iad1"]}',
        backupRegionHint: "us-east-1",
        vpsRegionLabel: null,
      });
    }
    const state = await call(actors.viewer, "/api/state");
    expect(state.status).toBe(200);
    const body = (await state.json()) as {
      settings: { region: string };
      region: { region: string; vercelRegion: string };
    };
    expect(body.settings.region).toBe("us-east");
    expect(body.region).toMatchObject({ region: "us-east", vercelRegion: "iad1" });
  });

  test("operators and viewers get 403 even with MFA and a matching grant", async () => {
    const request = { region: "eu-west", vpsRegionLabel: null };
    for (const role of ["operator", "viewer"] as const) {
      // Viewers cannot mint grants at all; operators can, but the owner gate comes first.
      if (role === "operator") await stepUp(actors.operator, request);
      const response = await putRegion(actors[role], request);
      expect(response.status).toBe(403);
      expect(((await response.json()) as { error: string }).error).toBe("Owner access is required.");
    }
    const [row] = await sql`SELECT region FROM platform_settings WHERE id = 'default'`;
    expect(row?.region).toBe("us-east");
  });

  test("owners need MFA and a single-use step-up grant bound to the exact request", async () => {
    const request = { region: "eu-central", vpsRegionLabel: "Hetzner fsn1" };
    const noMfa = await putRegion(actors.ownerWithoutMfa, request);
    expect(noMfa.status).toBe(403);
    expect(((await noMfa.json()) as { error: string }).error).toMatch(/MFA/);

    const noGrant = await putRegion(actors.owner, request);
    expect(noGrant.status).toBe(403);
    expect(((await noGrant.json()) as { error: string }).error).toMatch(/Verify your password/);

    await stepUp(actors.owner, { ...request, vpsRegionLabel: "Hetzner nbg1" });
    const mismatched = await putRegion(actors.owner, request);
    expect(mismatched.status).toBe(403);
  });

  test("the region is validated against shared/src/region.ts without burning the grant", async () => {
    const request = { region: "us-west", vpsRegionLabel: null };
    await stepUp(actors.owner, request);
    for (const body of [
      { region: "us-east-1", vpsRegionLabel: null },
      { region: "ap-south", vpsRegionLabel: null },
      { region: "us-west", vpsRegionLabel: "<b>bold</b>" },
      { region: "us-west", vpsRegionLabel: "x".repeat(65) },
    ]) {
      expect((await putRegion(actors.owner, body)).status, JSON.stringify(body)).toBe(422);
    }
    const accepted = await putRegion(actors.owner, request);
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toMatchObject({ region: "us-west", vercelRegion: "sfo1" });
  });

  test("a change updates the Vercel and backup suggestions, audits, and leaves AWS_REGION and SES alone", async () => {
    const awsRegionBefore = process.env.AWS_REGION;
    const credentials = {
      AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
      AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
      AWS_BOOTSTRAP_ACCESS_KEY_ID: process.env.AWS_BOOTSTRAP_ACCESS_KEY_ID,
      AWS_BOOTSTRAP_SECRET_ACCESS_KEY: process.env.AWS_BOOTSTRAP_SECRET_ACCESS_KEY,
    };
    // Without credentials SES planning stays offline, so the plan shows the region it would use.
    for (const key of Object.keys(credentials)) delete process.env[key];
    try {
      const sesBefore = await reconcileSes("region.example", "bounce.region.example");

      const request = { region: "eu-central", vpsRegionLabel: "  Hetzner fsn1 " };
      await stepUp(actors.owner, request);
      const response = await putRegion(actors.owner, request);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        region: "eu-central",
        vercelRegion: "fra1",
        vercelSnippet: '{"regions":["fra1"]}',
        backupRegionHint: "eu-central-1",
        vpsRegionLabel: "Hetzner fsn1",
      });
      const [row] = await sql`
        SELECT region, vps_region_label FROM platform_settings WHERE id = 'default'
      `;
      expect(row).toEqual({ region: "eu-central", vps_region_label: "Hetzner fsn1" });
      const read = await call(actors.viewer, "/api/settings/region");
      expect(await read.json()).toMatchObject({ vercelRegion: "fra1", backupRegionHint: "eu-central-1" });

      const [event] = await sql`
        SELECT action, resource_type, resource_id, role, detail FROM audit_events
        WHERE actor_id = ${actors.owner.userId} AND action = 'settings.region'
        ORDER BY created_at DESC LIMIT 1
      `;
      expect(event).toMatchObject({
        action: "settings.region",
        resource_type: "platform",
        resource_id: "platform",
        role: "owner",
        detail: {
          region: "eu-central",
          vpsRegionLabel: "Hetzner fsn1",
          previous: { region: "us-west", vpsRegionLabel: null },
        },
      });

      // The grant was single use.
      expect((await putRegion(actors.owner, request)).status).toBe(403);

      // SES keeps its own region: the environment and the SES plan are unchanged.
      expect(process.env.AWS_REGION).toBe(awsRegionBefore);
      const sesAfter = await reconcileSes("region.example", "bounce.region.example");
      expect(sesAfter).toEqual(sesBefore);
      expect(sesAfter.region).toBe(awsRegionBefore ?? "eu-west-1");
    } finally {
      for (const [key, value] of Object.entries(credentials)) {
        if (value !== undefined) process.env[key] = value;
      }
    }
  });

  test.each([
    { request: { region: "eu-west" }, label: null },
    { request: { region: "eu-west", vpsRegionLabel: "" }, label: null },
    { request: { region: "eu-west", vpsRegionLabel: "   " }, label: null },
    { request: { region: "eu-west", vpsRegionLabel: "  DO lon1  " }, label: "DO lon1" },
  ])("binds the original request and stores the normalized label: %j", async ({ request, label }) => {
    await stepUp(actors.owner, request);
    const response = await putRegion(actors.owner, request);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ region: "eu-west", vpsRegionLabel: label });
    const [row] = await sql`
      SELECT region, vps_region_label FROM platform_settings WHERE id = 'default'
    `;
    expect(row).toEqual({ region: "eu-west", vps_region_label: label });
    expect((await putRegion(actors.owner, request)).status).toBe(403);
  });
});
