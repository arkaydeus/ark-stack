import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createId } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";

import { app } from "./app.ts";
import { auth } from "./auth.ts";
import { sql } from "./db.ts";

test("mail-disabled API rejects mailbox provisioning without recording changes or claiming old work", async () => {
  const prevMail = process.env.ARK_MAIL_ENABLED;
  const ctx = await auth.$context;
  const user = await ctx.internalAdapter.createUser(
    { name: "Mail disabled fixture", email: `${createId("usr")}@example.test`, emailVerified: true },
    { method: "email-password" },
  );
  const domain = createId("dom");
  const oldJob = createId("op");
  const origin = new URL(process.env.BETTER_AUTH_URL!).origin;
  try {
    await sql`INSERT INTO platform_access (user_id, role) VALUES (${user.id}, 'owner')`;
    await sql`
      UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute'
      WHERE id = ${user.id}
    `;
    const session = await ctx.internalAdapter.createSession(user.id, false, { origin: "admin" });
    const signature = await makeSignature(session.token, ctx.secret);
    await sql`
      INSERT INTO domain_claims (id, name, ownership_token, status)
      VALUES (${domain}, ${`${domain}.example.test`}, 'ark-mail-disabled-fixture', 'verified')
    `;
    await sql`
      INSERT INTO operations (id, kind, actor_id, idempotency_key, plan_hash, target_ids, status)
      VALUES (${oldJob}, 'mail.provision', ${user.id}, ${oldJob}, 'test', '[]', 'queued')
    `;
    process.env.ARK_MAIL_ENABLED = "0";
    const response = await app.request(`${origin}/api/mailboxes`, {
      method: "POST",
      headers: {
        cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${session.token}.${signature}`)}`,
        origin,
        "content-type": "application/json",
      },
      body: JSON.stringify({ domainId: domain, localPart: "hello", displayName: "Hello", quotaGb: 1 }),
    });
    expect(response.status, await response.clone().text()).toBe(503);
    expect(await response.json()).toEqual({ error: "Mail is disabled on this installation." });
    expect(await sql`SELECT id FROM mailboxes WHERE domain_id = ${domain}`).toHaveLength(0);
    expect([...(await sql`SELECT id, status FROM operations WHERE actor_id = ${user.id}`)]).toEqual([
      { id: oldJob, status: "queued" },
    ]);
    const claim = await app.request("/api/internal/jobs", {
      headers: {
        authorization: `Bearer ${process.env.ARK_MAIL_WORKER_TOKEN}`,
        "x-ark-worker-kinds": "mail.,mailbox.,ses.",
      },
    });
    expect(claim.status).toBe(200);
    expect(await claim.json()).toEqual({ jobs: [] });
  } finally {
    if (prevMail === undefined) delete process.env.ARK_MAIL_ENABLED;
    else process.env.ARK_MAIL_ENABLED = prevMail;
    await sql`DELETE FROM operations WHERE actor_id = ${user.id}`;
    await sql`DELETE FROM domain_claims WHERE id = ${domain}`;
    await sql`DELETE FROM "user" WHERE id = ${user.id}`;
  }
});

test("authenticated Prometheus scrape reports the host reboot flag and enabled workers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ark-host-metrics-"));
  const original = {
    ARK_MAIL_ENABLED: process.env.ARK_MAIL_ENABLED,
    ARK_HOST_METRICS_DIR: process.env.ARK_HOST_METRICS_DIR,
  };
  const route = "/api/metrics/prometheus";
  const headers = { authorization: `Bearer ${process.env.ARK_METRICS_TOKEN}` };
  try {
    process.env.ARK_HOST_METRICS_DIR = directory;
    process.env.ARK_MAIL_ENABLED = "0";
    expect((await app.request(route)).status).toBe(401);
    const scrape = async () => {
      const response = await app.request(route, { headers });
      expect(response.status, await response.clone().text()).toBe(200);
      return response.text();
    };
    expect(await scrape()).not.toContain("ark_host_reboot_required");
    await writeFile(join(directory, "reboot-required"), "/run/reboot-required\n");
    const pending = await scrape();
    expect(pending).toContain("ark_host_reboot_required 1\n");
    expect(pending).not.toContain('ark_worker_heartbeat_stale{identity="mail"}');
    process.env.ARK_MAIL_ENABLED = "1";
    await writeFile(join(directory, "reboot-required"), "");
    const clear = await scrape();
    expect(clear).toContain("ark_host_reboot_required 0\n");
    expect(clear).toContain('ark_worker_heartbeat_stale{identity="mail"}');
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(directory, { recursive: true, force: true });
  }
});
