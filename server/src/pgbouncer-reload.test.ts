// FD-16 §3.14: a database endpoint certificate is not "serving" until PgBouncer has reloaded it
// through the admin socket and the served fingerprint matches. A failing reload is retried, raises
// an alert and fails the operation; the expiry alert keeps tracking the certificate still served.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PGBOUNCER_FILES, parseEnvFile } from "@ark-stack/shared";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { runOperation, enqueue, PGBOUNCER_RELOAD_ALERT } = await import("./coordinator.ts");
const { evaluateAlerts } = await import("./modules/alerts.ts");
const { PgbouncerReloadError } = await import("./modules/pgbouncer.ts");
const { db } = await import("./db.ts");
const { alerts, certificates, endpoints, operationSteps, operations } = await import("./schema.ts");
const { createId } = await import("@ark-stack/shared");
const { and, eq, gte, inArray } = await import("drizzle-orm");

const overrides: Record<string, string> = {};
const saved: Record<string, string | undefined> = {};
let work = "";
const endpointId = createId("end");
const hostname = `db-${endpointId.toLowerCase().replaceAll("_", "-")}.example.test`;
const operationIds: string[] = [];
const startedAt = new Date();

beforeAll(async () => {
  work = await mkdtemp(join(tmpdir(), "ark-pgbouncer-reload-"));
  Object.assign(overrides, {
    ARK_PGBOUNCER_DIR: join(work, "pgbouncer"),
    ARK_CERT_DIR: join(work, "certs"),
    ARK_CERTIFICATE_MODE: "development",
    ARK_PGBOUNCER_RELOAD: "1",
    ARK_PGBOUNCER_ADMIN_PASSWORD: "test-admin-password",
    // No PgBouncer listens here: every RELOAD attempt fails.
    ARK_PGBOUNCER_SOCKET_DIR: join(work, "no-socket"),
    ARK_PGBOUNCER_RELOAD_ATTEMPTS: "3",
    ARK_PGBOUNCER_RELOAD_RETRY_MS: "1",
  });
  for (const [name, value] of Object.entries(overrides)) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  delete saved.ARK_LEGO_BIN;
  await db
    .insert(endpoints)
    .values({ id: endpointId, kind: "database", hostname, exposure: "public", status: "verified" });
});

afterAll(async () => {
  for (const name of Object.keys(overrides)) {
    if (saved[name] === undefined) delete process.env[name];
    else process.env[name] = saved[name];
  }
  if (operationIds.length) {
    await db.update(operations).set({ status: "failed" }).where(inArray(operations.id, operationIds));
  }
  // Renewal also enqueues a platform edge.apply; leave nothing queued for other tests' workers.
  await db
    .update(operations)
    .set({ status: "failed" })
    .where(
      and(
        eq(operations.kind, "edge.apply"),
        eq(operations.status, "queued"),
        gte(operations.createdAt, startedAt),
      ),
    );
  await db.update(alerts).set({ resolvedAt: new Date() }).where(eq(alerts.dedupKey, PGBOUNCER_RELOAD_ALERT));
  const certs = await db.select().from(certificates).where(eq(certificates.endpointId, endpointId));
  if (certs.length) {
    await db
      .update(alerts)
      .set({ resolvedAt: new Date() })
      .where(
        inArray(
          alerts.dedupKey,
          certs.map((item) => `cert:${item.id}`),
        ),
      );
  }
  await db.delete(endpoints).where(eq(endpoints.id, endpointId));
  if (work) await rm(work, { recursive: true, force: true });
});

async function queuedReload() {
  const rows = await db
    .select()
    .from(operations)
    .where(and(eq(operations.kind, "pgbouncer.reload"), eq(operations.status, "queued")));
  return rows.find((row) => row.targetIds.includes(endpointId));
}

describe("database endpoint certificate renewal (§3.14)", () => {
  test("renewal stores the certificate as awaiting_reload and enqueues pgbouncer.reload", async () => {
    const renew = await enqueue({
      kind: "certificate.renew",
      targetIds: [endpointId],
      payload: { nonce: createId("n") },
    });
    operationIds.push(renew.id);
    await runOperation("certificate.renew", renew);
    const [certificate] = await db.select().from(certificates).where(eq(certificates.endpointId, endpointId));
    expect(certificate?.status).toBe("awaiting_reload");
    expect(certificate?.lastDeployedAt).toBeNull();
    expect(certificate?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, endpointId));
    expect(endpoint?.status).toBe("verified");
    const reload = await queuedReload();
    expect(reload).toBeDefined();
    operationIds.push(reload!.id);
    expect(reload!.payload).toEqual({
      certificateId: certificate!.id,
      expectFingerprint: certificate!.fingerprint,
    });
  });

  test("a failing reload is retried, alerts, and never marks the certificate serving", async () => {
    // The previous certificate is still the one PgBouncer serves, and it expires in three days.
    const servedId = createId("crt");
    await db.insert(certificates).values({
      id: servedId,
      endpointId,
      names: [hostname],
      issuer: "letsencrypt",
      fingerprint: "ab".repeat(32),
      expiresAt: new Date(Date.now() + 3 * 86_400_000),
      status: "issued",
      lastDeployedAt: new Date(Date.now() - 86_400_000),
    });
    const reload = (await db.select().from(operations).where(eq(operations.id, operationIds[1]!)))[0]!;
    const error = await runOperation("pgbouncer.reload", reload).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(PgbouncerReloadError);
    expect((error as InstanceType<typeof PgbouncerReloadError>).attempts).toBe(3);

    const steps = await db.select().from(operationSteps).where(eq(operationSteps.operationId, reload.id));
    const failed = steps.find((step) => step.name === "pgbouncer-reload-failed");
    expect((failed!.evidence as { failures: string[] }).failures).toHaveLength(3);
    expect(steps.some((step) => step.name === "pgbouncer-reload")).toBe(false);

    const [alert] = await db.select().from(alerts).where(eq(alerts.dedupKey, PGBOUNCER_RELOAD_ALERT));
    expect(alert?.severity).toBe("critical");
    expect(alert?.resolvedAt).toBeNull();
    expect(alert?.title).toMatch(/renewed database certificate is not being served/);

    const renewed = (
      await db.select().from(certificates).where(eq(certificates.endpointId, endpointId))
    ).find((item) => item.id !== servedId);
    expect(renewed?.status).toBe("awaiting_reload");
    expect(renewed?.lastDeployedAt).toBeNull();
    const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, endpointId));
    expect(endpoint?.status).toBe("verified");

    // The configuration was still written atomically, and never with an empty CA bundle.
    const bundle = await Bun.file(join(overrides.ARK_PGBOUNCER_DIR!, PGBOUNCER_FILES.caBundle)).text();
    expect(bundle).toContain("-----BEGIN CERTIFICATE-----");

    // Expiry alerting follows the certificate actually served, not the unserved renewal.
    await evaluateAlerts();
    const [expiry] = await db
      .select()
      .from(alerts)
      .where(eq(alerts.dedupKey, `cert:${servedId}`));
    expect(expiry?.severity).toBe("critical");
    expect(expiry?.resolvedAt).toBeNull();
  });
});
