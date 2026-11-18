// FD-16 §3.14: a database endpoint certificate is not "serving" until PgBouncer has reloaded it
// through the admin socket and the served fingerprint matches. A failing reload is retried, raises
// an alert and fails the operation; the expiry alert keeps tracking the certificate still served.
import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { PGBOUNCER_FILES, encryptSecret, generateInstallSecrets, parseEnvFile } from "@ark-stack/shared";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { runOperation, enqueue, PGBOUNCER_RELOAD_ALERT } = await import("./coordinator.ts");
const { poolerEdgeInput } = await import("./modules/pooler-policy.ts");
const { evaluateAlerts } = await import("./modules/alerts.ts");
const pooler = await import("./modules/pgbouncer.ts");
const { PgbouncerReloadError } = pooler;
const pki = await import("./modules/pki.ts");
const { db } = await import("./db.ts");
const {
  alerts,
  certificates,
  endpoints,
  operationSteps,
  operations,
  databaseClusters,
  managedDatabases,
  databaseRoles,
  databaseClients,
  platformSettings,
  privateCas,
  secrets,
} = await import("./schema.ts");
const { createId } = await import("@ark-stack/shared");
const { and, eq, gte, inArray } = await import("drizzle-orm");

const overrides: Record<string, string> = {};
const saved: Record<string, string | undefined> = {};
let work = "";
const endpointId = createId("end");
const hostname = `db-${endpointId.toLowerCase().replaceAll("_", "-")}.example.test`;
const operationIds: string[] = [];
const startedAt = new Date();
const clusterId = createId("dcl");
const databaseId = createId("mdb");
const roleId = createId("dbr");
const clientId = createId("dbc");
const secretId = createId("sec");
let caId = "";
let caKeyId = "";
let clientKeyId: string | null = null;
let savedPooler: Partial<typeof platformSettings.$inferSelect> | null = null;

beforeAll(async () => {
  work = await mkdtemp(join(tmpdir(), "ark-pgbouncer-reload-"));
  Object.assign(overrides, {
    ARK_PGBOUNCER_DIR: join(work, "pgbouncer"),
    ARK_CERT_DIR: join(work, "certs"),
    ARK_CERTIFICATE_MODE: "development",
    ARK_APPLY_NFT: "0",
    ARK_EMBEDDED_WORKERS: "1",
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
  // The public test database requests an unrestricted pooler (no CIDRs), so adopt exactly that as the
  // explicit pooler-wide policy (FD-26): without it the database could never become ready.
  const [current] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  savedPooler = current
    ? {
        poolerSourceCidrs: current.poolerSourceCidrs,
        poolerAllowInternet: current.poolerAllowInternet,
        poolerInternetConfirmedAt: current.poolerInternetConfirmedAt,
        poolerFencedAt: current.poolerFencedAt,
        poolerFenceReason: current.poolerFenceReason,
      }
    : null;
  const openPooler = {
    poolerSourceCidrs: [],
    poolerAllowInternet: true,
    poolerInternetConfirmedAt: new Date(),
  };
  await db
    .insert(platformSettings)
    .values({ id: "default", ...openPooler })
    .onConflictDoUpdate({ target: platformSettings.id, set: openPooler });
  await db
    .insert(endpoints)
    .values({ id: endpointId, kind: "database", hostname, exposure: "public", status: "verified" });
});

afterAll(async () => {
  if (savedPooler)
    await db.update(platformSettings).set(savedPooler).where(eq(platformSettings.id, "default"));
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
  await db.delete(databaseClients).where(eq(databaseClients.id, clientId));
  await db.delete(managedDatabases).where(eq(managedDatabases.id, databaseId));
  await db.delete(databaseClusters).where(eq(databaseClusters.id, clusterId));
  if (caId) await db.delete(privateCas).where(eq(privateCas.id, caId));
  await db
    .delete(secrets)
    .where(inArray(secrets.id, [secretId, caKeyId, ...(clientKeyId ? [clientKeyId] : [])].filter(Boolean)));
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
    // No client is admitted yet: public admission is fenced at the edge before the failed reload.
    expect((await poolerEdgeInput()).pooler).toBeNull();
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
  }, 15_000);
});

// These tests keep the coordinator and database updates real. Only the admin transport and
// served-fingerprint probe are stubbed; reloadAndVerify still executes all retries and checks.
describe("payload-less renewal recovery", () => {
  test("an unrelated reload cannot clear a mismatch alert; verified recovery updates all serving state", async () => {
    const pending = (
      await db.select().from(certificates).where(eq(certificates.endpointId, endpointId))
    ).find((row) => row.status === "awaiting_reload")!;
    const ca = await pki.createPrivateCa({ purpose: "db-client", name: `reload-${clientId}` });
    caId = ca.id;
    // The inventory summary never exposes the key secret ID, so read it from the row for cleanup.
    const [caRow] = await db.select().from(privateCas).where(eq(privateCas.id, ca.id));
    caKeyId = caRow?.keySecretId ?? "";
    const issued = await pki.issueClientCertificate({
      caId,
      subjectCn: "recovery_shop_production",
      keyOwner: { resourceType: "platform", resourceId: "platform" },
    });
    clientKeyId = issued.certificate.keySecretId;
    await db.insert(databaseClusters).values({ id: clusterId, name: clusterId, endpointId });
    await db
      .insert(managedDatabases)
      .values({ id: databaseId, clusterId, name: "recoverydb", exposure: "public" });
    await db.insert(secrets).values({
      id: secretId,
      kind: "database_password",
      resourceType: "database",
      resourceId: databaseId,
      ...encryptSecret(process.env.ARK_ROOT_KEY!, "runtime-password", "k1"),
    });
    await db
      .insert(databaseRoles)
      .values({ id: roleId, databaseId, name: "recovery_shop_production", kind: "runtime", secretId });
    await db.insert(databaseClients).values({
      id: clientId,
      databaseId,
      name: "shop",
      environment: "production",
      roleKind: "runtime",
      roleId,
      caId,
    });
    const reload = await enqueue({
      kind: "pgbouncer.reload",
      targetIds: [endpointId],
      payload: { nonce: createId("n") },
    });
    operationIds.push(reload.id);
    const admin = spyOn(pooler, "reloadPgbouncerAdmin").mockResolvedValue(undefined);
    const fingerprint = spyOn(pooler, "servedCertificateFingerprint").mockResolvedValue("ff".repeat(32));
    try {
      await expect(runOperation("pgbouncer.reload", reload)).rejects.toBeInstanceOf(PgbouncerReloadError);
      expect(fingerprint).toHaveBeenCalledTimes(3);
      let [alert] = await db.select().from(alerts).where(eq(alerts.dedupKey, PGBOUNCER_RELOAD_ALERT));
      expect(alert!.resolvedAt).toBeNull();
      let [certificate] = await db.select().from(certificates).where(eq(certificates.id, pending.id));
      expect(certificate!.status).toBe("awaiting_reload");
      expect(certificate!.lastDeployedAt).toBeNull();
      fingerprint.mockResolvedValue(pending.fingerprint!);
      await runOperation("pgbouncer.reload", reload);
      [certificate] = await db.select().from(certificates).where(eq(certificates.id, pending.id));
      expect(certificate!.status).toBe("untrusted"); // the development certificate is self-signed
      expect(certificate!.lastDeployedAt).toBeInstanceOf(Date);
      const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, endpointId));
      expect(endpoint!.status).toBe("certificate_untrusted");
      [alert] = await db.select().from(alerts).where(eq(alerts.dedupKey, PGBOUNCER_RELOAD_ALERT));
      expect(alert!.resolvedAt).toBeInstanceOf(Date);
      const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, databaseId));
      expect(database!.status).toBe("ready");
      // A confirmed reload with an admitted client lifts the fence: PgBouncer is routed on 5432.
      const edge = await poolerEdgeInput();
      expect(edge.fence).toBeNull();
      expect(edge.pooler).toMatchObject({ hostname, allowInternet: true, sourceCidrs: [] });
      expect(edge.evaluation.status).toBe("published");

      // Publicly trusted renewals use the same recovery path and become issued/testing.
      await db
        .update(certificates)
        .set({ status: "awaiting_reload", issuer: "letsencrypt", lastDeployedAt: null })
        .where(eq(certificates.id, pending.id));
      await runOperation("pgbouncer.reload", reload);
      const [trusted] = await db.select().from(certificates).where(eq(certificates.id, pending.id));
      expect(trusted!.status).toBe("issued");
      const [testing] = await db.select().from(endpoints).where(eq(endpoints.id, endpointId));
      expect(testing!.status).toBe("testing");
    } finally {
      admin.mockRestore();
      fingerprint.mockRestore();
    }
  });

  test("installer's relative certificate directory works through coordinator rendering", async () => {
    const previous = process.env.ARK_CERT_DIR;
    const reloadRequired = process.env.ARK_PGBOUNCER_RELOAD;
    const directory = generateInstallSecrets().ARK_CERT_DIR;
    process.env.ARK_CERT_DIR = directory;
    process.env.ARK_PGBOUNCER_RELOAD = "0";
    try {
      const operation = await enqueue({
        kind: "pgbouncer.reload",
        targetIds: [endpointId],
        payload: { nonce: createId("n") },
      });
      operationIds.push(operation.id);
      await runOperation("pgbouncer.reload", operation);
      const config = await Bun.file(join(overrides.ARK_PGBOUNCER_DIR!, PGBOUNCER_FILES.config)).text();
      expect(config).toContain(`client_tls_cert_file = ${resolve(directory, hostname)}/fullchain.pem`);
      expect(config).toContain(`client_tls_key_file = ${resolve(directory, hostname)}/privkey.pem`);
    } finally {
      process.env.ARK_CERT_DIR = previous;
      process.env.ARK_PGBOUNCER_RELOAD = reloadRequired;
    }
  });
});

test("revoking the last client fences public admission at the edge before a failed admin reload", async () => {
  // PgBouncer keeps its old admission configuration when RELOAD fails; the edge must stop routing to it.
  expect((await poolerEdgeInput()).pooler).not.toBeNull();
  await db.update(databaseClients).set({ status: "revoked" }).where(eq(databaseClients.id, clientId));
  const operation = await enqueue({
    kind: "pgbouncer.reload",
    targetIds: [endpointId],
    payload: { nonce: createId("n") },
  });
  operationIds.push(operation.id);
  const result = await runOperation("pgbouncer.reload", operation).catch((error: unknown) => error);
  expect(result).toBeInstanceOf(PgbouncerReloadError);
  const edge = await poolerEdgeInput();
  expect(edge.fence?.reason).toBe("no-admitted-client");
  expect(edge.pooler).toBeNull();
  // The retirement watchdog's fallback is the same durable edge fence.
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  expect(settings!.poolerFencedAt).toBeInstanceOf(Date);
}, 15_000);

test("startup installs ingress limits without reopening a revoked client or rewriting pooler files", async () => {
  const previousDir = process.env.ARK_PGBOUNCER_DIR;
  const dir = join(work, "startup-revoked");
  await mkdir(dir);
  await Bun.write(join(dir, PGBOUNCER_FILES.config), "existing pooler configuration\n");
  process.env.ARK_PGBOUNCER_DIR = dir;
  const admin = spyOn(pooler, "reloadPgbouncerAdmin").mockImplementation(async () => {
    throw new Error("Startup policy reconciliation must not reload PgBouncer.");
  });
  try {
    const operation = await enqueue({
      kind: "pgbouncer.reload",
      targetIds: [],
      payload: { reason: "startup-db-ingress-policy" },
    });
    operationIds.push(operation.id);
    await runOperation("pgbouncer.reload", operation);
    // No exposure toggle any more (FD-26): 5432 belongs to the edge, which renders be_pgbouncer.
    expect(await Bun.file(join(dir, "expose")).exists()).toBe(false);
    expect(await Bun.file(join(dir, PGBOUNCER_FILES.config)).text()).toBe("existing pooler configuration\n");
    const rules = await Bun.file(join(dir, "allowlist.nft")).text();
    // Limits only: no port-wide CIDR list that would also cut off Postgres routes on 5432.
    expect(rules).toContain("# ark-db-ingress: allowlist=open");
    expect(rules).toContain("ct count over 128");
    expect(rules).toContain("limit rate over 30/second burst 60 packets");
    expect(admin).not.toHaveBeenCalled();
    const steps = await db.select().from(operationSteps).where(eq(operationSteps.operationId, operation.id));
    expect(steps.some((step) => step.name === "db-ingress-startup")).toBe(true);
  } finally {
    admin.mockRestore();
    process.env.ARK_PGBOUNCER_DIR = previousDir;
  }
});
