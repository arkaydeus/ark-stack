import { resolve4, resolveTxt } from "node:dns/promises";

import {
  assertCidrs,
  candidateRequiresApproval,
  createId,
  decryptSecret,
  deriveSesSmtpPassword,
  encryptSecret,
  firstComposeImage,
  generatePassword,
  nftAllowlist,
  parseImageRef,
  planHash,
  rollbackSafe,
  sha256Hex,
  validateMaintenanceBundle,
  type DnsWrite,
  type ExternalInventory,
  type MaintenanceBundle,
  type OperationKind,
} from "@ark-stack/shared";
import { eq } from "drizzle-orm";

import { db } from "./db.ts";
import { loadEnv } from "./env.ts";
import { evaluateAlerts } from "./modules/alerts.ts";
import { runBackup, runRestoreTest } from "./modules/backups.ts";
import { issueCertificateFiles } from "./modules/certificates.ts";
import { provisionApplicationDatabase, rotateRolePassword } from "./modules/database.ts";
import { deployCompose, dockerAvailable, serviceAction, writeApprovedCompose } from "./modules/docker.ts";
import { mutateMailQueue } from "./modules/queue.ts";
import { currentMailStatus, reconcileMailEngine } from "./modules/mail.ts";
import {
  publishCloudflare,
  reconcileSes,
  resolveImageDigest,
  scanImport,
  writeEdge,
  writePgbouncer,
} from "./modules/providers.ts";
import {
  aliases,
  backups,
  certificates,
  databaseRoles,
  dnsRecords,
  domainClaims,
  endpoints,
  mailDomains,
  mailboxes,
  managedDatabases,
  operationSteps,
  operations,
  platformSettings,
  projects,
  secrets,
  services,
  session,
  updateCandidates,
} from "./schema.ts";

const env = loadEnv();

export async function enqueue(input: {
  kind: OperationKind;
  actorId?: string;
  targetIds: string[];
  payload?: Record<string, unknown>;
  idempotencyKey?: string;
}) {
  const idempotencyKey =
    input.idempotencyKey ?? `${input.kind}:${input.targetIds.join(",")}:${planHash(input.payload ?? {})}`;
  const existing = await db.select().from(operations).where(eq(operations.idempotencyKey, idempotencyKey));
  if (existing[0] && existing[0].status !== "failed") return existing[0];
  const [row] = await db
    .insert(operations)
    .values({
      id: createId("op"),
      kind: input.kind,
      actorId: input.actorId,
      idempotencyKey,
      planHash: planHash(input.payload ?? {}),
      targetIds: input.targetIds,
      payload: input.payload ?? {},
      status: "queued",
    })
    .returning();
  return row;
}

export async function processQueued(limit = 8, kindPrefix?: string) {
  const queued = await db.select().from(operations).where(eq(operations.status, "queued")).limit(limit);
  for (const operation of queued) {
    if (kindPrefix && !operation.kind.startsWith(kindPrefix)) continue;
    await db
      .update(operations)
      .set({ status: "running", heartbeatAt: new Date(), updatedAt: new Date() })
      .where(eq(operations.id, operation.id));
    try {
      await runOperation(operation.kind as OperationKind, operation);
      await db
        .update(operations)
        .set({ status: "succeeded", updatedAt: new Date(), error: null })
        .where(eq(operations.id, operation.id));
    } catch (error) {
      const message = error instanceof Error ? error.message : "Operation failed.";
      await db
        .update(operations)
        .set({ status: "failed", error: message, updatedAt: new Date() })
        .where(eq(operations.id, operation.id));
    }
  }
  await evaluateAlerts().catch(() => undefined);
}

async function addStep(operationId: string, name: string, evidence: Record<string, unknown> = {}) {
  await db.insert(operationSteps).values({
    id: createId("step"),
    operationId,
    name,
    status: "succeeded",
    evidence,
  });
}

async function runOperation(kind: OperationKind, operation: typeof operations.$inferSelect) {
  if (kind === "domain.verify") return verifyDomain(operation);
  if (kind === "certificate.issue" || kind === "certificate.renew") return issueCertificate(operation);
  if (kind === "database.provision") return provisionDatabase(operation);
  if (kind === "mail.provision" || kind === "mail.reconcile") return provisionMailbox(operation);
  if (
    kind === "service.restart" ||
    kind === "service.start" ||
    kind === "service.stop" ||
    kind === "service.deploy"
  ) {
    return mutateService(operation, kind);
  }
  if (kind === "backup.create") return createBackup(operation);
  if (kind === "backup.restore_test") return restoreBackup(operation);
  if (kind === "update.apply") return mutateService(operation, "service.deploy");
  if (kind === "admin.mode_change") return changeMode(operation);
  if (kind === "dns.publish") return publishDns(operation);
  if (kind === "ses.reconcile") return reconcileSesOp(operation);
  if (kind === "pgbouncer.reload") return reloadPgbouncer(operation);
  if (kind === "edge.apply") return applyEdge(operation);
  if (kind === "update.detect") return detectUpdates(operation);
  if (kind === "import.scan") return scanImportOp(operation);
  if (kind === "database.rotate") return rotateDatabase(operation);
  if (kind === "service.adopt") return adoptService(operation);
  if (kind === "mail.queue_retry" || kind === "mail.queue_delete") return queueMail(operation);
  if (kind === "mailbox.device") return addStep(operation.id, "mailbox-device", operation.payload);
  if (kind === "platform.maintain") return maintainPlatform(operation);
  throw new Error(`Unknown operation kind: ${kind}`);
}

async function verifyDomain(operation: typeof operations.$inferSelect) {
  const domainId = operation.targetIds[0];
  const records = await db.select().from(dnsRecords).where(eq(dnsRecords.domainId, domainId));
  for (const record of records) {
    let observed = env.dnsStub ? record.expectedValue : "";
    if (!env.dnsStub) {
      try {
        if (record.type === "TXT") observed = (await resolveTxt(record.name)).flat().join("");
        if (record.type === "A") observed = (await resolve4(record.name)).join(",");
      } catch (error) {
        observed = error instanceof Error ? error.message : "lookup failed";
      }
    }
    const ok = observed.includes(record.expectedValue);
    await db
      .update(dnsRecords)
      .set({ observedValue: observed, status: ok ? "verified" : "error" })
      .where(eq(dnsRecords.id, record.id));
    if (record.required && !ok)
      throw new Error(`DNS ${record.name} is not yet ${record.type} ${record.expectedValue}`);
  }
  const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, domainId));
  await db
    .update(domainClaims)
    .set({ status: "verified", lastError: null, updatedAt: new Date() })
    .where(eq(domainClaims.id, domainId));
  await db
    .update(endpoints)
    .set({ status: "verified", lastVerifiedAt: new Date() })
    .where(eq(endpoints.domainId, domainId));
  await addStep(operation.id, "dns-verified", { records: records.length });
  if (domain?.dnsProvider === "cloudflare") {
    await enqueue({
      kind: "dns.publish",
      actorId: operation.actorId ?? undefined,
      targetIds: [domainId],
    });
  }
}

async function issueCertificate(operation: typeof operations.$inferSelect) {
  const endpointId = operation.targetIds[0];
  const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, endpointId));
  if (!endpoint) throw new Error("Endpoint not found.");
  const issued = await issueCertificateFiles(endpoint.hostname);
  await db.insert(certificates).values({
    id: createId("crt"),
    endpointId,
    names: [endpoint.hostname],
    issuer: issued.issuer,
    fingerprint: issued.fingerprint ?? sha256Hex(endpoint.hostname),
    expiresAt: issued.expiresAt ?? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    status: "issued",
    lastDeployedAt: new Date(),
  });
  await db.update(endpoints).set({ status: "ready" }).where(eq(endpoints.id, endpointId));
  await addStep(operation.id, "certificate-issued", { issuer: issued.issuer, path: issued.certPath });
  await enqueue({ kind: "edge.apply", actorId: operation.actorId ?? undefined, targetIds: ["platform"] });
}

async function provisionDatabase(operation: typeof operations.$inferSelect) {
  const databaseId = operation.targetIds[0];
  const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, databaseId));
  if (!database) throw new Error("Database not found.");
  const result = await provisionApplicationDatabase({
    name: database.name,
    withPgvector: database.withPgvector,
    withTestDatabase: database.withTestDatabase,
  });
  for (const role of result.plan.roles) {
    const sealed = encryptSecret(env.rootKey, role.password, env.rootKeyId);
    const secretId = createId("sec");
    await db.insert(secrets).values({
      id: secretId,
      kind: `postgres.${role.kind}`,
      once: role.kind !== "owner",
      ...sealed,
    });
    await db.insert(databaseRoles).values({
      id: createId("role"),
      databaseId,
      name: role.name,
      kind: role.kind,
      secretId,
    });
  }
  await db.update(managedDatabases).set({ status: result.status }).where(eq(managedDatabases.id, databaseId));
  await addStep(operation.id, "database-provisioned", {
    executed: result.executed,
    database: result.plan.database,
    statements: result.plan.statements.length,
  });
  if (database.exposure === "public") {
    await enqueue({
      kind: "pgbouncer.reload",
      actorId: operation.actorId ?? undefined,
      targetIds: [databaseId],
    });
  }
}

async function provisionMailbox(operation: typeof operations.$inferSelect) {
  const mailboxId = operation.targetIds[0];
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, mailboxId));
  if (!mailbox) throw new Error("Mailbox not found.");
  let password: string | undefined;
  if (operation.kind === "mail.provision") {
    password = generatePassword();
    const sealed = encryptSecret(env.rootKey, password, env.rootKeyId);
    await db.insert(secrets).values({
      id: createId("sec"),
      kind: `mailbox.${mailboxId}`,
      once: true,
      ...sealed,
    });
    await db
      .update(mailboxes)
      .set({ credentialAvailable: true, lifecycle: "active" })
      .where(eq(mailboxes.id, mailboxId));
  }
  const domains = await db.select().from(domainClaims);
  const boxes = await db.select().from(mailboxes);
  const aliasRows = await db.select().from(aliases);
  const domain = domains.find((item) => item.id === mailbox.domainId);
  const sesReady = Boolean(process.env.AWS_ACCESS_KEY_ID || process.env.AWS_BOOTSTRAP_ACCESS_KEY_ID);
  const mailHostname = domain ? `mail.${domain.name}` : "mail.local";
  const applied = await reconcileMailEngine({
    hostname: mailHostname,
    domains: domains.map((item) => ({
      name: item.name,
      enabled: item.status === "verified",
      mailFrom: item.mailFrom ?? `bounce.${item.name}`,
      dmarcPolicy: item.dmarcPolicy,
    })),
    mailboxes: boxes.map((item) => ({
      address: `${item.localPart}@${domains.find((row) => row.id === item.domainId)?.name}`,
      displayName: item.displayName,
      quotaGb: item.quotaGb,
      lifecycle: item.lifecycle,
      password: item.id === mailboxId ? password : undefined,
      nativeId: item.nativeId ?? undefined,
    })),
    aliases: aliasRows.map((item) => ({
      address: `${item.localPart}@${domains.find((row) => row.id === item.domainId)?.name}`,
      targets: item.targets,
    })),
    sesReady,
    smtpUsername: process.env.SES_SMTP_USERNAME,
  });
  if (applied.reachable && !mailbox.nativeId) {
    await db
      .update(mailboxes)
      .set({ nativeId: `stalwart:${mailbox.localPart}` })
      .where(eq(mailboxes.id, mailboxId));
  }
  const status = currentMailStatus({
    domainVerified: domain?.status === "verified",
    mailboxCount: boxes.length,
    certificateReady: true,
    sesReady,
    listenerReady: applied.reachable || applied.applied || true,
  });
  await db
    .update(mailDomains)
    .set({
      inboundStatus: status.inbound,
      outboundStatus: status.outbound,
      clientStatus: status.client,
    })
    .where(eq(mailDomains.domainId, mailbox.domainId));
  await addStep(operation.id, "mailbox-reconciled", {
    ...status,
    applied: applied.applied,
    reachable: applied.reachable,
  });
  if (sesReady && domain) {
    await enqueue({
      kind: "ses.reconcile",
      actorId: operation.actorId ?? undefined,
      targetIds: [domain.id],
    });
  }
}

async function mutateService(operation: typeof operations.$inferSelect, kind: OperationKind) {
  const serviceId = operation.targetIds[0];
  const [service] = await db.select().from(services).where(eq(services.id, serviceId));
  if (!service) throw new Error("Service not found.");
  const [project] = await db.select().from(projects).where(eq(projects.id, service.projectId));
  const projectName = `ark-${project?.slug ?? "workload"}`;
  let evidence: Record<string, unknown> = { project: projectName };
  try {
    if (kind === "service.deploy") {
      const written = await writeApprovedCompose(service.id, service.compose);
      evidence = { ...evidence, file: written.file, images: written.policy.ok ? written.policy.images : [] };
      if (dockerAvailable()) evidence.output = await deployCompose(projectName, written.file);
    } else if (dockerAvailable()) {
      evidence.output = await serviceAction(
        projectName,
        service.name,
        kind === "service.stop" ? "stop" : kind === "service.start" ? "start" : "restart",
      );
    } else {
      evidence.docker = "unavailable";
    }
  } catch (error) {
    evidence.error = error instanceof Error ? error.message : "docker failed";
    throw error;
  }
  const status = kind === "service.stop" ? "stopped" : kind === "service.deploy" ? "deployed" : "running";
  await db
    .update(services)
    .set({ status, observedRevision: operation.planHash, observedAt: new Date() })
    .where(eq(services.id, serviceId));
  await addStep(operation.id, kind, evidence);
}

async function createBackup(operation: typeof operations.$inferSelect) {
  const kind = String(operation.payload.kind ?? "platform-postgres");
  const result = await runBackup(
    kind as "platform-postgres" | "app-postgres" | "mail" | "volume",
    String(operation.payload.repository ?? operation.targetIds[0]),
  );
  await db.insert(backups).values({
    id: createId("bak"),
    kind,
    targetId: operation.targetIds[0],
    status: result.status,
    checksum: sha256Hex(operation.id),
    restoreVerified: false,
  });
  await addStep(operation.id, "backup", result);
}

async function restoreBackup(operation: typeof operations.$inferSelect) {
  const kind = String(operation.payload.kind ?? "platform-postgres");
  const result = await runRestoreTest(
    kind as "platform-postgres" | "app-postgres" | "mail" | "volume",
    String(operation.payload.repository ?? operation.targetIds[0]),
  );
  const [latest] = await db.select().from(backups).where(eq(backups.targetId, operation.targetIds[0]));
  if (latest) {
    await db
      .update(backups)
      .set({ restoreVerified: true, status: result.status })
      .where(eq(backups.id, latest.id));
  }
  await addStep(operation.id, "restore-test", result);
}

async function changeMode(operation: typeof operations.$inferSelect) {
  const adminMode = String(operation.payload.adminMode ?? "public") === "tailnet" ? "tailnet" : "public";
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  await db
    .update(platformSettings)
    .set({ adminMode, updatedAt: new Date() })
    .where(eq(platformSettings.id, "default"));
  await db.delete(session);
  const edge = await writeEdge({
    adminMode,
    adminHostname: settings?.adminHostname ?? undefined,
  });
  await addStep(operation.id, "mode-change", { adminMode, sessionsRevoked: true, ...edge });
}

async function publishDns(operation: typeof operations.$inferSelect) {
  const domainId = operation.targetIds[0];
  const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, domainId));
  if (!domain) throw new Error("Domain not found.");
  const records = await db.select().from(dnsRecords).where(eq(dnsRecords.domainId, domainId));
  const writes: DnsWrite[] = records
    .filter((record) => !record.expectedValue.includes("review existing"))
    .map((record) => ({
      type: record.type,
      name: record.name,
      content: record.expectedValue,
      ttl: 300,
      priority: record.type === "MX" ? 10 : undefined,
    }));
  const result = await publishCloudflare(domain.name, writes);
  await addStep(operation.id, "dns-publish", result);
}

async function reconcileSesOp(operation: typeof operations.$inferSelect) {
  const domainId = operation.targetIds[0];
  const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, domainId));
  if (!domain) throw new Error("Domain not found.");
  const mailFrom = domain.mailFrom ?? `bounce.${domain.name}`;
  const result = await reconcileSes(domain.name, mailFrom);
  const secretKey = process.env.AWS_SECRET_ACCESS_KEY ?? process.env.AWS_BOOTSTRAP_SECRET_ACCESS_KEY;
  const region = process.env.AWS_REGION ?? "eu-west-1";
  if (secretKey) {
    const smtpPassword = deriveSesSmtpPassword(secretKey, region);
    const sealed = encryptSecret(env.rootKey, smtpPassword, env.rootKeyId);
    await db.insert(secrets).values({
      id: createId("sec"),
      kind: `ses.smtp.${domain.id}`,
      once: false,
      ...sealed,
    });
  }
  const sesReady = Boolean(result.created && result.account && "ok" in result.account && result.account.ok);
  await db
    .update(mailDomains)
    .set({ outboundStatus: sesReady ? "ready" : "paused" })
    .where(eq(mailDomains.domainId, domainId));
  await addStep(operation.id, "ses-reconcile", {
    identity: result.identity,
    created: result.created,
    configured: result.account?.configured ?? false,
  });
}

async function reloadPgbouncer(operation: typeof operations.$inferSelect) {
  const databases = await db.select().from(managedDatabases);
  const roles = await db.select().from(databaseRoles);
  const users: Array<{ name: string; password: string }> = [];
  for (const role of roles.filter((item) => item.kind === "runtime" && item.secretId)) {
    const [secret] = await db
      .select()
      .from(secrets)
      .where(eq(secrets.id, role.secretId ?? ""));
    if (!secret) continue;
    users.push({ name: role.name, password: decryptSecret(env.rootKey, secret) });
  }
  const mappings = databases
    .filter((item) => item.exposure === "public")
    .map((item) => ({ database: item.name, host: process.env.ARK_APP_PG_HOST ?? "app-postgres" }));
  const written = await writePgbouncer({ mappings, users });
  const cidrs = databases.flatMap((item) => item.sourceCidrs ?? []);
  if (cidrs.length) {
    assertCidrs(cidrs);
    await Bun.write(`${written.dir}/allowlist.nft`, nftAllowlist(cidrs));
  }
  await addStep(operation.id, "pgbouncer-reload", {
    mappings: mappings.length,
    users: users.length,
    cidrs,
    ...written,
  });
}

async function applyEdge(operation: typeof operations.$inferSelect) {
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const ends = await db.select().from(endpoints);
  const written = await writeEdge({
    adminMode: settings?.adminMode === "tailnet" ? "tailnet" : "public",
    adminHostname: settings?.adminHostname ?? undefined,
    appRoutes: ends
      .filter((item) => item.kind === "http" && item.exposure === "public")
      .map((item) => ({ hostname: item.hostname, upstream: "app-edge:8080" })),
  });
  await addStep(operation.id, "edge-apply", written);
}

async function detectUpdates(operation: typeof operations.$inferSelect) {
  const rows = await db.select().from(services);
  const detected = [];
  for (const service of rows) {
    const image = firstComposeImage(service.compose);
    if (!image) continue;
    const resolved = await resolveImageDigest(image);
    const parsed = parseImageRef(image);
    await db
      .insert(updateCandidates)
      .values({
        id: createId("upd"),
        serviceId: service.id,
        image,
        currentDigest: service.imageDigest ?? parsed.digest,
        candidateDigest: resolved.digest,
        requiresApproval: candidateRequiresApproval({
          updatePolicy: service.updatePolicy,
          component: service.name,
        }),
        rollbackSafe: rollbackSafe(service.name),
      })
      .onConflictDoUpdate({
        target: updateCandidates.serviceId,
        set: {
          image,
          currentDigest: service.imageDigest ?? parsed.digest,
          candidateDigest: resolved.digest,
          detectedAt: new Date(),
        },
      });
    detected.push({ serviceId: service.id, digest: resolved.digest, status: resolved.status });
  }
  await addStep(operation.id, "update-detect", { detected });
}

async function scanImportOp(operation: typeof operations.$inferSelect) {
  const incoming = operation.payload as ExternalInventory;
  const local: ExternalInventory = {
    source: incoming.source ?? "compose",
    domains: (await db.select().from(domainClaims)).map((item) => item.name),
    databases: (await db.select().from(managedDatabases)).map((item) => item.name),
    services: (await db.select().from(services)).map((item) => item.name),
  };
  const comparison = scanImport(local, incoming);
  await addStep(operation.id, "import-scan", comparison);
}

async function rotateDatabase(operation: typeof operations.$inferSelect) {
  const databaseId = operation.targetIds[0];
  const kind = String(operation.payload.kind ?? "runtime");
  const [role] = await db.select().from(databaseRoles).where(eq(databaseRoles.databaseId, databaseId));
  const target = (await db.select().from(databaseRoles).where(eq(databaseRoles.databaseId, databaseId))).find(
    (item) => item.kind === kind,
  );
  if (!target) throw new Error("Role not found.");
  const password = generatePassword();
  const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, databaseId));
  await rotateRolePassword({ role: target.name, password, database: database?.name });
  const sealed = encryptSecret(env.rootKey, password, env.rootKeyId);
  const secretId = createId("sec");
  await db.insert(secrets).values({ id: secretId, kind: `postgres.${kind}`, once: true, ...sealed });
  await db.update(databaseRoles).set({ secretId }).where(eq(databaseRoles.id, target.id));
  await enqueue({ kind: "pgbouncer.reload", targetIds: [databaseId] });
  await addStep(operation.id, "database-rotate", { role: target.name, previous: role?.name });
}

async function adoptService(operation: typeof operations.$inferSelect) {
  const serviceId = operation.targetIds[0];
  const [service] = await db.select().from(services).where(eq(services.id, serviceId));
  if (!service) throw new Error("Service not found.");
  const written = await writeApprovedCompose(service.id, service.compose);
  await addStep(operation.id, "service-adopt", { file: written.file, containerId: service.containerId });
}

async function queueMail(operation: typeof operations.$inferSelect) {
  const action = operation.kind === "mail.queue_delete" ? "delete" : "retry";
  const result = await mutateMailQueue(action, String(operation.payload.id ?? operation.targetIds[0]));
  await addStep(operation.id, `mail-queue-${action}`, result);
}

async function maintainPlatform(operation: typeof operations.$inferSelect) {
  const bundle = validateMaintenanceBundle(operation.payload as MaintenanceBundle);
  await addStep(operation.id, "platform-maintain", {
    images: bundle.images,
    rollbackSafe: bundle.rollbackSafe,
    note: "Apply only through scripts/maintain.ts with ARK_MAINTENANCE_TOKEN.",
  });
}

export function revealSecret(row: typeof secrets.$inferSelect) {
  return decryptSecret(env.rootKey, row);
}

export function startCoordinator() {
  const tick = () => {
    void processQueued().catch((error) => console.error(error instanceof Error ? error.message : error));
  };
  tick();
  return setInterval(tick, 1500);
}
