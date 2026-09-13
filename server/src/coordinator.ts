import { resolve4, resolve6, resolveCname, resolveMx, resolveTxt } from "node:dns/promises";

import {
  assertCidrs,
  backupProofAllowed,
  candidateRequiresApproval,
  createId,
  decryptSecret,
  deriveSesSmtpPassword,
  dnsRecordVerified,
  encryptSecret,
  firstComposeImage,
  generatePassword,
  isInFlight,
  observedDnsValue,
  parseImageRef,
  pinComposeImage,
  planHash,
  rollbackSafe,
  validateMaintenanceBundle,
  type DnsWrite,
  type ExternalInventory,
  type MaintenanceBundle,
  type OperationKind,
  type OperationState,
} from "@ark-stack/shared";
import { and, desc, eq } from "drizzle-orm";

import { db, sql } from "./db.ts";
import { loadEnv } from "./env.ts";
import { evaluateAlerts } from "./modules/alerts.ts";
import { runBackup, runRestoreTest } from "./modules/backups.ts";
import { issueCertificateFiles } from "./modules/certificates.ts";
import { provisionApplicationDatabase, rotateRolePassword } from "./modules/database.ts";
import {
  deployCompose,
  dockerAvailable,
  inspectServiceDigest,
  serviceAction,
  writeApprovedCompose,
} from "./modules/docker.ts";
import { mutateMailQueue } from "./modules/queue.ts";
import { currentMailStatus, reconcileMailEngine } from "./modules/mail.ts";
import {
  applyDatabaseAllowlist,
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

export class DelegateToAgent extends Error {
  payload: Record<string, unknown>;
  constructor(payload: Record<string, unknown>) {
    super("waiting_for_agent");
    this.name = "DelegateToAgent";
    this.payload = payload;
  }
}

export type DnsResolver = {
  txt(name: string): Promise<string[][]>;
  a(name: string): Promise<string[]>;
  aaaa(name: string): Promise<string[]>;
  mx(name: string): Promise<Array<{ priority: number; exchange: string }>>;
  cname(name: string): Promise<string[]>;
};

const nodeResolver: DnsResolver = {
  txt: (name) => resolveTxt(name),
  a: (name) => resolve4(name),
  aaaa: (name) => resolve6(name),
  mx: (name) => resolveMx(name),
  cname: (name) => resolveCname(name),
};

let dnsResolver: DnsResolver = nodeResolver;

export function setDnsResolver(next: DnsResolver = nodeResolver) {
  dnsResolver = next;
}

type OperationRow = typeof operations.$inferSelect;

function mapOperation(row: Record<string, unknown>): OperationRow {
  return {
    id: String(row.id),
    kind: String(row.kind),
    status: String(row.status),
    actorId: (row.actor_id as string | null) ?? null,
    idempotencyKey: String(row.idempotency_key),
    planHash: String(row.plan_hash),
    targetIds: (row.target_ids as string[]) ?? [],
    payload: (row.payload as Record<string, unknown>) ?? {},
    claimToken: (row.claim_token as string | null) ?? null,
    heartbeatAt: (row.heartbeat_at as Date | null) ?? null,
    error: (row.error as string | null) ?? null,
    createdAt: row.created_at as Date,
    updatedAt: row.updated_at as Date,
  };
}

export function operationIdempotencyKey(
  kind: string,
  targetIds: string[],
  payload?: Record<string, unknown>,
) {
  return `${kind}:${targetIds.join(",")}:${planHash(payload ?? {})}`;
}

export async function enqueue(input: {
  kind: OperationKind;
  actorId?: string;
  targetIds: string[];
  payload?: Record<string, unknown>;
  idempotencyKey?: string;
}) {
  const base = input.idempotencyKey ?? operationIdempotencyKey(input.kind, input.targetIds, input.payload);
  const related = await sql`
    SELECT * FROM operations
    WHERE idempotency_key = ${base} OR idempotency_key LIKE ${`${base}:%`}
    ORDER BY created_at DESC
  `;
  const inflight = related.map(mapOperation).find((row) => isInFlight(row.status));
  if (inflight) return inflight;
  const idempotencyKey = related.length ? `${base}:${createId("idem")}` : base;
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

export async function claimQueued(
  input: { limit?: number; kindPrefix?: string; excludePrefix?: string; agentOwned?: boolean } = {},
) {
  const limit = input.limit ?? 8;
  const token = createId("claim");
  const like = input.kindPrefix ? `${input.kindPrefix}%` : null;
  const unlike = input.excludePrefix ? `${input.excludePrefix}%` : null;
  const agentOwned = input.agentOwned ?? false;
  const rows = await sql`
    UPDATE operations
    SET status = 'running',
        claim_token = ${token},
        heartbeat_at = now(),
        updated_at = now()
    WHERE id IN (
      SELECT id FROM operations
      WHERE status = 'queued'
        AND (${like}::text IS NULL OR kind LIKE ${like})
        AND (${unlike}::text IS NULL OR kind NOT LIKE ${unlike})
        AND (
          ${agentOwned}::boolean IS NOT TRUE
          OR kind LIKE 'service.%'
          OR kind = 'update.apply'
        )
      ORDER BY created_at
      LIMIT ${limit}
      FOR UPDATE SKIP LOCKED
    )
    RETURNING *
  `;
  return { token, rows: rows.map(mapOperation) };
}

async function finishOperation(
  operation: OperationRow,
  token: string | null,
  status: OperationState,
  error?: string | null,
) {
  const filters = [eq(operations.id, operation.id)];
  if (token) filters.push(eq(operations.claimToken, token));
  await db
    .update(operations)
    .set({ status, error: error ?? null, updatedAt: new Date() })
    .where(and(...filters));
}

export async function processQueued(limit = 8, kindPrefix?: string) {
  const excludePrefix = !env.embeddedWorkers && !kindPrefix ? "service." : undefined;
  const { token, rows } = await claimQueued({ limit, kindPrefix, excludePrefix });
  for (const operation of rows) {
    if (kindPrefix && !operation.kind.startsWith(kindPrefix)) continue;
    if (
      !env.embeddedWorkers &&
      (operation.kind.startsWith("service.") ||
        (operation.kind === "update.apply" && operation.payload.file && operation.payload.project))
    ) {
      await finishOperation(operation, token, "queued");
      continue;
    }
    try {
      await runOperation(operation.kind as OperationKind, operation);
      await finishOperation(operation, token, "succeeded");
    } catch (error) {
      if (error instanceof DelegateToAgent) {
        await db
          .update(operations)
          .set({
            status: "queued",
            payload: error.payload,
            claimToken: null,
            updatedAt: new Date(),
          })
          .where(eq(operations.id, operation.id));
        continue;
      }
      const message = error instanceof Error ? error.message : "Operation failed.";
      await finishOperation(operation, token, "failed", message);
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

async function runOperation(kind: OperationKind, operation: OperationRow) {
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
  if (kind === "update.apply") return applyUpdate(operation);
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

async function observeDns(type: string, name: string) {
  if (type === "TXT") return observedDnsValue("TXT", (await dnsResolver.txt(name)).flat());
  if (type === "A") return observedDnsValue("A", await dnsResolver.a(name));
  if (type === "AAAA") return observedDnsValue("AAAA", await dnsResolver.aaaa(name));
  if (type === "MX") {
    const records = await dnsResolver.mx(name);
    return observedDnsValue(
      "MX",
      records.map((item) => `${item.priority} ${item.exchange}`),
    );
  }
  if (type === "CNAME") return observedDnsValue("CNAME", await dnsResolver.cname(name));
  return "";
}

async function verifyDomain(operation: OperationRow) {
  const domainId = operation.targetIds[0];
  const records = await db.select().from(dnsRecords).where(eq(dnsRecords.domainId, domainId));
  for (const record of records) {
    const stub = process.env.ARK_DNS_STUB === "1";
    let observed = stub ? record.expectedValue : "";
    if (!stub) {
      try {
        observed = await observeDns(record.type, record.name);
      } catch (error) {
        observed = error instanceof Error ? error.message : "lookup failed";
      }
    }
    const ok = stub
      ? observed.includes(record.expectedValue)
      : dnsRecordVerified(record.type, record.expectedValue, observed);
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

async function issueCertificate(operation: OperationRow) {
  const endpointId = operation.targetIds[0];
  const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, endpointId));
  if (!endpoint) throw new Error("Endpoint not found.");
  const issued = await issueCertificateFiles(endpoint.hostname);
  if (!issued.fingerprint || !issued.expiresAt) {
    throw new Error("Certificate metadata is missing; refusing to store invented expiry or fingerprint.");
  }
  await db.insert(certificates).values({
    id: createId("crt"),
    endpointId,
    names: [endpoint.hostname],
    issuer: issued.issuer,
    fingerprint: issued.fingerprint,
    expiresAt: issued.expiresAt,
    status: "issued",
    lastDeployedAt: new Date(),
  });
  await db.update(endpoints).set({ status: "ready" }).where(eq(endpoints.id, endpointId));
  await addStep(operation.id, "certificate-issued", { issuer: issued.issuer, path: issued.certPath });
  await enqueue({ kind: "edge.apply", actorId: operation.actorId ?? undefined, targetIds: ["platform"] });
}

async function provisionDatabase(operation: OperationRow) {
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

async function provisionMailbox(operation: OperationRow) {
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
  const mailEndpoints = await db.select().from(endpoints).where(eq(endpoints.domainId, mailbox.domainId));
  const mailEndpoint = mailEndpoints.find((item) => item.kind === "mail");
  const certs = mailEndpoint
    ? await db.select().from(certificates).where(eq(certificates.endpointId, mailEndpoint.id))
    : [];
  const certificateReady = certs.some(
    (item) => item.status === "issued" && item.expiresAt && item.expiresAt.getTime() > Date.now(),
  );
  const status = currentMailStatus({
    domainVerified: domain?.status === "verified",
    mailboxCount: boxes.length,
    certificateReady,
    sesReady,
    listenerReady: applied.reachable || applied.applied,
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
    certificateReady,
  });
  if (sesReady && domain) {
    await enqueue({
      kind: "ses.reconcile",
      actorId: operation.actorId ?? undefined,
      targetIds: [domain.id],
    });
  }
}

async function projectNameFor(service: typeof services.$inferSelect) {
  const [project] = await db.select().from(projects).where(eq(projects.id, service.projectId));
  return `ark-${project?.slug ?? "workload"}`;
}

async function mutateService(operation: OperationRow, kind: OperationKind) {
  const serviceId = operation.targetIds[0];
  const [service] = await db.select().from(services).where(eq(services.id, serviceId));
  if (!service) throw new Error("Service not found.");
  const projectName = String(operation.payload.project ?? (await projectNameFor(service)));
  let evidence: Record<string, unknown> = { project: projectName };
  const compose = String(operation.payload.compose ?? service.compose);
  try {
    if (kind === "service.deploy") {
      const written = await writeApprovedCompose(service.id, compose);
      evidence = { ...evidence, file: written.file, images: written.policy.ok ? written.policy.images : [] };
      if (dockerAvailable() && env.embeddedWorkers) {
        evidence.output = await deployCompose(projectName, written.file);
      } else {
        throw new DelegateToAgent({
          ...operation.payload,
          compose,
          name: service.name,
          file: written.file,
          project: projectName,
        });
      }
    } else if (dockerAvailable() && env.embeddedWorkers) {
      evidence.output = await serviceAction(
        projectName,
        service.name,
        kind === "service.stop" ? "stop" : kind === "service.start" ? "start" : "restart",
      );
    } else {
      throw new DelegateToAgent({
        ...operation.payload,
        containerId: service.containerId,
        project: projectName,
        name: service.name,
      });
    }
  } catch (error) {
    if (error instanceof DelegateToAgent) throw error;
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

async function applyUpdate(operation: OperationRow) {
  const serviceId = operation.targetIds[0];
  const digest = String(operation.payload.digest ?? "");
  if (!digest) throw new Error("Update apply requires a candidate digest.");
  const [candidate] = await db
    .select()
    .from(updateCandidates)
    .where(eq(updateCandidates.serviceId, serviceId));
  if (!candidate || candidate.candidateDigest !== digest) {
    throw new Error("Stale or unknown update candidate digest.");
  }
  const [service] = await db.select().from(services).where(eq(services.id, serviceId));
  if (!service) throw new Error("Service not found.");
  const nextCompose = pinComposeImage(service.compose, digest);
  const written = await writeApprovedCompose(service.id, nextCompose);
  const projectName = String(operation.payload.project ?? (await projectNameFor(service)));
  const desiredRevision = createId("rev");
  await db
    .update(services)
    .set({
      compose: nextCompose,
      imageDigest: digest,
      desiredRevision,
      status: "updating",
    })
    .where(eq(services.id, serviceId));
  if (!dockerAvailable() || !env.embeddedWorkers) {
    throw new DelegateToAgent({
      ...operation.payload,
      compose: nextCompose,
      file: written.file,
      project: projectName,
      name: service.name,
      digest,
    });
  }
  const output = await deployCompose(projectName, written.file);
  const observed = await inspectServiceDigest(projectName, service.name);
  if (observed && observed !== digest) {
    throw new Error(`Running digest ${observed} does not match approved ${digest}.`);
  }
  await db
    .update(services)
    .set({
      status: "deployed",
      imageDigest: digest,
      observedRevision: desiredRevision,
      observedAt: new Date(),
    })
    .where(eq(services.id, serviceId));
  await addStep(operation.id, "update.apply", { file: written.file, digest, observed, output });
}

async function createBackup(operation: OperationRow) {
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
    checksum: result.snapshotId ?? null,
    restoreVerified: false,
  });
  if (!backupProofAllowed(result) && result.executed === false) {
    await addStep(operation.id, "backup", result);
    return;
  }
  if (!backupProofAllowed(result)) throw new Error("Backup did not produce uploaded evidence.");
  await addStep(operation.id, "backup", result);
}

async function restoreBackup(operation: OperationRow) {
  const kind = String(operation.payload.kind ?? "platform-postgres");
  const result = await runRestoreTest(
    kind as "platform-postgres" | "app-postgres" | "mail" | "volume",
    String(operation.payload.repository ?? operation.targetIds[0]),
  );
  const backupId = typeof operation.payload.backupId === "string" ? operation.payload.backupId : null;
  const [latest] = backupId
    ? await db.select().from(backups).where(eq(backups.id, backupId))
    : await db
        .select()
        .from(backups)
        .where(eq(backups.targetId, operation.targetIds[0]))
        .orderBy(desc(backups.createdAt))
        .limit(1);
  if (latest && result.executed && result.status === "restore_verified") {
    await db
      .update(backups)
      .set({ restoreVerified: true, status: result.status, checksum: result.snapshotId ?? latest.checksum })
      .where(eq(backups.id, latest.id));
  } else if (latest && !result.executed) {
    await db.update(backups).set({ status: result.status }).where(eq(backups.id, latest.id));
  }
  await addStep(operation.id, "restore-test", { ...result, backupId: latest?.id });
}

async function changeMode(operation: OperationRow) {
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

async function publishDns(operation: OperationRow) {
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

async function reconcileSesOp(operation: OperationRow) {
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

async function reloadPgbouncer(operation: OperationRow) {
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
  let allowlist = { file: "", applied: true, enforced: false as boolean };
  if (cidrs.length) {
    assertCidrs(cidrs);
    allowlist = await applyDatabaseAllowlist(written.dir, cidrs);
  } else {
    allowlist = await applyDatabaseAllowlist(written.dir, []);
  }
  for (const database of databases) {
    await db
      .update(managedDatabases)
      .set({ allowlistEnforced: Boolean(database.sourceCidrs?.length) && allowlist.enforced })
      .where(eq(managedDatabases.id, database.id));
  }
  await addStep(operation.id, "pgbouncer-reload", {
    mappings: mappings.length,
    users: users.length,
    cidrs,
    ...written,
    ...allowlist,
  });
}

async function applyEdge(operation: OperationRow) {
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

async function detectUpdates(operation: OperationRow) {
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

async function scanImportOp(operation: OperationRow) {
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

async function rotateDatabase(operation: OperationRow) {
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

async function adoptService(operation: OperationRow) {
  const serviceId = operation.targetIds[0];
  const [service] = await db.select().from(services).where(eq(services.id, serviceId));
  if (!service) throw new Error("Service not found.");
  const written = await writeApprovedCompose(service.id, service.compose);
  await addStep(operation.id, "service-adopt", { file: written.file, containerId: service.containerId });
}

async function queueMail(operation: OperationRow) {
  const action = operation.kind === "mail.queue_delete" ? "delete" : "retry";
  const result = await mutateMailQueue(action, String(operation.payload.id ?? operation.targetIds[0]));
  await addStep(operation.id, `mail-queue-${action}`, result);
}

async function maintainPlatform(operation: OperationRow) {
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

let tickInFlight: Promise<void> | null = null;

export function startCoordinator() {
  const tick = () => {
    if (tickInFlight) return;
    tickInFlight = processQueued()
      .catch((error) => console.error(error instanceof Error ? error.message : error))
      .finally(() => {
        tickInFlight = null;
      });
  };
  tick();
  return setInterval(tick, 1500);
}
