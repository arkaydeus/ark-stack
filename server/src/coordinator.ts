import { resolve4, resolve6, resolveCname, resolveMx, resolveTxt } from "node:dns/promises";

import {
  assertCidrs,
  backupProofAllowed,
  buildProvisionPlan,
  candidateRequiresApproval,
  canViewDomain,
  canViewProject,
  classifySql,
  createId,
  decryptSecret,
  deriveSesSmtpPassword,
  dnsRecordVerified,
  encryptSecret,
  firstComposeImage,
  generatePassword,
  isInFlight,
  nextBackupStatus,
  observedDnsValue,
  parseImageRef,
  pinComposeImage,
  PGBOUNCER_PORT,
  PGBOUNCER_SOCKET_DIR,
  planHash,
  validateMaintenanceBundle,
  type BackupStatus,
  type DnsWrite,
  type ExternalInventory,
  type MaintenanceBundle,
  type OperationKind,
  type OperationState,
} from "@ark-stack/shared";
import { and, desc, eq, isNull } from "drizzle-orm";

import { db, sql } from "./db.ts";
import { loadEnv } from "./env.ts";
import { evaluateAlerts, raiseAlert } from "./modules/alerts.ts";
import { runBackup, runRestoreTest } from "./modules/backups.ts";
import { issueCertificateFiles } from "./modules/certificates.ts";
import {
  executeWorkspaceQuery,
  inspectDatabaseSchema,
  provisionApplicationDatabase,
  rotateRolePassword,
} from "./modules/database.ts";
import {
  deployCompose,
  dockerAvailable,
  inspectServiceDigest,
  serviceAction,
  writeApprovedCompose,
} from "./modules/docker.ts";
import {
  PgbouncerReloadError,
  planPgbouncer,
  reloadAndVerify,
  reloadPgbouncerAdmin,
  renderPgbouncerFiles,
  servedCertificateFingerprint,
  writePgbouncerFiles,
} from "./modules/pgbouncer.ts";
import { mutateMailQueue } from "./modules/queue.ts";
import { currentMailStatus, reconcileMailEngine } from "./modules/mail.ts";
import {
  applyDatabaseAllowlist,
  applyStalwartDevice,
  publishCloudflare,
  reconcileSes,
  resolveImageDigest,
  scanImport,
  pgbouncerDir,
  writeEdge,
} from "./modules/providers.ts";
import {
  alerts,
  aliases,
  backups,
  certificates,
  clientCertificates,
  databaseClients,
  databaseClusters,
  databaseRoles,
  deploymentRevisions,
  dnsRecords,
  domainClaims,
  endpoints,
  mailDomains,
  mailboxes,
  mailboxDevices,
  managedDatabases,
  operationSteps,
  operations,
  platformSettings,
  platformAccess,
  privateCas,
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

export type ClaimedJob = Omit<OperationRow, "createdAt" | "updatedAt" | "heartbeatAt"> & {
  createdAt: string | Date;
  updatedAt: string | Date;
  heartbeatAt: string | Date | null;
};

export async function executeClaimedJob(job: ClaimedJob) {
  if (!job.claimToken || job.status !== "running") throw new Error("Worker received an unclaimed job.");
  const operation: OperationRow = {
    ...job,
    createdAt: new Date(job.createdAt),
    updatedAt: new Date(job.updatedAt),
    heartbeatAt: job.heartbeatAt ? new Date(job.heartbeatAt) : null,
  };
  try {
    const evidence = await runOperation(operation.kind as OperationKind, operation);
    return {
      complete: true as const,
      evidence:
        evidence && typeof evidence === "object" && !Array.isArray(evidence)
          ? (evidence as Record<string, unknown>)
          : undefined,
    };
  } catch (error) {
    if (!(error instanceof DelegateToAgent)) throw error;
    const updated = await db
      .update(operations)
      .set({
        status: "queued",
        payload: error.payload,
        claimToken: null,
        heartbeatAt: null,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(operations.id, operation.id),
          eq(operations.status, "running"),
          eq(operations.claimToken, job.claimToken),
        ),
      )
      .returning({ id: operations.id });
    if (updated.length !== 1)
      throw new Error("Operation claim changed before agent delegation.", { cause: error });
    return { complete: false as const };
  }
}

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

function isUniqueViolation(error: unknown) {
  let current: unknown = error;
  for (let index = 0; index < 5 && current; index++) {
    if (current && typeof current === "object" && "code" in current && current.code === "23505") {
      return true;
    }
    current = current && typeof current === "object" && "cause" in current ? current.cause : undefined;
  }
  return false;
}

export async function enqueue(input: {
  kind: OperationKind;
  actorId?: string;
  targetIds: string[];
  payload?: Record<string, unknown>;
  idempotencyKey?: string;
}) {
  const base = input.idempotencyKey ?? operationIdempotencyKey(input.kind, input.targetIds, input.payload);
  // Serialise enqueues for one idempotency base. The unique index only protects the very first
  // enqueue: once a prior terminal operation exists every caller mints a distinct suffixed key,
  // so concurrent callers would both insert and leave two queued duplicates.
  const connection = await sql.reserve();
  try {
    await connection`SELECT pg_advisory_lock(hashtext(${`ark:enqueue:${base}`}))`;
    try {
      return await insertEnqueued(input, base);
    } finally {
      await connection`SELECT pg_advisory_unlock(hashtext(${`ark:enqueue:${base}`}))`;
    }
  } finally {
    connection.release();
  }
}

async function insertEnqueued(
  input: {
    kind: OperationKind;
    actorId?: string;
    targetIds: string[];
    payload?: Record<string, unknown>;
    idempotencyKey?: string;
  },
  base: string,
) {
  const related = await sql`
    SELECT * FROM operations
    WHERE idempotency_key = ${base} OR idempotency_key LIKE ${`${base}:%`}
    ORDER BY created_at DESC
  `;
  const inflight = related.map(mapOperation).find((row) => isInFlight(row.status));
  if (inflight) return inflight;
  const idempotencyKey = related.length ? `${base}:${createId("idem")}` : base;
  try {
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
  } catch (error) {
    if (!isUniqueViolation(error)) throw error;
    const [existing] = await db
      .select()
      .from(operations)
      .where(eq(operations.idempotencyKey, idempotencyKey));
    if (existing) return existing;
    const [retry] = related.map(mapOperation);
    if (retry) return retry;
    throw error;
  }
}

export async function claimQueued(
  input: {
    limit?: number;
    kindPrefix?: string;
    kindPrefixes?: string[];
    excludePrefix?: string;
    agentOwned?: boolean;
    leaseMs?: number;
  } = {},
) {
  const limit = input.limit ?? 8;
  const token = createId("claim");
  const prefixes = input.kindPrefixes ?? (input.kindPrefix ? [input.kindPrefix] : []);
  const patterns = prefixes.map((item) => `${item}%`);
  const unlike = input.excludePrefix ? `${input.excludePrefix}%` : null;
  const agentOwned = input.agentOwned ?? false;
  const leaseSeconds = Math.max(30, Math.floor((input.leaseMs ?? 90_000) / 1000));
  await sql`
    UPDATE operations
    SET status = 'queued', claim_token = NULL, heartbeat_at = NULL, updated_at = now(),
        error = 'Previous worker lease expired; operation reclaimed.'
    WHERE status = 'running'
      AND heartbeat_at < now() - (${leaseSeconds}::int * interval '1 second')
  `;
  // Two separate races have to be closed here. Across transactions, the overlap exclusion reads
  // rows another claimer has not committed as `running` yet, so the claim is serialised on an
  // advisory lock. Within one claim, a single multi-row UPDATE evaluates its exclusion against
  // the pre-statement snapshot, so rows that overlap *each other* would all be taken; claiming
  // one row per statement makes each subsequent statement see the preceding one.
  const rows = await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtext('ark:operations:claim'))`;
    const claimed: Record<string, unknown>[] = [];
    for (let taken = 0; taken < limit; taken++) {
      const batch = await tx`
        UPDATE operations
        SET status = 'running',
            claim_token = ${token},
            heartbeat_at = now(),
            updated_at = now()
        WHERE id IN (
          SELECT id FROM operations
          WHERE status = 'queued'
            AND (${patterns.length === 0}::boolean OR kind LIKE ANY(${patterns}::text[]))
            AND (${unlike}::text IS NULL OR kind NOT LIKE ${unlike})
            AND (
              ${agentOwned}::boolean IS NOT TRUE
              OR (kind = 'service.deploy' AND payload ?& ARRAY['compose', 'composeHash', 'project'])
              OR (kind = 'service.adopt' AND payload ?& ARRAY['compose', 'composeHash', 'containerId', 'name'])
              OR (kind IN ('service.start', 'service.stop', 'service.restart', 'service.logs', 'service.stats') AND payload ? 'name')
              OR (kind = 'service.discover' AND payload ->> 'request' = 'redacted-inventory-v1')
              OR (kind = 'update.apply' AND payload ?& ARRAY['compose', 'composeHash', 'project'])
            )
            AND NOT EXISTS (
              SELECT 1 FROM operations active
              WHERE active.status = 'running'
                AND active.id <> operations.id
                AND active.target_ids ?| ARRAY(SELECT jsonb_array_elements_text(operations.target_ids))
            )
          ORDER BY created_at
          LIMIT 1
          FOR UPDATE SKIP LOCKED
        )
        RETURNING *
      `;
      if (!batch.length) break;
      claimed.push(...batch);
    }
    return claimed;
  });
  return { token, rows: rows.map(mapOperation) };
}

export async function heartbeatClaim(operationId: string, claimToken: string) {
  const rows = await sql`
    UPDATE operations SET heartbeat_at = now(), updated_at = now()
    WHERE id = ${operationId} AND status = 'running' AND claim_token = ${claimToken}
    RETURNING id
  `;
  return rows.length === 1;
}

export async function heartbeatClaimed(claimToken: string) {
  const rows = await sql`
    UPDATE operations SET heartbeat_at = now(), updated_at = now()
    WHERE status = 'running' AND claim_token = ${claimToken}
    RETURNING id
  `;
  return rows.map((row) => String(row.id));
}

async function finishOperation(
  operation: OperationRow,
  token: string | null,
  status: OperationState,
  error?: string | null,
) {
  if (!token) throw new Error("A current claim token is required to finish an operation.");
  const updated = await db
    .update(operations)
    .set({ status, error: error ?? null, updatedAt: new Date() })
    .where(
      and(
        eq(operations.id, operation.id),
        eq(operations.claimToken, token),
        eq(operations.status, "running"),
      ),
    )
    .returning({ id: operations.id });
  if (updated.length !== 1) throw new Error("Operation claim is stale or no longer owned by this worker.");
}

/**
 * True once an operation's payload carries the canonical compose the Docker agent executes.
 * Such a row has already been planned and requeued for the agent; anyone else re-running it
 * would repeat the planning side effects.
 */
export function isDelegatedPayload(operation: Pick<OperationRow, "kind" | "payload">) {
  if (operation.kind !== "update.apply") return false;
  const payload = operation.payload as Record<string, unknown>;
  return typeof payload.composeHash === "string" && payload.composeHash.length > 0;
}

export async function processQueued(limit = 8, kindPrefix?: string) {
  const excludePrefix = !env.embeddedWorkers && !kindPrefix ? "service." : undefined;
  for (let index = 0; index < limit; index++) {
    const { token, rows } = await claimQueued({ limit: 1, kindPrefix, excludePrefix });
    if (!rows.length) break;
    const operation = rows[0]!;
    if (kindPrefix && !operation.kind.startsWith(kindPrefix)) continue;
    if (!env.embeddedWorkers && (operation.kind.startsWith("service.") || isDelegatedPayload(operation))) {
      await finishOperation(operation, token, "queued");
      continue;
    }
    // Operations that outlive the claim lease (lego, restore, compose pull+up) would otherwise
    // be reclaimed and re-executed by a concurrent claimer while still running here.
    const heartbeat = setInterval(() => {
      void heartbeatClaim(operation.id, token).catch(() => undefined);
    }, 15_000);
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
            heartbeatAt: null,
            updatedAt: new Date(),
          })
          .where(eq(operations.id, operation.id));
        continue;
      }
      const message = error instanceof Error ? error.message : "Operation failed.";
      await finishOperation(operation, token, "failed", message);
    } finally {
      clearInterval(heartbeat);
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

export async function runOperation(kind: OperationKind, operation: OperationRow) {
  await assertExecutionAuthorized(operation);
  if (kind === "domain.verify") return verifyDomain(operation);
  if (kind === "certificate.issue" || kind === "certificate.renew") return issueCertificate(operation);
  if (kind === "database.provision") return provisionDatabase(operation);
  if (kind === "database.query") return queryDatabase(operation);
  if (kind === "database.schema") return queryDatabaseSchema(operation);
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
  if (kind === "mailbox.device") return reconcileMailboxDevice(operation);
  if (kind === "platform.maintain") return maintainPlatform(operation);
  throw new Error(`Unknown operation kind: ${kind}`);
}

export async function assertExecutionAuthorized(operation: OperationRow) {
  if (!operation.actorId) return;
  const [row] = await db.select().from(platformAccess).where(eq(platformAccess.userId, operation.actorId));
  if (!row) throw new Error("Operation actor no longer has platform access.");
  const access = {
    userId: operation.actorId,
    role: row.role as "owner" | "operator" | "viewer",
    projectIds: row.projectIds,
    domainIds: row.domainIds,
  };
  if (access.role === "viewer") throw new Error("Operation actor no longer has mutation permission.");
  if (access.role === "owner") return;
  for (const targetId of operation.targetIds) {
    if (targetId === "platform") throw new Error("Only owners may execute platform-wide operations.");
    const [service] = await db.select().from(services).where(eq(services.id, targetId));
    if (service && !canViewProject(access, service.projectId)) throw new Error("Project grant was revoked.");
    const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, targetId));
    if (database) {
      if (database.projectId && !canViewProject(access, database.projectId)) {
        throw new Error("Database project grant was revoked.");
      }
      const [cluster] = await db
        .select()
        .from(databaseClusters)
        .where(eq(databaseClusters.id, database.clusterId));
      const [endpoint] = cluster?.endpointId
        ? await db.select().from(endpoints).where(eq(endpoints.id, cluster.endpointId))
        : [];
      if (!database.projectId && endpoint?.domainId && !canViewDomain(access, endpoint.domainId)) {
        throw new Error("Database domain grant was revoked.");
      }
    }
    const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, targetId));
    if (mailbox && !canViewDomain(access, mailbox.domainId))
      throw new Error("Mail domain grant was revoked.");
    const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, targetId));
    if (domain && !canViewDomain(access, domain.id)) throw new Error("Domain grant was revoked.");
  }
}

type QueryExecutor = Pick<typeof db, "select" | "update">;

export async function finalizeAgentCompletion(
  operation: OperationRow,
  succeeded = true,
  executor: QueryExecutor = db,
) {
  if (
    operation.kind === "service.logs" ||
    operation.kind === "service.stats" ||
    operation.kind === "service.discover"
  )
    return;
  const serviceId = operation.targetIds[0];
  if (!serviceId) throw new Error("Agent completion is missing its workload target.");
  const [service] = await executor.select().from(services).where(eq(services.id, serviceId));
  if (!service) throw new Error("Agent completion target no longer exists.");
  if (!succeeded) {
    await executor
      .update(services)
      .set({ status: "failed", observedAt: new Date() })
      .where(eq(services.id, serviceId));
    await executor
      .update(deploymentRevisions)
      .set({ status: "failed" })
      .where(eq(deploymentRevisions.desiredRevision, service.desiredRevision));
    return;
  }
  // Only a confirmed deploy promotes the planned compose and digest onto the service.
  const promotion: { compose?: string; imageDigest?: string } = {};
  if (operation.kind === "update.apply") {
    const digest = String(operation.payload.digest ?? "");
    const [planned] = await executor
      .select()
      .from(deploymentRevisions)
      .where(eq(deploymentRevisions.desiredRevision, service.desiredRevision));
    if (!digest || !planned || planned.imageDigest !== digest) {
      throw new Error("Agent update completion does not match the planned desired digest.");
    }
    promotion.compose = planned.compose;
    promotion.imageDigest = digest;
  }
  const status =
    operation.kind === "service.stop"
      ? "stopped"
      : operation.kind === "service.adopt"
        ? "adopted"
        : operation.kind === "service.deploy" || operation.kind === "update.apply"
          ? "deployed"
          : "running";
  await executor
    .update(services)
    .set({ ...promotion, status, observedRevision: service.desiredRevision, observedAt: new Date() })
    .where(eq(services.id, serviceId));
  await executor
    .update(deploymentRevisions)
    .set({ status: "deployed" })
    .where(eq(deploymentRevisions.desiredRevision, service.desiredRevision));
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
  const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, domainId));
  if (!domain) throw new Error("Domain not found.");
  const records = await db.select().from(dnsRecords).where(eq(dnsRecords.domainId, domainId));
  if (!records.length) throw new Error("Domain has no stored DNS ownership challenge.");
  const ownership = records.find(
    (record) =>
      record.type === "TXT" &&
      record.required &&
      record.name === `_ark-stack.${domain.name}` &&
      record.expectedValue === domain.ownershipToken &&
      record.purpose.toLowerCase().includes("ownership"),
  );
  if (!ownership)
    throw new Error("Domain ownership challenge is missing or does not match this installation.");
  const verifiedRecordIds = new Set<string>();
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
    if (ok) verifiedRecordIds.add(record.id);
  }
  if (!verifiedRecordIds.has(ownership.id)) {
    throw new Error(`DNS ownership proof ${ownership.name} is not yet published correctly.`);
  }
  await db
    .update(domainClaims)
    .set({ status: "verified", lastError: null, updatedAt: new Date() })
    .where(eq(domainClaims.id, domainId));
  const endpointRows = await db.select().from(endpoints).where(eq(endpoints.domainId, domainId));
  const verifiedEndpointIds = new Set<string>();
  for (const endpoint of endpointRows) {
    const endpointRecords = records.filter((record) => record.name === endpoint.hostname && record.required);
    const verified =
      endpoint.exposure !== "public" ||
      (endpointRecords.length > 0 && endpointRecords.every((record) => verifiedRecordIds.has(record.id)));
    await db
      .update(endpoints)
      .set({ status: verified ? "verified" : "awaiting_dns", lastVerifiedAt: verified ? new Date() : null })
      .where(eq(endpoints.id, endpoint.id));
    if (verified) {
      verifiedEndpointIds.add(endpoint.id);
      await enqueue({
        kind: "certificate.issue",
        actorId: operation.actorId ?? undefined,
        targetIds: [endpoint.id],
      });
    }
  }
  await addStep(operation.id, "dns-verified", { records: records.length });
  const clusters = await db.select().from(databaseClusters);
  for (const database of await db.select().from(managedDatabases)) {
    const cluster = clusters.find((item) => item.id === database.clusterId);
    if (cluster?.endpointId && verifiedEndpointIds.has(cluster.endpointId) && database.status === "queued") {
      await enqueue({
        kind: "database.provision",
        actorId: operation.actorId ?? undefined,
        targetIds: [database.id],
      });
    }
  }
  const mailEndpointReady = endpointRows.some(
    (item) => item.kind === "mail" && verifiedEndpointIds.has(item.id),
  );
  if (mailEndpointReady) {
    for (const mailbox of await db.select().from(mailboxes).where(eq(mailboxes.domainId, domainId))) {
      if (!mailbox.nativeId) {
        await enqueue({
          kind: "mail.provision",
          actorId: operation.actorId ?? undefined,
          targetIds: [mailbox.id],
        });
      }
    }
  }
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
  const action = operation.kind === "certificate.renew" ? "renew" : "run";
  const issued = await issueCertificateFiles(endpoint.hostname, action);
  if (!issued.fingerprint || !issued.expiresAt) {
    throw new Error("Certificate metadata is missing; refusing to store invented expiry or fingerprint.");
  }
  const certificateId = createId("crt");
  const publiclyTrusted = issued.issuer === "letsencrypt";
  // A database endpoint certificate is served by PgBouncer, which only picks up the renewed
  // files after a RELOAD. It is not marked as serving until the reload operation has confirmed
  // the new fingerprint on the public listener (§3.14).
  const servedByPgbouncer = endpoint.kind === "database";
  await db.insert(certificates).values({
    id: certificateId,
    endpointId,
    names: [endpoint.hostname],
    issuer: issued.issuer,
    fingerprint: issued.fingerprint,
    expiresAt: issued.expiresAt,
    status: servedByPgbouncer ? "awaiting_reload" : publiclyTrusted ? "issued" : "untrusted",
    lastDeployedAt: servedByPgbouncer ? null : new Date(),
  });
  if (servedByPgbouncer) {
    await enqueue({
      kind: "pgbouncer.reload",
      targetIds: [endpointId],
      payload: { certificateId, expectFingerprint: issued.fingerprint },
    });
  } else {
    await db
      .update(endpoints)
      .set({ status: publiclyTrusted ? "testing" : "certificate_untrusted" })
      .where(eq(endpoints.id, endpointId));
  }
  await addStep(operation.id, "certificate-issued", {
    issuer: issued.issuer,
    path: issued.certPath,
    awaitingReload: servedByPgbouncer,
  });
  // Applying the edge config is a platform-wide consequence of issuing a certificate, not an
  // action the actor requested. Carrying their id over would fail the owner-only platform check
  // for an operator who is allowed to verify their own domain.
  await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
}

async function provisionDatabase(operation: OperationRow) {
  const databaseId = operation.targetIds[0];
  const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, databaseId));
  if (!database) throw new Error("Database not found.");
  const existingRoles = await db.select().from(databaseRoles).where(eq(databaseRoles.databaseId, databaseId));
  const passwords = {} as Record<"owner" | "migration" | "runtime" | "readonly", string>;
  const roleKinds = ["owner", "migration", "runtime", "readonly"] as const;
  const credentials = new Map<
    (typeof roleKinds)[number],
    { existingRole?: (typeof existingRoles)[number]; existingSecret?: typeof secrets.$inferSelect }
  >();
  for (const kind of roleKinds) {
    const existingRole = existingRoles.find((item) => item.kind === kind);
    const existingSecret = existingRole?.secretId
      ? (await db.select().from(secrets).where(eq(secrets.id, existingRole.secretId)))[0]
      : undefined;
    if (existingRole && existingSecret) {
      passwords[kind] = decryptSecret(env.rootKey, existingSecret);
    } else {
      passwords[kind] = generatePassword();
    }
    credentials.set(kind, { existingRole, existingSecret });
  }
  const provisionPlan = buildProvisionPlan({
    name: database.name,
    withPgvector: database.withPgvector,
    withTestDatabase: database.withTestDatabase,
    passwords,
  });
  for (const kind of roleKinds) {
    const { existingRole, existingSecret } = credentials.get(kind)!;
    if (existingRole && existingSecret) continue;
    const plannedRole = provisionPlan.roles.find((item) => item.kind === kind)!;
    const sealed = encryptSecret(env.rootKey, passwords[kind], env.rootKeyId);
    const secretId = createId("sec");
    await db.insert(secrets).values({
      id: secretId,
      kind: `postgres.${kind}`,
      once: kind !== "owner",
      resourceType: "database",
      resourceId: databaseId,
      purpose: kind,
      sensitivity: kind === "owner" ? "root" : "credential",
      ...sealed,
    });
    if (existingRole) {
      await db.update(databaseRoles).set({ secretId }).where(eq(databaseRoles.id, existingRole.id));
    } else {
      await db.insert(databaseRoles).values({
        id: createId("role"),
        databaseId,
        name: plannedRole.name,
        kind,
        secretId,
      });
    }
  }
  const result = await provisionApplicationDatabase({
    name: database.name,
    withPgvector: database.withPgvector,
    withTestDatabase: database.withTestDatabase,
    passwords,
  });
  await db
    .update(managedDatabases)
    .set({ status: database.exposure === "public" ? "awaiting_configuration" : result.status })
    .where(eq(managedDatabases.id, databaseId));
  await addStep(operation.id, "database-provisioned", {
    executed: result.executed,
    database: result.plan.database,
    statements: result.plan.statements.length,
  });
  if (!result.executed) throw new Error("Database provisioning did not execute against a managed cluster.");
  if (database.exposure === "public") {
    await enqueue({
      kind: "pgbouncer.reload",
      actorId: operation.actorId ?? undefined,
      targetIds: [databaseId],
    });
  }
}

async function queryDatabase(operation: OperationRow) {
  const databaseId = operation.targetIds[0];
  const roleKind = String(operation.payload.role ?? "");
  const statement = String(operation.payload.sql ?? "");
  const readOnly = operation.payload.readOnly !== false;
  const executionId = String(operation.payload.executionId ?? "");
  const workspaceId = String(operation.payload.workspaceId ?? databaseId);
  if (!databaseId || !operation.actorId || !executionId) {
    throw new Error("Database query is missing its immutable actor, target, or execution identity.");
  }
  if (!(["readonly", "runtime", "migration"] as string[]).includes(roleKind)) {
    throw new Error("Database query role is not permitted.");
  }
  const classified = classifySql(statement, readOnly);
  const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, databaseId));
  if (!database) throw new Error("Database not found.");
  const [role] = await db
    .select()
    .from(databaseRoles)
    .where(and(eq(databaseRoles.databaseId, database.id), eq(databaseRoles.kind, roleKind)));
  if (!role?.secretId) throw new Error("Requested database role is not available.");
  const [secret] = await db.select().from(secrets).where(eq(secrets.id, role.secretId));
  if (!secret) throw new Error("Database role credential is missing.");
  const result = await executeWorkspaceQuery({
    executionId,
    actorId: operation.actorId,
    database: database.name,
    username: role.name,
    password: revealSecret(secret),
    sql: statement,
    readOnly,
  });
  return {
    query: {
      databaseId,
      workspaceId,
      role: roleKind,
      fingerprint: classified.fingerprint,
      ...result,
    },
  };
}

async function queryDatabaseSchema(operation: OperationRow) {
  const databaseId = operation.targetIds[0];
  if (!databaseId) throw new Error("Schema inspection is missing its database target.");
  const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, databaseId));
  if (!database) throw new Error("Database not found.");
  const [role] = await db
    .select()
    .from(databaseRoles)
    .where(and(eq(databaseRoles.databaseId, database.id), eq(databaseRoles.kind, "readonly")));
  if (!role?.secretId) throw new Error("Readonly database role is not available.");
  const [secret] = await db.select().from(secrets).where(eq(secrets.id, role.secretId));
  if (!secret) throw new Error("Readonly database credential is missing.");
  return {
    schema: await inspectDatabaseSchema({
      database: database.name,
      username: role.name,
      password: revealSecret(secret),
    }),
  };
}

async function provisionMailbox(operation: OperationRow) {
  const mailboxId = operation.targetIds[0];
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, mailboxId));
  if (!mailbox) throw new Error("Mailbox not found.");
  let password: string | undefined;
  if (operation.kind === "mail.provision") {
    const [plannedSecret] = await db
      .select()
      .from(secrets)
      .where(eq(secrets.kind, `mailbox.${mailboxId}`))
      .orderBy(desc(secrets.createdAt))
      .limit(1);
    if (plannedSecret) {
      password = decryptSecret(env.rootKey, plannedSecret);
    } else {
      password = generatePassword();
      const sealed = encryptSecret(env.rootKey, password, env.rootKeyId);
      await db.insert(secrets).values({
        id: createId("sec"),
        kind: `mailbox.${mailboxId}`,
        once: true,
        resourceType: "mailbox",
        resourceId: mailboxId,
        purpose: "login",
        ...sealed,
      });
    }
  }
  const domains = await db.select().from(domainClaims);
  const boxes = await db.select().from(mailboxes);
  const aliasRows = await db.select().from(aliases);
  const mailboxSecretRows = (await db.select().from(secrets))
    .filter((item) => item.kind.startsWith("mailbox.") && !item.kind.startsWith("mailbox.device."))
    .toSorted((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  const mailboxPasswords = new Map<string, string>();
  for (const item of mailboxSecretRows) {
    const mailboxSecretId = item.kind.slice("mailbox.".length);
    if (!mailboxPasswords.has(mailboxSecretId)) {
      mailboxPasswords.set(mailboxSecretId, decryptSecret(env.rootKey, item));
    }
  }
  const domain = domains.find((item) => item.id === mailbox.domainId);
  const sesReady = Boolean(process.env.AWS_ACCESS_KEY_ID || process.env.AWS_BOOTSTRAP_ACCESS_KEY_ID);
  const mailEndpointRows = await db.select().from(endpoints).where(eq(endpoints.domainId, mailbox.domainId));
  const selectedMailEndpoint = mailEndpointRows.find((item) => item.kind === "mail");
  const mailHostname = selectedMailEndpoint?.hostname ?? "mail.local";
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
      password: item.id === mailboxId ? password : mailboxPasswords.get(item.id),
      nativeId: item.nativeId ?? undefined,
    })),
    aliases: aliasRows
      .filter((item) => item.status === "active")
      .map((item) => ({
        address: `${item.localPart}@${domains.find((row) => row.id === item.domainId)?.name}`,
        targets: item.targets,
      })),
    removedAliases:
      typeof operation.payload.removedAlias === "object" && operation.payload.removedAlias !== null
        ? [operation.payload.removedAlias as { address: string; nativeId: string }]
        : undefined,
    sesReady,
    smtpUsername: process.env.SES_SMTP_USERNAME,
  });
  if (operation.kind === "mail.provision") {
    await db
      .update(mailboxes)
      .set({ credentialAvailable: true, lifecycle: "active" })
      .where(eq(mailboxes.id, mailboxId));
  }
  for (const item of boxes) {
    const itemDomain = domains.find((row) => row.id === item.domainId);
    const address = `${item.localPart}@${itemDomain?.name}`;
    const nativeId = applied.nativeIds.mailboxes[address];
    if (nativeId && nativeId !== item.nativeId) {
      await db.update(mailboxes).set({ nativeId }).where(eq(mailboxes.id, item.id));
    }
  }
  for (const item of aliasRows) {
    if (item.status !== "active") continue;
    const itemDomain = domains.find((row) => row.id === item.domainId);
    const address = `${item.localPart}@${itemDomain?.name}`;
    const nativeId = applied.nativeIds.aliases[address];
    if (nativeId && nativeId !== item.nativeId) {
      await db.update(aliases).set({ nativeId }).where(eq(aliases.id, item.id));
    }
  }
  if (typeof operation.payload.removedAliasId === "string") {
    await db.delete(aliases).where(eq(aliases.id, operation.payload.removedAliasId));
  }
  const mailEndpoint = selectedMailEndpoint;
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
    listenerReady: applied.applied,
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

async function reconcileMailboxDevice(operation: OperationRow) {
  const mailboxId = operation.targetIds[0];
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, mailboxId));
  if (!mailbox) throw new Error("Mailbox not found.");
  const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, mailbox.domainId));
  if (!domain) throw new Error("Mailbox domain not found.");
  const deviceId = String(operation.payload.deviceId ?? "");
  const [device] = await db.select().from(mailboxDevices).where(eq(mailboxDevices.id, deviceId));
  if (!device || device.mailboxId !== mailbox.id) throw new Error("Mailbox device not found.");
  const [primarySecret] = await db
    .select()
    .from(secrets)
    .where(eq(secrets.kind, `mailbox.${mailbox.id}`));
  if (!primarySecret) throw new Error("The mailbox primary credential is unavailable.");
  const action = operation.payload.action === "revoke" ? "revoke" : "create";
  const result = await applyStalwartDevice({
    address: `${mailbox.localPart}@${domain.name}`,
    password: decryptSecret(env.rootKey, primarySecret),
    action,
    label: device.label,
    nativeId: device.nativeId ?? undefined,
  });
  if (action === "create" && "secret" in result) {
    if (!result.secret) throw new Error("Stalwart did not return the device secret.");
    const secretId = createId("sec");
    await db.insert(secrets).values({
      id: secretId,
      kind: `mailbox.device.${device.id}`,
      once: true,
      resourceType: "mailbox",
      resourceId: mailbox.id,
      purpose: "device-login",
      ...encryptSecret(env.rootKey, result.secret, env.rootKeyId),
    });
    await db
      .update(mailboxDevices)
      .set({ nativeId: result.nativeId, secretId })
      .where(eq(mailboxDevices.id, device.id));
  } else if (action === "revoke") {
    await db.update(mailboxDevices).set({ revokedAt: new Date() }).where(eq(mailboxDevices.id, device.id));
  }
  await addStep(operation.id, `mailbox-device-${action}`, {
    deviceId: device.id,
    nativeId: result.nativeId,
    applied: true,
  });
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
      evidence = {
        ...evidence,
        composeHash: written.hash,
        images: written.policy.ok ? written.policy.images : [],
      };
      if (dockerAvailable() && env.embeddedWorkers) {
        evidence.output = await deployCompose(projectName, written.file);
      } else {
        throw new DelegateToAgent({
          ...operation.payload,
          compose: written.canonical,
          composeHash: written.hash,
          name: service.name,
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
  // Planning already ran and handed this payload to the agent. Re-planning would mint a second
  // deployment revision and rotate the desired revision out from under the in-flight deploy.
  if (isDelegatedPayload(operation)) {
    throw new DelegateToAgent(operation.payload as Record<string, unknown>);
  }
  const [candidate] = await db
    .select()
    .from(updateCandidates)
    .where(eq(updateCandidates.serviceId, serviceId));
  if (!candidate || candidate.candidateDigest !== digest) {
    throw new Error("Stale or unknown update candidate digest.");
  }
  const [service] = await db.select().from(services).where(eq(services.id, serviceId));
  if (!service) throw new Error("Service not found.");
  if (service.stateful) {
    const recoveryPoints = await db.select().from(backups).where(eq(backups.targetId, service.id));
    if (!recoveryPoints.some((backup) => backup.restoreVerified && backup.status === "restore_verified")) {
      throw new Error("Stateful updates require a restore-tested recovery point for this exact service.");
    }
  }
  const nextCompose = pinComposeImage(service.compose, digest);
  const written = await writeApprovedCompose(service.id, nextCompose);
  const projectName = String(operation.payload.project ?? (await projectNameFor(service)));
  const desiredRevision = createId("rev");
  await db.insert(deploymentRevisions).values({
    id: createId("drev"),
    serviceId: service.id,
    desiredRevision,
    compose: nextCompose,
    imageDigest: digest,
    status: "planned",
  });
  // The candidate compose and digest stay on the revision row until the deploy is confirmed.
  // Writing them onto the service here would make a failed rollout look like the running
  // state, so update detection would report the unapproved digest as current and a later
  // `service.deploy` would ship it.
  await db.update(services).set({ desiredRevision, status: "updating" }).where(eq(services.id, serviceId));
  if (!dockerAvailable() || !env.embeddedWorkers) {
    throw new DelegateToAgent({
      ...operation.payload,
      compose: written.canonical,
      composeHash: written.hash,
      images: written.policy.ok ? written.policy.images : [],
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
      compose: nextCompose,
      imageDigest: digest,
      observedRevision: desiredRevision,
      observedAt: new Date(),
    })
    .where(eq(services.id, serviceId));
  await db
    .update(deploymentRevisions)
    .set({ status: "deployed" })
    .where(eq(deploymentRevisions.desiredRevision, desiredRevision));
  await addStep(operation.id, "update.apply", { file: written.file, digest, observed, output });
}

async function createBackup(operation: OperationRow) {
  const kind = String(operation.payload.kind ?? "platform-postgres");
  const result = await runBackup(
    kind as "platform-postgres" | "app-postgres" | "mail" | "volume",
    operation.targetIds[0],
  );
  await db.insert(backups).values({
    id: createId("bak"),
    kind,
    targetId: operation.targetIds[0],
    status: result.status,
    checksum: result.snapshotId ?? null,
    nativeSnapshotId: result.snapshotId ?? null,
    restoreVerified: false,
  });
  if (!backupProofAllowed(result) && result.executed === false) {
    await addStep(operation.id, "backup", result);
    throw new Error("Backup execution is disabled; a plan cannot satisfy a backup operation.");
  }
  if (!backupProofAllowed(result)) throw new Error("Backup did not produce uploaded evidence.");
  await addStep(operation.id, "backup", result);
}

async function restoreBackup(operation: OperationRow) {
  const kind = String(operation.payload.kind ?? "platform-postgres");
  const backupId = typeof operation.payload.backupId === "string" ? operation.payload.backupId : null;
  if (!backupId) throw new Error("Restore verification requires an exact backup ID.");
  const [selected] = await db.select().from(backups).where(eq(backups.id, backupId));
  if (!selected || selected.targetId !== operation.targetIds[0] || selected.kind !== kind) {
    throw new Error("The selected backup does not belong to this restore target.");
  }
  const snapshotId = selected.nativeSnapshotId ?? selected.checksum;
  if (!snapshotId) throw new Error("The selected backup has no native snapshot identifier.");
  const result = await runRestoreTest(
    kind as "platform-postgres" | "app-postgres" | "mail" | "volume",
    operation.targetIds[0],
    snapshotId,
  );
  if (!result.executed) {
    await addStep(operation.id, "restore-test", { ...result, backupId });
    throw new Error("Restore execution is disabled; an extraction plan is not restore proof.");
  }
  const [latest] = await db.select().from(backups).where(eq(backups.id, backupId));
  if (latest) {
    // Drive the documented state machine rather than writing a status directly, so an
    // out-of-order transition is rejected instead of silently recorded.
    const status = nextBackupStatus(latest.status as BackupStatus, "integrity");
    await db.update(backups).set({ status }).where(eq(backups.id, latest.id));
  }
  await addStep(operation.id, "restore-test", {
    ...result,
    backupId: latest?.id,
    // A restored byte stream is not restore proof. `restore_verified` is only reached once an
    // operator confirms the restored copy actually booted and served its data.
    verification: "Confirm the restored copy boots and serves data to mark this restore verified.",
  });
}

async function changeMode(operation: OperationRow) {
  const adminMode = String(operation.payload.adminMode ?? "public") === "tailnet" ? "tailnet" : "public";
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const destinationOrigin =
    adminMode === "public"
      ? settings?.adminHostname
        ? `https://${settings.adminHostname}`
        : null
      : (process.env.ARK_TAILNET_AUTH_ORIGIN ?? null);
  if (!destinationOrigin) throw new Error("The destination administration origin is not configured.");
  if (new URL(destinationOrigin).origin !== new URL(env.authUrl).origin) {
    throw new Error(
      `Better Auth is configured for ${env.authUrl}; restart with BETTER_AUTH_URL=${destinationOrigin} before switching ingress.`,
    );
  }
  const edge = await writeEdge({
    adminMode,
    adminHostname: settings?.adminHostname ?? undefined,
  });
  await db
    .update(platformSettings)
    .set({ adminMode, authOrigin: destinationOrigin, updatedAt: new Date() })
    .where(eq(platformSettings.id, "default"));
  await db.delete(session);
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
      resourceType: "domain",
      resourceId: domain.id,
      purpose: "ses-relay",
      sensitivity: "provider",
      ...sealed,
    });
  }
  const sesReady = Boolean(
    result.created &&
    result.account.configured &&
    "production" in result.account &&
    result.account.production &&
    result.account.sending &&
    typeof result.identity === "object" &&
    result.identity !== null &&
    "verified" in result.identity &&
    result.identity.verified &&
    result.identity.dkimStatus === "SUCCESS" &&
    result.identity.mailFromStatus === "SUCCESS",
  );
  await db
    .update(mailDomains)
    .set({ outboundStatus: sesReady ? "ready" : "paused" })
    .where(eq(mailDomains.domainId, domainId));
  await addStep(operation.id, "ses-reconcile", {
    identity: result.identity,
    created: result.created,
    configured: result.account.configured,
  });
}

/** Dedup key of the alert raised when PgBouncer cannot be reloaded or serves the wrong certificate. */
export const PGBOUNCER_RELOAD_ALERT = "pgbouncer-reload";

function pgbouncerReloadRequired() {
  return process.env.ARK_PGBOUNCER_RELOAD === "1" || process.env.NODE_ENV === "production";
}

/**
 * Regenerate the public PgBouncer configuration from active database clients (§3.10.2-§3.10.4),
 * write it atomically, and RELOAD through the admin console on the shared unix socket. For a
 * database endpoint certificate change (§3.14) the served fingerprint must match before the
 * certificate is marked as serving; failures are retried, then alerted and the operation fails.
 */
async function reloadPgbouncer(operation: OperationRow) {
  const now = new Date();
  const databases = await db.select().from(managedDatabases);
  const roles = await db.select().from(databaseRoles);
  const clientRows = await db.select().from(databaseClients);
  const certificateRows = await db
    .select({
      id: clientCertificates.id,
      caId: clientCertificates.caId,
      status: clientCertificates.status,
      rolloverState: clientCertificates.rolloverState,
      supersededBy: clientCertificates.supersededBy,
      notAfter: clientCertificates.notAfter,
    })
    .from(clientCertificates);
  const caRows = await db
    .select({
      id: privateCas.id,
      purpose: privateCas.purpose,
      status: privateCas.status,
      certPem: privateCas.certPem,
      notAfter: privateCas.notAfter,
    })
    .from(privateCas);
  const publicIds = new Set(databases.filter((item) => item.exposure === "public").map((item) => item.id));
  const clients = [];
  for (const client of clientRows) {
    const role = roles.find((item) => item.id === client.roleId);
    let password: string | null = null;
    if (client.status === "active" && publicIds.has(client.databaseId) && role?.secretId) {
      const [secret] = await db.select().from(secrets).where(eq(secrets.id, role.secretId));
      if (secret) password = decryptSecret(env.rootKey, secret);
    }
    clients.push({
      id: client.id,
      databaseId: client.databaseId,
      environment: client.environment,
      status: client.status,
      caId: client.caId,
      role: { name: role?.name ?? "", connectionLimit: role?.connectionLimit ?? 0, password },
    });
  }
  const plan = planPgbouncer({
    databases,
    // Revoked clients always take part, so their CAs are excluded even if the role row is gone.
    clients: clients.filter((item) => item.status !== "active" || item.role.name),
    certificates: certificateRows,
    cas: caRows,
    now,
    host: process.env.ARK_APP_PG_HOST ?? "app-postgres",
  });
  const dbEndpoint = (await db.select().from(endpoints)).find((item) => item.kind === "database");
  const required = pgbouncerReloadRequired();
  const adminPassword = process.env.ARK_PGBOUNCER_ADMIN_PASSWORD ?? "";
  if (required && !adminPassword) {
    throw new Error("ARK_PGBOUNCER_ADMIN_PASSWORD is required to reload PgBouncer over its admin socket.");
  }
  const files = renderPgbouncerFiles({
    plan,
    adminPassword: adminPassword || undefined,
    certificateDir: dbEndpoint
      ? `${process.env.ARK_CERT_DIR ?? "/var/lib/ark/certs"}/${dbEndpoint.hostname}`
      : undefined,
  });
  const written = await writePgbouncerFiles(pgbouncerDir(), files);

  const certificateId =
    typeof operation.payload.certificateId === "string" ? operation.payload.certificateId : "";
  const expectedFingerprint =
    typeof operation.payload.expectFingerprint === "string" ? operation.payload.expectFingerprint : undefined;
  let reload: Awaited<ReturnType<typeof reloadAndVerify>> | null = null;
  if (required) {
    const socket = {
      socketDir: process.env.ARK_PGBOUNCER_SOCKET_DIR ?? PGBOUNCER_SOCKET_DIR,
      password: adminPassword,
    };
    try {
      reload = await reloadAndVerify({
        reload: () => reloadPgbouncerAdmin(socket),
        expectedFingerprint,
        servedFingerprint: () =>
          servedCertificateFingerprint({
            host: process.env.ARK_PGBOUNCER_TLS_HOST ?? "pgbouncer-public",
            port: Number(process.env.ARK_PGBOUNCER_TLS_PORT ?? PGBOUNCER_PORT),
            servername: dbEndpoint?.hostname,
          }),
        attempts: Number(process.env.ARK_PGBOUNCER_RELOAD_ATTEMPTS ?? 3),
        delayMs: Number(process.env.ARK_PGBOUNCER_RELOAD_RETRY_MS ?? 2_000),
      });
    } catch (error) {
      const failures = error instanceof PgbouncerReloadError ? error.failures : [];
      await addStep(operation.id, "pgbouncer-reload-failed", {
        certificateId: certificateId || undefined,
        expectedFingerprint,
        failures,
      });
      await raiseAlert({
        severity: "critical",
        title: expectedFingerprint
          ? "PgBouncer reload failed: the renewed database certificate is not being served"
          : "PgBouncer reload failed: the public database configuration was not applied",
        dedupKey: PGBOUNCER_RELOAD_ALERT,
      });
      throw error;
    }
    await db
      .update(alerts)
      .set({ resolvedAt: new Date() })
      .where(and(eq(alerts.dedupKey, PGBOUNCER_RELOAD_ALERT), isNull(alerts.resolvedAt)));
  } else if (expectedFingerprint) {
    // Development without an admin socket: never claim the renewed certificate is serving.
    await addStep(operation.id, "pgbouncer-reload-skipped", { certificateId, reason: "no admin socket" });
  }
  const reloaded = reload !== null;
  if (certificateId && reloaded) {
    const [certificate] = await db.select().from(certificates).where(eq(certificates.id, certificateId));
    if (certificate) {
      const trusted = certificate.issuer === "letsencrypt";
      await db
        .update(certificates)
        .set({ status: trusted ? "issued" : "untrusted", lastDeployedAt: new Date() })
        .where(eq(certificates.id, certificateId));
      await db
        .update(endpoints)
        .set({ status: trusted ? "testing" : "certificate_untrusted" })
        .where(eq(endpoints.id, certificate.endpointId));
    }
  }
  const publicDatabases = databases.filter((item) => item.exposure === "public");
  const cidrs = [...new Set(publicDatabases.flatMap((item) => item.sourceCidrs ?? []))];
  if (cidrs.length) assertCidrs(cidrs);
  // With no admitted client, PgBouncer is not routed publicly at all.
  const allowlist = await applyDatabaseAllowlist(written.dir, cidrs, 5432, { expose: plan.routed });
  const mapped = new Set(plan.mappings.map((item) => item.database));
  for (const database of databases) {
    const allowlistReady = !database.sourceCidrs?.length || allowlist.enforced;
    await db
      .update(managedDatabases)
      .set({
        allowlistEnforced:
          database.exposure === "public" && Boolean(database.sourceCidrs?.length) && allowlist.enforced,
        status:
          database.exposure === "public" && reloaded && allowlistReady && mapped.has(database.name)
            ? "ready"
            : database.exposure === "public"
              ? "awaiting_configuration"
              : database.status,
      })
      .where(eq(managedDatabases.id, database.id));
  }
  await addStep(operation.id, "pgbouncer-reload", {
    routed: plan.routed,
    mappings: plan.mappings.length,
    users: plan.users.length,
    generations: plan.generations,
    excluded: plan.excluded,
    cidrs,
    dir: written.dir,
    reloaded,
    attempts: reload?.attempts ?? 0,
    servedFingerprint: reload?.fingerprint,
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
        requiresApproval:
          service.stateful ||
          candidateRequiresApproval({
            updatePolicy: service.updatePolicy,
          }),
        rollbackSafe: !service.stateful,
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
  const pendingKind = `postgres.${kind}.pending.${operation.id}`;
  const [plannedSecret] = await db
    .select()
    .from(secrets)
    .where(eq(secrets.kind, pendingKind))
    .orderBy(desc(secrets.createdAt))
    .limit(1);
  const password = plannedSecret ? decryptSecret(env.rootKey, plannedSecret) : generatePassword();
  const secretId = plannedSecret?.id ?? createId("sec");
  if (!plannedSecret) {
    await db.insert(secrets).values({
      id: secretId,
      kind: pendingKind,
      once: true,
      resourceType: "database",
      resourceId: databaseId,
      purpose: kind,
      ...encryptSecret(env.rootKey, password, env.rootKeyId),
    });
  }
  const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, databaseId));
  await rotateRolePassword({ role: target.name, password, database: database?.name });
  await db.update(databaseRoles).set({ secretId }).where(eq(databaseRoles.id, target.id));
  await enqueue({ kind: "pgbouncer.reload", targetIds: [databaseId] });
  await addStep(operation.id, "database-rotate", { role: target.name, previous: role?.name });
}

async function adoptService(operation: OperationRow) {
  const serviceId = operation.targetIds[0];
  const [service] = await db.select().from(services).where(eq(services.id, serviceId));
  if (!service) throw new Error("Service not found.");
  const written = await writeApprovedCompose(service.id, service.compose);
  throw new DelegateToAgent({
    ...operation.payload,
    compose: written.canonical,
    composeHash: written.hash,
    containerId: service.containerId,
    name: service.name,
  });
}

async function queueMail(operation: OperationRow) {
  const action = operation.kind === "mail.queue_delete" ? "delete" : "retry";
  const result = await mutateMailQueue(action, String(operation.payload.id ?? operation.targetIds[0]));
  if (!result.executed) throw new Error("No native Stalwart queue mutation executor is configured.");
  await addStep(operation.id, `mail-queue-${action}`, result);
}

async function maintainPlatform(operation: OperationRow) {
  const bundle = validateMaintenanceBundle(operation.payload as MaintenanceBundle);
  await addStep(operation.id, "platform-maintain", {
    images: bundle.images,
    rollbackSafe: bundle.rollbackSafe,
    note: "Apply only through scripts/maintain.ts with ARK_MAINTENANCE_TOKEN.",
  });
  throw new Error(
    "The API recorded a maintenance approval but cannot execute self-maintenance; use the independent signed release runner.",
  );
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
