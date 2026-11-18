import { Resolver, type resolveCaa } from "node:dns/promises";
import { join, resolve } from "node:path";

import {
  allowedBackends,
  routeIdentityKey,
  routeIdentityHostname,
  type EdgeL4Input,
  type EdgeL4Pooler,
  CaddyWithdrawalAdapter,
  caddyState,
  backupProofAllowed,
  buildProvisionPlan,
  candidateRequiresApproval,
  canViewDomain,
  canViewProject,
  classifySql,
  createId,
  dnsPublishInput,
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
  planEdge,
  servedHttpHostnames,
  servedHttpRoutes,
  planHash,
  platformDbIngressLimits,
  redactLogLine,
  validateMaintenanceBundle,
  type BackupStatus,
  type ExternalInventory,
  type EdgeWithdrawalAdapter,
  type MaintenanceBundle,
  type OperationKind,
  type OperationState,
} from "@ark-stack/shared";
import { and, desc, eq, isNotNull, isNull, like, or, sql as drizzleSql } from "drizzle-orm";

import { db, sql, type DbTransaction } from "./db.ts";
import { withPgbouncerLock } from "./modules/pgbouncer-lock.ts";
import { loadEnv } from "./env.ts";
import { canonicalHost, currentLoginHost, isAdminHost, refreshLoginHost } from "./origin-hosts.ts";
import { evaluateAlerts, raiseAlert, resolveAlert } from "./modules/alerts.ts";
import { runBackup, runRestoreTest } from "./modules/backups.ts";
import {
  evaluateBackupAlerts,
  exportTarget,
  startBackupSchedule,
  verifyTarget,
  type TargetEvidence,
} from "./modules/offsite-backups.ts";
import { acmeAccountUri, issueCertificateFiles } from "./modules/certificates.ts";
import { applyFrontIngress } from "./modules/front-ingress.ts";
import {
  edgeL4Configured,
  edgeL4Settings,
  haproxyAdapter,
  missingHttpRoutes,
  missingL4Routes,
  writeEdgeL4,
} from "./modules/edge-l4.ts";
import { edgeHttpRoutes } from "./modules/edge-routes.ts";
import { edgeL4Routes, enabledSniPorts, type OmittedL4Route } from "./modules/l4-routes.ts";
import { refreshRouteCrls, routeCrlsDue } from "./modules/route-pki.ts";
import {
  edgeLeaseDocument,
  ensureGateRevocationDrain,
  markGateRevocationsApplied,
  pendingGateRevocations,
} from "./modules/gate-revocations.ts";
import {
  EDGE_OBSERVE_TARGET,
  edgePolicy,
  observeEdgeTailnet,
  startEdgeObserveSchedule,
} from "./modules/edge-observe.ts";
import {
  routesAfterCertificate,
  routesAfterDnsCheck,
  routesCertificateFailed,
} from "./modules/front-routes.ts";
import { edgeLocalApi, edgeSocketPath } from "./modules/tailnet-localapi.ts";
import {
  backupLocalApi,
  backupSocketPath,
  observeBackupTailnet,
  startBackupObserveSchedule,
} from "./modules/backup-observe.ts";
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
  auditIssued,
  auditRevoked,
  issueDatabaseClient,
  issueEvidence,
  revokeDatabaseClient,
} from "./modules/db-clients.ts";
import {
  PgbouncerReloadError,
  RetirementError,
  killRoleClients,
  planPgbouncer,
  reloadAndVerify,
  reloadPgbouncerAdmin,
  renderPgbouncerFiles,
  retireGeneration,
  servedCertificateFingerprint,
  shutdownPgbouncerAdmin,
  socketAdmin,
  writePgbouncerFiles,
} from "./modules/pgbouncer.ts";
import {
  claimRetirement,
  completeRetirement,
  dueRetirements,
  ensureRetirement,
  evaluateRolloverAlerts,
  failRetirement,
  issueSuccessor,
  markGenerationRetired,
  markSuccessorsTrusted,
  overdueRetirements,
  recordWatchdog,
  retirementAlertKey,
  runScheduledRollover,
  successorEvidence,
  type DueRetirement,
  type IssueSuccessorResult,
} from "./modules/db-client-rollover.ts";
import {
  evaluateVercelTokenAlerts,
  pushVercelRollover,
  queueVercelPush,
} from "./modules/vercel-integrations.ts";
import {
  commitDnsSnapshot,
  confirmWithdrawals,
  desiredDns,
  domainsDueForDns,
  observedWithdrawals,
  pendingWithdrawal,
  publishReviewedDns,
  readDnsSnapshot,
  saveProjection,
  rememberUnexpectedAaaa,
  withdrawAuthorizedAaaa,
  type StoredDnsRecord,
} from "./modules/domain-dns.ts";
import { dnsBlockingError, emptyIfNoDnsData, isCloudflareProxyAddress } from "./modules/dns-verification.ts";
import { mutateMailQueue } from "./modules/queue.ts";
import { currentMailStatus, reconcileMailEngine } from "./modules/mail.ts";
import { poolerEdgeInput } from "./modules/pooler-policy.ts";
import {
  applyDatabaseIngress,
  applyStalwartDevice,
  reconcileSes,
  resolveImageDigest,
  scanImport,
  pgbouncerDir,
  writeEdge,
} from "./modules/providers.ts";
import {
  alerts,
  aliases,
  auditEvents,
  backups,
  backupTargets,
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
  caa?: typeof resolveCaa;
  mx(name: string): Promise<Array<{ priority: number; exchange: string }>>;
  cname(name: string): Promise<string[]>;
};

// Public answers are the evidence for ACME and withdrawal. They must not come from local or
// split-horizon tailnet DNS.
const publicResolver = new Resolver({ timeout: 2_000, tries: 2 });
publicResolver.setServers(["1.1.1.1", "8.8.8.8"]);
const nodeResolver: DnsResolver = {
  txt: (name) => publicResolver.resolveTxt(name),
  a: (name) => publicResolver.resolve4(name),
  aaaa: (name) => publicResolver.resolve6(name),
  caa: (name) => publicResolver.resolveCaa(name),
  mx: (name) => publicResolver.resolveMx(name),
  cname: (name) => publicResolver.resolveCname(name),
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

type EnqueueInput = {
  kind: OperationKind;
  actorId?: string;
  targetIds: string[];
  payload?: Record<string, unknown>;
  idempotencyKey?: string;
};

export function enqueue(input: EnqueueInput) {
  return db.transaction((tx) => enqueueInTransaction(tx, input));
}

async function enqueueInTransaction(tx: DbTransaction, input: EnqueueInput) {
  const base = input.idempotencyKey ?? operationIdempotencyKey(input.kind, input.targetIds, input.payload);
  // A unique index protects the first enqueue; the lock also serializes retries after a terminal order.
  await tx.execute(drizzleSql`SELECT pg_advisory_xact_lock(hashtext(${`ark:enqueue:${base}`}))`);
  const related = await tx
    .select()
    .from(operations)
    .where(or(eq(operations.idempotencyKey, base), like(operations.idempotencyKey, `${base}:%`)))
    .orderBy(desc(operations.createdAt));
  // A running edge apply may already have captured an older desired state. Reuse only queued
  // successors: every mutation during a running apply must leave durable work behind it.
  const inflight = related.find((row) =>
    input.kind === "edge.l4_apply" ? row.status === "queued" : isInFlight(row.status),
  );
  if (inflight) return inflight;
  const idempotencyKey = related.length ? `${base}:${createId("idem")}` : base;
  const [row] = await tx
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
    .onConflictDoNothing({ target: operations.idempotencyKey })
    .returning();
  if (row) return row;
  const [existing] = await tx.select().from(operations).where(eq(operations.idempotencyKey, idempotencyKey));
  return existing!;
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
  // Durable retry for gate revocations (FD-11, §3.9.3): a failed or lost forced-reload drain is
  // queued again while any revocation is pending.
  await ensureGateRevocationDrain().catch((error) =>
    console.error(`gate revocation drain check failed: ${(error as Error).message}`),
  );
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

export async function processQueued(
  limit = 8,
  kindPrefix?: string,
  excludePrefix = !env.embeddedWorkers && !kindPrefix ? "service." : undefined,
) {
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
  if (kindPrefix !== "integration.") await evaluateAlerts().catch(() => undefined);
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

type ClientOperationRuntime = {
  issue: typeof issueDatabaseClient;
  revoke: typeof revokeDatabaseClient;
  /** Regenerate and reload PgBouncer; reports the mapped databases when it knows them. */
  reload: (
    operation: OperationRow,
    now?: Date,
  ) => Promise<Awaited<ReturnType<typeof reloadPgbouncer>> | void>;
  kill: typeof killRoleClients;
  reloadRequired: typeof pgbouncerReloadRequired;
  /** FD-28: the clock every rollover decision uses; tests inject a timeline. */
  now: () => Date;
  vercelPush: typeof pushVercelRollover;
  /** FD-28: successor issuance (db-client-rollover.issueSuccessor). */
  issueSuccessor: typeof issueSuccessor;
  /** FD-28: fence, reduced reload, role and pre-auth drain, reopen (pgbouncer.retireGeneration). */
  retire: typeof retireGeneration;
  /** FD-28: the retirement watchdog's escalation when a drain misses its deadline. */
  watchdog: RetirementWatchdog;
};
const clientOperationRuntime: ClientOperationRuntime = {
  issue: issueDatabaseClient,
  revoke: revokeDatabaseClient,
  reload: reloadPgbouncer,
  kill: killRoleClients,
  reloadRequired: pgbouncerReloadRequired,
  now: () => new Date(),
  issueSuccessor,
  vercelPush: pushVercelRollover,
  retire: retireGeneration,
  watchdog: {
    fence: (database) => socketAdmin(pgbouncerSocket())(`DISABLE ${database}`).then(() => undefined),
    stop: () => shutdownPgbouncerAdmin(pgbouncerSocket()),
    fenceListener: () => fencePoolerListener("retirement-watchdog"),
  },
};
export type { ClientOperationRuntime };

export async function runOperation(
  kind: OperationKind,
  operation: OperationRow,
  overrides: Partial<ClientOperationRuntime> = {},
) {
  const runtime = { ...clientOperationRuntime, ...overrides };
  await assertExecutionAuthorized(operation);
  if (kind === "integration.vercel_push") return runtime.vercelPush(operation);
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
  if (kind === "backup.export") return exportBackupTarget(operation);
  if (kind === "backup.verify_target") return verifyBackupTarget(operation);
  if (kind === "backup.observe") return observeBackup(operation);
  if (kind === "update.apply") return applyUpdate(operation);
  if (kind === "admin.mode_change") return changeMode(operation);
  if (kind === "dns.publish") return publishDns(operation);
  if (kind === "ses.reconcile") return reconcileSesOp(operation);
  if (kind === "pgbouncer.reload") return reloadPgbouncer(operation);
  if (kind === "edge.apply") return applyEdge(operation);
  if (kind === "edge.l4_apply") return applyEdgeL4(operation);
  if (kind === "edge.observe") return observeEdge(operation);
  if (kind === "edge.drain") return drainEdge(operation);
  if (kind === "update.detect") return detectUpdates(operation);
  if (kind === "import.scan") return scanImportOp(operation);
  if (kind === "database.rotate") return rotateDatabase(operation);
  if (kind === "database.client_issue") return issueDatabaseClientOp(operation, runtime);
  if (kind === "database.client_revoke") return revokeDatabaseClientOp(operation, runtime);
  if (kind === "database.client_rollover") return rolloverDatabaseClientsOp(operation, runtime);
  if (kind === "database.client_retire") return retireClientCertificateOp(operation, runtime);
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
  if (
    [
      "database.client_issue",
      "database.client_revoke",
      "database.client_rollover",
      "integration.vercel_push",
    ].includes(operation.kind)
  )
    throw new Error("Only owners may execute database client operations.");
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

function publicAddresses(type: string, name: string) {
  return emptyIfNoDnsData(type === "A" ? dnsResolver.a(name) : dnsResolver.aaaa(name));
}

async function observeDns(type: string, name: string, addresses: typeof publicAddresses) {
  if (type === "TXT") return observedDnsValue("TXT", (await dnsResolver.txt(name)).flat());
  if (type === "A" || type === "AAAA") return observedDnsValue(type, await addresses(type, name));
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
  const routeEndpointsOnly = operation.payload.routeEndpointsOnly === true;
  const scheduled = operation.payload.scheduledDns === true;
  const stub = process.env.ARK_DNS_STUB === "1";
  const autoErrors = await withdrawAuthorizedAaaa(domainId);
  const snapshot = await readDnsSnapshot(domainId);
  const { domain, records, endpointRows: allEndpoints } = snapshot;
  const lookups = new Map<string, Promise<string[]>>();
  const addresses: typeof publicAddresses = (type, name) => {
    const key = `${type}:${name}`;
    let result = lookups.get(key);
    if (!result) {
      result = publicAddresses(type, name);
      lookups.set(key, result);
    }
    return result;
  };
  const now = new Date();
  // Test stubs cover desired records only. A withdrawal needs a real or explicitly injected lookup.
  const confirmed = stub ? [] : await observedWithdrawals(records, addresses, now);
  const withdrawals = records.filter((record) => pendingWithdrawal(record) && !confirmed.includes(record.id));
  const endpointRows = allEndpoints.filter((endpoint) => !routeEndpointsOnly || endpoint.kind === "route");
  const endpointNames = new Set(endpointRows.map((endpoint) => endpoint.hostname));
  const active = records.filter(
    (record) =>
      desiredDns(record) &&
      (!routeEndpointsOnly || record.name === `_ark-stack.${domain.name}` || endpointNames.has(record.name)),
  );
  const ownership = active.find(
    (record) =>
      record.type === "TXT" &&
      record.required &&
      record.name === `_ark-stack.${domain.name}` &&
      record.expectedValue === domain.ownershipToken &&
      record.purpose.toLowerCase().includes("ownership"),
  );
  const observations = new Map<string, { observed: string; ok: boolean }>();
  for (const record of ownership ? active : []) {
    let observed = record.expectedValue;
    let ok = stub;
    if (!stub) {
      try {
        observed = await observeDns(record.type, record.name, addresses);
        ok = dnsRecordVerified(record.type, record.expectedValue, observed);
      } catch (error) {
        observed = error instanceof Error ? error.message : "lookup failed";
      }
    }
    observations.set(record.id, { observed, ok });
  }
  const ownershipError = !ownership
    ? "Domain ownership challenge is missing or does not match this installation."
    : !observations.get(ownership.id)?.ok
      ? `DNS ownership proof ${ownership.name} is not yet published correctly.`
      : null;

  const checkedProxyHosts = new Set<string>();
  const proxyAaaaHosts = new Set<string>();
  const endpointChecks: Array<{
    endpoint: (typeof endpointRows)[number];
    required: StoredDnsRecord[];
    pending: Array<{ type: string; name: string; expected: string; observed: string }>;
    blockingError: string | null;
    unexpectedAaaa: string[];
  }> = [];
  const caa = dnsResolver.caa ?? (async () => []);
  for (const endpoint of ownershipError ? [] : endpointRows) {
    const required = active.filter((record) => record.name === endpoint.hostname && record.required);
    const hasAddresses = required.some((record) => record.type === "A" || record.type === "AAAA");
    let blockingError: string | null = null;
    let unexpectedAaaa: string[] = [];
    if (endpoint.exposure === "public" && hasAddresses && !stub) {
      blockingError = await dnsBlockingError({
        hostname: endpoint.hostname,
        records: required,
        addresses,
        caa,
        accountUri: () => acmeAccountUri(endpoint.hostname),
      });
      if (required.some((record) => record.type === "AAAA")) {
        checkedProxyHosts.add(endpoint.hostname);
      } else {
        const found = await addresses("AAAA", endpoint.hostname).catch(() => null);
        if (found) {
          checkedProxyHosts.add(endpoint.hostname);
          if (found.some(isCloudflareProxyAddress)) proxyAaaaHosts.add(endpoint.hostname);
          unexpectedAaaa = found.filter((ip) => !isCloudflareProxyAddress(ip));
        }
      }
    }
    const pending = required
      .filter((record) => !observations.get(record.id)?.ok)
      .map((record) => ({
        type: record.type,
        name: record.name,
        expected: record.expectedValue,
        observed: observations.get(record.id)?.observed ?? "",
      }));
    endpointChecks.push({ endpoint, required, pending, blockingError, unexpectedAaaa });
  }

  const verifiedEndpointIds = new Set<string>();
  let remainingProxyHosts: string[] = [];
  const blocked = await commitDnsSnapshot(snapshot, async (tx, locked) => {
    await saveProjection(tx, locked.stored, locked.records);
    await confirmWithdrawals(tx, confirmed, now);
    for (const [id, { observed, ok }] of observations) {
      await tx
        .update(dnsRecords)
        .set({ observedValue: observed, status: ok ? "verified" : "error" })
        .where(eq(dnsRecords.id, id));
    }
    const errors: Array<{ hostname: string; error: string }> = [];
    for (const {
      endpoint,
      required,
      pending,
      unexpectedAaaa,
      blockingError: policyError,
    } of endpointChecks) {
      let blockingError = policyError;
      if (endpoint.exposure === "public") {
        if (unexpectedAaaa.length) {
          withdrawals.push(
            ...(await rememberUnexpectedAaaa(tx, domain, records, endpoint.hostname, unexpectedAaaa)),
          );
        }
        if (
          !blockingError &&
          withdrawals.some((record) => record.name === endpoint.hostname && record.type === "AAAA")
        ) {
          blockingError = `IPv6 withdrawal is pending for ${endpoint.hostname}. Remove the prior AAAA and wait for DNS to confirm its absence.`;
        }
        if (
          !blockingError &&
          domain.dnsProvider === "cloudflare" &&
          required.some((record) => !record.publishedAt)
        ) {
          blockingError = `Review and publish the Cloudflare DNS plan for ${endpoint.hostname}, then recheck DNS.`;
        }
      }
      if (blockingError) errors.push({ hostname: endpoint.hostname, error: blockingError });
      if (
        !blockingError &&
        endpoint.kind === "mail" &&
        domain.dnsProvider === "cloudflare" &&
        active.some(
          (record) =>
            record.type === "MX" &&
            record.required &&
            (!record.publishedAt || !observations.get(record.id)?.ok),
        )
      ) {
        blockingError = "The incoming mail MX record needs review and public DNS verification.";
        errors.push({ hostname: endpoint.hostname, error: blockingError });
      }
      const verified =
        !blockingError && (endpoint.exposure !== "public" || (required.length > 0 && !pending.length));
      await tx
        .update(endpoints)
        .set({
          status: verified ? "verified" : "awaiting_dns",
          lastVerifiedAt: verified ? now : null,
        })
        .where(eq(endpoints.id, endpoint.id));
      if (verified) verifiedEndpointIds.add(endpoint.id);
      if (endpoint.kind === "route") {
        const { issueCertificate: shouldIssue } = await routesAfterDnsCheck(
          {
            endpointId: endpoint.id,
            verified,
            pending,
            blockingError: blockingError ?? undefined,
            operationId: operation.id,
            allowCertificateRetry: !routeEndpointsOnly && !scheduled,
          },
          tx,
        );
        if (!shouldIssue) continue;
      } else if (!verified) {
        continue;
      } else if (scheduled) {
        const [prior] = await tx
          .select({ id: operations.id })
          .from(operations)
          .where(
            and(
              eq(operations.kind, "certificate.issue"),
              drizzleSql`${operations.targetIds} ? ${endpoint.id}`,
            ),
          )
          .limit(1);
        const [certificate] = await tx
          .select({ id: certificates.id })
          .from(certificates)
          .where(eq(certificates.endpointId, endpoint.id))
          .limit(1);
        if (prior || certificate || !["awaiting_dns", "draft", "verified"].includes(endpoint.status))
          continue;
      }

      // A recovery may overlap the original job's completion. Give it a distinct queue key;
      // the operation target fence keeps it from executing while the old order is running.
      const [rejectedOrder] =
        endpoint.kind === "route"
          ? await tx
              .select({ id: operations.id })
              .from(operations)
              .where(
                and(
                  eq(operations.kind, "certificate.issue"),
                  drizzleSql`${operations.targetIds} ? ${endpoint.id}`,
                  drizzleSql`${operations.payload} @> '{"dnsRecheckRejected": true}'::jsonb`,
                ),
              )
              .orderBy(desc(operations.createdAt), desc(operations.id))
              .limit(1)
          : [];
      // Readiness, route lifecycle, and their certificate handoff commit together.
      await enqueueInTransaction(tx, {
        kind: "certificate.issue",
        actorId: operation.actorId ?? undefined,
        targetIds: [endpoint.id],
        payload: { verifiedDns: true },
        idempotencyKey: rejectedOrder && "certificate.issue:dns-recovery:" + rejectedOrder.id,
      });
    }
    const retainedProxyHosts = locked.domain.proxyAaaaHosts.filter(
      (name) =>
        !checkedProxyHosts.has(name) &&
        locked.endpointRows.some((endpoint) => endpoint.exposure === "public" && endpoint.hostname === name),
    );
    remainingProxyHosts = [...retainedProxyHosts, ...proxyAaaaHosts].toSorted();
    await tx
      .update(domainClaims)
      .set({
        status: ownershipError ? locked.domain.status : "verified",
        lastError: ownershipError ?? autoErrors[0] ?? errors[0]?.error ?? null,
        proxyAaaaHosts: remainingProxyHosts,
        updatedAt: now,
      })
      .where(eq(domainClaims.id, domainId));
    return errors;
  });

  const pendingName = withdrawals.find((record) => record.type === "AAAA")?.name ?? remainingProxyHosts[0];
  const dedupKey = `dns-aaaa-withdrawal:${domainId}`;
  if (pendingName) {
    await raiseAlert({
      dedupKey,
      severity: "warning",
      title: autoErrors[0] ?? `IPv6 DNS removal pending for ${pendingName}`,
    });
  } else {
    await resolveAlert(dedupKey);
  }
  if (ownershipError) {
    if (scheduled) return;
    throw new Error(ownershipError);
  }
  await addStep(operation.id, "dns-verified", {
    records: active.length,
    blocked,
  });
  if (routeEndpointsOnly) return;
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
}

async function issueCertificate(operation: OperationRow) {
  if (operation.payload.dnsRecheckRejected === true)
    throw new Error(
      "The previous DNS check blocked this certificate order. DNS verification will queue a new order.",
    );
  const endpointId = operation.targetIds[0];
  const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, endpointId));
  if (!endpoint) throw new Error("Endpoint not found.");
  const action = operation.kind === "certificate.renew" ? "renew" : "run";
  let issued: Awaited<ReturnType<typeof issueCertificateFiles>>;
  let attemptedOrder = false;
  try {
    // The DNS check and certificate order are separate jobs. Recheck policy and address
    // eligibility in case a toggle, preflight result or resolver answer changed in between.
    if (
      operation.payload.verifiedDns &&
      endpoint.exposure === "public" &&
      endpoint.domainId &&
      process.env.ARK_DNS_STUB !== "1"
    ) {
      const snapshot = await readDnsSnapshot(endpoint.domainId);
      const live = snapshot.endpointRows.find((row) => row.id === endpoint.id);
      if (!live || live.hostname !== endpoint.hostname || live.exposure !== endpoint.exposure) {
        throw new Error("Endpoint changed before certificate issuance. Recheck DNS.");
      }
      const matching = snapshot.records.filter((record) => record.name === endpoint.hostname);
      const required = matching.filter((record) => desiredDns(record) && record.required);
      const error = await dnsBlockingError({
        hostname: endpoint.hostname,
        records: required,
        addresses: publicAddresses,
        caa: dnsResolver.caa ?? (async () => []),
        accountUri: () => acmeAccountUri(endpoint.hostname),
      });
      if (error) throw new Error(error);
      if (
        matching.some((record) => record.type === "AAAA" && pendingWithdrawal(record)) ||
        (snapshot.domain.dnsProvider === "cloudflare" && required.some((record) => !record.publishedAt))
      ) {
        throw new Error(
          `DNS publishing or withdrawal is pending for ${endpoint.hostname}. Review and recheck DNS.`,
        );
      }
      if (
        !required.length ||
        !(
          await Promise.all(
            required.map(async (record) =>
              dnsRecordVerified(
                record.type,
                record.expectedValue,
                await observeDns(record.type, record.name, publicAddresses),
              ),
            ),
          )
        ).every(Boolean)
      ) {
        throw new Error(
          `Public DNS for ${endpoint.hostname} changed. Recheck it before requesting a certificate.`,
        );
      }
      await commitDnsSnapshot(snapshot, async () => {});
    }
    attemptedOrder = true;
    issued = await issueCertificateFiles(endpoint.hostname, action);
  } catch (error) {
    if (endpoint.kind === "route")
      await routesCertificateFailed(
        endpoint.id,
        (error as Error).message,
        !attemptedOrder && action === "run" ? operation.id : undefined,
      );
    throw error;
  }
  if (!issued.fingerprint || !issued.expiresAt) {
    throw new Error("Certificate metadata is missing; refusing to store invented expiry or fingerprint.");
  }
  const certificateId = createId("crt");
  const publiclyTrusted = issued.issuer === "letsencrypt";
  // A database endpoint certificate is served by PgBouncer, which only picks up the renewed
  // files after a RELOAD. It is not marked as serving until the reload operation has confirmed
  // the new fingerprint on the public listener (§3.14).
  const servedByPgbouncer = endpoint.kind === "database";
  const certificateStatus = servedByPgbouncer ? "awaiting_reload" : publiclyTrusted ? "issued" : "untrusted";
  await db.insert(certificates).values({
    id: certificateId,
    endpointId,
    names: [endpoint.hostname],
    issuer: issued.issuer,
    fingerprint: issued.fingerprint,
    expiresAt: issued.expiresAt,
    status: certificateStatus,
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
  if (endpoint.kind === "route") {
    // FD-08: the route becomes `ready` only after a fresh edge-netns probe, which edge.observe runs.
    const { observe } = await routesAfterCertificate({
      endpointId,
      status: certificateStatus,
      issuer: issued.issuer,
      operationId: operation.id,
    });
    if (observe) await enqueue({ kind: "edge.observe", targetIds: [EDGE_OBSERVE_TARGET] });
  }
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
  const type = ["full", "diff", "incr"].includes(String(operation.payload.type))
    ? (String(operation.payload.type) as "full" | "diff" | "incr")
    : "full";
  const result = await runBackup(
    kind as "platform-postgres" | "app-postgres" | "mail" | "volume",
    operation.targetIds[0],
    { type },
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
  if (result.status === "local") {
    // FD-21: a PostgreSQL backup lands in the local repo2 first; ship it to every target now rather
    // than at the next five-minute tick.
    await addStep(operation.id, "backup", result);
    for (const target of await db.select().from(backupTargets).where(eq(backupTargets.enabled, true))) {
      await enqueue({ kind: "backup.export", targetIds: [target.id], payload: { fresh: true } });
    }
    return;
  }
  if (!backupProofAllowed(result) && result.executed === false) {
    await addStep(operation.id, "backup", result);
    throw new Error("Backup execution is disabled; a plan cannot satisfy a backup operation.");
  }
  if (!backupProofAllowed(result)) throw new Error("Backup did not produce uploaded evidence.");
  await addStep(operation.id, "backup", result);
}

/** `backup.export` (FD-21): stage and upload both PostgreSQL clusters to one target. */
async function exportBackupTarget(operation: OperationRow) {
  const result = await exportTarget(operation.targetIds[0], { fresh: operation.payload.fresh === true });
  await addStep(operation.id, "backup-export", result as unknown as Record<string, unknown>);
}

/** `backup.verify_target` (FD-21): the append-only canary with the deployed writer credentials. */
async function verifyBackupTarget(operation: OperationRow) {
  const evidence = await verifyTarget<TargetEvidence>(
    operation.targetIds[0],
    operation.payload.revision as string | undefined,
  );
  await addStep(operation.id, "append-only-canary", {
    status: evidence.status,
    findings: evidence.findings,
    retentionUntil: evidence.retentionUntil,
  });
}

/**
 * `backup.observe` (FD-30, front door §3.18.3): backup-ts's own LocalAPI status, read-only, as one
 * complete `source = 'backup'` generation. Alerts are re-evaluated either way, so an expired or
 * failed observation raises the critical suspension alert at once.
 */
async function observeBackup(operation: OperationRow) {
  const socket = backupSocketPath();
  try {
    if (!socket) {
      throw new Error(
        "ARK_BACKUP_TS_SOCKET is not set: backup-ts's LocalAPI socket is not mounted here (backup worker only).",
      );
    }
    const result = await observeBackupTailnet({ api: backupLocalApi(socket), operationId: operation.id });
    await addStep(operation.id, "backup-observe", result as unknown as Record<string, unknown>);
    return result;
  } finally {
    await evaluateBackupAlerts().catch(() => undefined);
  }
}

/** Schedules `backup.observe` every five minutes where backup-ts's socket is mounted (FD-30). */
export function scheduleBackupObserve(intervalMs?: number) {
  if (!backupSocketPath()) return null;
  return startBackupObserveSchedule({
    enqueue: (input) => enqueue(input),
    intervalMs,
    log: (line) => console.error(redactLogLine(line)),
  });
}

/**
 * Backup schedules (FD-21): observe the executors and enqueue due full/differential backups, an
 * export per target every five minutes and the weekly canary. Run by the backup worker when backups
 * execute; queued or running operations are reused, so a stopped worker does not pile them up.
 */
export function scheduleBackups() {
  if (process.env.ARK_BACKUP_EXECUTE !== "1") return null;
  return startBackupSchedule({
    enqueue: (input) => enqueue(input),
    log: (line) => console.error(redactLogLine(line)),
  });
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
  return withEdgeLock(() => changeModeLocked(operation));
}

async function changeModeLocked(operation: OperationRow) {
  const adminMode = String(operation.payload.adminMode ?? "public") === "tailnet" ? "tailnet" : "public";
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const destinationOrigin =
    adminMode === "public"
      ? settings?.adminHostname
        ? `https://${settings.adminHostname}`
        : null
      : (process.env.ARK_TAILNET_AUTH_ORIGIN ?? null);
  if (!destinationOrigin) throw new Error("The destination administration origin is not configured.");
  const plan = await edgePlan(adminMode, settings?.adminHostname);
  if (adminMode === "public" && plan.adminHostname && plan.awaitingCertificate.includes(plan.adminHostname)) {
    throw new Error(`The admin certificate for ${plan.adminHostname} is not issued yet.`);
  }
  // Better Auth's dynamic base URL (front door §3.9.1) serves only registered hosts, so the
  // destination admin origin must be one of its admin `allowedHosts`, over the configured scheme,
  // and never the public login origin.
  const destination = new URL(destinationOrigin);
  await refreshLoginHost(true);
  const destinationHost = canonicalHost(destination.host);
  if (
    destination.protocol !== new URL(env.authUrl).protocol ||
    !isAdminHost(destinationHost) ||
    destinationHost === currentLoginHost()
  ) {
    throw new Error(
      `Better Auth's admin hosts do not include ${destination.origin}; restart with BETTER_AUTH_URL=${destinationOrigin} before switching ingress.`,
    );
  }
  const edge = await writeEdge(plan);
  await db
    .update(platformSettings)
    .set({ adminMode, authOrigin: destinationOrigin, updatedAt: new Date() })
    .where(eq(platformSettings.id, "default"));
  if (edgeL4Configured()) await enqueue({ kind: "edge.l4_apply", targetIds: ["platform"] });
  await db.delete(session);
  await addStep(operation.id, "mode-change", { adminMode, sessionsRevoked: true, ...edge });
}

async function publishDns(operation: OperationRow) {
  const input = dnsPublishInput.parse(operation.payload.reviewed ?? { planHash: operation.payload.planHash });
  const [actor] = await db
    .select()
    .from(platformAccess)
    .where(eq(platformAccess.userId, operation.actorId ?? ""));
  if (
    (actor?.role !== "owner" && actor?.role !== "operator") ||
    (operation.payload.role && actor.role !== operation.payload.role)
  )
    throw new Error("DNS publisher is no longer authorized.");
  await publishReviewedDns(operation, input, { userId: actor.userId, role: actor.role });
}

export async function runDnsMaintenance() {
  for (const { domainId, routeEndpointsOnly } of await domainsDueForDns()) {
    await enqueue({
      kind: "domain.verify",
      targetIds: [domainId],
      payload: { routeEndpointsOnly, scheduledDns: true },
      idempotencyKey: "dns.maintenance:" + domainId,
    });
  }
}

export function scheduleDnsMaintenance(intervalMs = 120_000) {
  let running = false;
  async function tick() {
    if (running) return;
    running = true;
    try {
      await runDnsMaintenance();
    } catch (error) {
      console.error("DNS maintenance failed:", error instanceof Error ? error.message : error);
    } finally {
      running = false;
    }
  }
  void tick();
  return setInterval(() => void tick(), intervalMs).unref();
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

/** Reconcile persisted pre-upgrade policy through the normal, observable worker operation. */
export async function reconcileDatabaseIngressOnStartup() {
  const publicDatabases = await db
    .select({ id: managedDatabases.id })
    .from(managedDatabases)
    .where(eq(managedDatabases.exposure, "public"));
  if (!publicDatabases.length) {
    if (poolerEdgeManaged()) return enqueue({ kind: "edge.l4_apply", targetIds: ["platform"] });
    return null;
  }
  return enqueue({
    kind: "pgbouncer.reload",
    targetIds: [],
    payload: { reason: "startup-db-ingress-policy" },
  });
}

/**
 * The host nft policy for tcp/5432 (`ark_db_ingress`, FD-18): per-source limits only. Since FD-26 the
 * source allowlist is HAProxy's: the pooler-wide policy in `be_pgbouncer` and each `postgres` route's
 * own list. A port-wide CIDR list here would also cut off the Postgres routes sharing 5432, and a
 * union of database CIDRs would advertise an isolation the listener cannot enforce (§3.8.3).
 */
async function applyCurrentDatabaseIngress(dir: string) {
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const limits = platformDbIngressLimits(settings);
  const allowlist = await applyDatabaseIngress(dir, limits);
  return { limits, allowlist };
}

/**
 * Whether a domain worker renders `fe_pg5432`. The database worker that changes the pooler does not
 * mount the edge-l4 tree itself, so production (and any external-worker deployment) always queues.
 */
function poolerEdgeManaged() {
  return (
    edgeL4Configured() || process.env.NODE_ENV === "production" || process.env.ARK_EMBEDDED_WORKERS === "0"
  );
}

/** Re-render `fe_pg5432` after a pooler change; a queued `edge.l4_apply` is reused. */
export async function queuePoolerEdgeApply() {
  if (poolerEdgeManaged()) await enqueue({ kind: "edge.l4_apply", targetIds: ["platform"] });
}

/**
 * The retirement watchdog's fallback (FD-28) when PgBouncer cannot be stopped over its admin socket:
 * close public admission to PgBouncer at the edge instead. The fence is durable (edge.l4_apply omits
 * `be_pgbouncer` while it is set, also after restarts) and waits for the applied generation. The next
 * successful `pgbouncer.reload` lifts it, as the old `expose` toggle was rewritten by the next apply.
 */
export async function fencePoolerListener(
  reason: string,
  { timeoutMs = 10_000, wait = true }: { timeoutMs?: number; wait?: boolean } = {},
) {
  const fencedAt = new Date();
  await db
    .update(platformSettings)
    .set({ poolerFencedAt: fencedAt, poolerFenceReason: reason, updatedAt: fencedAt })
    .where(eq(platformSettings.id, "default"));
  if (!poolerEdgeManaged()) return;
  const operation = await enqueue({
    kind: "edge.l4_apply",
    targetIds: ["platform"],
    payload: { reason: "pooler-fence", fencedAt: fencedAt.toISOString() },
  });
  if (!wait) return;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const [row] = await db
      .select({ status: operations.status })
      .from(operations)
      .where(eq(operations.id, operation.id));
    if (row?.status === "succeeded") {
      const [step] = await db
        .select()
        .from(operationSteps)
        .where(and(eq(operationSteps.operationId, operation.id), eq(operationSteps.name, "edge-l4-apply")))
        .orderBy(desc(operationSteps.createdAt))
        .limit(1);
      const detail = step?.evidence as
        | { applied?: boolean; poolerPolicy?: { fence?: { at?: string } } }
        | undefined;
      if (detail?.applied && detail.poolerPolicy?.fence?.at === fencedAt.toISOString()) return;
      break;
    }
    if (row?.status === "failed") break;
    await Bun.sleep(100);
  }
  throw new Error("The edge did not confirm the PgBouncer fence; the fence stays recorded and is retried.");
}

async function liftPoolerFence() {
  const lifted = await db
    .update(platformSettings)
    .set({ poolerFencedAt: null, poolerFenceReason: null, updatedAt: new Date() })
    .where(and(eq(platformSettings.id, "default"), isNotNull(platformSettings.poolerFencedAt)))
    .returning({ id: platformSettings.id });
  return lifted.length > 0;
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
async function reloadPgbouncer(
  operation: OperationRow,
  now = new Date(),
): Promise<{ routed: boolean; mappings: string[]; reloaded: boolean }> {
  return withPgbouncerLock(() => reloadPgbouncerLocked(operation, now));
}

async function reloadPgbouncerLocked(operation: OperationRow, now: Date) {
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
  // Revoke public admission before any rendering, secret or socket error can leave the old PgBouncer
  // configuration reachable: with no admitted client the edge stops routing to PgBouncer at all.
  const startup = operation.payload?.reason === "startup-db-ingress-policy";
  // The startup policy pass reloads nothing, so it records the fence without waiting for the edge
  // (the domain worker may still be starting); the edge applies it from the durable record.
  if (!plan.routed) await fencePoolerListener("no-admitted-client", { wait: !startup });
  if (startup) {
    // An upgrade changes only the host firewall policy and the edge's pooler policy. Existing
    // PgBouncer configuration, credentials and TLS files must not depend on a separate reload
    // executor being present.
    const { limits, allowlist } = await applyCurrentDatabaseIngress(pgbouncerDir());
    await queuePoolerEdgeApply();
    await addStep(operation.id, "db-ingress-startup", { limits, ...allowlist });
    return { routed: plan.routed, mappings: plan.mappings.map((item) => item.database), reloaded: false };
  }
  const dbEndpoint = (await db.select().from(endpoints)).find((item) => item.kind === "database");
  // A payload-less reload must recover an earlier failed renewal too. The latest pending row
  // describes the files on disk; an older queued operation must not verify a superseded leaf.
  const [pendingCertificate] = dbEndpoint
    ? await db
        .select()
        .from(certificates)
        .where(and(eq(certificates.endpointId, dbEndpoint.id), eq(certificates.status, "awaiting_reload")))
        .orderBy(desc(certificates.expiresAt), desc(certificates.id))
        .limit(1)
    : [];
  const certificateId = pendingCertificate?.id ?? "";
  const expectedFingerprint =
    pendingCertificate?.fingerprint ??
    (typeof operation.payload.expectFingerprint === "string"
      ? operation.payload.expectFingerprint
      : undefined);
  const required = pgbouncerReloadRequired();
  const adminPassword = process.env.ARK_PGBOUNCER_ADMIN_PASSWORD ?? "";
  if (required && !adminPassword) {
    throw new Error("ARK_PGBOUNCER_ADMIN_PASSWORD is required to reload PgBouncer over its admin socket.");
  }
  const files = renderPgbouncerFiles({
    plan,
    adminPassword: adminPassword || undefined,
    certificateDir: dbEndpoint
      ? resolve(process.env.ARK_CERT_DIR ?? "/var/lib/ark/certs", dbEndpoint.hostname)
      : undefined,
  });
  const written = await writePgbouncerFiles(pgbouncerDir(), files);

  let reload: Awaited<ReturnType<typeof reloadAndVerify>> | null = null;
  if (required) {
    const socket = {
      socketDir: process.env.ARK_PGBOUNCER_SOCKET_DIR ?? PGBOUNCER_SOCKET_DIR,
      password: adminPassword,
    };
    try {
      if (pendingCertificate && !expectedFingerprint)
        throw new Error("Pending database certificate has no fingerprint.");
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
  // Apply persisted rate limits on tcp/5432; admission itself is the edge's pooler-wide policy.
  const { limits, allowlist } = await applyCurrentDatabaseIngress(written.dir);
  // A confirmed reload with admitted clients is PgBouncer serving again: lift the fence (watchdog or
  // no-client) and re-render the edge. Development without an admin socket counts as confirmed.
  const fenceLifted = plan.routed && (reloaded || !required) ? await liftPoolerFence() : false;
  await queuePoolerEdgeApply();
  // Ready needs a published pooler (no unreviewed conflict, a policy that admits someone). There is
  // no per-database enforcement status: the pooler-wide policy applies to every database (§3.8.3).
  const { evaluation: pooler } = await poolerEdgeInput();
  const mapped = new Set(plan.mappings.map((item) => item.database));
  for (const database of databases) {
    await db
      .update(managedDatabases)
      .set({
        status:
          database.exposure === "public" && reloaded && pooler.publishable && mapped.has(database.name)
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
    pooler: {
      status: pooler.status,
      scope: pooler.scope,
      admits: pooler.policy.admits,
      conflict: pooler.conflict,
    },
    fenceLifted,
    limits,
    dir: written.dir,
    reloaded,
    attempts: reload?.attempts ?? 0,
    servedFingerprint: reload?.fingerprint,
    ...allowlist,
  });
  return { routed: plan.routed, mappings: plan.mappings.map((item) => item.database), reloaded };
}

function pgbouncerSocket() {
  return {
    socketDir: process.env.ARK_PGBOUNCER_SOCKET_DIR ?? PGBOUNCER_SOCKET_DIR,
    password: process.env.ARK_PGBOUNCER_ADMIN_PASSWORD ?? "",
  };
}

/**
 * `database.client_issue` (FD-17): CA generation, 90-day certificate, login role and sealed
 * password, then an inline PgBouncer reload so the role and its CA are admitted when this
 * operation succeeds. Evidence and audit carry no key, password or PEM material.
 */
async function issueDatabaseClientOp(operation: OperationRow, runtime: ClientOperationRuntime) {
  const payload = operation.payload as Record<string, unknown>;
  const roleKind =
    payload.roleKind === "runtime" ? "runtime" : payload.roleKind === "readonly" ? "readonly" : null;
  if (!roleKind) throw new Error("database.client_issue needs a role kind.");
  const result = await runtime.issue({
    clientId: String(payload.clientId ?? ""),
    databaseId: operation.targetIds[0] ?? "",
    name: String(payload.name ?? ""),
    environment: String(payload.environment ?? ""),
    roleKind,
    csrPem: typeof payload.csrPem === "string" ? payload.csrPem : undefined,
    actorId: operation.actorId,
  });
  await addStep(operation.id, "database-client-issued", issueEvidence(result));
  await runtime.reload(operation, runtime.now());
  await db
    .update(databaseClients)
    .set({ issuedAt: new Date() })
    .where(and(eq(databaseClients.id, result.client.id), isNull(databaseClients.revokedAt)));
  await auditIssued(result, { actorId: operation.actorId, operationId: operation.id });
}

/** Dedup key of the alert raised when a revoked client's PgBouncer sessions cannot be killed. */
export const PGBOUNCER_REVOKE_ALERT = "pgbouncer-revoke";

/**
 * `database.client_revoke` (FD-17, §3.10.4): revoke the client, its certificates and CA
 * generations and rotate its role password (revokeDatabaseClient), then reload PgBouncer with
 * the reduced CA bundle and userlist, then KILL_CLIENT every live session of that role. Other
 * clients' sessions and credentials are untouched.
 */
async function revokeDatabaseClientOp(operation: OperationRow, runtime: ClientOperationRuntime) {
  return withPgbouncerLock(() => revokeDatabaseClientLocked(operation, runtime));
}

async function revokeDatabaseClientLocked(operation: OperationRow, runtime: ClientOperationRuntime) {
  const databaseId = operation.targetIds[0] ?? "";
  const result = await runtime.revoke({
    databaseId,
    clientId: String((operation.payload as Record<string, unknown>).clientId ?? ""),
    actorId: operation.actorId,
  });
  await addStep(operation.id, "database-client-revoked", result);
  await runtime.reload(operation, runtime.now());
  let killed: number | null = null;
  if (runtime.reloadRequired()) {
    try {
      const kill = await runtime.kill(result.role, pgbouncerSocket());
      if (kill.remaining !== 0) throw new Error("Revoked client sessions remain.");
      killed = kill.killed;
      await db
        .update(alerts)
        .set({ resolvedAt: new Date() })
        .where(
          and(eq(alerts.dedupKey, `${PGBOUNCER_REVOKE_ALERT}:${result.role}`), isNull(alerts.resolvedAt)),
        );
      await addStep(operation.id, "pgbouncer-kill-client", { role: result.role, ...kill });
    } catch (error) {
      await raiseAlert({
        severity: "critical",
        title: `Revoked database client ${result.role} may still have live PgBouncer sessions`,
        dedupKey: `${PGBOUNCER_REVOKE_ALERT}:${result.role}`,
      });
      throw error;
    }
  } else {
    await addStep(operation.id, "pgbouncer-kill-client-skipped", {
      role: result.role,
      reason: "no admin socket",
    });
  }
  await db
    .update(databaseClients)
    .set({ revocationCompletedAt: new Date() })
    .where(eq(databaseClients.id, result.clientId));
  await dueRetirements({ now: runtime.now() });
  await auditRevoked(
    { ...result, killed },
    { databaseId, actorId: operation.actorId, operationId: operation.id },
  );
}

// ---- Client certificate rollover (FD-28, §3.10.4) ------------------------------------------------

/** What the watchdog does when a retirement misses its not_after + 5 s deadline. */
export type RetirementWatchdog = {
  /** Fence admission for the database (`DISABLE`) over the admin socket. */
  fence: (database: string) => Promise<void>;
  /** Stop PgBouncer (`SHUTDOWN`); its restart reads the reduced files already on disk. */
  stop: () => Promise<void>;
  /** Close the public database listener on the host, independent of the admin socket. */
  fenceListener: () => Promise<void>;
};

async function auditRolloverIssued(result: IssueSuccessorResult, operation: OperationRow) {
  if (result.outcome !== "issued" || !result.databaseId) return;
  await db.insert(auditEvents).values({
    id: createId("aud"),
    actorId: operation.actorId,
    action: "database.client_rollover_issued",
    resourceType: "database",
    resourceId: result.databaseId,
    operationId: operation.id,
    detail: successorEvidence(result),
  });
}

/**
 * `database.client_rollover`. With `clientId` in the payload it is an owner's early rollover:
 * one successor on demand, under the same one-successor rule. Without, it is the daily job:
 * every usable client whose unsuperseded current certificate is within 30 days of not_after
 * gets exactly one successor from a fresh CA generation. Either way PgBouncer reloads once so
 * the new generations join the bundle beside their predecessors, the rollover alerts are
 * re-evaluated, and any overdue retirement is retried as a safety net.
 */
async function rolloverDatabaseClientsOp(operation: OperationRow, runtime: ClientOperationRuntime) {
  const now = runtime.now();
  const payload = operation.payload as Record<string, unknown>;
  const results: IssueSuccessorResult[] = [];
  if (typeof payload.clientId === "string" && payload.clientId) {
    results.push(
      await runtime.issueSuccessor({
        clientId: payload.clientId,
        now,
        reason: "early",
        csrPem: typeof payload.csrPem === "string" ? payload.csrPem : undefined,
      }),
    );
  } else {
    for (const result of await runScheduledRollover({ now })) results.push(result);
  }
  for (const result of results)
    await addStep(operation.id, "client-rollover-successor", successorEvidence(result));
  const issued = results.filter((result) => result.outcome === "issued");
  const deliverable = results.filter((result) => result.outcome === "issued" || result.outcome === "exists");
  if (deliverable.length) {
    await runtime.reload(operation, now);
    await markSuccessorsTrusted(
      deliverable.flatMap((result) => (result.successor ? [result.successor.id] : [])),
      now,
    );
  }
  for (const { databaseId, clientId, successor } of deliverable) {
    if (databaseId && successor) await queueVercelPush({ databaseId, clientId }, successor.id, now);
  }
  for (const result of issued) await auditRolloverIssued(result, operation);
  const alertsRaised = await evaluateRolloverAlerts(now);
  const retired = payload.clientId ? [] : await runDueRetirements(runtime, { operation });
  const evidence = {
    issued: issued.map((result) => result.successor?.id),
    existing: results.filter((result) => result.outcome === "exists").map((result) => result.clientId),
    needsCsr: results.filter((result) => result.outcome === "needs_csr").map((result) => result.clientId),
    alerts: alertsRaised.length,
    retired,
  };
  await addStep(operation.id, "client-rollover", evidence);
  return evidence;
}

/**
 * Retire one generation (§3.10.4 step 4). The apply step takes it out of the trust set and runs
 * the normal PgBouncer reload; retireGeneration fences the database first and drains the role's
 * sessions and any pre-auth logins before reopening. Without an admin socket (development) the
 * reload still runs and the drain is recorded as skipped.
 */
async function retireOne(
  item: DueRetirement,
  operation: OperationRow,
  runtime: ClientOperationRuntime,
  preclaimed = false,
): Promise<Record<string, unknown>> {
  return withPgbouncerLock(() => retireOneLocked(item, operation, runtime, preclaimed));
}

async function retireOneLocked(
  item: DueRetirement,
  operation: OperationRow,
  runtime: ClientOperationRuntime,
  preclaimed: boolean,
) {
  const claimed = preclaimed || (await claimRetirement(item, runtime.now()));
  if (!claimed) return { certificateId: item.certificate.id, skipped: "claimed elsewhere or complete" };
  let applying: Promise<{ databaseMapped: boolean }> | undefined;
  const apply = () =>
    (applying = (async () => {
      await markGenerationRetired(item.certificate.id);
      const reloaded = await runtime.reload(operation, runtime.now());
      return { databaseMapped: reloaded?.mappings.includes(item.databaseName) ?? true };
    })());
  try {
    let timeline: Record<string, unknown> & {
      fencedAt?: number;
      reloadedAt?: number;
      drainedAt?: number;
      reopenedAt?: number;
    };
    if (runtime.reloadRequired()) {
      timeline = await runtime.retire({
        database: item.databaseName,
        role: item.role,
        deadline: item.deadline,
        admin: socketAdmin(pgbouncerSocket()),
        apply,
        clock: () => runtime.now().getTime(),
      });
    } else {
      await apply();
      timeline = { reloadedAt: runtime.now().getTime(), drain: "skipped (no admin socket)" };
    }
    const done = await completeRetirement(item, { now: runtime.now(), timeline, operationId: operation.id });
    await addStep(operation.id, "client-certificate-retired", {
      certificateId: item.certificate.id,
      role: item.role,
      notAfter: item.certificate.notAfter.toISOString(),
      deadline: item.deadline.toISOString(),
      ...timeline,
      ...done,
    });
    return { certificateId: item.certificate.id, ...done };
  } catch (error) {
    const timeline = error instanceof RetirementError ? error.timeline : undefined;
    const message = error instanceof Error ? error.message : String(error);
    await failRetirement(item, { now: runtime.now(), error: message, timeline });
    await addStep(operation.id, "client-certificate-retire-failed", {
      certificateId: item.certificate.id,
      role: item.role,
      error: message,
      ...timeline,
    });
    throw error;
  } finally {
    // A timed-out apply may still be writing files. Retain the writer lock until it settles;
    // the independent watchdog can stop/fence the pooler while this writer is stuck.
    await applying?.catch(() => undefined);
  }
}

/** Run every retirement that is due now. Failures stay open for the next tick and are alerted. */
async function runDueRetirements(
  runtime: ClientOperationRuntime,
  options: { operation?: OperationRow; certificateId?: string } = {},
) {
  const due = (await dueRetirements({ now: runtime.now() })).filter(
    (item) => !options.certificateId || item.certificate.id === options.certificateId,
  );
  // Persist all deadlines before waiting on the shared writer lock. The independent watchdog
  // must see simultaneous expiries even while another retirement owns that lock.
  for (const item of due) await ensureRetirement(item);
  const outcomes: Array<Record<string, unknown>> = [];
  for (const item of due) {
    if (options.operation) {
      try {
        outcomes.push(await retireOne(item, options.operation, runtime));
      } catch (error) {
        outcomes.push({ certificateId: item.certificate.id, error: String(error) });
      }
    } else {
      outcomes.push(await runInlineRetirement(item, runtime));
    }
  }
  return outcomes;
}

/** `database.client_retire`: the durable record (and requeue path) of one retirement. */
async function retireClientCertificateOp(operation: OperationRow, runtime: ClientOperationRuntime) {
  const certificateId = String((operation.payload as Record<string, unknown>).certificateId ?? "");
  const item = (await dueRetirements({ now: runtime.now() })).find(
    (candidate) => candidate.certificate.id === certificateId,
  );
  if (!item) {
    await addStep(operation.id, "client-certificate-retire-noop", {
      certificateId,
      reason: "not due or retired",
    });
    return { certificateId, skipped: true };
  }
  return retireOne(item, operation, runtime);
}

/**
 * Run a retirement right now, without waiting for a worker poll, under an operation row this
 * process claims itself. If the process dies the lease expires and the database worker runs the
 * same operation from the queue.
 */
async function runInlineRetirement(item: DueRetirement, runtime: ClientOperationRuntime) {
  return withPgbouncerLock(async () => {
    if (!(await claimRetirement(item, runtime.now())))
      return { certificateId: item.certificate.id, skipped: "claimed elsewhere or complete" };
    const token = createId("claim");
    const payload = { certificateId: item.certificate.id };
    const [operation] = await db
      .insert(operations)
      .values({
        id: createId("op"),
        kind: "database.client_retire",
        targetIds: [item.client.databaseId, item.client.id],
        payload,
        idempotencyKey: `database.client_retire:${item.certificate.id}`,
        planHash: planHash(payload),
        status: "running",
        claimToken: token,
        heartbeatAt: new Date(),
      })
      .onConflictDoUpdate({
        target: operations.idempotencyKey,
        set: {
          status: "running",
          claimToken: token,
          heartbeatAt: new Date(),
          error: null,
          updatedAt: new Date(),
        },
      })
      .returning();
    try {
      const result = await retireOne(item, operation!, runtime, true);
      await finishOperation(operation!, token, "succeeded");
      return result as Record<string, unknown>;
    } catch (error) {
      await finishOperation(
        operation!,
        token,
        "failed",
        error instanceof Error ? error.message : String(error),
      );
      return {
        certificateId: item.certificate.id,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  });
}

/**
 * The independent watchdog: a retirement still open after not_after + 5 s is a failure. Fence
 * admission (`DISABLE`), stop PgBouncer (`SHUTDOWN`, so the restart serves the reduced files and
 * holds no session), and if the admin socket is unusable close the public listener on the host.
 * The task stays open and is retried; the critical alert stays until it completes.
 */
async function boundedWatchdogAction(action: () => Promise<void>, timeoutMs = 500) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      action(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("Watchdog action timed out")), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

const watchdogRunning = new Set<string>();

export async function runRetirementWatchdog(overrides: Partial<ClientOperationRuntime> = {}) {
  const runtime = { ...clientOperationRuntime, ...overrides };
  const now = runtime.now();
  const actions: Array<Record<string, unknown>> = [];
  for (const task of await overdueRetirements(now)) {
    if (task.watchdogAt || watchdogRunning.has(task.certificateId)) continue;
    watchdogRunning.add(task.certificateId);
    try {
      const evidence: Record<string, unknown> = {
        at: now.toISOString(),
        deadline: task.deadline.toISOString(),
      };
      let succeeded = false;
      if (runtime.reloadRequired()) {
        const attempt = async (name: string, action: () => Promise<void>) => {
          try {
            await boundedWatchdogAction(action);
            evidence[name] = "ok";
            return true;
          } catch (error) {
            evidence[name] = error instanceof Error ? error.message : String(error);
            return false;
          }
        };
        const fenced = await attempt("fence", () => runtime.watchdog.fence(task.databaseName));
        const stopped = await attempt("stop", () => runtime.watchdog.stop());
        const listener = !stopped && (await attempt("fenceListener", () => runtime.watchdog.fenceListener()));
        // DISABLE alone cannot close established sessions. Only a confirmed stop or independent
        // listener fallback ends escalation; record failed attempts without suppressing retries.
        succeeded = stopped || listener;
        evidence.fenced = fenced;
      } else {
        evidence.skipped = "no admin socket";
      }
      await recordWatchdog(task.certificateId, now, evidence, succeeded);
      await raiseAlert({
        severity: "critical",
        title: `Database client ${task.role}: retirement deadline ${task.deadline.toISOString()} missed; watchdog stop/fence ${succeeded ? "confirmed" : "failed; will retry"}, retrying the drain`,
        dedupKey: retirementAlertKey(task.certificateId),
      });
      actions.push({ certificateId: task.certificateId, ...evidence });
    } finally {
      watchdogRunning.delete(task.certificateId);
    }
  }
  return actions;
}

/** Key of the once-per-UTC-day rollover job. */
export const dailyRolloverKey = (now: Date) =>
  `database.client_rollover:daily:${now.toISOString().slice(0, 10)}`;

/** Queue today's `database.client_rollover` job once (idempotent per UTC day across processes). */
export async function queueDailyRollover(now: Date) {
  const key = dailyRolloverKey(now);
  const [row] = await db
    .insert(operations)
    .values({
      id: createId("op"),
      kind: "database.client_rollover",
      targetIds: [],
      payload: { day: key.slice(-10) },
      idempotencyKey: key,
      planHash: planHash({ day: key.slice(-10) }),
      status: "queued",
    })
    .onConflictDoNothing({ target: operations.idempotencyKey })
    .returning();
  return row ?? null;
}

const rolloverAlertSweeps = [evaluateRolloverAlerts, evaluateVercelTokenAlerts];

type RolloverAlertSweep = { nextAt: number; running?: Promise<void> };
type RolloverTickState = {
  alertSweeps?: RolloverAlertSweep[];
  alertTask?: Promise<void>;
  timers?: Map<string, ReturnType<typeof setTimeout>>;
  tickMs?: number;
};

/**
 * One scheduler tick (database worker, or the embedded coordinator): queue the daily job,
 * re-evaluate rollover alerts hourly, run due retirements immediately, and watch deadlines.
 * Retirements due before the next tick get a timer at exactly not_after.
 */
export async function rolloverTick(
  overrides: Partial<ClientOperationRuntime> = {},
  state: RolloverTickState = {},
) {
  const runtime = { ...clientOperationRuntime, ...overrides };
  const now = runtime.now();
  const queued = await queueDailyRollover(now);
  const sweeps = (state.alertSweeps ??= rolloverAlertSweeps.map<RolloverAlertSweep>(() => ({ nextAt: 0 })));
  rolloverAlertSweeps.forEach((evaluate, index) => {
    const sweep = sweeps[index]!;
    if (sweep.running || now.getTime() < sweep.nextAt) return;
    sweep.running = evaluate(now)
      .then(() => {
        sweep.nextAt = runtime.now().getTime() + 3_600_000;
      })
      .catch(() => {
        sweep.nextAt = runtime.now().getTime() + 5_000;
        console.error("Rollover alert evaluation failed");
      })
      .finally(() => {
        sweep.running = undefined;
      });
  });
  state.alertTask = Promise.all(sweeps.map((sweep) => sweep.running)).then(() => {});
  const timers = state.timers;
  if (timers) {
    for (const item of await dueRetirements({ now, lookaheadMs: (state.tickMs ?? 1_000) * 2 })) {
      const wait = item.certificate.notAfter.getTime() - now.getTime();
      if (wait <= 0 || timers.has(item.certificate.id)) continue;
      await ensureRetirement(item);
      timers.set(
        item.certificate.id,
        setTimeout(() => {
          void runDueRetirements(runtime, { certificateId: item.certificate.id })
            .catch((error) => console.error(error instanceof Error ? error.message : error))
            .finally(() => timers.delete(item.certificate.id));
        }, wait),
      );
    }
  }
  const [retired, watchdog] = await Promise.all([runDueRetirements(runtime), runRetirementWatchdog(runtime)]);
  return { queued: queued?.id ?? null, retired, watchdog };
}

/** Start the rollover scheduler; it runs where the PgBouncer admin socket is (database worker). */
export function startRolloverScheduler(
  tickMs = Number(process.env.ARK_ROLLOVER_TICK_MS ?? 1_000),
  overrides: Partial<ClientOperationRuntime> = {},
) {
  const state = { timers: new Map<string, ReturnType<typeof setTimeout>>(), tickMs };
  let running = false;
  const tick = () => {
    if (running) return;
    running = true;
    void rolloverTick(overrides, state)
      .catch((error) => console.error(error instanceof Error ? error.message : "rollover tick failed"))
      .finally(() => {
        running = false;
      });
  };
  tick();
  const interval = setInterval(tick, tickMs);
  // This loop has its own guard: a pending drain/reload never suppresses deadline escalation.
  let watching = false;
  const watchdogInterval = setInterval(
    () => {
      if (watching) return;
      watching = true;
      void runRetirementWatchdog(overrides)
        .catch((error) => console.error(error instanceof Error ? error.message : error))
        .finally(() => {
          watching = false;
        });
    },
    Math.min(tickMs, 250),
  );
  return () => {
    clearInterval(interval);
    clearInterval(watchdogInterval);
    for (const timer of state.timers.values()) clearTimeout(timer);
  };
}

// The edge serves only hostnames whose current certificate is `issued`. Public `http` endpoints
// have no upstream yet, so they are rendered as unrouted (a fixed 503 naming no internal host).
// Front-door HTTP routes are read from `front_routes` and rendered only while the lease allows them
// (front door §3.2, FD-06): `public` routes directly, `sso` routes behind the login gate (FD-11).
export async function edgePlan(
  adminMode: "public" | "tailnet",
  adminHostname: string | null | undefined,
  policyRoutes?: Awaited<ReturnType<typeof edgePolicy>>["routes"],
) {
  const [settings] = await db
    .select({ mode: platformSettings.gateLoginMode, hostname: platformSettings.gateLoginHostname })
    .from(platformSettings)
    .where(eq(platformSettings.id, "default"));
  return planEdge({
    adminMode,
    adminHostname,
    // The public login origin (FD-10), served once its certificate is issued.
    gateHostname: settings?.mode === "public" ? settings.hostname : null,
    endpoints: await db.select().from(endpoints),
    certificates: await db.select().from(certificates),
    httpRoutes: await edgeHttpRoutes(policyRoutes ?? (await edgePolicy()).routes),
  });
}

async function applyEdge(operation: OperationRow) {
  return withEdgeLock(() => applyEdgeLocked(operation));
}

async function applyEdgeLocked(operation: OperationRow) {
  // The forced Caddy load and HAProxy drain apply the revocations in this snapshot. A
  // revocation that commits during this apply waits for the next drain.
  const revocations = await pendingGateRevocations();
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const plan = await edgePlan(
    settings?.adminMode === "tailnet" ? "tailnet" : "public",
    settings?.adminHostname,
  );
  // Queue the SNI generation before marking revocations applied. It takes this same lock before
  // reading policy, so the reload can re-admit a drained route once its new handler is active.
  if (edgeL4Configured()) await enqueue({ kind: "edge.l4_apply", targetIds: ["platform"] });
  const written = await writeEdge({
    ...plan,
    revokedRouteIds: [...new Set(revocations.map((item) => item.routeId))],
  });
  // Without an edge to reload (development, tests) there is no socket to close either.
  const applied =
    written.applied || (!process.env.ARK_EDGE_RELOAD_URL && process.env.NODE_ENV !== "production")
      ? await markGateRevocationsApplied(
          revocations.map((item) => item.id),
          written.applied ? operation.id : `${operation.id}:no-edge`,
        )
      : 0;
  await addStep(operation.id, "edge-apply", {
    ...written,
    unrouted: plan.appRoutes.map((route) => route.hostname),
    awaitingCertificate: plan.awaitingCertificate,
    // Routes the lease allows but this release cannot serve (invalid stored values).
    omitted: plan.omitted,
    gateRevocationsApplied: applied,
  });
}

/**
 * Serializes edge-l4 apply, reload and drain (§3.8.6: one edge lock). A transaction-scoped advisory
 * lock, so a crashed worker never leaves it held.
 */
export async function withEdgeLock<T>(work: () => Promise<T>) {
  return (await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtext('ark:edge:l4'))`;
    return work();
  })) as T;
}

// HAProxy SNI router on 443 (front door §3.8.5). HTTP routes each get a backend to Caddy over
// PROXY v2. Unmatched SNI is refused. The HTTP hostnames are
// exactly the ones the same plan gives Caddy a site for (FD-09): servable routes with an issued
// certificate, never an omitted or unservable route. TLS-TCP routes (on 443 or an enabled shared SNI
// port) and raw-TCP routes (dedicated ports) are the lease-allowed `tls`/`tcp` routes (FD-14).
export function edgeL4Input(
  plan: Pick<Awaited<ReturnType<typeof edgePlan>>, "certificates"> &
    Partial<Pick<Awaited<ReturnType<typeof edgePlan>>, "httpRoutes">>,
  l4: Partial<
    Pick<Awaited<ReturnType<typeof edgeL4Routes>>, "tlsRoutes" | "tcpRoutes" | "postgresRoutes">
  > = {},
  sniPorts: number[] = [],
  pooler: EdgeL4Pooler | null = null,
): EdgeL4Input {
  return {
    httpHostnames: servedHttpHostnames(plan),
    httpRoutes: servedHttpRoutes(plan),
    tlsRoutes: l4.tlsRoutes ?? [],
    tcpRoutes: l4.tcpRoutes ?? [],
    postgresRoutes: l4.postgresRoutes ?? [],
    pooler,
    sniPorts,
  };
}

async function applyEdgeL4(operation: OperationRow) {
  // Load desired state after taking the lock, so a delayed older operation cannot overwrite a
  // newer generation. Mutations during this apply enqueue a successor rather than reusing it.
  return withEdgeLock(() => applyEdgeL4Locked(operation));
}

async function applyEdgeL4Locked(operation: OperationRow) {
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const policy = await edgeLeaseDocument();
  const pending = new Set(policy.revocations?.map((item) => item.routeId));
  const plan = await edgePlan(
    settings?.adminMode === "tailnet" ? "tailnet" : "public",
    settings?.adminHostname,
    // Even a recent pending revocation may already have fenced admission before a failed load.
    policy.routes.filter((route) => !pending.has(route.id)),
  );
  // Route CAs must carry a current CRL: OpenSSL refuses every client certificate once it expires.
  const crls = await refreshRouteCrls();
  const sniPorts = enabledSniPorts();
  const l4 = await edgeL4Routes({ policyRoutes: policy.routes, sniPorts });
  // PgBouncer on 5432 (FD-26): only while the pooler-wide policy is publishable and not fenced.
  const pooler = await poolerEdgeInput();
  const input = edgeL4Input(plan, l4, sniPorts, pooler.pooler);
  const adminUrl = process.env.ARK_EDGE_RELOAD_URL;
  if (adminUrl && input.httpRoutes?.length) {
    // HAProxy must never admit a new identity while Caddy still serves that hostname's old pin.
    const identities = await new CaddyWithdrawalAdapter(adminUrl).activeRoutes();
    const active = new Set(identities);
    const proxyHosts = new Set(identities.map(routeIdentityHostname));
    const inactive = new Set(
      servedHttpRoutes(plan)
        .filter((route) =>
          route.redirectTo ? proxyHosts.has(route.hostname) : !active.has(routeIdentityKey(route)),
        )
        .map((route) => route.hostname),
    );
    input.httpHostnames = input.httpHostnames.filter((hostname) => !inactive.has(hostname));
    input.httpRoutes = input.httpRoutes.filter((route) => !inactive.has(route.hostname));
  }
  if (edgeL4Configured() && !edgeL4Settings().validatorSocket)
    throw new Error("ARK_HAPROXY_VALIDATOR_SOCKET is required to apply edge-l4.");
  const firewall = edgeL4Configured()
    ? await applyFrontIngress(input, platformDbIngressLimits(settings))
    : null;
  const written = await writeEdgeL4(input);
  const omitted: OmittedL4Route[] = l4.omitted;
  await addStep(operation.id, "edge-l4-apply", {
    ...written,
    firewall,
    omittedL4Routes: omitted,
    crls,
    poolerPolicy: {
      status: pooler.evaluation.status,
      admits: pooler.evaluation.policy.admits,
      conflict: pooler.evaluation.conflict,
      fence: pooler.fence,
    },
  });
  return written;
}

/** Thrown when `edge.observe` has no LocalAPI to read; nothing is changed. */
function requireEdgeSocket() {
  const socket = edgeSocketPath();
  if (!socket) {
    throw new Error("ARK_EDGE_TS_SOCKET is not set: the edge node's LocalAPI socket is not mounted here.");
  }
  return socket;
}

// Edge observer (front door §3.2, §3.6, FD-06): read-only LocalAPI status, one complete generation.
async function observeEdge(operation: OperationRow) {
  const result = await observeEdgeTailnet({
    api: edgeLocalApi(requireEdgeSocket()),
    enqueue,
    operationId: operation.id,
  });
  const reconcile = await reconcileServedRoutes();
  const l4Adapter = haproxyAdapter();
  let l4Recovery: { missing?: string[]; error?: string } = {};
  if (edgeL4Configured() && l4Adapter) {
    try {
      const missing = await missingL4Routes((await edgePolicy()).routes, l4Adapter.master);
      // Also reconcile the pooler and its durable fence. Route-server presence alone cannot
      // detect a stale source policy or a missed pooler mutation after a worker restart.
      await queuePoolerEdgeApply();
      l4Recovery = { missing };
    } catch (error) {
      // Inspection uncertainty needs a durable retry, too.
      await enqueue({ kind: "edge.l4_apply", targetIds: ["platform"] });
      l4Recovery = { error: (error as Error).message };
    }
  }
  // Weekly route CRL refresh (FD-14): edge.l4_apply regenerates due CRLs before rendering.
  const crlsDue = (await routeCrlsDue()).length;
  if (crlsDue && edgeL4Configured()) await enqueue({ kind: "edge.l4_apply", targetIds: ["platform"] });
  await addStep(operation.id, "edge-observe", { ...result, reconcile, l4Recovery, routeCrlsDue: crlsDue });
  return { ...result, reconcile };
}

/**
 * Re-applies the edge when an allowed HTTP route is missing from the running Caddy, for example
 * after Caddy started from the closed config during a restart, or after a withdrawal on a policy
 * that has since been renewed. Only ever adds what the policy allows, through edge.apply.
 */
async function reconcileServedRoutes() {
  const adminUrl = process.env.ARK_EDGE_RELOAD_URL;
  if (!adminUrl) return { checked: false };
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const policy = await edgeLeaseDocument();
  const pending = new Set(policy.revocations?.map((item) => item.routeId));
  const plan = await edgePlan(
    settings?.adminMode === "tailnet" ? "tailnet" : "public",
    settings?.adminHostname,
    policy.routes.filter((route) => !pending.has(route.id)),
  );
  const routed = servedHttpRoutes(plan);
  // Redirect-only routes dial no backend, so they carry no identity to look for.
  const allowed = routed.filter((route) => !route.redirectTo);
  if (!routed.length) return { checked: true, missing: [] };
  let active: string[];
  let missingHttp: string[] = [];
  try {
    active = await new CaddyWithdrawalAdapter(
      adminUrl,
      fetch,
      3_000,
      caddyState(process.env.ARK_EDGE_DIR ?? join(process.cwd(), "infra", "platform")),
    ).activeRoutes();
    const control = haproxyAdapter();
    if (control && edgeL4Configured()) {
      missingHttp = await missingHttpRoutes(routed, control.master);
    }
  } catch (error) {
    return { checked: false, error: (error as Error).message };
  }
  const missing = [
    ...new Set([
      ...allowed.filter((route) => !active.includes(routeIdentityKey(route))).map((route) => route.id),
      ...missingHttp,
    ]),
  ];
  if (missing.length) await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
  return { checked: true, missing };
}

export const EDGE_WITHDRAWAL_ALERT = "edge-withdrawal";

// Withdraws tailnet backends that the current policy no longer allows from the running proxies.
// Caddy is enforced through its admin API and HAProxy through its master CLI (every current and
// leaving worker, admission first), here and by the edge-local watchdog every second.
async function drainEdge(operation: OperationRow) {
  // The gate drain fences affected HAProxy backends around the forced Caddy load.
  if (operation.payload.reason === "gate_revocation") return applyEdge(operation);
  return withEdgeLock(() => drainEdgeLocked(operation));
}

async function drainEdgeLocked(operation: OperationRow) {
  const adminUrl = process.env.ARK_EDGE_RELOAD_URL;
  const backends = Array.isArray(operation.payload.backends) ? operation.payload.backends : [];
  const allowed = allowedBackends(await edgeLeaseDocument());
  const control = haproxyAdapter();
  // Even if HAProxy cannot be verified, Caddy may need to stop to close streams
  // accepted through a legacy shared worker.
  const haproxy = await drainHaproxyLocked(allowed, control, raiseAlert).then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  if (!adminUrl) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("ARK_EDGE_RELOAD_URL is required to drain edge routes in production.");
    }
    if ("error" in haproxy) throw haproxy.error;
    await addStep(operation.id, "edge-drain", {
      backends,
      caddy: "not configured",
      haproxy: haproxy.result,
    });
    return;
  }
  const adapter = new CaddyWithdrawalAdapter(adminUrl, fetch, 3_000, {
    ...caddyState(process.env.ARK_EDGE_DIR ?? join(process.cwd(), "infra", "platform")),
    scopedHttp: control ? () => control.ensureHttpControl() : undefined,
  });
  const result = await adapter.enforce(allowed);
  if (result.error) {
    let outcome = "Caddy was stopped";
    try {
      await adapter.stop();
    } catch (error) {
      outcome = `Caddy stop failed: ${(error as Error).message}`;
    }
    await raiseAlert({
      severity: "critical",
      title: `Edge route withdrawal failed; ${outcome} (${result.error})`,
      dedupKey: EDGE_WITHDRAWAL_ALERT,
    });
    throw new Error(`Caddy withdrawal failed; ${outcome}: ${result.error}`);
  }
  if ("error" in haproxy) throw haproxy.error;
  await addStep(operation.id, "edge-drain", {
    reason: operation.payload.reason ?? null,
    routeIds: operation.payload.routeIds ?? [],
    backends,
    caddy: { active: result.active, withdrawn: result.withdrawn, restarting: !!result.unreachable },
    haproxy: haproxy.result,
  });
}

/** HAProxy half of `edge.drain`, under the edge lock; a failure fences protected traffic and alerts. */
export async function drainHaproxy(
  allowed: ReadonlySet<string>,
  adapter: EdgeWithdrawalAdapter | null = haproxyAdapter(),
  alert: (input: Parameters<typeof raiseAlert>[0]) => Promise<unknown> = raiseAlert,
) {
  return withEdgeLock(() => drainHaproxyLocked(allowed, adapter, alert));
}

async function drainHaproxyLocked(
  allowed: ReadonlySet<string>,
  adapter: EdgeWithdrawalAdapter | null,
  alert: (input: Parameters<typeof raiseAlert>[0]) => Promise<unknown>,
) {
  if (!adapter) return "not configured";
  const result = await adapter.enforce(allowed);
  if (result.error) {
    let outcome = "HAProxy tailnet backends were fenced";
    try {
      await adapter.stop();
    } catch (error) {
      outcome = `HAProxy stop failed: ${(error as Error).message}`;
    }
    await alert({
      severity: "critical",
      title: `Edge route withdrawal failed; ${outcome} (${result.error})`,
      dedupKey: EDGE_WITHDRAWAL_ALERT,
    });
    throw new Error(`HAProxy withdrawal failed; ${outcome}: ${result.error}`);
  }
  return { active: result.active, withdrawn: result.withdrawn };
}

/** Schedules `edge.observe` every five minutes where the edge node's socket is mounted (§3.4). */
export function scheduleEdgeObserve(intervalMs?: number) {
  if (!edgeSocketPath()) return null;
  return startEdgeObserveSchedule({
    enqueue,
    intervalMs,
    log: (line) => console.error(line),
  });
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

function reportCoordinatorError(error: unknown) {
  console.error(error instanceof Error ? error.message : error);
}

export function startCoordinator() {
  let coreInFlight = false;
  let integrationInFlight = false;
  const tick = () => {
    if (!coreInFlight) {
      coreInFlight = true;
      void processQueued(8, undefined, "integration.")
        .catch(reportCoordinatorError)
        .finally(() => {
          coreInFlight = false;
        });
    }
    if (!integrationInFlight) {
      integrationInFlight = true;
      void processQueued(1, "integration.")
        .catch(reportCoordinatorError)
        .finally(() => {
          integrationInFlight = false;
        });
    }
  };
  tick();
  // Embedded workers include the database worker's duties, so they run the rollover scheduler.
  startRolloverScheduler();
  scheduleEdgeObserve();
  scheduleDnsMaintenance();
  // ...and the backup worker's (FD-21), when backups execute, and its backup-ts observation (FD-30).
  scheduleBackups();
  scheduleBackupObserve();
  return setInterval(tick, 1500);
}
