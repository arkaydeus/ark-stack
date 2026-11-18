import {
  createId,
  decryptSecret,
  encryptSecret,
  isInFlight,
  planHash,
  VERCEL_ENV_NAMES,
  vercelCredentialBundle,
} from "@ark-stack/shared";
import { and, desc, eq, sql } from "drizzle-orm";
import { z } from "zod";

import { db, type DbTransaction } from "../db.ts";
import { loadEnv } from "../env.ts";
import { databaseClients, operations, secrets, vercelIntegrations } from "../schema.ts";
import { raiseAlert, resolveAlert } from "./alerts.ts";
import {
  evaluateRolloverAlerts,
  lockRolloverClient,
  pendingOf,
  recordRolloverDelivery,
  vercelPushAlertKey,
} from "./db-client-rollover.ts";
import { auditEvent, certificateChain, DatabaseClientError, loadLinkedCertificates } from "./db-clients.ts";
import { CLIENT_KEY_SECRET_KIND } from "./pki.ts";
import { removeVercelIntegration } from "./pooler-policy.ts";
import {
  deployHookBranch,
  deployHookUrl,
  projectIdPattern,
  readScopeProbes,
  reviewedVercelScopeProof,
  teamIdPattern,
  triggerVercelHook,
  upsertVercelVariable,
  VercelApi,
  type VercelCall,
  type VercelScopeProof,
  type VercelSelection,
  type VercelTransport,
  verifiedScope,
  vercelHookDeployment,
} from "./vercel-api.ts";

const TOKEN_KIND = "vercel.integration.token";
const HOOK_KIND = "vercel.integration.deploy_hook";
const DAY_MS = 86_400_000;
const PUSH_WINDOW_MS = 30 * 60_000;

export const vercelConnectInput = z
  .object({
    projectId: z.string().max(80).regex(projectIdPattern),
    teamId: z.string().max(80).regex(teamIdPattern),
    otherProjectId: z.string().max(80).regex(projectIdPattern),
    target: z.enum(["production", "preview"]),
    gitBranch: z.string().max(250).trim().min(1).optional(),
    token: z
      .string()
      .min(1)
      .max(512)
      .regex(/^[a-zA-Z0-9_-]+$/),
    deployHook: z.string().min(1).max(512),
  })
  .strict();

type Integration = typeof vercelIntegrations.$inferSelect;
type VerifiedIntegration = Integration & {
  scopeVerifiedAt: Date;
  vercelTeamId: string;
  otherProjectId: string;
  tokenExpiresAt: Date;
  deployHookSecretId: string;
  hookBranch: string;
};
type Client = typeof databaseClients.$inferSelect;
type Certificate = NonNullable<ReturnType<typeof pendingOf>>;
type ClientRef = { databaseId: string; clientId: string };
type ActorRef = ClientRef & { actorId: string; actorRole: string };

function isVerified(row: Integration | undefined): row is VerifiedIntegration {
  return !!(
    row?.scopeVerifiedAt &&
    row.vercelTeamId &&
    row.otherProjectId &&
    row.tokenExpiresAt &&
    row.deployHookSecretId &&
    row.hookBranch
  );
}

function scopeSelection(row: VerifiedIntegration): VercelSelection {
  return {
    projectId: row.vercelProjectId,
    teamId: row.vercelTeamId,
    otherProjectId: row.otherProjectId,
    target: row.envTarget,
    gitBranch: row.gitBranch,
  };
}

function publicIntegration(row: VerifiedIntegration, now = new Date()) {
  const remaining = row.tokenExpiresAt.getTime() - now.getTime();
  return {
    tokenExpiryStatus: remaining <= 0 ? "expired" : remaining <= 30 * DAY_MS ? "expiring" : "valid",
    projectId: row.vercelProjectId,
    target: row.envTarget,
    gitBranch: row.gitBranch,
    tokenExpiresAt: row.tokenExpiresAt,
    lastPushAt: row.lastPushAt,
    lastPushStatus: row.lastPushStatus,
    lastDeploymentId: row.lastDeploymentId,
  };
}

const tokenAlertKey = (clientId: string) => `vercel-token-expiry:${clientId}`;

async function lockedClient(tx: DbTransaction, ref: ClientRef) {
  await lockRolloverClient(tx, ref.clientId);
  const [client] = await tx
    .select()
    .from(databaseClients)
    .where(and(eq(databaseClients.databaseId, ref.databaseId), eq(databaseClients.id, ref.clientId)))
    .for("update");
  return client;
}

async function integrationFor(clientId: string, executor: Pick<DbTransaction, "select"> = db) {
  const [row] = await executor
    .select()
    .from(vercelIntegrations)
    .where(eq(vercelIntegrations.databaseClientId, clientId));
  return row;
}

function supportsVercel(client: Client) {
  return client.keySource === "generated" && ["production", "preview"].includes(client.environment);
}

function activeClient(client: Client | undefined): client is Client {
  return !!client && client.status === "active" && !!client.issuedAt && !client.revokedAt;
}

async function pendingCertificate(client: Client, tx: DbTransaction) {
  return pendingOf(certificateChain(client.caId, await loadLinkedCertificates([client.caId], tx)));
}

async function openSecret(executor: Pick<DbTransaction, "select">, id: string, kind: string) {
  const [row] = await executor.select().from(secrets).where(eq(secrets.id, id));
  if (!row || row.kind !== kind) throw new Error("A sealed Vercel delivery credential is missing.");
  return decryptSecret(loadEnv().rootKey, row);
}

async function sealSecret(tx: DbTransaction, integrationId: string, kind: string, value: string) {
  const id = createId("sec");
  const { rootKey, rootKeyId } = loadEnv();
  await tx.insert(secrets).values({
    id,
    kind,
    resourceType: "vercel_integration",
    resourceId: integrationId,
    purpose: "certificate-rollover",
    sensitivity: "provider",
    ...encryptSecret(rootKey, value, rootKeyId),
  });
  return id;
}

function providerAudit(
  ref: ClientRef & { actorId?: string; actorRole?: string; operationId?: string },
  selection: VercelSelection,
  transport?: VercelTransport,
) {
  const calls: VercelCall[] = [];
  return {
    api: new VercelApi(transport, (call) => calls.push(call)),
    async flush() {
      for (const call of calls.splice(0)) {
        await auditEvent({
          databaseId: ref.databaseId,
          actorId: ref.actorId,
          role: ref.actorRole,
          operationId: ref.operationId,
          action: "integration.vercel_call",
          detail: {
            clientId: ref.clientId,
            projectId: selection.projectId,
            target: selection.target,
            ...call,
          },
        });
      }
    },
  };
}

async function verifyConnection(
  api: VercelApi,
  input: VercelSelection,
  proof: VercelScopeProof,
  token: string,
  hook: URL,
  now: () => Date,
) {
  const verification = verifiedScope(await readScopeProbes(api, input, token), input, proof, now());
  if (!verification)
    throw new DatabaseClientError(422, "Vercel did not prove sole project scope and a valid expiry.");
  const branch = deployHookBranch(verification.project, hook, input);
  if (!branch)
    throw new DatabaseClientError(422, "The deploy hook must match the selected project, target and branch.");
  return { expiresAt: verification.expiresAt, branch };
}

export async function vercelIntegrationStatus(ref: ClientRef) {
  const [client] = await db
    .select()
    .from(databaseClients)
    .where(and(eq(databaseClients.databaseId, ref.databaseId), eq(databaseClients.id, ref.clientId)));
  if (!client) throw new DatabaseClientError(404, "Database client not found.");
  const row = await integrationFor(ref.clientId);
  return {
    connectEnabled: !!reviewedVercelScopeProof(),
    eligible: activeClient(client) && supportsVercel(client),
    integration: isVerified(row) ? publicIntegration(row) : null,
    requiresReconnect: !!row && !isVerified(row),
  };
}

type ConnectionRuntime = {
  proof?: VercelScopeProof | null;
  transport?: VercelTransport;
  now?: () => Date;
};

export async function connectVercel(
  ref: ActorRef,
  input: z.infer<typeof vercelConnectInput>,
  runtime: ConnectionRuntime = {},
) {
  const proof = runtime.proof === undefined ? reviewedVercelScopeProof() : runtime.proof;
  if (!proof)
    throw new DatabaseClientError(409, "Vercel connection awaits live verification of project token scope.");
  if (input.projectId === input.otherProjectId || (input.target === "production" && input.gitBranch)) {
    throw new DatabaseClientError(
      422,
      "Select a different comparison project and use branch overrides only for Preview.",
    );
  }
  const hook = deployHookUrl(input.deployHook, input.projectId);
  if (!hook) throw new DatabaseClientError(422, "Enter a Vercel deploy hook for the selected project.");
  const now = runtime.now ?? (() => new Date());
  const audit = providerAudit(ref, input, runtime.transport);
  const verification = await verifyConnection(audit.api, input, proof, input.token, hook, now).finally(
    audit.flush,
  );

  const row = await db.transaction(async (tx) => {
    const client = await lockedClient(tx, ref);
    if (!client) throw new DatabaseClientError(404, "Database client not found.");
    if (!activeClient(client) || !supportsVercel(client))
      throw new DatabaseClientError(
        409,
        "Vercel delivery requires an active production or preview client with an Ark-generated key.",
      );
    if (client.environment !== input.target)
      throw new DatabaseClientError(422, "The Vercel target must match the database client's environment.");
    if (verification.expiresAt <= now()) throw new DatabaseClientError(422, "The Vercel token has expired.");
    const id = createId("vci");
    const tokenSecretId = await sealSecret(tx, id, TOKEN_KIND, input.token);
    const deployHookSecretId = await sealSecret(tx, id, HOOK_KIND, hook.href);
    const [saved] = await tx
      .insert(vercelIntegrations)
      .values({
        id,
        databaseClientId: client.id,
        vercelProjectId: input.projectId,
        vercelTeamId: input.teamId,
        otherProjectId: input.otherProjectId,
        tokenSecretId,
        tokenExpiresAt: verification.expiresAt,
        deployHookSecretId,
        envTarget: input.target,
        gitBranch: input.gitBranch,
        hookBranch: verification.branch,
        scopeVerifiedAt: now(),
        createdBy: ref.actorId,
      })
      .onConflictDoNothing()
      .returning();
    if (!saved)
      throw new DatabaseClientError(
        409,
        "The client or this Vercel project target already has a connection.",
      );
    const pending = await pendingCertificate(client, tx);
    if (!isVerified(saved)) throw new Error("The verified Vercel connection could not be saved.");
    if (pending) await enqueuePush(tx, saved, client.databaseId, pending, now());
    return saved;
  });
  await auditEvent({
    ...ref,
    role: ref.actorRole,
    action: "integration.vercel_connected",
    detail: { clientId: ref.clientId, projectId: row.vercelProjectId, target: row.envTarget },
  });
  await evaluateTokenExpiry(row, now());
  return publicIntegration(row, now());
}

export async function testVercelConnection(ref: ActorRef, runtime: ConnectionRuntime = {}) {
  const proof = runtime.proof === undefined ? reviewedVercelScopeProof() : runtime.proof;
  if (!proof)
    throw new DatabaseClientError(409, "Vercel connection awaits live verification of project token scope.");
  const stored = await db.transaction(async (tx) => {
    const client = await lockedClient(tx, ref);
    const row = client && (await integrationFor(client.id, tx));
    if (!row) throw new DatabaseClientError(404, "Vercel integration not found.");
    if (!isVerified(row))
      throw new DatabaseClientError(409, "Reconnect this integration to verify project scope.");
    return {
      row,
      token: await openSecret(tx, row.tokenSecretId, TOKEN_KIND),
      hook: await openSecret(tx, row.deployHookSecretId, HOOK_KIND),
    };
  });
  const selection = scopeSelection(stored.row);
  const hook = deployHookUrl(stored.hook, selection.projectId);
  if (!hook) throw new Error("The sealed deploy hook is invalid.");
  const audit = providerAudit(ref, selection, runtime.transport);
  const verification = await verifyConnection(
    audit.api,
    selection,
    proof,
    stored.token,
    hook,
    runtime.now ?? (() => new Date()),
  ).finally(audit.flush);
  if (verification.branch !== stored.row.hookBranch)
    throw new DatabaseClientError(422, "The Vercel deploy hook has changed branch.");
  return { ok: true, tokenExpiresAt: verification.expiresAt };
}

export async function disconnectVercel(ref: ActorRef) {
  const row = await db.transaction(async (tx) => {
    if (!(await lockedClient(tx, ref))) throw new DatabaseClientError(404, "Database client not found.");
    return removeVercelIntegration(tx, ref.clientId);
  });
  if (row)
    await auditEvent({
      ...ref,
      role: ref.actorRole,
      action: "integration.vercel_disconnected",
      detail: { clientId: ref.clientId, projectId: row.vercelProjectId, target: row.envTarget },
    });
  return { disconnected: !!row };
}

async function enqueuePush(
  tx: DbTransaction,
  row: VerifiedIntegration,
  databaseId: string,
  cert: Certificate,
  now: Date,
) {
  if (!cert.trustAppliedAt || !cert.keySecretId || cert.notAfter <= now) return;
  if (row.tokenExpiresAt <= now) return;
  // A retry can check an identified deployment. An ambiguous hook must never be dispatched twice.
  if (row.pushCertificateId === cert.id && row.hookRequestedAt && !row.hookJobId) return;
  const payload = {
    integrationId: row.id,
    clientId: row.databaseClientId,
    certificateId: cert.id,
    databaseId,
  };
  // The caller holds the client lock, so concurrent schedulers reuse the same pending attempt.
  const base = `integration.vercel_push:${row.id}:${cert.id}`;
  const prior = await tx
    .select({ status: operations.status })
    .from(operations)
    .where(
      and(
        eq(operations.kind, "integration.vercel_push"),
        sql`${operations.payload}->>'integrationId' = ${row.id}`,
        sql`${operations.payload}->>'certificateId' = ${cert.id}`,
      ),
    )
    .orderBy(desc(operations.createdAt));
  if (prior.some(({ status }) => isInFlight(status)) || (prior.length && prior[0]?.status !== "failed"))
    return;
  await tx
    .insert(operations)
    .values({
      id: createId("op"),
      kind: "integration.vercel_push",
      targetIds: [row.id],
      payload,
      idempotencyKey: prior.length ? `${base}:${createId("idem")}` : base,
      planHash: planHash(payload),
      status: "queued",
    })
    .onConflictDoNothing({ target: operations.idempotencyKey });
}

export async function queueVercelPush(ref: ClientRef, certificateId: string, now: Date) {
  await db.transaction(async (tx) => {
    const client = await lockedClient(tx, ref);
    if (!activeClient(client)) return;
    const row = await integrationFor(client.id, tx);
    if (!isVerified(row)) return;
    const pending = await pendingCertificate(client, tx);
    if (pending?.id === certificateId) await enqueuePush(tx, row, client.databaseId, pending, now);
  });
}

async function evaluateTokenExpiry(row: VerifiedIntegration, now: Date) {
  const remaining = row.tokenExpiresAt.getTime() - now.getTime();
  if (remaining > 30 * DAY_MS) return;
  await raiseAlert({
    dedupKey: tokenAlertKey(row.id),
    severity: remaining <= 0 ? "critical" : "warning",
    title:
      remaining <= 0
        ? `Vercel token for ${row.vercelProjectId} has expired. Use manual certificate rollover or reconnect with a new token.`
        : `Vercel token for ${row.vercelProjectId} expires on ${row.tokenExpiresAt.toISOString().slice(0, 10)}.`,
  });
  if ((await integrationFor(row.databaseClientId))?.id !== row.id)
    await resolveAlert(tokenAlertKey(row.id), now);
}

export async function evaluateVercelTokenAlerts(now: Date) {
  for (const row of await db.select().from(vercelIntegrations)) {
    if (isVerified(row)) await evaluateTokenExpiry(row, now);
  }
}

const pushPayload = z.object({
  integrationId: z.string(),
  clientId: z.string(),
  databaseId: z.string(),
  certificateId: z.string(),
});

type PushOperation = Pick<typeof operations.$inferSelect, "id" | "payload" | "claimToken">;
type PushRuntime = ConnectionRuntime & { sleep?: (ms: number) => Promise<unknown> };
type PushContext = { tx: DbTransaction; row: VerifiedIntegration; cert: Certificate };

export async function pushVercelRollover(operation: PushOperation, runtime: PushRuntime = {}) {
  const ref = pushPayload.parse(operation.payload);
  const now = runtime.now ?? (() => new Date());
  const sleep = runtime.sleep ?? Bun.sleep;
  const proof = runtime.proof === undefined ? reviewedVercelScopeProof() : runtime.proof;

  async function withPending<T>(fn: (context: PushContext) => Promise<T>): Promise<T | undefined> {
    return db.transaction(async (tx) => {
      const client = await lockedClient(tx, ref);
      if (!activeClient(client)) return;
      const row = await integrationFor(client.id, tx);
      if (!isVerified(row) || row.id !== ref.integrationId) return;
      const cert = await pendingCertificate(client, tx);
      if (
        cert?.id !== ref.certificateId ||
        !cert.trustAppliedAt ||
        !cert.keySecretId ||
        cert.notAfter <= now()
      )
        return;
      if (!operation.claimToken) return;
      const [claim] = await tx
        .select({ id: operations.id })
        .from(operations)
        .where(
          and(
            eq(operations.id, operation.id),
            eq(operations.status, "running"),
            eq(operations.claimToken, operation.claimToken),
          ),
        )
        .for("update");
      if (claim) return fn({ tx, row, cert });
    });
  }

  const integration = await withPending(async ({ row }) => row);
  if (!integration) return { skipped: true };
  const selection = scopeSelection(integration);
  const audit = providerAudit({ ...ref, operationId: operation.id }, selection, runtime.transport);
  async function credentials(tx: DbTransaction, row: VerifiedIntegration) {
    if (row.tokenExpiresAt <= now()) throw new Error("The Vercel token has expired.");
    const token = await openSecret(tx, row.tokenSecretId, TOKEN_KIND);
    const hook = deployHookUrl(await openSecret(tx, row.deployHookSecretId, HOOK_KIND), selection.projectId);
    if (!hook) throw new Error("The sealed deploy hook is invalid.");
    return { token, hook };
  }

  try {
    const prepared = await withPending(async ({ tx, row, cert }) => {
      if (!proof) throw new Error("Vercel connection awaits live verification of project token scope.");
      if (row.pushCertificateId === cert.id && row.hookRequestedAt) {
        if (!row.hookJobId)
          throw new Error("Vercel hook receipt is unknown. Use manual certificate rollover.");
        return {
          requestedAt: row.hookRequestedAt,
          jobId: row.hookJobId,
          retry: row.lastPushStatus === "failed",
        };
      }
      const { token, hook } = await credentials(tx, row);
      if (!cert.keySecretId || !cert.certPem) return;
      const key = await openSecret(tx, cert.keySecretId, CLIENT_KEY_SECRET_KIND);
      await tx
        .update(vercelIntegrations)
        .set({
          pushCertificateId: cert.id,
          lastPushAt: now(),
          lastPushStatus: "pushing",
          hookRequestedAt: null,
          hookJobId: null,
        })
        .where(eq(vercelIntegrations.id, row.id));
      return { token, hook, bundle: vercelCredentialBundle(cert.certPem, key) };
    });
    if (!prepared) return { skipped: true };

    let { requestedAt, jobId } = prepared;
    if (prepared.hook && proof) {
      const { token, hook, bundle } = prepared;
      const verified = await verifyConnection(audit.api, selection, proof, token, hook, now).finally(
        audit.flush,
      );
      if (verified.branch !== integration.hookBranch)
        throw new Error("The Vercel deploy hook has changed branch.");
      if (!(await withPending(async () => true))) return { skipped: true };
      await upsertVercelVariable(audit.api, selection, token, VERCEL_ENV_NAMES.bundle, bundle).finally(
        audit.flush,
      );

      // Commit dispatch intent before the non-idempotent call. An unknown receipt requires
      // manual delivery because the provider may already have accepted the hook.
      requestedAt = await withPending(async ({ tx, row }) => {
        const at = now();
        await tx
          .update(vercelIntegrations)
          .set({ hookRequestedAt: at })
          .where(eq(vercelIntegrations.id, row.id));
        return at;
      });
      if (!requestedAt || !(await withPending(async () => true))) return { skipped: true };
      jobId = await triggerVercelHook(audit.api, hook).finally(audit.flush);
      const receipt = jobId;
      const recorded = await withPending(async ({ tx, row }) => {
        await tx
          .update(vercelIntegrations)
          .set({ hookJobId: receipt })
          .where(eq(vercelIntegrations.id, row.id));
        return true;
      });
      if (!recorded) return { skipped: true };
    }
    if (!requestedAt || !jobId) return { skipped: true };

    const deadline = requestedAt.getTime() + PUSH_WINDOW_MS;
    // A later attempt can check the recorded deployment once after the original polling window.
    // New deployments are only created before dispatch intent is recorded.
    let retry = prepared.retry;
    while (true) {
      const finalCheck = now().getTime() >= deadline;
      if (finalCheck && !retry) break;
      retry = false;
      const token = await withPending(async ({ tx, row }) => (await credentials(tx, row)).token);
      if (!token) return { skipped: true };
      const deploymentId = await vercelHookDeployment(
        audit.api,
        { ...selection, gitBranch: integration.hookBranch },
        token,
        jobId,
        requestedAt,
      ).finally(audit.flush);
      if (!finalCheck && now().getTime() >= deadline) break;
      if (deploymentId) {
        const deliveredAt = now();
        const delivered = await withPending(async ({ tx, row }) => {
          await recordRolloverDelivery(tx, { ...ref, source: "integration", now: deliveredAt });
          await tx
            .update(vercelIntegrations)
            .set({
              lastPushAt: deliveredAt,
              lastPushStatus: "delivered",
              lastDeploymentId: deploymentId,
            })
            .where(eq(vercelIntegrations.id, row.id));
          return true;
        });
        if (!delivered) return { skipped: true };
        await resolveAlert(vercelPushAlertKey(ref.clientId), deliveredAt);
        await evaluateRolloverAlerts(deliveredAt, ref.clientId);
        return { certificateId: ref.certificateId, deploymentId, deliveredAt: deliveredAt.toISOString() };
      }
      if (finalCheck) break;
      await sleep(Math.min(5_000, deadline - now().getTime()));
    }
    throw new Error("The Vercel deployment was not ready within 30 minutes.");
  } catch {
    const failed = await withPending(async ({ tx, row, cert }) => {
      await tx
        .update(vercelIntegrations)
        .set({
          lastPushAt: now(),
          lastPushStatus: "failed",
          ...(row.pushCertificateId !== cert.id
            ? { pushCertificateId: cert.id, hookRequestedAt: null, hookJobId: null }
            : {}),
        })
        .where(eq(vercelIntegrations.id, row.id));
      return true;
    });
    if (!failed) return { skipped: true };
    await raiseAlert({
      dedupKey: vercelPushAlertKey(ref.clientId),
      severity: "warning",
      title: `Vercel certificate delivery failed for ${selection.projectId}. Reveal the successor, redeploy and confirm to finish manually.`,
    });
    if (!(await withPending(async () => true))) await resolveAlert(vercelPushAlertKey(ref.clientId), now());
    // Keep upstream errors, URLs and response bodies out of operations and worker logs.
    throw new Error("Vercel certificate delivery failed. Manual rollover is available.");
  }
}
