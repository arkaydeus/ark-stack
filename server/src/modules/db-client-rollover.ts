// Database client certificate rollover (docs/design/front-door.md §3.10.4, ticket FD-28).
//
// Every certificate is valid for 90 days. Thirty days before the current certificate's not_after
// the daily `database.client_rollover` job issues exactly one successor from a fresh CA
// generation, links it through `superseded_by` (unique) under a per-client lock, and the
// coordinator reloads PgBouncer so both generations are trusted. The owner reveals the successor
// once, deploys it and confirms; confirming sets `delivered_at` once, promotes the successor
// through `delivered` to `current`, marks the predecessor `superseded` and moves the client's CA
// pointer. At the predecessor's not_after a durable retirement task (coordinator) removes its
// generation, reloads, and drains the role by not_after + 5 s.
//
// Every function takes the clock as an argument (`now`), so tests can run whole cycles on an
// injected timeline. Nothing here logs, audits or returns key material except the one-time
// successor reveal, whose audit row carries IDs, serials and fingerprints only.

import {
  RETIREMENT_ALERT_PREFIX,
  RETIREMENT_DEADLINE_MS,
  ROLLOVER_ALERT_PREFIX,
  clientRolloverStatus,
  createId,
  databaseClientRolloverGuide,
  decryptSecret,
  isInFlight,
  planHash,
  rolloverAlertLevel,
  rolloverAlertTitle,
  rolloverDue,
  ROLLOVER_LEAD_DAYS,
} from "@ark-stack/shared";
import { and, eq, inArray, isNull, lt, lte, or, sql } from "drizzle-orm";

import { db } from "../db.ts";
import { loadEnv } from "../env.ts";
import {
  alerts,
  auditEvents,
  clientCertificateRetirements,
  clientCertificates,
  databaseClients,
  databaseRoles,
  managedDatabases,
  operations,
  privateCas,
  secrets,
  vercelIntegrations,
} from "../schema.ts";
import { raiseAlert, resolveAlert } from "./alerts.ts";
import { DatabaseClientError, auditEvent, certificateChain, loadLinkedCertificates } from "./db-clients.ts";
import * as pki from "./pki.ts";

type ClientRow = typeof databaseClients.$inferSelect;
type CertificateRow = typeof clientCertificates.$inferSelect;
type Executor = pki.Executor;

const DAY_MS = 86_400_000;

export const rolloverAlertKey = (clientId: string) => `${ROLLOVER_ALERT_PREFIX}${clientId}`;
export const vercelPushAlertKey = (clientId: string) => `vercel-push:${clientId}`;
export const retirementAlertKey = (certificateId: string) => `${RETIREMENT_ALERT_PREFIX}${certificateId}`;

function isUniqueViolation(error: unknown) {
  let current: unknown = error;
  for (let index = 0; index < 5 && current; index++) {
    if (typeof current === "object" && current && "code" in current && current.code === "23505") return true;
    current = typeof current === "object" && current && "cause" in current ? current.cause : undefined;
  }
  return false;
}

/** The certificate the client uses now: its newest issued `current` (or transient `delivered`). */
export function currentOf(chain: CertificateRow[]) {
  return (
    chain.findLast(
      (row) =>
        row.status === "issued" && (row.rolloverState === "current" || row.rolloverState === "delivered"),
    ) ?? null
  );
}

/** The undelivered successor, if one is in flight. */
export function pendingOf(chain: CertificateRow[]) {
  return chain.findLast((row) => row.status === "issued" && row.rolloverState === "pending") ?? null;
}

const predecessorOf = (chain: CertificateRow[], certificate: CertificateRow) =>
  chain.find((row) => row.supersededBy === certificate.id) ?? null;

async function roleName(client: Pick<ClientRow, "roleId">, executor: Pick<Executor, "select"> = db) {
  const [role] = await executor
    .select({ name: databaseRoles.name })
    .from(databaseRoles)
    .where(eq(databaseRoles.id, client.roleId));
  if (!role) throw new Error("The client's login role row is missing.");
  return role.name;
}

export const lockRolloverClient = (tx: Executor, clientId: string) =>
  tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`client-rollover:${clientId}`}))`);

/** Active, fully issued clients that are not being revoked: the only ones that roll over. */
const usable = (client: ClientRow) =>
  client.status === "active" && client.issuedAt !== null && client.revokedAt === null;

// ---- Successor issuance ------------------------------------------------------------------------

export type SuccessorOutcome = "issued" | "exists" | "not_due" | "needs_csr" | "no_current" | "inactive";

export type IssueSuccessorResult = {
  outcome: SuccessorOutcome;
  clientId: string;
  databaseId: string | null;
  role: string | null;
  predecessor: CertificateRow | null;
  successor: CertificateRow | null;
};

/**
 * Issue the client's next certificate, at most once per certificate (§3.10.4 step 1). Under a
 * per-client transaction lock it selects the unsuperseded current certificate; if that already
 * has a successor it returns it (`exists`). Otherwise it creates a fresh `db-client` CA
 * generation, issues a 90-day `pending` certificate from it (a generated key sealed for the
 * one-time reveal, or the submitted CSR) and sets `superseded_by` on the predecessor, all in one
 * transaction. The unique index on `superseded_by` backs the lock: a concurrent duplicate fails
 * and rolls back its CA and certificate. The caller reloads PgBouncer.
 *
 * `scheduled` issues only within ROLLOVER_LEAD_DAYS of not_after; `early` (owner request) skips
 * that check but follows the same one-successor rule. A CSR client cannot get a generated key:
 * without a CSR it reports `needs_csr` and the rollover alert asks the owner for one.
 */
export async function issueSuccessor(input: {
  clientId: string;
  now: Date;
  reason: "scheduled" | "early";
  csrPem?: string;
  leadDays?: number;
}): Promise<IssueSuccessorResult> {
  if (input.csrPem !== undefined) pki.validateCsr(input.csrPem);
  const empty = {
    clientId: input.clientId,
    databaseId: null,
    role: null,
    predecessor: null,
    successor: null,
  };
  try {
    return await db.transaction(async (tx) => {
      await lockRolloverClient(tx, input.clientId);
      const [client] = await tx
        .select()
        .from(databaseClients)
        .where(eq(databaseClients.id, input.clientId))
        .for("update");
      if (!client) throw new DatabaseClientError(404, "Database client not found.");
      const base = { ...empty, databaseId: client.databaseId };
      if (!usable(client)) return { ...base, outcome: "inactive" as const };
      const role = await roleName(client, tx);
      const chain = certificateChain(client.caId, await loadLinkedCertificates([client.caId], tx));
      const pending = pendingOf(chain);
      if (pending)
        return {
          ...base,
          role,
          predecessor: predecessorOf(chain, pending),
          successor: pending,
          outcome: "exists" as const,
        };
      const current = currentOf(chain);
      if (!current) return { ...base, role, outcome: "no_current" as const };
      if (current.supersededBy) {
        const successor = chain.find((row) => row.id === current.supersededBy) ?? null;
        return { ...base, role, predecessor: current, successor, outcome: "exists" as const };
      }
      if (input.reason === "scheduled" && !rolloverDue(current.notAfter, input.now, input.leadDays))
        return { ...base, role, predecessor: current, outcome: "not_due" as const };
      if (client.keySource === "csr" && input.csrPem === undefined)
        return { ...base, role, predecessor: current, outcome: "needs_csr" as const };

      const ca = await pki.createPrivateCa(
        { purpose: "db-client", name: `${client.name}/${client.environment}`, now: input.now },
        tx,
      );
      const issued = await pki.issueClientCertificate(
        {
          caId: ca.id,
          subjectCn: role,
          csrPem: input.csrPem,
          keyOwner:
            input.csrPem === undefined
              ? { resourceType: "database", resourceId: client.databaseId }
              : undefined,
          rolloverState: "pending",
          now: input.now,
        },
        tx,
      );
      const linked = await tx
        .update(clientCertificates)
        .set({ supersededBy: issued.certificate.id })
        .where(and(eq(clientCertificates.id, current.id), isNull(clientCertificates.supersededBy)))
        .returning({ id: clientCertificates.id });
      if (linked.length !== 1) throw new Error("The predecessor gained a successor concurrently.");
      const [successor] = await tx
        .select()
        .from(clientCertificates)
        .where(eq(clientCertificates.id, issued.certificate.id));
      return {
        ...base,
        role,
        predecessor: { ...current, supersededBy: issued.certificate.id },
        successor: successor ?? null,
        outcome: "issued" as const,
      };
    });
  } catch (error) {
    // The lock makes this unreachable between Ark processes sharing the database; the index is
    // the last line. Either way the transaction rolled back: report the surviving successor.
    if (!isUniqueViolation(error)) throw error;
    const [client] = await db.select().from(databaseClients).where(eq(databaseClients.id, input.clientId));
    if (!client) throw error;
    const chain = certificateChain(client.caId, await loadLinkedCertificates([client.caId]));
    const current = currentOf(chain);
    return {
      ...empty,
      databaseId: client.databaseId,
      role: await roleName(client),
      predecessor: current,
      successor: chain.find((row) => row.id === current?.supersededBy) ?? null,
      outcome: "exists",
    };
  }
}

/** Evidence for steps and audit rows: IDs, serials, fingerprints and dates only. */
export function successorEvidence(result: IssueSuccessorResult) {
  return {
    clientId: result.clientId,
    outcome: result.outcome,
    role: result.role,
    predecessorId: result.predecessor?.id ?? null,
    predecessorNotAfter: result.predecessor?.notAfter.toISOString() ?? null,
    successorId: result.successor?.id ?? null,
    successorCaId: result.successor?.caId ?? null,
    successorSerial: result.successor?.serial ?? null,
    successorFingerprintSha256: result.successor?.fingerprintSha256 ?? null,
    successorNotAfter: result.successor?.notAfter.toISOString() ?? null,
  };
}

/**
 * The daily job's scan: every usable client whose unsuperseded current certificate is within
 * the lead time. issueSuccessor rechecks everything under the client lock, so a repeated or
 * concurrent run creates nothing new.
 */
export async function runScheduledRollover(input: { now: Date; leadDays?: number }) {
  const clients = (await db.select().from(databaseClients)).filter(usable);
  const all = await loadLinkedCertificates(clients.map((client) => client.caId));
  const results: IssueSuccessorResult[] = [];
  for (const client of clients) {
    const chain = certificateChain(client.caId, all);
    const current = currentOf(chain);
    const pending = pendingOf(chain);
    if (!pending && (!current || !rolloverDue(current.notAfter, input.now, input.leadDays))) continue;
    results.push(
      await issueSuccessor({
        clientId: client.id,
        now: input.now,
        reason: "scheduled",
        leadDays: input.leadDays,
      }),
    );
  }
  return results;
}

// ---- Early rollover (owner request) --------------------------------------------------------------

/**
 * `POST …/clients/:clientId/rollover`: queue an on-demand successor. Refused while a successor
 * already exists (the one-successor rule) or another rollover for the client is in flight.
 */
export async function queueEarlyRollover(input: {
  databaseId: string;
  clientId: string;
  actorId: string;
  csrPem?: string;
}) {
  if (input.csrPem !== undefined) pki.validateCsr(input.csrPem);
  return db.transaction(async (tx) => {
    await lockRolloverClient(tx, input.clientId);
    const [client] = await tx
      .select()
      .from(databaseClients)
      .where(and(eq(databaseClients.id, input.clientId), eq(databaseClients.databaseId, input.databaseId)))
      .for("update");
    if (!client) throw new DatabaseClientError(404, "Database client not found.");
    if (client.status !== "active" || client.revokedAt)
      throw new DatabaseClientError(409, "This client was revoked; it cannot roll over.");
    if (!client.issuedAt) throw new DatabaseClientError(409, "Client issuance has not completed.");
    const chain = certificateChain(client.caId, await loadLinkedCertificates([client.caId], tx));
    const current = currentOf(chain);
    if (!current) throw new DatabaseClientError(409, "The client has no current certificate to roll over.");
    if (current.supersededBy)
      throw new DatabaseClientError(
        409,
        "A successor certificate already exists for the current certificate; deliver and confirm it first.",
      );
    if (client.keySource === "csr" && input.csrPem === undefined)
      throw new DatabaseClientError(422, "This client uses CSR issuance; submit a CSR for the successor.");
    const inflight = await tx
      .select({ id: operations.id, status: operations.status })
      .from(operations)
      .where(
        and(
          eq(operations.kind, "database.client_rollover"),
          sql`${operations.payload}->>'clientId' = ${input.clientId}`,
        ),
      );
    if (inflight.some((op) => isInFlight(op.status)))
      throw new DatabaseClientError(409, "A rollover for this client is already in progress.");
    const payload = {
      clientId: input.clientId,
      early: true,
      ...(input.csrPem === undefined ? {} : { csrPem: input.csrPem }),
    };
    const [operation] = await tx
      .insert(operations)
      .values({
        id: createId("op"),
        kind: "database.client_rollover",
        actorId: input.actorId,
        targetIds: [input.databaseId, input.clientId],
        payload,
        idempotencyKey: createId("client-rollover"),
        planHash: planHash(payload),
        status: "queued",
      })
      .returning();
    return { operation: operation!, predecessor: current };
  });
}

// ---- Delivery: reveal, then confirm --------------------------------------------------------------

/**
 * The successor's one-time reveal (manual guided path): its certificate, the generated key (then
 * deleted from storage), its CA, and the §3.12 rollover commands with real values. The password
 * and env var names do not change. A second reveal fails.
 */
export async function revealRolloverSuccessor(input: {
  databaseId: string;
  clientId: string;
  actorId: string;
  actorRole: string;
  now?: Date;
}) {
  const { rootKey } = loadEnv();
  const now = input.now ?? new Date();
  return db.transaction(async (tx) => {
    await lockRolloverClient(tx, input.clientId);
    const [client] = await tx
      .select()
      .from(databaseClients)
      .where(and(eq(databaseClients.id, input.clientId), eq(databaseClients.databaseId, input.databaseId)))
      .for("update");
    if (!client) throw new DatabaseClientError(404, "Database client not found.");
    if (client.status !== "active" || client.revokedAt)
      throw new DatabaseClientError(409, "This client was revoked; its credentials cannot be revealed.");
    const chain = certificateChain(client.caId, await loadLinkedCertificates([client.caId], tx));
    const pending = pendingOf(chain);
    if (!pending) throw new DatabaseClientError(409, "No successor certificate is waiting for delivery.");
    const [successor] = await tx
      .select()
      .from(clientCertificates)
      .where(eq(clientCertificates.id, pending.id))
      .for("update");
    if (!successor?.certPem) throw new Error("The successor certificate is missing.");
    assertTrustApplied(successor);
    if (successor.revealedAt)
      throw new DatabaseClientError(
        409,
        "The successor was already revealed. Deliver it and confirm, or revoke the client if it was lost.",
      );
    let keyPem: string | null = null;
    if (successor.keySecretId) {
      const [keySecret] = await tx.select().from(secrets).where(eq(secrets.id, successor.keySecretId));
      if (!keySecret || keySecret.kind !== pki.CLIENT_KEY_SECRET_KIND)
        throw new Error("The successor's sealed key is missing.");
      keyPem = decryptSecret(rootKey, keySecret);
    }
    await tx
      .update(clientCertificates)
      .set({ revealedAt: now, keySecretId: null })
      .where(eq(clientCertificates.id, successor.id));
    if (successor.keySecretId) await tx.delete(secrets).where(eq(secrets.id, successor.keySecretId));
    const [ca] = await tx
      .select({ certPem: privateCas.certPem })
      .from(privateCas)
      .where(eq(privateCas.id, successor.caId));
    const role = await roleName(client, tx);
    const predecessor = predecessorOf(chain, successor);
    await tx.insert(auditEvents).values({
      id: createId("aud"),
      actorId: input.actorId,
      action: "database.client_rollover_reveal",
      resourceType: "database",
      resourceId: input.databaseId,
      role: input.actorRole,
      detail: {
        clientId: client.id,
        role,
        certificateId: successor.id,
        serial: successor.serial,
        fingerprintSha256: successor.fingerprintSha256,
        keyDeleted: keyPem !== null,
      },
    });
    return {
      clientId: client.id,
      role,
      environment: client.environment,
      certificate: {
        id: successor.id,
        pem: successor.certPem,
        serial: successor.serial,
        fingerprintSha256: successor.fingerprintSha256,
        notBefore: successor.notBefore,
        notAfter: successor.notAfter,
      },
      privateKey: keyPem,
      clientCaPem: ca?.certPem ?? null,
      predecessor: predecessor
        ? { id: predecessor.id, notAfter: predecessor.notAfter, serial: predecessor.serial }
        : null,
      guide: databaseClientRolloverGuide({
        environment: client.environment,
        secrets: { certPem: successor.certPem, keyPem },
      }),
      confirm: {
        method: "POST",
        path: `/api/databases/${input.databaseId}/clients/${client.id}/rollover/confirm`,
        body: { certificateId: successor.id },
      },
    };
  });
}

/**
 * Record delivery (§3.10.4 step 2). In one idempotent transaction: `delivered_at` is set once,
 * the successor moves through `delivered` to `current`, the predecessor becomes `superseded`
 * (unless it already retired), and the client's CA pointer moves to the successor's generation.
 * The rollover alert is cleared. Confirming an already delivered successor changes nothing.
 * The trusted generations do not change, so PgBouncer needs no reload.
 */
type DeliveryInput = {
  databaseId: string;
  clientId: string;
  certificateId: string;
  actorId?: string | null;
  actorRole?: string;
  source?: "manual" | "integration";
  now: Date;
};

export async function recordRolloverDelivery(tx: Executor, input: DeliveryInput) {
  await lockRolloverClient(tx, input.clientId);
  const [client] = await tx
    .select()
    .from(databaseClients)
    .where(and(eq(databaseClients.id, input.clientId), eq(databaseClients.databaseId, input.databaseId)))
    .for("update");
  if (!client) throw new DatabaseClientError(404, "Database client not found.");
  if (client.status !== "active" || client.revokedAt)
    throw new DatabaseClientError(409, "This client was revoked; it cannot roll over.");
  const chain = certificateChain(client.caId, await loadLinkedCertificates([client.caId], tx));
  if (!chain.some((row) => row.id === input.certificateId))
    throw new DatabaseClientError(404, "That certificate does not belong to this client.");
  const [successor] = await tx
    .select()
    .from(clientCertificates)
    .where(eq(clientCertificates.id, input.certificateId))
    .for("update");
  if (!successor) throw new DatabaseClientError(404, "That certificate does not belong to this client.");
  const predecessor = predecessorOf(chain, successor);
  if (!predecessor) throw new DatabaseClientError(409, "That certificate is not a rollover successor.");
  if (successor.deliveredAt && successor.rolloverState !== "pending")
    return { client, successor, predecessor, alreadyDelivered: true };
  assertTrustApplied(successor);
  if (successor.status !== "issued" || successor.rolloverState !== "pending")
    throw new DatabaseClientError(409, `The successor is ${successor.status}/${successor.rolloverState}.`);
  if (successor.notAfter.getTime() <= input.now.getTime())
    throw new DatabaseClientError(409, "The successor has already expired.");
  if ((input.source ?? "manual") === "manual" && successor.keySecretId)
    throw new DatabaseClientError(
      409,
      "Reveal the successor bundle and deploy it before confirming delivery.",
    );
  // Through `delivered` (durable delivered_at) to `current`, in this one transaction.
  await tx
    .update(clientCertificates)
    .set({
      rolloverState: "delivered",
      ...(input.source === "integration" ? { keySecretId: null } : {}),
      deliveredAt: sql`COALESCE(${clientCertificates.deliveredAt}, ${input.now.toISOString()}::timestamptz)`,
    })
    .where(eq(clientCertificates.id, successor.id));
  await tx
    .update(clientCertificates)
    .set({ rolloverState: "current" })
    .where(and(eq(clientCertificates.id, successor.id), eq(clientCertificates.rolloverState, "delivered")));
  await tx
    .update(clientCertificates)
    .set({ rolloverState: "superseded" })
    .where(
      and(
        eq(clientCertificates.id, predecessor.id),
        inArray(clientCertificates.rolloverState, ["current", "delivered"]),
      ),
    );
  if (input.source === "integration" && successor.keySecretId)
    await tx.delete(secrets).where(eq(secrets.id, successor.keySecretId));
  if ((input.source ?? "manual") === "manual") {
    await tx
      .update(vercelIntegrations)
      .set({ lastPushStatus: "cancelled" })
      .where(
        and(
          eq(vercelIntegrations.databaseClientId, client.id),
          eq(vercelIntegrations.lastPushStatus, "pushing"),
          eq(vercelIntegrations.pushCertificateId, successor.id),
        ),
      );
  }
  await tx.update(databaseClients).set({ caId: successor.caId }).where(eq(databaseClients.id, client.id));
  const [updatedSuccessor] = await tx
    .select()
    .from(clientCertificates)
    .where(eq(clientCertificates.id, successor.id));
  const [updatedPredecessor] = await tx
    .select()
    .from(clientCertificates)
    .where(eq(clientCertificates.id, predecessor.id));
  await tx.insert(auditEvents).values({
    id: createId("aud"),
    actorId: input.actorId ?? null,
    action: "database.client_rollover_delivered",
    resourceType: "database",
    resourceId: input.databaseId,
    role: input.actorRole,
    detail: {
      clientId: client.id,
      source: input.source ?? "manual",
      successorId: successor.id,
      successorSerial: successor.serial,
      successorCaId: successor.caId,
      predecessorId: predecessor.id,
      predecessorSerial: predecessor.serial,
      deliveredAt: updatedSuccessor?.deliveredAt?.toISOString() ?? null,
    },
  });
  return {
    client,
    successor: updatedSuccessor!,
    predecessor: updatedPredecessor!,
    alreadyDelivered: false,
  };
}

export async function confirmRolloverDelivery(input: DeliveryInput) {
  const result = await db.transaction((tx) => recordRolloverDelivery(tx, input));
  if (!result.alreadyDelivered) await resolveAlert(vercelPushAlertKey(input.clientId), input.now);
  await evaluateRolloverAlerts(input.now, input.clientId);
  return {
    clientId: input.clientId,
    alreadyDelivered: result.alreadyDelivered,
    successor: {
      id: result.successor.id,
      rolloverState: result.successor.rolloverState,
      deliveredAt: result.successor.deliveredAt,
      notAfter: result.successor.notAfter,
    },
    predecessor: {
      id: result.predecessor.id,
      rolloverState: result.predecessor.rolloverState,
      notAfter: result.predecessor.notAfter,
      retirementDeadline: new Date(result.predecessor.notAfter.getTime() + RETIREMENT_DEADLINE_MS),
    },
  };
}

/** Reconcile delivery readiness only after a successful bundle reload. */
export async function markSuccessorsTrusted(ids: string[], now: Date) {
  if (!ids.length) return;
  await db.update(clientCertificates).set({ trustAppliedAt: now }).where(inArray(clientCertificates.id, ids));
}

function assertTrustApplied(certificate: CertificateRow) {
  if (
    (process.env.ARK_PGBOUNCER_RELOAD === "1" || process.env.NODE_ENV === "production") &&
    !certificate.trustAppliedAt
  )
    throw new DatabaseClientError(
      409,
      "The successor is awaiting a successful PgBouncer reload; retry delivery after reconciliation.",
    );
}

/** Inventory view of one certificate: no PEM, key or secret ID. */
const certificateView = (row: CertificateRow | null) =>
  row && {
    id: row.id,
    caId: row.caId,
    serial: row.serial,
    fingerprintSha256: row.fingerprintSha256,
    notBefore: row.notBefore,
    notAfter: row.notAfter,
    status: row.status,
    rolloverState: row.rolloverState,
    deliveredAt: row.deliveredAt,
    revealed: row.revealedAt !== null,
    retiredAt: row.retiredAt,
  };

/** `GET …/clients/:clientId/rollover`: where the client is in its cycle, with the guide. */
export async function rolloverStatus(input: { databaseId: string; clientId: string; now: Date }) {
  const [client] = await db
    .select()
    .from(databaseClients)
    .where(and(eq(databaseClients.id, input.clientId), eq(databaseClients.databaseId, input.databaseId)));
  if (!client) throw new DatabaseClientError(404, "Database client not found.");
  const chain = certificateChain(client.caId, await loadLinkedCertificates([client.caId]));
  const current = currentOf(chain);
  const pending = pendingOf(chain);
  const predecessor = pending ? predecessorOf(chain, pending) : null;
  const expiring = predecessor ?? current;
  const [alert] = await db
    .select({ severity: alerts.severity, title: alerts.title })
    .from(alerts)
    .where(and(eq(alerts.dedupKey, rolloverAlertKey(client.id)), isNull(alerts.resolvedAt)));
  return {
    clientId: client.id,
    status: clientRolloverStatus(chain),
    keySource: client.keySource,
    current: certificateView(current),
    successor: certificateView(pending),
    predecessor: certificateView(predecessor),
    nextRolloverAt:
      current && !current.supersededBy
        ? new Date(current.notAfter.getTime() - ROLLOVER_LEAD_DAYS * DAY_MS)
        : null,
    retirementDeadline: expiring ? new Date(expiring.notAfter.getTime() + RETIREMENT_DEADLINE_MS) : null,
    alert: alert ?? null,
    history: chain.map((row) => ({
      id: row.id,
      caId: row.caId,
      serial: row.serial,
      notAfter: row.notAfter,
      status: row.status,
      rolloverState: row.rolloverState,
      deliveredAt: row.deliveredAt,
      retiredAt: row.retiredAt,
    })),
    guide: databaseClientRolloverGuide({ environment: client.environment }),
  };
}

// ---- Alerts --------------------------------------------------------------------------------------

/**
 * The rollover-pending alert per client (§3.10.4 step 3): from T−30 while the successor is not
 * delivered (or not even issued, e.g. a CSR client), `info` → `warning` at T−14 → `critical` at
 * T−7 and after expiry. Delivery, revocation or a new cycle resolve it.
 */
export async function evaluateRolloverAlerts(now: Date, clientId?: string) {
  const clients = await db
    .select()
    .from(databaseClients)
    .where(clientId ? eq(databaseClients.id, clientId) : undefined);
  const all = await loadLinkedCertificates(clients.filter(usable).map((client) => client.caId));
  const raised: Array<{ clientId: string; severity: string; notAfter: Date }> = [];
  for (const client of clients) {
    const key = rolloverAlertKey(client.id);
    if (!usable(client)) {
      await resolveAlert(key, now);
      continue;
    }
    const chain = certificateChain(client.caId, all);
    const pending = pendingOf(chain);
    const current = currentOf(chain);
    const expiring =
      (pending ? predecessorOf(chain, pending) : current) ??
      chain
        .filter((row) => row.notAfter <= now)
        .toSorted((a, b) => b.notAfter.getTime() - a.notAfter.getTime())[0];
    const level = expiring ? rolloverAlertLevel(expiring.notAfter, now) : null;
    if (!expiring || !level || (!pending && current?.supersededBy)) {
      await resolveAlert(key, now);
      continue;
    }
    const role = await roleName(client);
    await raiseAlert({
      severity: level,
      title: rolloverAlertTitle({
        role,
        notAfter: expiring.notAfter,
        now,
        needsCsr: !pending && client.keySource === "csr",
      }),
      dedupKey: key,
    });
    raised.push({ clientId: client.id, severity: level, notAfter: expiring.notAfter });
  }
  return raised;
}

// ---- Retirement bookkeeping (the coordinator drives PgBouncer) -----------------------------------

export type DueRetirement = {
  certificate: CertificateRow;
  client: ClientRow;
  role: string;
  databaseName: string;
  deadline: Date;
};

/**
 * Certificates of usable clients whose not_after is at or before `now + lookaheadMs` and whose
 * retirement has not completed (issued ones, and ones a failed attempt already removed from the
 * bundle): the predecessor at T, and also an undelivered successor at its
 * own not_after. Missing delivery never postpones retirement (§3.10.4 step 6).
 */
export async function dueRetirements(input: { now: Date; lookaheadMs?: number }) {
  const horizon = new Date(input.now.getTime() + (input.lookaheadMs ?? 0));
  const expiring = await db
    .select({ id: clientCertificates.id })
    .from(clientCertificates)
    .where(
      and(
        // Issued, or already taken out of the bundle by an attempt whose drain has not finished.
        or(eq(clientCertificates.status, "issued"), eq(clientCertificates.rolloverState, "retired")),
        isNull(clientCertificates.retiredAt),
        lt(clientCertificates.notAfter, new Date(horizon.getTime() + 1)),
      ),
    );
  const open = await db
    .select()
    .from(clientCertificateRetirements)
    .where(isNull(clientCertificateRetirements.completedAt));
  const openIds = new Set(open.map((row) => row.certificateId));
  const ids = new Set([...expiring.map((row) => row.id), ...openIds]);
  if (!ids.size) return [];
  const clients = (await db.select().from(databaseClients)).filter(
    (client) => usable(client) || open.some((row) => row.clientId === client.id),
  );
  const all = await loadLinkedCertificates(clients.map((client) => client.caId));
  const due: DueRetirement[] = [];
  for (const client of clients) {
    for (const certificate of certificateChain(client.caId, all)) {
      if (!ids.has(certificate.id) || certificate.notAfter > horizon) continue;
      if (!usable(client) && !openIds.has(certificate.id)) continue;
      const task = open.find((row) => row.certificateId === certificate.id);
      if (client.revocationCompletedAt) {
        await db
          .update(clientCertificateRetirements)
          .set({
            completedAt: input.now,
            leaseUntil: null,
            updatedAt: input.now,
            evidence: { cancelled: "client revocation drained sessions" },
          })
          .where(eq(clientCertificateRetirements.certificateId, certificate.id));
        await resolveAlert(retirementAlertKey(certificate.id), input.now);
        continue;
      }
      if (task?.leaseUntil && task.leaseUntil > input.now) continue;
      const [database] = await db
        .select({ name: managedDatabases.name })
        .from(managedDatabases)
        .where(eq(managedDatabases.id, client.databaseId));
      due.push({
        certificate,
        client,
        role: await roleName(client),
        databaseName: database?.name ?? "",
        deadline: new Date(certificate.notAfter.getTime() + RETIREMENT_DEADLINE_MS),
      });
    }
  }
  return due.toSorted((a, b) => a.certificate.notAfter.getTime() - b.certificate.notAfter.getTime());
}

/** Persist a deadline before waiting for a configuration writer, without claiming it. */
export async function ensureRetirement(item: DueRetirement) {
  await db
    .insert(clientCertificateRetirements)
    .values({
      certificateId: item.certificate.id,
      clientId: item.client.id,
      role: item.role,
      databaseName: item.databaseName,
      notAfter: item.certificate.notAfter,
      deadline: item.deadline,
    })
    .onConflictDoNothing({ target: clientCertificateRetirements.certificateId });
}

/** Lease one task; null while another runner owns it, during backoff, or after completion. */
export async function claimRetirement(item: DueRetirement, now: Date, leaseMs = 30_000) {
  await ensureRetirement(item);
  const claimed = await db
    .update(clientCertificateRetirements)
    .set({
      leaseUntil: new Date(now.getTime() + leaseMs),
      attempts: sql`${clientCertificateRetirements.attempts} + 1`,
      updatedAt: now,
    })
    .where(
      and(
        eq(clientCertificateRetirements.certificateId, item.certificate.id),
        isNull(clientCertificateRetirements.completedAt),
        or(
          isNull(clientCertificateRetirements.leaseUntil),
          lte(clientCertificateRetirements.leaseUntil, now),
        ),
      ),
    )
    .returning();
  return claimed[0] ?? null;
}

/**
 * Take the generation out of the trust set before the reload: the certificate becomes
 * `expired`/`retired` (its `delivered_at` stays), and its CA is retired when no other issued
 * certificate uses it. Idempotent.
 */
export async function markGenerationRetired(certificateId: string) {
  await db.transaction(async (tx) => {
    const [row] = await tx
      .select()
      .from(clientCertificates)
      .where(eq(clientCertificates.id, certificateId))
      .for("update");
    if (!row) throw new Error("The retiring certificate is missing.");
    if (row.status === "issued") {
      await tx
        .update(clientCertificates)
        .set({ status: "expired", rolloverState: "retired", keySecretId: null })
        .where(eq(clientCertificates.id, certificateId));
      // An unrevealed successor that expires undelivered takes its sealed key with it.
      if (row.keySecretId) await tx.delete(secrets).where(eq(secrets.id, row.keySecretId));
    }
    const others = await tx
      .select({ id: clientCertificates.id })
      .from(clientCertificates)
      .where(and(eq(clientCertificates.caId, row.caId), eq(clientCertificates.status, "issued")));
    if (!others.length)
      await tx
        .update(privateCas)
        .set({ status: "retired" })
        .where(and(eq(privateCas.id, row.caId), eq(privateCas.status, "active")));
  });
}

export type RetirementTimelineRecord = {
  fencedAt?: number;
  reloadedAt?: number;
  drainedAt?: number;
  reopenedAt?: number;
  [key: string]: unknown;
};

const at = (value: number | undefined) => (value === undefined ? undefined : new Date(value));

/** The retirement finished: record the measured timeline, clear its alert, audit it. */
export async function completeRetirement(
  item: DueRetirement,
  input: { now: Date; timeline: RetirementTimelineRecord; operationId?: string },
) {
  const drainedAt = at(input.timeline.drainedAt);
  const missed = drainedAt ? drainedAt.getTime() > item.deadline.getTime() : false;
  await db.transaction(async (tx) => {
    await tx
      .update(clientCertificates)
      .set({ retiredAt: input.now })
      .where(eq(clientCertificates.id, item.certificate.id));
    await tx
      .update(clientCertificateRetirements)
      .set({
        completedAt: input.now,
        leaseUntil: null,
        lastError: null,
        fencedAt: at(input.timeline.fencedAt),
        reloadedAt: at(input.timeline.reloadedAt),
        drainedAt,
        reopenedAt: at(input.timeline.reopenedAt),
        ...(missed ? { deadlineMissed: true } : {}),
        evidence: input.timeline,
        updatedAt: input.now,
      })
      .where(eq(clientCertificateRetirements.certificateId, item.certificate.id));
  });
  if (!missed) await resolveAlert(retirementAlertKey(item.certificate.id), input.now);
  else
    // Expiry without a timely drain is a failure even once the sessions are gone: keep it visible
    // until an operator acknowledges it.
    await raiseAlert({
      severity: "critical",
      title: `Database client ${item.role}: certificate ${item.certificate.serial} was drained ${Math.ceil(((drainedAt?.getTime() ?? input.now.getTime()) - item.deadline.getTime()) / 1000)} s after its retirement deadline`,
      dedupKey: retirementAlertKey(item.certificate.id),
    });
  await auditEvent({
    action: "database.client_certificate_retired",
    databaseId: item.client.databaseId,
    operationId: input.operationId,
    detail: {
      clientId: item.client.id,
      role: item.role,
      certificateId: item.certificate.id,
      serial: item.certificate.serial,
      caId: item.certificate.caId,
      notAfter: item.certificate.notAfter.toISOString(),
      deadline: item.deadline.toISOString(),
      deadlineMissed: missed,
      timeline: input.timeline,
    },
  });
  return { deadlineMissed: missed };
}

/** A failed attempt: keep the task open for retry, record the error and raise a critical alert. */
export async function failRetirement(
  item: DueRetirement,
  input: { now: Date; error: string; timeline?: RetirementTimelineRecord },
) {
  const missed = input.now.getTime() > item.deadline.getTime();
  await db
    .update(clientCertificateRetirements)
    .set({
      leaseUntil: sql`${input.now.toISOString()}::timestamptz + make_interval(secs => LEAST(power(2, LEAST(${clientCertificateRetirements.attempts}, 9)), 300)::int)`,
      lastError: input.error.slice(0, 1000),
      ...(missed ? { deadlineMissed: true } : {}),
      ...(input.timeline?.fencedAt ? { fencedAt: at(input.timeline.fencedAt) } : {}),
      ...(input.timeline?.reloadedAt ? { reloadedAt: at(input.timeline.reloadedAt) } : {}),
      evidence: input.timeline ?? {},
      updatedAt: input.now,
    })
    .where(eq(clientCertificateRetirements.certificateId, item.certificate.id));
  await raiseAlert({
    severity: "critical",
    title: missed
      ? `Database client ${item.role}: certificate ${item.certificate.serial} expired but its sessions were not drained by the deadline; retrying`
      : `Database client ${item.role}: draining the retiring certificate ${item.certificate.serial} failed; retrying`,
    dedupKey: retirementAlertKey(item.certificate.id),
  });
  return { deadlineMissed: missed };
}

/** Open retirement tasks past their deadline: the watchdog's work list. */
export async function overdueRetirements(now: Date) {
  await db
    .update(clientCertificateRetirements)
    .set({
      completedAt: now,
      leaseUntil: null,
      updatedAt: now,
      evidence: { cancelled: "client revocation drained sessions" },
    })
    .where(
      and(
        isNull(clientCertificateRetirements.completedAt),
        sql`${clientCertificateRetirements.clientId} IN (SELECT id FROM database_clients WHERE revocation_completed_at IS NOT NULL)`,
      ),
    );
  return db
    .select()
    .from(clientCertificateRetirements)
    .where(
      and(isNull(clientCertificateRetirements.completedAt), lt(clientCertificateRetirements.deadline, now)),
    );
}

export async function recordWatchdog(
  certificateId: string,
  now: Date,
  evidence: Record<string, unknown>,
  succeeded = true,
) {
  await db
    .update(clientCertificateRetirements)
    .set({
      watchdogAt: succeeded ? now : null,
      deadlineMissed: true,
      evidence: sql`${clientCertificateRetirements.evidence} || ${JSON.stringify({ watchdog: evidence })}::jsonb`,
      updatedAt: now,
    })
    .where(eq(clientCertificateRetirements.certificateId, certificateId));
}
