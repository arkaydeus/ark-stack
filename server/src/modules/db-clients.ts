// Database clients: issuance, one-time reveal and revocation (docs/design/front-door.md §3.10.3,
// §3.10.4, §3.12, ticket FD-17).
//
// One client is one app environment of one public database. Issuance (database worker,
// `database.client_issue`) creates a fresh `db-client` CA generation, a 90-day certificate (Ark
// generates the key, or signs a submitted CSR), a login role `<db>_<client>_<env>` IN ROLE the
// runtime or readonly group with its own sealed password, and then reloads PgBouncer so the role
// joins `[users]` and the CA joins the trust bundle. The owner reveals the bundle exactly once.
//
// Revocation (`database.client_revoke`) marks the client, its certificates and its CA
// generations revoked (so the bundle drops them), rotates the role's password to one nobody sees
// with NOLOGIN, reloads PgBouncer and then kills the role's live sessions; the coordinator does
// the last two steps (reload and KILL_CLIENT) because they share the admin socket.
//
// Secrets: the client key and role password are sealed in `secrets`; the key is deleted at reveal
// and the password is never returned again. Nothing here logs, audits or records key, password
// or PEM material; audit details carry IDs, names, serials and fingerprints only.

import {
  DB_CLIENT_CONNECTION_LIMITS,
  clientGroupRole,
  clientRoleName,
  createId,
  databaseClientGuide,
  decryptSecret,
  encryptSecret,
  generatePassword,
  redactValue,
  regionSummary,
  planHash,
  isInFlight,
  type DbClientRoleKind,
} from "@ark-stack/shared";
import { and, asc, eq, inArray, isNull, isNotNull, lt, desc, sql } from "drizzle-orm";

import { db } from "../db.ts";
import { loadEnv } from "../env.ts";
import {
  auditEvents,
  clientIssueLimits,
  operations,
  clientCertificates,
  databaseClients,
  databaseClusters,
  databaseRoles,
  endpoints,
  managedDatabases,
  platformSettings,
  privateCas,
  secrets,
} from "../schema.ts";
import { appRoleExists, applyClientRole, revokeClientRole } from "./database.ts";
import * as pki from "./pki.ts";

/** Sealed password of a client login role. Revealed once with the bundle; never deleted while active. */
export const CLIENT_PASSWORD_SECRET_KIND = "postgres.client";
/** Role kind recorded in `database_roles` for client login roles (never `runtime`/`readonly`). */
export const CLIENT_ROLE_KIND = "client";

/** A refusal with the HTTP status the API should report. Messages carry no secret material. */
export class DatabaseClientError extends Error {
  override name = "DatabaseClientError";
  readonly status: 404 | 409 | 422;
  constructor(status: 404 | 409 | 422, message: string) {
    super(message);
    this.status = status;
  }
}

type ClientRow = typeof databaseClients.$inferSelect;
type CertificateRow = typeof clientCertificates.$inferSelect;

function sealing() {
  const env = loadEnv();
  return { rootKey: env.rootKey, rootKeyId: env.rootKeyId };
}

export async function auditEvent(input: {
  actorId?: string | null;
  action: string;
  databaseId: string;
  operationId?: string;
  role?: string;
  detail: Record<string, unknown>;
}) {
  await db.insert(auditEvents).values({
    id: createId("aud"),
    actorId: input.actorId ?? null,
    action: input.action,
    resourceType: "database",
    resourceId: input.databaseId,
    role: input.role,
    operationId: input.operationId,
    detail: redactValue(input.detail) as Record<string, unknown>,
  });
}

/** The public database, its endpoint hostname, and the platform region (for Vercel `regions`). */
export async function databaseClientContext(databaseId: string, executor: Pick<typeof db, "select"> = db) {
  const [database] = await executor
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, databaseId));
  if (!database) throw new DatabaseClientError(404, "Database not found.");
  const [cluster] = await executor
    .select()
    .from(databaseClusters)
    .where(eq(databaseClusters.id, database.clusterId));
  const [endpoint] = cluster?.endpointId
    ? await executor.select().from(endpoints).where(eq(endpoints.id, cluster.endpointId))
    : (await executor.select().from(endpoints).where(eq(endpoints.kind, "database"))).slice(0, 1);
  const [settings] = await executor.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  return {
    database,
    host: endpoint?.hostname ?? "<database hostname>",
    region: regionSummary(settings ?? null).region,
  };
}

/** One recursive query for all connected generations, including cross-CA rollovers. */
export async function loadLinkedCertificates(caIds: string[], executor: Pick<typeof db, "select"> = db) {
  if (!caIds.length) return [];
  return executor.select().from(clientCertificates).where(sql`${clientCertificates.id} IN (
    WITH RECURSIVE linked AS (
      SELECT id, superseded_by FROM client_certificates WHERE ${inArray(clientCertificates.caId, caIds)}
      UNION
      SELECT c.id, c.superseded_by FROM client_certificates c JOIN linked l
        ON c.id = l.superseded_by OR c.superseded_by = l.id
    ) SELECT id FROM linked
  )`);
}

/** The certificates of the chain through `caId`, oldest first (rollovers cross CAs). */
export function certificateChain(caId: string, rows: CertificateRow[]) {
  const byId = new Map(rows.map((row) => [row.id, row]));
  const predecessors = new Map<string, CertificateRow[]>();
  for (const row of rows)
    if (row.supersededBy) {
      const previous = predecessors.get(row.supersededBy) ?? [];
      previous.push(row);
      predecessors.set(row.supersededBy, previous);
    }
  const seen = new Map<string, CertificateRow>();
  const todo = rows.filter((row) => row.caId === caId);
  while (todo.length) {
    const row = todo.pop()!;
    if (seen.has(row.id)) continue;
    seen.set(row.id, row);
    if (row.supersededBy && byId.has(row.supersededBy)) todo.push(byId.get(row.supersededBy)!);
    todo.push(...(predecessors.get(row.id) ?? []));
  }
  return [...seen.values()].toSorted((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
}

export async function linkedCertificates(
  client: Pick<ClientRow, "caId">,
  executor: Pick<typeof db, "select"> = db,
) {
  return certificateChain(client.caId, await loadLinkedCertificates([client.caId], executor));
}

/** The certificate a client connects with now: its current (or newest issued) generation. */
function currentCertificate(certificates: CertificateRow[]) {
  const issued = certificates.filter((row) => row.status === "issued");
  return (
    issued.findLast((row) => row.rolloverState === "current" || row.rolloverState === "delivered") ??
    issued.at(-1) ??
    certificates.at(-1) ??
    null
  );
}

export type DatabaseClientSummary = {
  id: string;
  databaseId: string;
  name: string;
  environment: string;
  roleKind: DbClientRoleKind;
  readOnly: boolean;
  role: string;
  status: "provisioning" | "active" | "revoked";
  revocationCompletedAt: Date | null;
  keySource: "generated" | "csr";
  revealed: boolean;
  revealedAt: Date | null;
  revocationRequested: boolean;
  revokedAt: Date | null;
  createdAt: Date;
  certificates: Array<{
    id: string;
    caId: string;
    serial: string;
    fingerprintSha256: string;
    notBefore: Date;
    notAfter: Date;
    status: string;
    rolloverState: string;
  }>;
};

/** Inventory view: names, states, serials and fingerprints. No PEM, key, password or secret ID. */
export async function listDatabaseClients(
  databaseId: string,
  executor: Pick<typeof db, "select"> = db,
): Promise<DatabaseClientSummary[]> {
  const rows = await executor
    .select()
    .from(databaseClients)
    .where(eq(databaseClients.databaseId, databaseId))
    .orderBy(asc(databaseClients.createdAt), asc(databaseClients.id));
  const roleRows = rows.length
    ? await executor
        .select({ id: databaseRoles.id, name: databaseRoles.name })
        .from(databaseRoles)
        .where(
          inArray(
            databaseRoles.id,
            rows.map((row) => row.roleId),
          ),
        )
    : [];
  const allCertificates = await loadLinkedCertificates(
    rows.map((row) => row.caId),
    executor,
  );
  const summaries: DatabaseClientSummary[] = [];
  for (const row of rows) {
    const certificates = certificateChain(row.caId, allCertificates);
    summaries.push({
      id: row.id,
      databaseId: row.databaseId,
      name: row.name,
      environment: row.environment,
      roleKind: row.roleKind,
      readOnly: row.roleKind === "readonly",
      role: roleRows.find((role) => role.id === row.roleId)?.name ?? "",
      status: row.status === "active" && !row.issuedAt ? "provisioning" : row.status,
      revocationCompletedAt: row.revocationCompletedAt,
      keySource: row.keySource,
      revealed: row.revealedAt !== null,
      revealedAt: row.revealedAt,
      revocationRequested: row.revokedAt !== null,
      revokedAt: row.revokedAt,
      createdAt: row.createdAt,
      certificates: certificates.map((item) => ({
        id: item.id,
        caId: item.caId,
        serial: item.serial,
        fingerprintSha256: item.fingerprintSha256,
        notBefore: item.notBefore,
        notAfter: item.notAfter,
        status: item.status,
        rolloverState: item.rolloverState,
      })),
    });
  }
  return summaries;
}

export async function getDatabaseClient(
  databaseId: string,
  clientId: string,
  executor: Pick<typeof db, "select"> = db,
) {
  const [row] = await executor
    .select()
    .from(databaseClients)
    .where(and(eq(databaseClients.id, clientId), eq(databaseClients.databaseId, databaseId)));
  return row ?? null;
}

/**
 * Checks shared by the API (before enqueueing) and the worker (before creating anything): the
 * database is public, the role name is valid and free in Ark and in the cluster, and the
 * name/environment pair is unused (revoked clients keep their names).
 */
export async function planDatabaseClient(
  input: { databaseId: string; name: string; environment: string },
  executor: Pick<typeof db, "select"> = db,
) {
  const { database } = await databaseClientContext(input.databaseId, executor);
  if (database.exposure !== "public")
    throw new DatabaseClientError(
      409,
      "Database clients connect through the public PgBouncer; this database is private.",
    );
  const role = clientRoleName(database.name, input.name, input.environment);
  const [existing] = await executor
    .select({ id: databaseClients.id, status: databaseClients.status })
    .from(databaseClients)
    .where(
      and(
        eq(databaseClients.databaseId, input.databaseId),
        eq(databaseClients.name, input.name),
        eq(databaseClients.environment, input.environment),
      ),
    );
  if (existing)
    throw new DatabaseClientError(
      409,
      existing.status === "revoked"
        ? `${input.name}/${input.environment} was revoked; issue the new client under another name.`
        : `${input.name}/${input.environment} already exists for this database.`,
    );
  const [taken] = await executor
    .select({ id: databaseRoles.id })
    .from(databaseRoles)
    .where(eq(databaseRoles.name, role));
  if (taken) throw new DatabaseClientError(409, `The login role ${role} is already in use.`);
  return { database, role };
}

export type IssueDatabaseClientInput = {
  clientId: string;
  databaseId: string;
  name: string;
  environment: string;
  roleKind: DbClientRoleKind;
  csrPem?: string;
  actorId?: string | null;
  now?: Date;
};

/**
 * `database.client_issue` (database worker), idempotent on `clientId`: a retry after a partial
 * run only re-applies the cluster role. The caller reloads PgBouncer afterwards.
 */
export async function issueDatabaseClient(input: IssueDatabaseClientInput, applyRole = applyClientRole) {
  const { rootKey, rootKeyId } = sealing();
  const [existing] = await db.select().from(databaseClients).where(eq(databaseClients.id, input.clientId));
  if (existing) {
    if (existing.databaseId !== input.databaseId) throw new Error("Client ID belongs to another database.");
    if (existing.status !== "active" || existing.revokedAt)
      throw new DatabaseClientError(409, "The client was revoked.");
    const [role] = await db.select().from(databaseRoles).where(eq(databaseRoles.id, existing.roleId));
    const [secret] = role?.secretId
      ? await db.select().from(secrets).where(eq(secrets.id, role.secretId))
      : [];
    if (!role || !secret) throw new Error("The client role or its sealed password is missing.");
    const { database } = await databaseClientContext(input.databaseId);
    await applyRole({
      role: role.name,
      group: clientGroupRole(database.name, existing.roleKind),
      password: decryptSecret(rootKey, secret),
      connectionLimit: role.connectionLimit,
    });
    const certificate = currentCertificate(await linkedCertificates(existing));
    return { client: existing, role: role.name, certificate, created: false };
  }

  const { database, role } = await planDatabaseClient(input);
  if (await appRoleExists(role))
    throw new DatabaseClientError(409, `A PostgreSQL role named ${role} already exists in the cluster.`);
  // Validate the CSR before creating anything, so a refused request leaves no CA behind.
  if (input.csrPem !== undefined) pki.validateCsr(input.csrPem);

  const ca = await pki.createPrivateCa({
    purpose: "db-client",
    name: `${input.name}/${input.environment}`,
    now: input.now,
  });
  let certificateId: string | null = null;
  try {
    const issued = await pki.issueClientCertificate({
      caId: ca.id,
      subjectCn: role,
      csrPem: input.csrPem,
      keyOwner:
        input.csrPem === undefined ? { resourceType: "database", resourceId: input.databaseId } : undefined,
      rolloverState: "current",
      now: input.now,
    });
    certificateId = issued.certificate.id;
    const password = generatePassword();
    const connectionLimit = DB_CLIENT_CONNECTION_LIMITS[input.roleKind];
    const roleId = createId("role");
    const secretId = createId("sec");
    const client = await db.transaction(async (tx) => {
      await tx.insert(secrets).values({
        id: secretId,
        kind: CLIENT_PASSWORD_SECRET_KIND,
        resourceType: "database",
        resourceId: input.databaseId,
        purpose: "db-client",
        sensitivity: "credential",
        once: true,
        ...encryptSecret(rootKey, password, rootKeyId),
      });
      await tx.insert(databaseRoles).values({
        id: roleId,
        databaseId: input.databaseId,
        name: role,
        kind: CLIENT_ROLE_KIND,
        secretId,
        connectionLimit,
      });
      const [row] = await tx
        .insert(databaseClients)
        .values({
          id: input.clientId,
          databaseId: input.databaseId,
          name: input.name,
          environment: input.environment,
          roleKind: input.roleKind,
          roleId,
          caId: ca.id,
          status: "active",
          issuedAt: null,
          keySource: input.csrPem === undefined ? "generated" : "csr",
          createdBy: input.actorId ?? null,
          ...(input.now ? { createdAt: input.now } : {}),
        })
        .returning();
      return row!;
    });
    await applyRole({
      role,
      group: clientGroupRole(database.name, input.roleKind),
      password,
      connectionLimit,
    });
    const [certificate] = await db
      .select()
      .from(clientCertificates)
      .where(eq(clientCertificates.id, issued.certificate.id));
    return { client, role, certificate: certificate ?? null, created: true };
  } catch (error) {
    // Nothing links an orphaned generation into the bundle, but retire it explicitly anyway.
    const [linked] = await db
      .select({ id: databaseClients.id })
      .from(databaseClients)
      .where(eq(databaseClients.caId, ca.id));
    if (!linked) {
      if (certificateId)
        await pki.revokeClientCertificate({ id: certificateId, reason: "cessationOfOperation" });
      await pki.setPrivateCaStatus(ca.id, "revoked");
    }
    throw error;
  }
}

/** Audit/step evidence for an issued client. IDs, names, serial and fingerprint only. */
export function issueEvidence(result: Awaited<ReturnType<typeof issueDatabaseClient>>) {
  return {
    clientId: result.client.id,
    role: result.role,
    environment: result.client.environment,
    roleKind: result.client.roleKind,
    keySource: result.client.keySource,
    caId: result.client.caId,
    certificateId: result.certificate?.id ?? null,
    serial: result.certificate?.serial ?? null,
    fingerprintSha256: result.certificate?.fingerprintSha256 ?? null,
    notAfter: result.certificate?.notAfter.toISOString() ?? null,
    created: result.created,
  };
}

export async function auditIssued(
  result: Awaited<ReturnType<typeof issueDatabaseClient>>,
  input: { actorId?: string | null; operationId: string },
) {
  await auditEvent({
    actorId: input.actorId,
    action: "database.client_issued",
    databaseId: result.client.databaseId,
    operationId: input.operationId,
    detail: issueEvidence(result),
  });
}

/** Durable sliding window, serialized across API processes and pruned on every request. */
export async function consumeClientIssueAttempt(userId: string, now = new Date(), executor = db) {
  return executor.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`client-rate:${userId}`}))`);
    await tx
      .delete(clientIssueLimits)
      .where(lt(clientIssueLimits.updatedAt, new Date(now.getTime() - 600_000)));
    const [row] = await tx.select().from(clientIssueLimits).where(eq(clientIssueLimits.userId, userId));
    const attempts = (row?.attempts ?? []).filter((at) => now.getTime() - at < 600_000);
    if (attempts.length >= 10) return false;
    attempts.push(now.getTime());
    await tx
      .insert(clientIssueLimits)
      .values({ userId, attempts, updatedAt: now })
      .onConflictDoUpdate({ target: clientIssueLimits.userId, set: { attempts, updatedAt: now } });
    return true;
  });
}

/** Queue intent and metadata atomically; failed attempts reuse the original client identity. */
export async function queueClientIssue(
  input: Omit<IssueDatabaseClientInput, "clientId" | "now"> & { actorId: string },
) {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`client-queue:${input.databaseId}`}))`);
    const [previous] = await tx
      .select()
      .from(operations)
      .where(
        and(
          eq(operations.kind, "database.client_issue"),
          sql`${operations.targetIds} @> ${JSON.stringify([input.databaseId])}::jsonb`,
          sql`${operations.payload}->>'name' = ${input.name}`,
          sql`${operations.payload}->>'environment' = ${input.environment}`,
        ),
      )
      .orderBy(desc(operations.createdAt))
      .limit(1);
    const payload = {
      name: input.name,
      environment: input.environment,
      roleKind: input.roleKind,
      ...(input.csrPem === undefined ? {} : { csrPem: input.csrPem }),
    };
    let clientId = createId("dbc");
    const { database } = await databaseClientContext(input.databaseId, tx);
    const role = clientRoleName(database.name, input.name, input.environment);
    if (previous) {
      if (isInFlight(previous.status) || !["failed", "needs_recovery"].includes(previous.status))
        throw new DatabaseClientError(409, "This client already exists or issuance is in progress.");
      const { clientId: priorId, ...priorPayload } = previous.payload as Record<string, unknown>;
      if (planHash(priorPayload) !== planHash(payload))
        throw new DatabaseClientError(409, "Retry issuance with the original request settings.");
      clientId = String(priorId);
      const client = await getDatabaseClient(input.databaseId, clientId, tx);
      if (client && (client.revokedAt || client.status === "revoked" || client.issuedAt))
        throw new DatabaseClientError(409, "The client was already issued or revoked.");
    } else await planDatabaseClient(input, tx);
    const [operation] = await tx
      .insert(operations)
      .values({
        id: createId("op"),
        kind: "database.client_issue",
        actorId: input.actorId,
        targetIds: [input.databaseId],
        payload: { clientId, ...payload },
        idempotencyKey: createId("client-issue"),
        planHash: planHash({ clientId, ...payload }),
        status: "queued",
      })
      .returning();
    return { clientId, role, operation: operation! };
  });
}

export async function queueClientRevocation(input: {
  databaseId: string;
  clientId: string;
  actorId: string;
}) {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`client-queue:${input.databaseId}`}))`);
    const [client] = await tx
      .select()
      .from(databaseClients)
      .where(and(eq(databaseClients.id, input.clientId), eq(databaseClients.databaseId, input.databaseId)))
      .for("update");
    if (!client) throw new DatabaseClientError(404, "Database client not found.");
    if (client.revocationCompletedAt) throw new DatabaseClientError(409, "This client is already revoked.");
    const prior = await tx
      .select()
      .from(operations)
      .where(
        and(
          eq(operations.kind, "database.client_revoke"),
          sql`${operations.payload}->>'clientId' = ${input.clientId}`,
        ),
      );
    if (prior.some((op) => isInFlight(op.status)))
      throw new DatabaseClientError(409, "Revocation is already in progress.");
    // Do not let a failed issuance be resumed while its revocation is queued.
    const issueOps = await tx
      .select()
      .from(operations)
      .where(
        and(
          eq(operations.kind, "database.client_issue"),
          sql`${operations.payload}->>'clientId' = ${input.clientId}`,
        ),
      );
    if (issueOps.some((op) => isInFlight(op.status)))
      throw new DatabaseClientError(409, "Issuance is still in progress.");
    await tx
      .update(databaseClients)
      .set({ revokedAt: client.revokedAt ?? new Date(), revokedBy: client.revokedBy ?? input.actorId })
      .where(eq(databaseClients.id, input.clientId));
    const payload = { clientId: input.clientId };
    const [operation] = await tx
      .insert(operations)
      .values({
        id: createId("op"),
        kind: "database.client_revoke",
        actorId: input.actorId,
        targetIds: [input.databaseId, input.clientId],
        payload,
        idempotencyKey: createId("client-revoke"),
        planHash: planHash(payload),
        status: "queued",
      })
      .returning();
    return operation!;
  });
}

/**
 * `database.client_revoke` steps 1-2 (§3.10.4): mark the client, all its certificates and CA
 * generations revoked (destroying any unrevealed key), then rotate the role password to a fresh
 * one nobody sees, with NOLOGIN, and terminate its cluster backends. Idempotent. The caller then
 * reloads PgBouncer without the role and its CAs, and kills the role's PgBouncer sessions.
 */
export async function revokeDatabaseClient(
  input: {
    databaseId: string;
    clientId: string;
    actorId?: string | null;
    now?: Date;
  },
  revokeRole = revokeClientRole,
) {
  const { rootKey, rootKeyId } = sealing();
  const client = await getDatabaseClient(input.databaseId, input.clientId);
  if (!client) throw new DatabaseClientError(404, "Database client not found.");
  const [role] = await db.select().from(databaseRoles).where(eq(databaseRoles.id, client.roleId));
  if (!role) throw new Error("The client's login role row is missing.");
  const now = input.now ?? new Date();
  const certificates = await linkedCertificates(client);
  const caIds = [...new Set([client.caId, ...certificates.map((item) => item.caId)])];
  await db
    .update(databaseClients)
    .set({
      status: "revoked",
      revokedAt: client.revokedAt ?? now,
      revokedBy: client.revokedBy ?? input.actorId ?? null,
    })
    .where(eq(databaseClients.id, client.id));
  for (const certificate of certificates) {
    await pki.revokeClientCertificate({ id: certificate.id, reason: "cessationOfOperation", now });
  }
  for (const caId of caIds) await pki.setPrivateCaStatus(caId, "revoked");

  const password = generatePassword();
  const cluster = await revokeRole({ role: role.name, password });
  const secretId = createId("sec");
  await db.transaction(async (tx) => {
    await tx.insert(secrets).values({
      id: secretId,
      kind: `${CLIENT_PASSWORD_SECRET_KIND}.revoked`,
      resourceType: "database",
      resourceId: input.databaseId,
      purpose: "db-client",
      sensitivity: "credential",
      once: true,
      revealedAt: now, // never revealable: nobody needs this password
      ...encryptSecret(rootKey, password, rootKeyId),
    });
    await tx.update(databaseRoles).set({ secretId }).where(eq(databaseRoles.id, role.id));
    if (role.secretId) await tx.delete(secrets).where(eq(secrets.id, role.secretId));
  });
  return {
    clientId: client.id,
    role: role.name,
    certificateIds: certificates.map((item) => item.id),
    serials: certificates.map((item) => item.serial),
    caIds,
    roleRotated: true,
    clusterRoleExisted: cluster.existed,
  };
}

export async function auditRevoked(
  result: Awaited<ReturnType<typeof revokeDatabaseClient>> & { killed?: number | null },
  input: { databaseId: string; actorId?: string | null; operationId: string },
) {
  await auditEvent({
    actorId: input.actorId,
    action: "database.client_revoked",
    databaseId: input.databaseId,
    operationId: input.operationId,
    detail: result,
  });
}

/**
 * The one-time reveal. Atomically claims the client's reveal (a second call fails), deletes the
 * sealed generated key, and returns the certificate, key, password, CA-verified server settings
 * and the filled-in Vercel guide. The audit row is written in the same transaction and carries
 * no secret material.
 */
export async function revealDatabaseClient(input: {
  databaseId: string;
  clientId: string;
  actorId: string;
  actorRole: string;
}) {
  const { rootKey } = sealing();
  const context = await databaseClientContext(input.databaseId);
  return db.transaction(async (tx) => {
    const [client] = await tx
      .update(databaseClients)
      .set({ revealedAt: new Date() })
      .where(
        and(
          eq(databaseClients.id, input.clientId),
          eq(databaseClients.databaseId, input.databaseId),
          eq(databaseClients.status, "active"),
          isNotNull(databaseClients.issuedAt),
          isNull(databaseClients.revealedAt),
          isNull(databaseClients.revokedAt),
        ),
      )
      .returning();
    if (!client) {
      const [current] = await tx
        .select()
        .from(databaseClients)
        .where(and(eq(databaseClients.id, input.clientId), eq(databaseClients.databaseId, input.databaseId)));
      if (!current) throw new DatabaseClientError(404, "Database client not found.");
      if (!current.issuedAt)
        throw new DatabaseClientError(409, "Client issuance has not completed; retry issuance first.");
      if (current.status !== "active" || current.revokedAt)
        throw new DatabaseClientError(409, "This client was revoked; its credentials cannot be revealed.");
      throw new DatabaseClientError(
        409,
        "This client's credentials were already revealed. Revoke it and issue a new client to obtain new ones.",
      );
    }
    const [role] = await tx.select().from(databaseRoles).where(eq(databaseRoles.id, client.roleId));
    const [passwordSecret] = role?.secretId
      ? await tx.select().from(secrets).where(eq(secrets.id, role.secretId))
      : [];
    if (!role || !passwordSecret) throw new Error("The client role or its sealed password is missing.");
    // The password stays sealed for PgBouncer's userlist; it is marked revealed, never returned again.
    await tx.update(secrets).set({ revealedAt: new Date() }).where(eq(secrets.id, passwordSecret.id));
    const certificate = currentCertificate(
      (await tx.select().from(clientCertificates).where(eq(clientCertificates.caId, client.caId))).toSorted(
        (a, b) => a.createdAt.getTime() - b.createdAt.getTime(),
      ),
    );
    if (!certificate?.certPem || certificate.status !== "issued")
      throw new Error("The client has no issued certificate to reveal.");
    let keyPem: string | null = null;
    if (certificate.keySecretId) {
      const [keySecret] = await tx.select().from(secrets).where(eq(secrets.id, certificate.keySecretId));
      if (!keySecret || keySecret.kind !== pki.CLIENT_KEY_SECRET_KIND)
        throw new Error("The client's sealed key is missing.");
      keyPem = decryptSecret(rootKey, keySecret);
      // §3.10.1: the plaintext key is deleted from storage after the reveal.
      await tx
        .update(clientCertificates)
        .set({ keySecretId: null })
        .where(eq(clientCertificates.id, certificate.id));
      await tx.delete(secrets).where(eq(secrets.id, keySecret.id));
    } else if (client.keySource === "generated") {
      throw new Error("The client's generated key is no longer stored.");
    }
    const [ca] = await tx
      .select({ certPem: privateCas.certPem })
      .from(privateCas)
      .where(eq(privateCas.id, client.caId));
    await tx.insert(auditEvents).values({
      id: createId("aud"),
      actorId: input.actorId,
      action: "database.client_reveal",
      resourceType: "database",
      resourceId: input.databaseId,
      role: input.actorRole,
      detail: {
        clientId: client.id,
        role: role.name,
        certificateId: certificate.id,
        serial: certificate.serial,
        fingerprintSha256: certificate.fingerprintSha256,
        keySource: client.keySource,
        keyDeleted: keyPem !== null,
      },
    });
    const password = decryptSecret(rootKey, passwordSecret);
    const guide = databaseClientGuide({
      host: context.host,
      database: context.database.name,
      role: role.name,
      environment: client.environment,
      roleKind: client.roleKind,
      region: context.region,
      secrets: { password, certPem: certificate.certPem, keyPem },
    });
    return {
      clientId: client.id,
      name: client.name,
      environment: client.environment,
      roleKind: client.roleKind,
      readOnly: client.roleKind === "readonly",
      role: role.name,
      password,
      certificate: {
        id: certificate.id,
        pem: certificate.certPem,
        serial: certificate.serial,
        fingerprintSha256: certificate.fingerprintSha256,
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
      },
      privateKey: keyPem,
      keySource: client.keySource,
      clientCaPem: ca?.certPem ?? null,
      server: {
        host: context.host,
        port: 5432,
        database: context.database.name,
        user: role.name,
        sslmode: "verify-full",
        tlsMinVersion: "TLSv1.3",
        serverName: context.host,
        serverCertificate:
          "Publicly trusted (Let's Encrypt): verify it with the system trust store, no custom CA.",
      },
      vercel: guide,
    };
  });
}

/** The placeholder guide (`GET .../vercel`): names, commands and snippets, no secrets. */
export async function databaseClientVercelGuide(databaseId: string, clientId: string) {
  const context = await databaseClientContext(databaseId);
  const client = await getDatabaseClient(databaseId, clientId);
  if (!client) throw new DatabaseClientError(404, "Database client not found.");
  const [role] = await db
    .select({ name: databaseRoles.name })
    .from(databaseRoles)
    .where(eq(databaseRoles.id, client.roleId));
  return {
    clientId: client.id,
    status: client.status,
    ...databaseClientGuide({
      host: context.host,
      database: context.database.name,
      role: role?.name ?? "",
      environment: client.environment,
      roleKind: client.roleKind,
      region: context.region,
    }),
  };
}
