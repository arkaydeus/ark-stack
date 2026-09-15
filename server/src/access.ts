import {
  assertPrivileged,
  canManageDomain,
  canViewDomain,
  canViewProject,
  hasMfaAssurance,
  type Access,
  type PrivilegedAction,
} from "@ark-stack/shared";
import { eq } from "drizzle-orm";
import { HTTPException } from "hono/http-exception";

import { db, sql } from "./db.ts";
import { databaseClusters, endpoints, mailboxes, managedDatabases } from "./schema.ts";

export type SessionValue = {
  user: { id: string; name: string; email: string; twoFactorEnabled?: boolean; mfaEnrolledAt?: Date | null };
  session: { id: string; createdAt: Date; updatedAt?: Date };
};

export function requireOperator(access: Access) {
  if (access.role !== "owner" && access.role !== "operator") {
    throw new HTTPException(403, { message: "Operator access is required." });
  }
}

export function requireMfa(session: SessionValue) {
  if (
    !hasMfaAssurance({
      twoFactorEnabled: Boolean(session.user.twoFactorEnabled),
      mfaEnrolledAt: session.user.mfaEnrolledAt ?? null,
      sessionCreatedAt: new Date(session.session.createdAt),
    })
  ) {
    throw new HTTPException(403, { message: "Enroll and verify administrator MFA before making changes." });
  }
}

export async function consumePrivilegedGrant(input: {
  userId: string;
  sessionId: string;
  action: PrivilegedAction;
  expectedPlanHash: string;
}) {
  const rows = await sql`
    UPDATE step_up_grants
    SET consumed_at = now()
    WHERE id = (
      SELECT id FROM step_up_grants
      WHERE user_id = ${input.userId}
        AND session_id = ${input.sessionId}
        AND action = ${input.action}
        AND plan_hash = ${input.expectedPlanHash}
        AND expires_at > now()
        AND consumed_at IS NULL
      ORDER BY created_at DESC
      LIMIT 1
      FOR UPDATE
    )
    AND consumed_at IS NULL
    AND expires_at > now()
    RETURNING *
  `;
  return rows[0] ?? null;
}

export async function requirePrivileged(
  access: Access,
  session: SessionValue,
  action: PrivilegedAction,
  expectedPlanHash: string,
) {
  requireOperator(access);
  requireMfa(session);
  if (!expectedPlanHash) {
    throw new HTTPException(403, {
      message: `Verify your password and MFA for ${action} before continuing.`,
    });
  }
  const grant = await consumePrivilegedGrant({
    userId: access.userId,
    sessionId: session.session.id,
    action,
    expectedPlanHash,
  });
  if (!grant) {
    throw new HTTPException(403, {
      message: `Verify your password and MFA for ${action} before continuing.`,
    });
  }
  try {
    assertPrivileged(access, action, new Date(grant.created_at as string | Date));
  } catch (error) {
    throw new HTTPException(403, {
      message:
        error instanceof Error ? error.message : "Re-authenticate to continue with this privileged action.",
    });
  }
  return grant;
}

export async function requireDomainMailbox(domainId: string) {
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.domainId, domainId)).limit(1);
  if (!mailbox) {
    throw new HTTPException(409, {
      message: "Create a mailbox on this domain before changing native mail aliases.",
    });
  }
  return mailbox;
}

export function requireProject(access: Access, projectId: string) {
  if (!canViewProject(access, projectId)) {
    throw new HTTPException(403, { message: "You do not have access to this project." });
  }
}

export function requireDomain(access: Access, domainId: string, mode: "view" | "manage" = "view") {
  const allowed = mode === "manage" ? canManageDomain(access, domainId) : canViewDomain(access, domainId);
  if (!allowed) throw new HTTPException(403, { message: "You do not have access to this domain." });
}

/**
 * Appends in SQL rather than read-modify-write: two concurrent creates by the same user (two
 * `POST /api/projects` in flight) would otherwise each write back the array they read and drop
 * one of the grants.
 */
export async function grantAccess(userId: string, grant: { projectId?: string; domainId?: string }) {
  if (grant.projectId) {
    await sql`
      UPDATE platform_access
      SET project_ids = project_ids || to_jsonb(${grant.projectId}::text)
      WHERE user_id = ${userId} AND NOT (project_ids ? ${grant.projectId})
    `;
  }
  if (grant.domainId) {
    await sql`
      UPDATE platform_access
      SET domain_ids = domain_ids || to_jsonb(${grant.domainId}::text)
      WHERE user_id = ${userId} AND NOT (domain_ids ? ${grant.domainId})
    `;
  }
}

export async function databaseScope(databaseId: string) {
  const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, databaseId));
  if (!database) return null;
  let domainId: string | null = null;
  const [cluster] = await db
    .select()
    .from(databaseClusters)
    .where(eq(databaseClusters.id, database.clusterId));
  if (cluster?.endpointId) {
    const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, cluster.endpointId));
    domainId = endpoint?.domainId ?? null;
  }
  return { database, projectId: database.projectId, domainId };
}

export async function requireDatabaseAccess(
  access: Access,
  databaseId: string,
  mode: "view" | "manage" = "view",
) {
  const scope = await databaseScope(databaseId);
  if (!scope) throw new HTTPException(404, { message: "Database not found." });
  if (scope.projectId) requireProject(access, scope.projectId);
  else if (scope.domainId) requireDomain(access, scope.domainId, mode);
  else if (access.role !== "owner") {
    throw new HTTPException(403, { message: "You do not have access to this database." });
  }
  return scope;
}

export function redactDomain<T extends { id: string; ownershipToken?: string }>(domain: T, access: Access) {
  if (access.role === "owner" || canManageDomain(access, domain.id)) return domain;
  const { ownershipToken: _token, ...rest } = domain;
  return rest;
}

export function visibleResourceIds(input: {
  access: Access;
  projectIds: string[];
  domainIds: string[];
  databaseIds: string[];
  serviceIds: string[];
  mailboxIds: string[];
}) {
  const ids = new Set<string>(["platform"]);
  for (const id of input.projectIds) if (canViewProject(input.access, id)) ids.add(id);
  for (const id of input.domainIds) if (canViewDomain(input.access, id)) ids.add(id);
  for (const id of input.databaseIds) ids.add(id);
  for (const id of input.serviceIds) ids.add(id);
  for (const id of input.mailboxIds) ids.add(id);
  return ids;
}
