import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";

import {
  assertAliasGraph,
  assertExternalForwarding,
  canTransition,
  canonicalizeComposeSource,
  canViewDomain,
  canViewProject,
  classifySql,
  createId,
  createToken,
  privilegedRequestHash,
  localPart,
  normalizeHostname,
  redactValue,
  secureEqual,
  adoptionPreview,
  assertCidrs,
  canMutateQueue,
  classifyDiscovery,
  clientAllowed,
  maintainInput,
  queueActionInput,
  deviceInput,
  cidrInput,
  adoptInput,
  redactQueueItem,
  validateComposeSource,
  wizardInput,
  domainInput,
  mailboxInput,
  aliasInput,
  databaseInput,
  projectInput,
  serviceInput,
  sqlInput,
  sqlCancelInput,
  settingsInput,
  regionSettingsInput,
  regionSummary,
  dbIngressCounterMetrics,
  dbIngressLimitsInput,
  dbIngressLimitsSummary,
  platformDbIngressLimits,
  buildDomainPlan,
  nextBackupStatus,
  redactLogLine,
  ValidationError,
  type Access,
  type BackupStatus,
  type OperationState,
  type Role,
} from "@ark-stack/shared";
import { serveStatic } from "@hono/node-server/serve-static";
import { and, desc, eq, isNull } from "drizzle-orm";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { HTTPException } from "hono/http-exception";
import { z } from "zod";

import { auth } from "./auth.ts";
import {
  assertSecretRevealable,
  grantAccess,
  redactDomain,
  requireDatabaseAccess,
  requireDomain,
  requireDomainMailbox,
  requireMfa,
  requireOperator,
  requireOwner,
  requirePrivileged,
  requireProject,
  type SessionValue,
} from "./access.ts";
import {
  assertExecutionAuthorized,
  claimQueued,
  enqueue,
  finalizeAgentCompletion,
  heartbeatClaim,
} from "./coordinator.ts";
import { db, sql } from "./db.ts";
import { loadEnv } from "./env.ts";
import { revealSecret } from "./coordinator.ts";
import { getChallenge } from "./modules/certificates.ts";
import { cancelWorkspaceQuery } from "./modules/database.ts";
import { writeApprovedCompose } from "./modules/docker.ts";
import { dbIngressCountersFile } from "./modules/providers.ts";
import { listMailQueue } from "./modules/queue.ts";
import {
  alerts,
  aliases,
  auditEvents,
  backups,
  certificates,
  databaseClusters,
  databaseRoles,
  dnsRecords,
  domainClaims,
  endpoints,
  mailDomains,
  mailboxes,
  mailboxDevices,
  managedDatabases,
  operationSteps,
  operations,
  platformAccess,
  platformSettings,
  platformSetup,
  projects,
  secrets,
  services,
  stepUpGrants,
  updateCandidates,
  user,
  workerHeartbeats,
} from "./schema.ts";

type AppEnv = {
  Variables: {
    session: SessionValue;
    access: Access;
    worker: string;
  };
};

const env = loadEnv();
export const app = new Hono<AppEnv>();

app.use("/api/*", bodyLimit({ maxSize: 256 * 1024 }));
app.onError((error, c) => {
  if (error instanceof HTTPException) return c.json({ error: error.message }, error.status);
  if (error instanceof z.ZodError) return c.json({ error: z.prettifyError(error) }, 422);
  // Better Auth surfaces its own failures (a wrong step-up password, for example) as APIError.
  // Reporting those as 500 hides an actionable message behind a generic one.
  if (isApiError(error)) {
    const status =
      error.status === 401
        ? 401
        : error.status === 403
          ? 403
          : error.status === 404
            ? 404
            : error.status === 409
              ? 409
              : error.status === 429
                ? 429
                : 422;
    return c.json({ error: redactLogLine(error.message) }, status);
  }
  // Input validators in shared/ reject with plain Errors. They describe a caller mistake, not a
  // server fault, so they belong in the response rather than only in the log.
  if (error instanceof ValidationError) return c.json({ error: error.message }, 422);
  console.error(error instanceof Error ? error.message : error);
  return c.json({ error: "The request could not be completed." }, 500);
});

const STEP_UP_MAX_FAILURES = 5;
const STEP_UP_LOCKOUT_MS = 15 * 60 * 1000;
const stepUpFailures = new Map<string, { count: number; firstAt: number }>();

function assertStepUpAttemptAllowed(userId: string) {
  const record = stepUpFailures.get(userId);
  if (!record) return;
  if (Date.now() - record.firstAt > STEP_UP_LOCKOUT_MS) {
    stepUpFailures.delete(userId);
    return;
  }
  if (record.count >= STEP_UP_MAX_FAILURES) {
    throw new HTTPException(429, {
      message: "Too many failed verification attempts. Wait before requesting another step-up grant.",
    });
  }
}

function recordStepUpFailure(userId: string) {
  const now = Date.now();
  const record = stepUpFailures.get(userId);
  if (!record || now - record.firstAt > STEP_UP_LOCKOUT_MS) {
    stepUpFailures.set(userId, { count: 1, firstAt: now });
    return;
  }
  record.count += 1;
}

function clearStepUpFailures(userId: string) {
  stepUpFailures.delete(userId);
}

function isApiError(error: unknown): error is Error & { status: number } {
  if (!(error instanceof Error) || !("status" in error)) return false;
  const status = (error as { status: unknown }).status;
  return typeof status === "number" && status >= 400 && status < 500;
}

app.get("/api/health", async (c) => {
  await sql`SELECT 1`;
  return c.json({ status: "ok" });
});

app.get("/.well-known/acme-challenge/:token", (c) => {
  const challenge = getChallenge(c.req.param("token"));
  if (!challenge) return c.text("not found", 404);
  return c.text(challenge.keyAuthorization);
});

app.get("/api/setup/status", async (c) => {
  const [setup] = await db.select().from(platformSetup).where(eq(platformSetup.id, "default"));
  return c.json({
    required: !setup?.completed,
    wizardRequired: Boolean(setup?.completed && !setup.wizardCompleted),
  });
});

app.post("/api/auth/sign-up/email", async (c) => {
  const connection = await sql.reserve();
  await connection`SELECT pg_advisory_lock(8042102)`;
  try {
    const [setup] = await connection`SELECT completed FROM platform_setup WHERE id='default'`;
    const [existing] = await connection`SELECT count(*)::int AS count FROM "user"`;
    if (!setup?.completed && existing.count) {
      await connection`INSERT INTO platform_access(user_id, role) SELECT id, 'owner' FROM "user" ON CONFLICT DO NOTHING`;
      await connection`UPDATE platform_setup SET completed=true, bootstrap_closed_at=now() WHERE id='default'`;
      throw new HTTPException(403, {
        message: "Setup is already complete. Sign in with the existing administrator.",
      });
    }
    if (setup?.completed || !secureEqual(c.req.header("x-setup-token") ?? "", env.setupToken)) {
      throw new HTTPException(403, { message: "Administrator setup is closed or the token is invalid." });
    }
    const response = await auth.handler(c.req.raw);
    if (response.ok) {
      await connection`INSERT INTO platform_access(user_id, role) SELECT id, 'owner' FROM "user" ON CONFLICT DO NOTHING`;
      await connection`UPDATE platform_setup SET completed=true, bootstrap_closed_at=now() WHERE id='default'`;
    }
    return response;
  } finally {
    await connection`SELECT pg_advisory_unlock(8042102)`;
    connection.release();
  }
});

app.all("/api/auth/*", async (c) => {
  const enrollmentVerification = c.req.path.endsWith("/two-factor/verify-totp");
  const sessionBefore = enrollmentVerification
    ? await auth.api.getSession({ headers: c.req.raw.headers })
    : null;
  const response = await auth.handler(c.req.raw);
  if (response.ok && enrollmentVerification && sessionBefore?.user.id) {
    const [verifiedUser] = await db.select().from(user).where(eq(user.id, sessionBefore.user.id));
    if (verifiedUser?.twoFactorEnabled && !verifiedUser.mfaEnrolledAt) {
      await sql`
        UPDATE "user"
        SET mfa_enrolled_at = (
          SELECT max(created_at) FROM session WHERE user_id = ${sessionBefore.user.id}
        ), updated_at = now()
        WHERE id = ${sessionBefore.user.id}
          AND two_factor_enabled = true
          AND mfa_enrolled_at IS NULL
      `;
    }
  }
  return response;
});

// `update.apply` belongs to the agent alone: its planning half delegates a compose payload and
// requeues, so a module worker holding the `update.` prefix would re-plan the same operation on
// every poll, minting a deployment revision each time. Module workers get `update.detect` only.
const workerPrefixes: Record<string, string[]> = {
  database: ["database.", "pgbouncer."],
  // `integration.` (front door §3.4): the domain worker is the only worker with external egress.
  domains: ["domain.", "dns.", "certificate.", "edge.", "admin.", "integration."],
  mail: ["mail.", "mailbox.", "ses."],
  backup: ["backup.", "update.detect", "import."],
  agent: ["service.", "update.apply"],
  module: [
    "database.",
    "pgbouncer.",
    "mail.",
    "mailbox.",
    "ses.",
    "domain.",
    "dns.",
    "certificate.",
    "edge.",
    "admin.",
    "backup.",
    "update.detect",
    "import.",
  ],
};

function workerCanExecute(identity: string, kind: string) {
  return (workerPrefixes[identity] ?? []).some((prefix) =>
    prefix.endsWith(".") ? kind.startsWith(prefix) : kind === prefix,
  );
}

app.use("/api/internal/*", async (c, next) => {
  const supplied = c.req.header("authorization") ?? "";
  let identity = "";
  if (secureEqual(supplied, `Bearer ${env.agentToken}`)) identity = "agent";
  else {
    for (const name of ["database", "domains", "mail", "backup"] as const) {
      if (
        process.env[`ARK_${name === "domains" ? "DOMAIN" : name.toUpperCase()}_WORKER_TOKEN`] &&
        secureEqual(supplied, `Bearer ${env.workerTokens[name]}`)
      ) {
        identity = name;
        break;
      }
    }
  }
  if (!identity && secureEqual(supplied, `Bearer ${env.internalToken}`)) identity = "module";
  if (!identity) throw new HTTPException(401, { message: "Invalid worker credential." });
  c.set("worker", identity);
  await next();
});

app.post("/api/internal/heartbeat", async (c) => {
  const body = z.object({ version: z.string().min(1).max(100) }).parse(await c.req.json());
  await db
    .insert(workerHeartbeats)
    .values({ identity: c.get("worker"), version: body.version, lastSeenAt: new Date() })
    .onConflictDoUpdate({
      target: workerHeartbeats.identity,
      set: { version: body.version, lastSeenAt: new Date() },
    });
  return c.json({ ok: true });
});

app.get("/api/internal/jobs", async (c) => {
  if (c.get("worker") === "agent") {
    const claimed = await claimQueued({ limit: 1, agentOwned: true });
    const authorized = [];
    for (const row of claimed.rows) {
      try {
        await assertExecutionAuthorized(row);
        authorized.push(row);
      } catch (error) {
        await db
          .update(operations)
          .set({
            status: "failed",
            claimToken: null,
            error: String(redactValue(error instanceof Error ? error.message : "Authorization was revoked.")),
            updatedAt: new Date(),
          })
          .where(and(eq(operations.id, row.id), eq(operations.claimToken, claimed.token)));
      }
    }
    return c.json({
      jobs: authorized.map((row) => ({ ...row, claimToken: claimed.token })),
    });
  }
  const requested = (c.req.header("x-ark-worker-kinds") ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const allowed = new Set(workerPrefixes[c.get("worker")] ?? []);
  if (!requested.length || requested.some((item) => !allowed.has(item))) {
    throw new HTTPException(403, { message: "A valid worker job allowlist is required." });
  }
  const claimed = await claimQueued({ limit: 1, kindPrefixes: requested });
  return c.json({ jobs: claimed.rows.map((row) => ({ ...row, claimToken: claimed.token })) });
});

app.post("/api/internal/jobs/:id/heartbeat", async (c) => {
  const body = z.object({ claimToken: z.string().min(1) }).parse(await c.req.json());
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("id")));
  if (!operation || !workerCanExecute(c.get("worker"), operation.kind)) {
    throw new HTTPException(403, { message: "This worker may not heartbeat that operation kind." });
  }
  if (c.get("worker") === "agent") {
    await assertExecutionAuthorized(operation).catch(() => {
      throw new HTTPException(403, { message: "The operation actor is no longer authorized." });
    });
  }
  if (!(await heartbeatClaim(c.req.param("id"), body.claimToken))) {
    throw new HTTPException(409, { message: "The operation lease is stale or no longer owned." });
  }
  return c.json({ ok: true });
});

app.post("/api/internal/jobs/:id/complete", async (c) => {
  const body = z
    .object({
      status: z.enum(["succeeded", "failed"]),
      error: z.string().optional(),
      evidence: z.record(z.string(), z.unknown()).optional(),
      claimToken: z.string().min(1).optional(),
    })
    .parse(await c.req.json());
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("id")));
  if (!operation) throw new HTTPException(404, { message: "Operation not found." });
  if (!workerCanExecute(c.get("worker"), operation.kind)) {
    throw new HTTPException(403, { message: "This worker may not complete that operation kind." });
  }
  if (operation.status !== "running") {
    throw new HTTPException(409, { message: "Operation is not claimed for completion." });
  }
  if (!body.claimToken || !operation.claimToken || operation.claimToken !== body.claimToken) {
    throw new HTTPException(403, { message: "Claim token does not match this job." });
  }
  if (c.get("worker") === "agent" && body.status === "succeeded") {
    await assertExecutionAuthorized(operation).catch(() => {
      throw new HTTPException(403, { message: "The operation actor is no longer authorized." });
    });
  }
  if (!canTransition(operation.status as OperationState, body.status)) {
    throw new HTTPException(409, {
      message: `Operation cannot move from ${operation.status} to ${body.status}.`,
    });
  }
  try {
    await db.transaction(async (tx) => {
      const updated = await tx
        .update(operations)
        .set({
          status: body.status,
          error: body.error ? String(redactValue(body.error)).slice(0, 1000) : null,
          claimToken: null,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(operations.id, operation.id),
            eq(operations.status, "running"),
            eq(operations.claimToken, body.claimToken!),
          ),
        )
        .returning({ id: operations.id });
      if (updated.length !== 1) {
        throw new HTTPException(409, { message: "The operation lease changed before completion." });
      }
      if (body.evidence) {
        await tx.insert(operationSteps).values({
          id: createId("step"),
          operationId: operation.id,
          name: "worker-complete",
          status: body.status,
          evidence: redactValue(body.evidence) as Record<string, unknown>,
          error: body.error ? String(redactValue(body.error)).slice(0, 1000) : undefined,
        });
      }
      if (c.get("worker") === "agent") {
        await finalizeAgentCompletion(operation, body.status === "succeeded", tx);
      }
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    throw error;
  }
  return c.json({ ok: true });
});

async function readDbIngressCounters() {
  try {
    return JSON.parse(await readFile(dbIngressCountersFile(), "utf8")) as unknown;
  } catch {
    return null;
  }
}

app.get("/api/metrics/prometheus", async (c) => {
  if (!secureEqual(c.req.header("authorization") ?? "", `Bearer ${env.metricsToken}`)) {
    throw new HTTPException(401, { message: "Invalid metrics credential." });
  }
  const [opRows, backupRows, certRows, heartbeatRows] = await Promise.all([
    db.select().from(operations),
    db.select().from(backups),
    db.select().from(certificates),
    db.select().from(workerHeartbeats),
  ]);
  const lines = [
    "# TYPE ark_operations gauge",
    `ark_operations{status="failed"} ${opRows.filter((item) => item.status === "failed").length}`,
    `ark_operations{status="running"} ${opRows.filter((item) => item.status === "running").length}`,
    `ark_operations{status="waiting_external"} ${opRows.filter((item) => item.status === "waiting_external").length}`,
    `ark_operations{status="needs_recovery"} ${opRows.filter((item) => item.status === "needs_recovery").length}`,
    "# TYPE ark_backups_unverified gauge",
    `ark_backups_unverified ${backupRows.filter((item) => !item.restoreVerified).length}`,
    "# TYPE ark_certificates_expiring gauge",
    `ark_certificates_expiring ${certRows.filter((item) => item.expiresAt && item.expiresAt.getTime() < Date.now() + 14 * 86_400_000).length}`,
    "# TYPE ark_worker_heartbeat_stale gauge",
    ...["agent", "database", "domains", "mail", "backup"].map((identity) => {
      const item = heartbeatRows.find((row) => row.identity === identity);
      return `ark_worker_heartbeat_stale{identity="${identity}"} ${!item || Date.now() - item.lastSeenAt.getTime() > 90_000 ? 1 : 0}`;
    }),
    // nft drop counters for the public database port (front door §3.11, FD-18), written by the
    // host-namespace database-ingress reconciler. A missing or unreadable snapshot reports 0.
    ...dbIngressCounterMetrics(await readDbIngressCounters()),
  ];
  return c.text(`${lines.join("\n")}\n`, 200, { "content-type": "text/plain; version=0.0.4" });
});

app.use("/api/*", async (c, next) => {
  if (
    c.req.path.startsWith("/api/internal/") ||
    c.req.path.startsWith("/api/auth/") ||
    c.req.path === "/api/setup/status" ||
    c.req.path === "/api/health"
  ) {
    return next();
  }
  const sessionValue = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!sessionValue) throw new HTTPException(401, { message: "Sign in to continue." });
  // Better Auth's two-factor plugin owns `twoFactorEnabled`, while Ark owns the
  // enrollment boundary timestamp. Read both from the authoritative row rather
  // than relying on the plugin's deliberately narrow session serializer.
  const [currentUser] = await db.select().from(user).where(eq(user.id, sessionValue.user.id));
  if (!currentUser) throw new HTTPException(401, { message: "The signed-in account no longer exists." });
  c.set("session", {
    ...sessionValue,
    user: {
      ...sessionValue.user,
      twoFactorEnabled: currentUser.twoFactorEnabled,
      mfaEnrolledAt: currentUser.mfaEnrolledAt,
    },
  } as SessionValue);
  const [access] = await db
    .select()
    .from(platformAccess)
    .where(eq(platformAccess.userId, sessionValue.user.id));
  c.set("access", {
    userId: sessionValue.user.id,
    role: (access?.role as Role) ?? "viewer",
    projectIds: access?.projectIds ?? [],
    domainIds: access?.domainIds ?? [],
  });
  await next();
});

const browserOrigins = new Set([env.authUrl, ...env.trustedOrigins].map((item) => new URL(item).origin));
app.use("/api/*", async (c, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(c.req.method)) return next();
  const origin = c.req.header("origin");
  if (!origin || !browserOrigins.has(origin)) {
    throw new HTTPException(403, { message: "The request origin is not trusted." });
  }
  const mediaType = (c.req.header("content-type") ?? "").split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") {
    throw new HTTPException(415, { message: "Custom API mutations require application/json." });
  }
  await next();
});

async function audit(
  actorId: string | undefined,
  action: string,
  resourceType: string,
  resourceId: string | undefined,
  detail: Record<string, unknown> = {},
  operationId?: string,
  role?: string,
) {
  await db.insert(auditEvents).values({
    id: createId("aud"),
    actorId,
    action,
    resourceType,
    resourceId,
    role,
    operationId,
    detail: redactValue(detail) as Record<string, unknown>,
  });
}

async function consumeOneTimeSecret(
  secretId: string,
  input: { actorId: string; role: string; resourceType: string; resourceId: string; kind: string },
) {
  return db.transaction(async (tx) => {
    const [consumed] = await tx
      .update(secrets)
      .set({ revealedAt: new Date() })
      .where(and(eq(secrets.id, secretId), isNull(secrets.revealedAt)))
      .returning();
    if (!consumed) return null;
    await tx.insert(auditEvents).values({
      id: createId("aud"),
      actorId: input.actorId,
      action: "secret.reveal",
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      role: input.role,
      detail: { kind: input.kind },
    });
    return consumed;
  });
}

async function requireTargetScope(access: Access, targetId: string, mode: "view" | "manage" = "manage") {
  const [database] = await db.select().from(managedDatabases).where(eq(managedDatabases.id, targetId));
  if (database) return requireDatabaseAccess(access, targetId, mode);
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, targetId));
  if (mailbox) return requireDomain(access, mailbox.domainId, mode);
  const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, targetId));
  if (domain) return requireDomain(access, domain.id, mode);
  const [service] = await db.select().from(services).where(eq(services.id, targetId));
  if (service) return requireProject(access, service.projectId);
  const [project] = await db.select().from(projects).where(eq(projects.id, targetId));
  if (project) return requireProject(access, project.id);
  if (targetId === "platform" && access.role === "owner") return;
  throw new HTTPException(403, { message: "The target is not granted to your account." });
}

async function requireSecretScope(access: Access, secret: typeof secrets.$inferSelect) {
  assertSecretRevealable(secret);
  if (!secret.resourceId || !secret.resourceType) {
    throw new HTTPException(403, { message: "This legacy secret has no verified resource owner." });
  }
  await requireTargetScope(access, secret.resourceId, "manage");
}

app.get("/api/state", async (c) => {
  const access = c.get("access");
  const session = c.get("session");
  const [setup] = await db.select().from(platformSetup).where(eq(platformSetup.id, "default"));
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const [
    domains,
    records,
    ends,
    certs,
    clusterRows,
    dbs,
    roles,
    mailboxRows,
    aliasRows,
    projectRows,
    serviceRows,
    opRows,
    stepRows,
    backupRows,
    alertRows,
    auditRows,
    candidateRows,
  ] = await Promise.all([
    db.select().from(domainClaims),
    db.select().from(dnsRecords),
    db.select().from(endpoints),
    db.select().from(certificates),
    db.select().from(databaseClusters),
    db.select().from(managedDatabases),
    db.select().from(databaseRoles),
    db.select().from(mailboxes),
    db.select().from(aliases),
    db.select().from(projects),
    db.select().from(services),
    db.select().from(operations).orderBy(desc(operations.createdAt)).limit(50),
    db.select().from(operationSteps).orderBy(desc(operationSteps.createdAt)).limit(200),
    db.select().from(backups).orderBy(desc(backups.createdAt)).limit(50),
    db.select().from(alerts).orderBy(desc(alerts.createdAt)).limit(50),
    db.select().from(auditEvents).orderBy(desc(auditEvents.createdAt)).limit(50),
    db.select().from(updateCandidates).orderBy(desc(updateCandidates.detectedAt)).limit(50),
  ]);
  const visibleDomains = domains.filter((item) => canViewDomain(access, item.id));
  const visibleDomainIds = new Set(visibleDomains.map((item) => item.id));
  const visibleProjects = projectRows.filter((item) => canViewProject(access, item.id));
  const visibleProjectIds = new Set(visibleProjects.map((item) => item.id));
  const clusterById = new Map(clusterRows.map((item) => [item.id, item]));
  const endpointById = new Map(ends.map((item) => [item.id, item]));
  const visibleDatabases = dbs.filter((item) => {
    if (item.projectId) return visibleProjectIds.has(item.projectId);
    const cluster = clusterById.get(item.clusterId);
    const endpoint = cluster?.endpointId ? endpointById.get(cluster.endpointId) : undefined;
    if (endpoint?.domainId) return visibleDomainIds.has(endpoint.domainId);
    return access.role === "owner";
  });
  const visibleDatabaseIds = new Set(visibleDatabases.map((item) => item.id));
  const visibleServices = serviceRows.filter((item) => visibleProjectIds.has(item.projectId));
  const visibleServiceIds = new Set(visibleServices.map((item) => item.id));
  const visibleMailboxes = mailboxRows.filter((item) => visibleDomainIds.has(item.domainId));
  const visibleMailboxIds = new Set(visibleMailboxes.map((item) => item.id));
  const visibleIds = new Set<string>([
    ...visibleDomainIds,
    ...visibleProjectIds,
    ...visibleDatabaseIds,
    ...visibleServiceIds,
    ...visibleMailboxIds,
  ]);
  if (access.role === "owner" || access.role === "operator") visibleIds.add("platform");
  const visibleEndpoints = ends.filter((item) => !item.domainId || visibleDomainIds.has(item.domainId));
  const visibleEndpointIds = new Set(visibleEndpoints.map((item) => item.id));
  const visibleMailDomainRows = (await db.select().from(mailDomains)).filter((item) =>
    visibleDomainIds.has(item.domainId),
  );
  const deviceRows = await db.select().from(mailboxDevices);
  return c.json({
    user: { ...session.user, role: access.role },
    setup: {
      completed: Boolean(setup?.completed),
      wizardCompleted: Boolean(setup?.wizardCompleted),
      mfaEnrolled: Boolean(session.user.twoFactorEnabled && session.user.mfaEnrolledAt),
      mfaAssured: Boolean(
        session.user.twoFactorEnabled &&
        session.user.mfaEnrolledAt &&
        new Date(session.session.createdAt).getTime() >= new Date(session.user.mfaEnrolledAt).getTime(),
      ),
    },
    settings,
    region: regionSummary(settings ?? null),
    dbIngress: dbIngressLimitsSummary(settings ?? null),
    domains: visibleDomains.map((domain) => ({
      ...redactDomain(domain, access),
      records: records.filter((record) => record.domainId === domain.id),
    })),
    endpoints: visibleEndpoints,
    certificates: certs
      .filter((item) => visibleEndpointIds.has(item.endpointId))
      .map((item) => ({ ...item, fingerprint: item.fingerprint })),
    clusters: clusterRows.filter((item) => {
      const endpoint = item.endpointId ? endpointById.get(item.endpointId) : undefined;
      return !endpoint?.domainId || visibleDomainIds.has(endpoint.domainId);
    }),
    databases: visibleDatabases.map((item) => ({
      ...item,
      roles: roles
        .filter((role) => role.databaseId === item.id)
        .map((role) => ({ ...role, secretId: role.secretId ? "stored" : null })),
    })),
    mailboxes: visibleMailboxes.map((item) => {
      const domain = domains.find((row) => row.id === item.domainId);
      return { ...item, address: domain ? `${item.localPart}@${domain.name}` : item.localPart };
    }),
    aliases: aliasRows
      .filter((item) => visibleDomainIds.has(item.domainId))
      .map((item) => {
        const domain = domains.find((row) => row.id === item.domainId);
        return { ...item, address: domain ? `${item.localPart}@${domain.name}` : item.localPart };
      }),
    mailDomains: visibleMailDomainRows,
    devices: deviceRows
      .filter((item) => visibleMailboxIds.has(item.mailboxId))
      .map((item) => ({
        ...item,
        secretId: item.secretId ? "stored" : null,
      })),
    projects: visibleProjects,
    services: visibleServices.map((item) => ({
      id: item.id,
      projectId: item.projectId,
      name: item.name,
      imageDigest: item.imageDigest,
      desiredRevision: item.desiredRevision,
      observedRevision: item.observedRevision,
      status: item.status,
      updatePolicy: item.updatePolicy,
      stateful: item.stateful,
      observedAt: item.observedAt,
      createdAt: item.createdAt,
    })),
    operations: opRows
      .filter((item) => access.role === "owner" || item.targetIds.some((id) => visibleIds.has(id)))
      .map((item) => ({
        id: item.id,
        kind: item.kind,
        status: item.status,
        targetIds: item.targetIds,
        error: item.error ? String(redactValue(item.error)).slice(0, 500) : null,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt,
      })),
    steps: stepRows
      .filter((item) =>
        opRows.some(
          (op) =>
            op.id === item.operationId &&
            (access.role === "owner" || op.targetIds.some((id) => visibleIds.has(id))),
        ),
      )
      .map((item) => ({
        id: item.id,
        operationId: item.operationId,
        name: item.name,
        status: item.status,
        createdAt: item.createdAt,
      })),
    backups: backupRows.filter((item) => access.role === "owner" || visibleIds.has(item.targetId)),
    alerts: access.role === "owner" || access.role === "operator" ? alertRows : [],
    audit: (access.role === "owner"
      ? auditRows
      : auditRows.filter((item) => item.actorId === access.userId)
    ).map((item) => ({
      id: item.id,
      actorId: item.actorId,
      action: item.action,
      resourceType: item.resourceType,
      resourceId: item.resourceId,
      role: item.role,
      operationId: item.operationId,
      createdAt: item.createdAt,
    })),
    updateCandidates: candidateRows.filter((item) => visibleServiceIds.has(item.serviceId)),
    providers: {
      cloudflare: Boolean(process.env.DNS_API_TOKEN || process.env.CLOUDFLARE_API_TOKEN),
      ses: Boolean(process.env.AWS_ACCESS_KEY_ID || process.env.AWS_BOOTSTRAP_ACCESS_KEY_ID),
      stalwart: Boolean(process.env.STALWART_URL),
      alertWebhook: Boolean(process.env.ARK_ALERT_WEBHOOK),
    },
  });
});

app.post("/api/wizard", async (c) => {
  const access = c.get("access");
  const session = c.get("session");
  // The wizard writes the same admin exposure settings that `/api/settings` and
  // `/api/settings/mode` guard with owner plus an `exposure.public` step-up. Without these
  // checks an operator could re-run it to reach those settings by the back door.
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  requireMfa(session);
  const [wizardSetup] = await db.select().from(platformSetup).where(eq(platformSetup.id, "default"));
  if (wizardSetup?.wizardCompleted) {
    throw new HTTPException(409, {
      message: "First-run setup is already complete. Change these settings from Settings instead.",
    });
  }
  const input = wizardInput.parse(await c.req.json());
  const ownershipToken = `ark-own-${createToken(16)}`;
  const plan = buildDomainPlan({
    baseDomain: input.baseDomain,
    publicIpv4: input.publicIpv4,
    publicIpv6: input.publicIpv6,
    adminMode: input.adminMode,
    adminHostname: input.adminHostname,
    databaseHostname: input.databaseHostname,
    mailHostname: input.mailHostname,
    ownershipToken,
    includeDatabase: input.includeDatabase,
    includeMail: input.includeMail,
  });
  const domainId = createId("dom");
  await db.insert(domainClaims).values({
    id: domainId,
    name: plan.zone,
    ownershipToken,
    status: "awaiting_dns",
    dnsProvider: input.dnsProvider,
    mailFrom: `bounce.${plan.zone}`,
  });
  for (const record of plan.records) {
    await db.insert(dnsRecords).values({
      id: createId("dns"),
      domainId,
      type: record.type,
      name: record.name,
      relativeName: record.relativeName,
      expectedValue: record.value,
      purpose: record.purpose,
      required: record.required,
    });
  }
  const createdEndpoints: string[] = [];
  const addEndpoint = async (kind: string, hostname: string, exposure: string) => {
    const id = createId("ep");
    await db.insert(endpoints).values({ id, kind, hostname, domainId, exposure, status: "awaiting_dns" });
    createdEndpoints.push(id);
    return id;
  };
  if (input.includeDatabase) {
    const endpointId = await addEndpoint(
      "database",
      normalizeHostname(input.databaseHostname ?? `db.${plan.zone}`),
      "public",
    );
    const clusterId = createId("cl");
    await db
      .insert(databaseClusters)
      .values({ id: clusterId, name: "application", endpointId, status: "provisioning" });
    if (input.firstDatabaseName) {
      const databaseId = createId("db");
      await db.insert(managedDatabases).values({
        id: databaseId,
        clusterId,
        name: input.firstDatabaseName,
        exposure: "public",
        status: "queued",
      });
    }
  }
  if (input.includeMail) {
    await addEndpoint("mail", normalizeHostname(input.mailHostname ?? `mail.${plan.zone}`), "public");
    await db.insert(mailDomains).values({
      id: createId("md"),
      domainId,
      inboundStatus: "pending",
      outboundStatus: "paused",
    });
    if (input.firstMailboxLocalPart) {
      const mailboxId = createId("mbx");
      await db.insert(mailboxes).values({
        id: mailboxId,
        domainId,
        localPart: localPart(input.firstMailboxLocalPart),
        displayName: "First mailbox",
      });
    }
  }
  if (input.adminMode === "public") {
    await addEndpoint("admin", normalizeHostname(input.adminHostname ?? `admin.${plan.zone}`), "public");
  }
  await db
    .update(platformSettings)
    .set({
      adminMode: input.adminMode,
      baseDomain: plan.zone,
      adminHostname:
        input.adminMode === "public" ? normalizeHostname(input.adminHostname ?? `admin.${plan.zone}`) : null,
      publicIpv4: input.publicIpv4,
      dnsProvider: input.dnsProvider,
      authOrigin: env.authUrl,
      updatedAt: new Date(),
    })
    .where(eq(platformSettings.id, "default"));
  await db.update(platformSetup).set({ wizardCompleted: true }).where(eq(platformSetup.id, "default"));
  await grantAccess(access.userId, { domainId });
  const verify = await enqueue({ kind: "domain.verify", actorId: access.userId, targetIds: [domainId] });
  await audit(
    access.userId,
    "wizard.complete",
    "domain",
    domainId,
    { adminMode: input.adminMode },
    verify.id,
    access.role,
  );
  return c.json({ domainId, records: plan.records, operationId: verify.id });
});

app.post("/api/step-up", async (c) => {
  const access = c.get("access");
  const sessionValue = c.get("session");
  requireOperator(access);
  requireMfa(sessionValue);
  const body = z
    .object({
      password: z.string().min(1).max(1024),
      action: z.enum([
        "role.grant",
        "secret.reveal",
        "resource.delete",
        "restore.overwrite",
        "exposure.public",
        "credential.rotate",
        "platform.update",
      ]),
      planHash: z.string().max(200).optional(),
      request: z.record(z.string(), z.unknown()).optional(),
    })
    .parse(await c.req.json());
  const planHash = body.request ? privilegedRequestHash(body.action, body.request) : body.planHash;
  if (!planHash) {
    throw new HTTPException(422, {
      message: "A request binding or plan hash is required for a single-use step-up grant.",
    });
  }
  // `auth.api.verifyPassword` bypasses Better Auth's rate limiter, which only wraps
  // `auth.handler`. Without a throttle here a stolen post-MFA session cookie could brute-force
  // the account password to mint grants for secret reveal and credential rotation.
  assertStepUpAttemptAllowed(access.userId);
  try {
    await auth.api.verifyPassword({ body: { password: body.password }, headers: c.req.raw.headers });
  } catch (error) {
    recordStepUpFailure(access.userId);
    await audit(access.userId, "auth.step_up_failed", "session", sessionValue.session.id, {
      action: body.action,
    });
    throw error;
  }
  clearStepUpFailures(access.userId);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await db.insert(stepUpGrants).values({
    id: createId("sup"),
    userId: access.userId,
    sessionId: sessionValue.session.id,
    action: body.action,
    planHash,
    expiresAt,
  });
  await audit(access.userId, "auth.step_up", "session", sessionValue.session.id, {
    action: body.action,
    expiresAt: expiresAt.toISOString(),
  });
  c.header("cache-control", "no-store");
  return c.json({ action: body.action, expiresAt });
});

app.post("/api/domains", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = domainInput.parse(await c.req.json());
  const name = normalizeHostname(input.name);
  const id = createId("dom");
  const ownershipToken = `ark-own-${createToken(16)}`;
  await db.insert(domainClaims).values({
    id,
    name,
    ownershipToken,
    status: "awaiting_dns",
    mailFrom: input.mailFrom ? normalizeHostname(input.mailFrom) : `bounce.${name}`,
    dmarcPolicy: input.dmarcPolicy,
  });
  await db.insert(dnsRecords).values({
    id: createId("dns"),
    domainId: id,
    type: "TXT",
    name: `_ark-stack.${name}`,
    relativeName: "_ark-stack",
    expectedValue: ownershipToken,
    purpose: "Installation-bound domain ownership proof",
    required: true,
  });
  await grantAccess(access.userId, { domainId: id });
  await audit(access.userId, "domain.create", "domain", id, { name }, undefined, access.role);
  return c.json({
    id,
    records: [{ type: "TXT", name: `_ark-stack.${name}`, value: ownershipToken, required: true }],
  });
});

app.post("/api/domains/:id/verify", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireDomain(access, c.req.param("id"), "manage");
  const operation = await enqueue({
    kind: "domain.verify",
    actorId: access.userId,
    targetIds: [c.req.param("id")],
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/domains/:id/publish", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  requireDomain(access, c.req.param("id"), "manage");
  const operation = await enqueue({
    kind: "dns.publish",
    actorId: access.userId,
    targetIds: [c.req.param("id")],
  });
  await audit(access.userId, "dns.publish", "domain", c.req.param("id"), {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/projects", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = projectInput.parse(await c.req.json());
  const id = createId("prj");
  await db.insert(projects).values({ id, name: input.name, slug: input.slug });
  await grantAccess(access.userId, { projectId: id });
  await audit(access.userId, "project.create", "project", id, input, undefined, access.role);
  return c.json({ id });
});

app.post("/api/databases", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = databaseInput.parse(await c.req.json());
  let clusterId = input.clusterId;
  if (!clusterId) {
    const [cluster] = await db.select().from(databaseClusters);
    clusterId = cluster?.id;
  }
  if (!clusterId)
    throw new HTTPException(400, { message: "Complete the domain wizard so an application cluster exists." });
  const [cluster] = await db.select().from(databaseClusters).where(eq(databaseClusters.id, clusterId));
  if (cluster?.endpointId) {
    const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, cluster.endpointId));
    if (endpoint?.domainId) requireDomain(access, endpoint.domainId, "manage");
  } else if (access.role !== "owner") {
    throw new HTTPException(403, { message: "You do not have access to this database cluster." });
  }
  const id = createId("db");
  await db.insert(managedDatabases).values({
    id,
    clusterId,
    name: input.name,
    exposure: input.exposure,
    withPgvector: input.withPgvector,
    withTestDatabase: input.withTestDatabase,
    sourceCidrs: input.sourceCidrs ?? [],
  });
  const operation = await enqueue({ kind: "database.provision", actorId: access.userId, targetIds: [id] });
  await audit(access.userId, "database.create", "database", id, input, operation.id, access.role);
  return c.json({ id, operationId: operation.id });
});

app.post("/api/mailboxes", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = mailboxInput.parse(await c.req.json());
  requireDomain(access, input.domainId, "manage");
  const id = createId("mbx");
  await db.insert(mailboxes).values({
    id,
    domainId: input.domainId,
    localPart: localPart(input.localPart),
    displayName: input.displayName,
    quotaGb: input.quotaGb,
  });
  const operation = await enqueue({ kind: "mail.provision", actorId: access.userId, targetIds: [id] });
  await audit(access.userId, "mail.mailbox.create", "mailbox", id, input, operation.id, access.role);
  return c.json({ id, operationId: operation.id });
});

app.post("/api/aliases", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = aliasInput.parse(await c.req.json());
  requireDomain(access, input.domainId, "manage");
  const existing = await db.select().from(aliases);
  const domains = await db.select().from(domainClaims);
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  assertExternalForwarding({
    targets: input.targets,
    localDomains: domains.map((item) => item.name),
    allowExternalForwarding: Boolean(settings?.allowExternalForwarding),
    allowExternal: input.allowExternal,
  });
  const graph = existing
    .filter((item) => item.status === "active")
    .map((item) => {
      const domain = domains.find((row) => row.id === item.domainId);
      return { address: `${item.localPart}@${domain?.name}`, targets: item.targets };
    });
  const domain = domains.find((row) => row.id === input.domainId);
  graph.push({ address: `${localPart(input.localPart)}@${domain?.name}`, targets: input.targets });
  assertAliasGraph(graph);
  const mailbox = await requireDomainMailbox(input.domainId);
  const id = createId("als");
  await db.insert(aliases).values({
    id,
    domainId: input.domainId,
    localPart: localPart(input.localPart),
    description: input.description,
    targets: input.targets,
  });
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [mailbox.id],
  });
  await audit(access.userId, "mail.alias.create", "alias", id, input, operation.id, access.role);
  return c.json({ id, operationId: operation.id });
});

app.patch("/api/aliases/:id", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z
    .object({
      description: z.string().max(200).optional(),
      targets: z.array(z.string().email()).min(1).max(20),
      allowExternal: z.boolean().optional(),
    })
    .parse(await c.req.json());
  const [alias] = await db
    .select()
    .from(aliases)
    .where(eq(aliases.id, c.req.param("id")));
  if (!alias || alias.status !== "active") throw new HTTPException(404, { message: "Alias not found." });
  requireDomain(access, alias.domainId, "manage");
  const domains = await db.select().from(domainClaims);
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  assertExternalForwarding({
    targets: body.targets,
    localDomains: domains.map((item) => item.name),
    allowExternalForwarding: Boolean(settings?.allowExternalForwarding),
    allowExternal: body.allowExternal,
  });
  const graph = (await db.select().from(aliases))
    .filter((item) => item.id !== alias.id && item.status === "active")
    .map((item) => ({
      address: `${item.localPart}@${domains.find((domain) => domain.id === item.domainId)?.name}`,
      targets: item.targets,
    }));
  const domain = domains.find((item) => item.id === alias.domainId);
  graph.push({ address: `${alias.localPart}@${domain?.name}`, targets: body.targets });
  assertAliasGraph(graph);
  const mailbox = await requireDomainMailbox(alias.domainId);
  await db
    .update(aliases)
    .set({ targets: body.targets, description: body.description })
    .where(eq(aliases.id, alias.id));
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [mailbox.id],
  });
  await audit(access.userId, "mail.alias.update", "alias", alias.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.delete("/api/aliases/:id", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const [alias] = await db
    .select()
    .from(aliases)
    .where(eq(aliases.id, c.req.param("id")));
  if (!alias || alias.status !== "active") throw new HTTPException(404, { message: "Alias not found." });
  requireDomain(access, alias.domainId, "manage");
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "resource.delete",
    privilegedRequestHash("resource.delete", { aliasId: c.req.param("id") }),
  );
  if (!alias.nativeId) {
    await db.delete(aliases).where(eq(aliases.id, alias.id));
    await audit(
      access.userId,
      "mail.alias.delete",
      "alias",
      alias.id,
      { native: false },
      undefined,
      access.role,
    );
    return c.json({ operationId: null });
  }
  const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, alias.domainId));
  const mailbox = await requireDomainMailbox(alias.domainId);
  if (!domain) throw new HTTPException(409, { message: "The alias domain is no longer available." });
  await db.update(aliases).set({ status: "pending_delete" }).where(eq(aliases.id, alias.id));
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [mailbox.id],
    payload: {
      removedAliasId: alias.id,
      removedAlias: { address: `${alias.localPart}@${domain.name}`, nativeId: alias.nativeId },
    },
  });
  await audit(access.userId, "mail.alias.delete", "alias", alias.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/services", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = serviceInput.parse(await c.req.json());
  requireProject(access, input.projectId);
  const policy = validateComposeSource(input.compose);
  if (!policy.ok)
    throw new HTTPException(422, { message: policy.violations.map((item) => item.message).join(" ") });
  const id = createId("svc");
  // Write the approved compose artefact first: if the filesystem write fails the request must
  // not leave behind a registered service row with no deploy operation behind it.
  const written = await writeApprovedCompose(id, input.compose);
  await db.insert(services).values({
    id,
    projectId: input.projectId,
    name: input.name,
    compose: canonicalizeComposeSource(input.compose),
    desiredRevision: createId("rev"),
    imageDigest: policy.images[0] ?? null,
    status: "registered",
    updatePolicy: input.updatePolicy,
    stateful: input.stateful,
  });
  const [project] = await db.select().from(projects).where(eq(projects.id, input.projectId));
  const operation = await enqueue({
    kind: "service.deploy",
    actorId: access.userId,
    targetIds: [id],
    payload: {
      images: policy.images,
      compose: written.canonical,
      composeHash: written.hash,
      name: input.name,
      project: `ark-${project?.slug ?? "workload"}`,
    },
  });
  await audit(
    access.userId,
    "service.create",
    "service",
    id,
    { name: input.name, projectId: input.projectId },
    operation.id,
    access.role,
  );
  return c.json({ id, operationId: operation.id, preview: policy });
});

app.post("/api/services/discover", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner")
    throw new HTTPException(403, { message: "Only owners can discover host resources." });
  requireMfa(c.get("session"));
  await c.req.json();
  const operation = await enqueue({
    kind: "service.discover",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: { request: "redacted-inventory-v1" },
  });
  await audit(access.userId, "service.discover", "platform", "platform", {}, operation.id, access.role);
  return c.json({ operationId: operation.id, status: operation.status });
});

app.get("/api/services/discovery/:operationId", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner")
    throw new HTTPException(403, { message: "Only owners can view host discovery." });
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("operationId")));
  if (!operation || operation.kind !== "service.discover" || !operation.targetIds.includes("platform")) {
    throw new HTTPException(404, { message: "Discovery result was not found." });
  }
  if (operation.status !== "succeeded") {
    return c.json({ status: operation.status, available: false, error: operation.error });
  }
  const [step] = await db
    .select()
    .from(operationSteps)
    .where(eq(operationSteps.operationId, operation.id))
    .orderBy(desc(operationSteps.createdAt))
    .limit(1);
  const evidence = (step?.evidence ?? {}) as Record<string, unknown>;
  const inventory = Array.isArray(evidence.inventory)
    ? evidence.inventory.slice(0, 100).flatMap((raw) => {
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
        const item = raw as Record<string, unknown>;
        const names = Array.isArray(item.Names) ? item.Names : [];
        const labels = item.Labels && typeof item.Labels === "object" ? item.Labels : {};
        return [
          {
            id: String(item.Id ?? "").slice(0, 64),
            name: String(names[0] ?? "")
              .replace(/^\//, "")
              .slice(0, 128),
            image: String(item.Image ?? "").slice(0, 512),
            state: String(item.State ?? "unknown").slice(0, 32),
            labels: labels as Record<string, string>,
          },
        ];
      })
    : [];
  const registered = (await db.select().from(services)).map((item) => item.name);
  return c.json({ status: operation.status, available: true, ...classifyDiscovery(inventory, registered) });
});

app.post("/api/services/adopt", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = adoptInput.parse(await c.req.json());
  requireProject(access, input.projectId);
  const preview = adoptionPreview(input.compose);
  if (!preview.ok) throw new HTTPException(422, { message: "Unsupported compose cannot be adopted." });
  const id = createId("svc");
  // Same ordering as registration: a failed artefact write must not leave an orphan row.
  const written = await writeApprovedCompose(id, input.compose);
  await db.insert(services).values({
    id,
    projectId: input.projectId,
    name: input.name,
    compose: input.compose,
    desiredRevision: createId("rev"),
    containerId: input.containerId,
    adoptedFrom: input.containerId,
    status: "adoption_pending",
    updatePolicy: "notify",
  });
  const operation = await enqueue({
    kind: "service.adopt",
    actorId: access.userId,
    targetIds: [id],
    payload: { ...input, compose: written.canonical, composeHash: written.hash },
  });
  await audit(
    access.userId,
    "service.adopt",
    "service",
    id,
    { name: input.name, projectId: input.projectId },
    operation.id,
    access.role,
  );
  return c.json({ id, operationId: operation.id, preview });
});

app.post("/api/services/:id/observe", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = z.object({ kind: z.enum(["logs", "stats"]) }).parse(await c.req.json());
  const [service] = await db
    .select()
    .from(services)
    .where(eq(services.id, c.req.param("id")));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  requireProject(access, service.projectId);
  const operation = await enqueue({
    kind: input.kind === "logs" ? "service.logs" : "service.stats",
    actorId: access.userId,
    targetIds: [service.id],
    payload: { name: service.name },
  });
  await audit(access.userId, `service.${input.kind}`, "service", service.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id, status: operation.status });
});

app.get("/api/services/:id/observations/:operationId", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const [service] = await db
    .select()
    .from(services)
    .where(eq(services.id, c.req.param("id")));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  requireProject(access, service.projectId);
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("operationId")));
  if (
    !operation ||
    !operation.targetIds.includes(service.id) ||
    (operation.kind !== "service.logs" && operation.kind !== "service.stats")
  ) {
    throw new HTTPException(404, { message: "Service observation was not found." });
  }
  if (operation.status !== "succeeded") {
    return c.json({ status: operation.status, available: false, error: operation.error });
  }
  const [step] = await db
    .select()
    .from(operationSteps)
    .where(eq(operationSteps.operationId, operation.id))
    .orderBy(desc(operationSteps.createdAt))
    .limit(1);
  const evidence = (step?.evidence ?? {}) as Record<string, unknown>;
  if (operation.kind === "service.logs") {
    const lines = Array.isArray(evidence.lines)
      ? evidence.lines.filter((item): item is string => typeof item === "string").slice(-500)
      : [];
    return c.json({ status: operation.status, available: true, lines });
  }
  const stats =
    evidence.stats && typeof evidence.stats === "object" && !Array.isArray(evidence.stats)
      ? evidence.stats
      : {};
  return c.json({ status: operation.status, available: true, stats });
});

app.post("/api/services/:id/:action", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const action = c.req.param("action");
  const kind =
    action === "restart"
      ? "service.restart"
      : action === "start"
        ? "service.start"
        : action === "stop"
          ? "service.stop"
          : null;
  if (!kind) throw new HTTPException(404, { message: "Unknown service action." });
  const [service] = await db
    .select()
    .from(services)
    .where(eq(services.id, c.req.param("id")));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  requireProject(access, service.projectId);
  const [project] = await db.select().from(projects).where(eq(projects.id, service.projectId));
  const operation = await enqueue({
    kind,
    actorId: access.userId,
    targetIds: [c.req.param("id")],
    payload: { name: service.name, project: `ark-${project?.slug ?? "workload"}` },
  });
  await audit(access.userId, kind, "service", c.req.param("id"), {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/sql/query", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const input = sqlInput.parse(await c.req.json());
  const classified = classifySql(input.sql, input.readOnly);
  await requireDatabaseAccess(access, input.databaseId, "manage");
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { databaseId: input.databaseId, kind: "sql.query" }),
  );
  const [database] = await db
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, input.databaseId));
  if (!database) throw new HTTPException(404, { message: "Database not found." });
  const [role] = await db
    .select()
    .from(databaseRoles)
    .where(and(eq(databaseRoles.databaseId, database.id), eq(databaseRoles.kind, input.role)));
  if (!role?.secretId)
    throw new HTTPException(404, { message: "That role is not available for this database." });
  const operation = await enqueue({
    kind: "database.query",
    actorId: access.userId,
    targetIds: [database.id],
    payload: {
      executionId: input.executionId,
      workspaceId: input.workspaceId,
      role: input.role,
      sql: input.sql,
      readOnly: input.readOnly,
      fingerprint: classified.fingerprint,
    },
  });
  await audit(
    access.userId,
    "sql.execute",
    "database",
    input.databaseId,
    { fingerprint: classified.fingerprint, role: input.role, workspaceId: input.workspaceId },
    operation.id,
    access.role,
  );
  return c.json({
    operationId: operation.id,
    status: operation.status,
    databaseId: input.databaseId,
    workspaceId: input.workspaceId,
    role: input.role,
    fingerprint: classified.fingerprint,
  });
});

app.get("/api/sql/results/:operationId", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const [operation] = await db
    .select()
    .from(operations)
    .where(eq(operations.id, c.req.param("operationId")));
  if (
    !operation ||
    !["database.query", "database.schema"].includes(operation.kind) ||
    operation.targetIds.length !== 1
  ) {
    throw new HTTPException(404, { message: "Database result was not found." });
  }
  await requireDatabaseAccess(access, operation.targetIds[0]!, "manage");
  if (operation.status !== "succeeded") {
    return c.json({ status: operation.status, available: false, error: operation.error });
  }
  const [step] = await db
    .select()
    .from(operationSteps)
    .where(eq(operationSteps.operationId, operation.id))
    .orderBy(desc(operationSteps.createdAt))
    .limit(1);
  const evidence = (step?.evidence ?? {}) as Record<string, unknown>;
  const key = operation.kind === "database.query" ? "query" : "schema";
  const result = evidence[key];
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new HTTPException(409, { message: "Database worker completed without a bounded result." });
  }
  return c.json({ status: operation.status, available: true, [key]: result });
});

app.post("/api/sql/cancel", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = sqlCancelInput.parse(await c.req.json());
  const scope = await requireDatabaseAccess(access, input.databaseId, "manage");
  let cancelled = false;
  if (env.embeddedWorkers) {
    cancelled = await cancelWorkspaceQuery({
      executionId: input.executionId,
      actorId: access.userId,
      database: scope.database.name,
    });
  } else {
    const workerUrl = process.env.ARK_DATABASE_WORKER_URL;
    if (!workerUrl) throw new HTTPException(503, { message: "Database cancellation worker is unavailable." });
    const response = await fetch(`${workerUrl.replace(/\/$/, "")}/cancel`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.workerTokens.database}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        executionId: input.executionId,
        actorId: access.userId,
        database: scope.database.name,
      }),
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok)
      throw new HTTPException(503, { message: "Database cancellation worker rejected the request." });
    const result = (await response.json()) as { cancelled?: boolean };
    cancelled = result.cancelled === true;
  }
  return c.json({ executionId: input.executionId, cancelled });
});

app.post("/api/databases/:id/schema", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  await requireDatabaseAccess(access, c.req.param("id"));
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { databaseId: c.req.param("id"), kind: "schema" }),
  );
  const [database] = await db
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, c.req.param("id")));
  if (!database) throw new HTTPException(404, { message: "Database not found." });
  const [role] = await db
    .select()
    .from(databaseRoles)
    .where(and(eq(databaseRoles.databaseId, database.id), eq(databaseRoles.kind, "readonly")));
  if (!role?.secretId) throw new HTTPException(404, { message: "Readonly role is not available." });
  const operation = await enqueue({
    kind: "database.schema",
    actorId: access.userId,
    targetIds: [database.id],
    payload: {},
  });
  await audit(access.userId, "database.schema", "database", database.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id, status: operation.status });
});

app.post("/api/databases/:id/rotate", async (c) => {
  const access = c.get("access");
  const body = z.object({ kind: z.enum(["runtime", "readonly", "migration"]) }).parse(await c.req.json());
  await requireDatabaseAccess(access, c.req.param("id"), "manage");
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "credential.rotate",
    privilegedRequestHash("credential.rotate", { databaseId: c.req.param("id"), kind: body.kind }),
  );
  const operation = await enqueue({
    kind: "database.rotate",
    actorId: access.userId,
    targetIds: [c.req.param("id")],
    payload: body,
  });
  await audit(
    access.userId,
    "credential.rotate",
    "database",
    c.req.param("id"),
    body,
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id });
});

app.put("/api/databases/:id/cidrs", async (c) => {
  const access = c.get("access");
  const input = cidrInput.parse(await c.req.json());
  await requireDatabaseAccess(access, c.req.param("id"), "manage");
  const cidrs = assertCidrs(input.sourceCidrs);
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "exposure.public",
    privilegedRequestHash("exposure.public", { databaseId: c.req.param("id"), cidrs: input.sourceCidrs }),
  );
  await db
    .update(managedDatabases)
    .set({ sourceCidrs: cidrs })
    .where(eq(managedDatabases.id, c.req.param("id")));
  const operation = await enqueue({
    kind: "pgbouncer.reload",
    actorId: access.userId,
    targetIds: [c.req.param("id")],
    payload: { cidrs },
  });
  await audit(
    access.userId,
    "database.cidrs",
    "database",
    c.req.param("id"),
    { cidrs },
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id, cidrs });
});

app.get("/api/databases/:id/admission", async (c) => {
  requireOperator(c.get("access"));
  await requireDatabaseAccess(c.get("access"), c.req.param("id"));
  const [database] = await db
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, c.req.param("id")));
  if (!database) throw new HTTPException(404, { message: "Database not found." });
  return c.json(clientAllowed(database.sourceCidrs ?? [], String(c.req.query("ip") ?? "")));
});

app.get("/api/mail/queue", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  // Queue entries carry sender and recipient addresses for every tenant. Scope reads to the
  // domains the caller may view, matching the domain scoping the mutation route already does.
  const domainRows = await db.select().from(domainClaims);
  const visible = new Set(
    domainRows.filter((item) => canViewDomain(access, item.id)).map((item) => item.name.toLowerCase()),
  );
  const items = (await listMailQueue())
    .filter((item) => {
      const recipient = item.recipient.split("@")[1]?.toLowerCase() ?? "";
      const sender = item.sender.split("@")[1]?.toLowerCase() ?? "";
      return visible.has(recipient) || visible.has(sender);
    })
    .map(redactQueueItem);
  return c.json({ items });
});

app.post("/api/mail/queue", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = queueActionInput.parse(await c.req.json());
  const native = (await listMailQueue()).find((item) => item.id === input.item.id);
  if (!native) throw new HTTPException(404, { message: "Queue item not found." });
  const domainRows = await db.select().from(domainClaims);
  const domains = domainRows.map((item) => item.name);
  const allowed = canMutateQueue({ action: input.action, item: native, localDomains: domains });
  if (!allowed.ok) throw new HTTPException(422, { message: allowed.reason });
  const recipientDomain = native.recipient.split("@")[1]?.toLowerCase();
  const domain = domainRows.find((item) => item.name === recipientDomain);
  if (!domain) throw new HTTPException(403, { message: "Queue item is outside managed mail domains." });
  requireDomain(access, domain.id, "manage");
  const operation = await enqueue({
    kind: input.action === "delete" ? "mail.queue_delete" : "mail.queue_retry",
    actorId: access.userId,
    targetIds: [input.item.id],
    payload: native,
  });
  await audit(
    access.userId,
    `mail.queue.${input.action}`,
    "mail-queue",
    input.item.id,
    { action: input.action, recipient: native.recipient },
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id });
});

app.post("/api/mailboxes/:id/devices", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = deviceInput.parse(await c.req.json());
  const [mailbox] = await db
    .select()
    .from(mailboxes)
    .where(eq(mailboxes.id, c.req.param("id")));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  const id = createId("dev");
  await db.insert(mailboxDevices).values({ id, mailboxId: mailbox.id, label: input.label });
  const operation = await enqueue({
    kind: "mailbox.device",
    actorId: access.userId,
    targetIds: [mailbox.id],
    payload: { action: "create", deviceId: id, label: input.label },
  });
  await audit(
    access.userId,
    "mailbox.device.create",
    "mailbox",
    mailbox.id,
    { deviceId: id, label: input.label },
    operation.id,
    access.role,
  );
  return c.json({ id, operationId: operation.id });
});

app.post("/api/devices/:id/credential", async (c) => {
  const access = c.get("access");
  const [device] = await db
    .select()
    .from(mailboxDevices)
    .where(eq(mailboxDevices.id, c.req.param("id")));
  if (!device) throw new HTTPException(404, { message: "Device not found." });
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, device.mailboxId));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  if (!device.secretId) throw new HTTPException(409, { message: "The native credential is not ready." });
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { deviceId: c.req.param("id") }),
  );
  const consumed = await consumeOneTimeSecret(device.secretId, {
    actorId: access.userId,
    role: access.role,
    resourceType: "mailbox-device",
    resourceId: device.id,
    kind: `mailbox-device.${device.id}`,
  });
  if (!consumed) throw new HTTPException(409, { message: "This device password was already shown." });
  c.header("cache-control", "no-store");
  return c.json({ password: revealSecret(consumed) });
});

app.post("/api/devices/:id/revoke", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const [device] = await db
    .select()
    .from(mailboxDevices)
    .where(eq(mailboxDevices.id, c.req.param("id")));
  if (!device) throw new HTTPException(404, { message: "Device not found." });
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, device.mailboxId));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  const operation = await enqueue({
    kind: "mailbox.device",
    actorId: access.userId,
    targetIds: [mailbox.id],
    payload: { action: "revoke", deviceId: device.id },
  });
  await audit(access.userId, "mailbox.device.revoke", "mailbox", mailbox.id, {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/platform/maintain", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  const input = maintainInput.parse(await c.req.json());
  // Falling back to a placeholder would turn the second factor into a public constant, so an
  // unconfigured maintenance token has to fail closed.
  if (!env.maintenanceToken) {
    throw new HTTPException(503, {
      message: "ARK_MAINTENANCE_TOKEN is not configured; platform maintenance is unavailable.",
    });
  }
  if (!secureEqual(c.req.header("x-maintenance-token") ?? "", env.maintenanceToken)) {
    throw new HTTPException(403, { message: "Maintenance token is invalid." });
  }
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "platform.update",
    privilegedRequestHash("platform.update", { maintain: input }),
  );
  const operation = await enqueue({
    kind: "platform.maintain",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: input,
  });
  await audit(
    access.userId,
    "platform.maintain",
    "platform",
    "platform",
    input as Record<string, unknown>,
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id });
});

app.post("/api/secrets/:id/reveal", async (c) => {
  const access = c.get("access");
  const [secret] = await db
    .select()
    .from(secrets)
    .where(eq(secrets.id, c.req.param("id")));
  if (!secret) throw new HTTPException(404, { message: "Secret not found." });
  await requireSecretScope(access, secret);
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { secretId: c.req.param("id") }),
  );
  let consumed = secret;
  if (secret.once) {
    const winner = await consumeOneTimeSecret(secret.id, {
      actorId: access.userId,
      role: access.role,
      resourceType: secret.resourceType!,
      resourceId: secret.resourceId!,
      kind: secret.kind,
    });
    if (!winner)
      throw new HTTPException(409, {
        message: "This credential was already revealed. Rotate it to obtain a new value.",
      });
    consumed = winner;
  } else {
    await audit(
      access.userId,
      "secret.reveal",
      secret.resourceType!,
      secret.resourceId!,
      { kind: secret.kind },
      undefined,
      access.role,
    );
  }
  const value = revealSecret(consumed);
  c.header("cache-control", "no-store");
  return c.json({ value, kind: secret.kind });
});

app.post("/api/databases/:id/credential", async (c) => {
  const access = c.get("access");
  await requireDatabaseAccess(access, c.req.param("id"), "manage");
  const [role] = await db
    .select()
    .from(databaseRoles)
    .where(and(eq(databaseRoles.databaseId, c.req.param("id")), eq(databaseRoles.kind, "runtime")));
  if (!role?.secretId) throw new HTTPException(404, { message: "Runtime credential is not available." });
  const [secret] = await db.select().from(secrets).where(eq(secrets.id, role.secretId));
  if (!secret) throw new HTTPException(404, { message: "Runtime credential is not available." });
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { databaseId: c.req.param("id"), kind: "runtime" }),
  );
  const consumed = await consumeOneTimeSecret(secret.id, {
    actorId: access.userId,
    role: access.role,
    resourceType: "database",
    resourceId: c.req.param("id"),
    kind: secret.kind,
  });
  if (!consumed)
    throw new HTTPException(409, {
      message: "This password was already shown. Rotate the role to generate a new one.",
    });
  const password = revealSecret(consumed);
  const [database] = await db
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, c.req.param("id")));
  const [cluster] = await db
    .select()
    .from(databaseClusters)
    .where(eq(databaseClusters.id, database?.clusterId ?? ""));
  const [endpoint] = cluster?.endpointId
    ? await db.select().from(endpoints).where(eq(endpoints.id, cluster.endpointId))
    : [];
  const hostname = endpoint?.hostname ?? "db.local";
  c.header("cache-control", "no-store");
  return c.json({
    username: role.name,
    password,
    connectionString: `postgresql://${role.name}:${encodeURIComponent(password)}@${hostname}:5432/${database?.name}?sslmode=verify-full`,
  });
});

app.post("/api/mailboxes/:id/credential", async (c) => {
  const access = c.get("access");
  const [mailbox] = await db
    .select()
    .from(mailboxes)
    .where(eq(mailboxes.id, c.req.param("id")));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  // Scope first: answering 409-vs-403 before the grant check would tell a caller without access
  // whether a foreign mailbox still holds an unrevealed credential.
  requireDomain(access, mailbox.domainId, "manage");
  if (!mailbox.credentialAvailable)
    throw new HTTPException(409, { message: "No one-time mailbox credential remains." });
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "secret.reveal",
    privilegedRequestHash("secret.reveal", { mailboxId: c.req.param("id") }),
  );
  const [secret] = await db
    .select()
    .from(secrets)
    .where(eq(secrets.kind, `mailbox.${mailbox.id}`))
    .orderBy(desc(secrets.createdAt))
    .limit(1);
  if (!secret) throw new HTTPException(409, { message: "No one-time mailbox credential remains." });
  const consumed = await consumeOneTimeSecret(secret.id, {
    actorId: access.userId,
    role: access.role,
    resourceType: "mailbox",
    resourceId: mailbox.id,
    kind: secret.kind,
  });
  if (!consumed) throw new HTTPException(409, { message: "No one-time mailbox credential remains." });
  const password = revealSecret(consumed);
  await db.update(mailboxes).set({ credentialAvailable: false }).where(eq(mailboxes.id, mailbox.id));
  c.header("cache-control", "no-store");
  return c.json({ password });
});

app.post("/api/backups", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z
    .object({ kind: z.enum(["platform-postgres", "app-postgres", "mail", "volume"]), targetId: z.string() })
    .parse(await c.req.json());
  await requireTargetScope(access, body.targetId);
  const operation = await enqueue({
    kind: "backup.create",
    actorId: access.userId,
    targetIds: [body.targetId],
    payload: body,
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/backups/restore-test", async (c) => {
  const access = c.get("access");
  const body = z
    .object({
      kind: z.enum(["platform-postgres", "app-postgres", "mail", "volume"]),
      targetId: z.string(),
      backupId: z.string().min(1),
    })
    .parse(await c.req.json());
  await requireTargetScope(access, body.targetId);
  const [selected] = await db.select().from(backups).where(eq(backups.id, body.backupId));
  if (!selected || selected.targetId !== body.targetId || selected.kind !== body.kind) {
    throw new HTTPException(404, { message: "The selected backup does not belong to this target." });
  }
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "restore.overwrite",
    privilegedRequestHash("restore.overwrite", {
      kind: body.kind,
      targetId: body.targetId,
      backupId: body.backupId,
    }),
  );
  const operation = await enqueue({
    kind: "backup.restore_test",
    actorId: access.userId,
    targetIds: [body.targetId],
    payload: body,
  });
  await audit(
    access.userId,
    "backup.restore_test",
    "backup",
    body.backupId,
    { kind: body.kind, targetId: body.targetId },
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id });
});

/**
 * A completed restore test only proves the bytes came back. Restore proof — the state stateful
 * updates gate on — requires a human to confirm the restored copy actually booted and served
 * its data, which is what this route records.
 */
app.post("/api/backups/:id/verify-restore", async (c) => {
  const access = c.get("access");
  const [selected] = await db
    .select()
    .from(backups)
    .where(eq(backups.id, c.req.param("id")));
  if (!selected) throw new HTTPException(404, { message: "Backup not found." });
  await requireTargetScope(access, selected.targetId);
  const body = z
    .object({ confirmation: z.literal("restored copy booted and served its data") })
    .parse(await c.req.json());
  await requirePrivileged(
    access,
    c.get("session"),
    "restore.overwrite",
    privilegedRequestHash("restore.overwrite", { backupId: selected.id, verify: true }),
  );
  let status: string;
  try {
    status = nextBackupStatus(selected.status as BackupStatus, "restore");
  } catch (error) {
    throw new HTTPException(409, {
      message: error instanceof Error ? error.message : "Backup cannot be marked restore verified.",
    });
  }
  await db.update(backups).set({ status, restoreVerified: true }).where(eq(backups.id, selected.id));
  await audit(
    access.userId,
    "backup.restore_verified",
    "backup",
    selected.id,
    { confirmation: body.confirmation },
    undefined,
    access.role,
  );
  return c.json({ id: selected.id, status, restoreVerified: true });
});

app.post("/api/mail/reconcile", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z.object({ mailboxId: z.string() }).parse(await c.req.json());
  const [mailbox] = await db.select().from(mailboxes).where(eq(mailboxes.id, body.mailboxId));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [body.mailboxId],
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/ses/reconcile", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z.object({ domainId: z.string() }).parse(await c.req.json());
  requireDomain(access, body.domainId, "manage");
  const operation = await enqueue({
    kind: "ses.reconcile",
    actorId: access.userId,
    targetIds: [body.domainId],
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/mailboxes/:id/lifecycle", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z
    .object({ lifecycle: z.enum(["active", "suspended", "retained", "purged"]) })
    .parse(await c.req.json());
  const [mailbox] = await db
    .select()
    .from(mailboxes)
    .where(eq(mailboxes.id, c.req.param("id")));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  requireDomain(access, mailbox.domainId, "manage");
  if (mailbox.lifecycle === "purged")
    throw new HTTPException(409, { message: "A purged mailbox address stays reserved." });
  if (body.lifecycle === "purged") {
    await requirePrivileged(
      access,
      c.get("session"),
      "resource.delete",
      privilegedRequestHash("resource.delete", { mailboxId: c.req.param("id"), lifecycle: "purged" }),
    );
    const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, mailbox.domainId));
    const address = `${mailbox.localPart}@${domain?.name}`.toLowerCase();
    const dependencies = (await db.select().from(aliases)).filter(
      (alias) =>
        alias.status === "active" && alias.targets.some((target) => target.toLowerCase() === address),
    );
    if (dependencies.length) {
      throw new HTTPException(409, {
        message: `Remove ${dependencies.length} alias dependency before permanently purging this mailbox.`,
      });
    }
  }
  await db.update(mailboxes).set({ lifecycle: body.lifecycle }).where(eq(mailboxes.id, mailbox.id));
  const operation = await enqueue({
    kind: "mail.reconcile",
    actorId: access.userId,
    targetIds: [mailbox.id],
    payload: { lifecycle: body.lifecycle },
  });
  await audit(access.userId, "mailbox.lifecycle", "mailbox", mailbox.id, body, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/updates/detect", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  const operation = await enqueue({
    kind: "update.detect",
    actorId: access.userId,
    targetIds: ["platform"],
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/import/scan", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  const body = z
    .object({
      source: z.enum(["orkmail", "pgstack", "compose"]),
      domains: z.array(z.string()).optional(),
      databases: z.array(z.string()).optional(),
      services: z.array(z.string()).optional(),
    })
    .parse(await c.req.json());
  const operation = await enqueue({
    kind: "import.scan",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: body,
  });
  await audit(
    access.userId,
    "import.scan",
    "platform",
    "platform",
    { source: body.source },
    operation.id,
    access.role,
  );
  return c.json({ operationId: operation.id, ownersImported: false });
});

app.post("/api/alerts/:id/ack", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  await db
    .update(alerts)
    .set({ acknowledged: true })
    .where(eq(alerts.id, c.req.param("id")));
  return c.json({ ok: true });
});

app.post("/api/alerts/:id/silence", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z.object({ minutes: z.number().int().min(5).max(10_080) }).parse(await c.req.json());
  const [alert] = await db
    .select()
    .from(alerts)
    .where(eq(alerts.id, c.req.param("id")));
  if (!alert) throw new HTTPException(404, { message: "Alert not found." });
  const silencedUntil = new Date(Date.now() + body.minutes * 60_000);
  await db.update(alerts).set({ silencedUntil }).where(eq(alerts.id, alert.id));
  await audit(
    access.userId,
    "alert.silence",
    "alert",
    alert.id,
    { silencedUntil: silencedUntil.toISOString() },
    undefined,
    access.role,
  );
  return c.json({ silencedUntil });
});

app.post("/api/updates/apply", async (c) => {
  const access = c.get("access");
  const body = z.object({ serviceId: z.string(), digest: z.string() }).parse(await c.req.json());
  const [service] = await db.select().from(services).where(eq(services.id, body.serviceId));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  requireProject(access, service.projectId);
  // Consume the single-use grant only after the target and inputs are known good, so a 404,
  // scope rejection, or validation error does not burn it and force a fresh password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "platform.update",
    privilegedRequestHash("platform.update", { serviceId: body.serviceId, digest: body.digest }),
  );
  const operation = await enqueue({
    kind: "update.apply",
    actorId: access.userId,
    targetIds: [body.serviceId],
    payload: body,
  });
  await audit(access.userId, "update.apply", "service", body.serviceId, body, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/settings/mode", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  const body = z.object({ adminMode: z.enum(["public", "tailnet"]) }).parse(await c.req.json());
  await requirePrivileged(
    access,
    c.get("session"),
    "exposure.public",
    privilegedRequestHash("exposure.public", { adminMode: body.adminMode }),
  );
  const operation = await enqueue({
    kind: "admin.mode_change",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: body,
  });
  await audit(access.userId, "settings.mode", "platform", "platform", body, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.put("/api/settings", async (c) => {
  const access = c.get("access");
  if (access.role !== "owner") throw new HTTPException(403, { message: "Owner access is required." });
  requireMfa(c.get("session"));
  const input = settingsInput.parse(await c.req.json());
  await db
    .update(platformSettings)
    .set({
      timezone: input.timezone,
      defaultQuotaGb: input.defaultQuotaGb,
      allowExternalForwarding: input.allowExternalForwarding,
      updatedAt: new Date(),
    })
    .where(eq(platformSettings.id, "default"));
  await audit(access.userId, "settings.update", "platform", "platform", input, undefined, access.role);
  return c.json({ ok: true });
});

// Region preset (front door §3.15, FD-03). Every signed-in role can read the suggestions; the
// Vercel guide and backup wizard render them. The setting never touches AWS_REGION or SES.
app.get("/api/settings/region", async (c) => {
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  return c.json(regionSummary(settings ?? null));
});

app.put("/api/settings/region", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const request = await c.req.json();
  const input = regionSettingsInput.parse(request);
  // Validate before consuming the single-use grant, so a typo does not burn a password+MFA round.
  // Bind to the original JSON, just as /api/step-up does; normalize only the stored values.
  await requirePrivileged(
    access,
    c.get("session"),
    "platform.update",
    privilegedRequestHash("platform.update", request),
  );
  const [previous] = await db
    .select({ region: platformSettings.region, vpsRegionLabel: platformSettings.vpsRegionLabel })
    .from(platformSettings)
    .where(eq(platformSettings.id, "default"));
  const values = { region: input.region, vpsRegionLabel: input.vpsRegionLabel, updatedAt: new Date() };
  const [settings] = await db
    .insert(platformSettings)
    .values({ id: "default", ...values })
    .onConflictDoUpdate({ target: platformSettings.id, set: values })
    .returning();
  await audit(
    access.userId,
    "settings.region",
    "platform",
    "platform",
    { ...input, previous: previous ?? null },
    undefined,
    access.role,
  );
  return c.json(regionSummary(settings ?? null));
});

// Per-source limits on the public database port (front door §3.11, FD-18). Every signed-in role
// can read them; changing them re-renders `inet ark_db_ingress` through a pgbouncer.reload.
app.get("/api/settings/db-ingress", async (c) => {
  const [settings] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  return c.json(dbIngressLimitsSummary(settings ?? null));
});

app.put("/api/settings/db-ingress", async (c) => {
  const access = c.get("access");
  requireOwner(access);
  requireMfa(c.get("session"));
  const request = await c.req.json();
  const input = dbIngressLimitsInput.parse(request);
  // Validate before consuming the single-use grant, so a typo does not burn a password+MFA round.
  await requirePrivileged(
    access,
    c.get("session"),
    "platform.update",
    privilegedRequestHash("platform.update", request),
  );
  const [previous] = await db.select().from(platformSettings).where(eq(platformSettings.id, "default"));
  const values = {
    dbIngressMaxConnections: input.maxConnectionsPerSource,
    dbIngressRatePerSecond: input.newConnectionsPerSecond,
    dbIngressRateBurst: input.newConnectionBurst,
    updatedAt: new Date(),
  };
  const [settings] = await db
    .insert(platformSettings)
    .values({ id: "default", ...values })
    .onConflictDoUpdate({ target: platformSettings.id, set: values })
    .returning();
  const operation = await enqueue({
    kind: "pgbouncer.reload",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: { dbIngressLimits: input },
  });
  await audit(
    access.userId,
    "settings.db_ingress",
    "platform",
    "platform",
    { ...input, previous: previous ? platformDbIngressLimits(previous) : null },
    operation.id,
    access.role,
  );
  return c.json({ ...dbIngressLimitsSummary(settings ?? null), operationId: operation.id });
});

app.get("/api/metrics", async (c) => {
  const [ops, backupRows, certs] = await Promise.all([
    db.select().from(operations),
    db.select().from(backups),
    db.select().from(certificates),
  ]);
  return c.json({
    operationsFailed: ops.filter((item) => item.status === "failed").length,
    operationsRunning: ops.filter((item) => item.status === "running").length,
    backupsWithoutRestoreProof: backupRows.filter((item) => !item.restoreVerified).length,
    certificatesExpiringSoon: certs.filter(
      (item) => item.expiresAt && item.expiresAt.getTime() < Date.now() + 14 * 24 * 60 * 60 * 1000,
    ).length,
  });
});

app.get("/api/me", async (c) => {
  const [row] = await db
    .select()
    .from(user)
    .where(eq(user.id, c.get("session").user.id));
  return c.json({ user: row, access: c.get("access") });
});

const webDist = new URL("../../web/dist", import.meta.url).pathname;
if (existsSync(webDist)) {
  app.use("/*", serveStatic({ root: webDist }));
  app.get("*", serveStatic({ path: `${webDist}/index.html` }));
}
