import { existsSync } from "node:fs";

import {
  assertAliasGraph,
  canMutate,
  classifySql,
  createId,
  createToken,
  encryptSecret,
  generatePassword,
  hasMfaAssurance,
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
  settingsInput,
  buildDomainPlan,
  type Access,
  type Role,
} from "@ark-stack/shared";
import { serveStatic } from "@hono/node-server/serve-static";
import { and, desc, eq } from "drizzle-orm";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { HTTPException } from "hono/http-exception";
import { z } from "zod";

import { auth } from "./auth.ts";
import { enqueue } from "./coordinator.ts";
import { db, sql } from "./db.ts";
import { loadEnv } from "./env.ts";
import { revealSecret } from "./coordinator.ts";
import { getChallenge } from "./modules/certificates.ts";
import { inspectDatabaseSchema, executeWorkspaceQuery } from "./modules/database.ts";
import { discoverContainers, dockerAvailable, serviceLogs, serviceStats } from "./modules/docker.ts";
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
  updateCandidates,
  user,
} from "./schema.ts";

type SessionValue = {
  user: { id: string; name: string; email: string; twoFactorEnabled?: boolean; mfaEnrolledAt?: Date | null };
  session: { createdAt: Date };
};

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
  console.error(error instanceof Error ? error.message : error);
  return c.json({ error: "The request could not be completed." }, 500);
});

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

app.all("/api/auth/*", (c) => auth.handler(c.req.raw));

app.use("/api/internal/*", async (c, next) => {
  const supplied = c.req.header("authorization") ?? "";
  if (secureEqual(supplied, `Bearer ${env.internalToken}`)) c.set("worker", "module");
  else if (secureEqual(supplied, `Bearer ${env.agentToken}`)) c.set("worker", "agent");
  else throw new HTTPException(401, { message: "Invalid worker credential." });
  await next();
});

app.get("/api/internal/jobs", async (c) => {
  const rows = await db.select().from(operations).where(eq(operations.status, "queued")).limit(20);
  return c.json({
    jobs: rows.filter((row) => (c.get("worker") === "agent" ? row.kind.startsWith("service.") : true)),
  });
});

app.post("/api/internal/jobs/:id/complete", async (c) => {
  const body = z
    .object({
      status: z.enum(["succeeded", "failed"]),
      error: z.string().optional(),
      evidence: z.record(z.string(), z.unknown()).optional(),
    })
    .parse(await c.req.json());
  await db
    .update(operations)
    .set({ status: body.status, error: body.error ?? null, updatedAt: new Date() })
    .where(eq(operations.id, c.req.param("id")));
  return c.json({ ok: true });
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
  c.set("session", sessionValue as SessionValue);
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

function requireOperator(access: Access) {
  if (!canMutate(access)) throw new HTTPException(403, { message: "Operator access is required." });
}

function requireMfa(session: SessionValue) {
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
  return c.json({
    user: { ...session.user, role: access.role },
    setup: { completed: Boolean(setup?.completed), wizardCompleted: Boolean(setup?.wizardCompleted) },
    settings,
    domains: domains.map((domain) => ({
      ...domain,
      records: records.filter((record) => record.domainId === domain.id),
    })),
    endpoints: ends,
    certificates: certs.map((item) => ({ ...item, fingerprint: item.fingerprint })),
    clusters: clusterRows,
    databases: dbs.map((item) => ({
      ...item,
      roles: roles
        .filter((role) => role.databaseId === item.id)
        .map((role) => ({ ...role, secretId: role.secretId ? "stored" : null })),
    })),
    mailboxes: mailboxRows.map((item) => {
      const domain = domains.find((row) => row.id === item.domainId);
      return { ...item, address: domain ? `${item.localPart}@${domain.name}` : item.localPart };
    }),
    aliases: aliasRows.map((item) => {
      const domain = domains.find((row) => row.id === item.domainId);
      return { ...item, address: domain ? `${item.localPart}@${domain.name}` : item.localPart };
    }),
    mailDomains: await db.select().from(mailDomains),
    devices: (await db.select().from(mailboxDevices)).map((item) => ({
      ...item,
      secretId: item.secretId ? "stored" : null,
    })),
    projects: projectRows,
    services: serviceRows.map((item) => ({
      ...item,
      compose: undefined,
      composePreview: item.compose.slice(0, 400),
    })),
    operations: opRows,
    steps: stepRows,
    backups: backupRows,
    alerts: alertRows,
    audit: auditRows,
    updateCandidates: candidateRows,
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
  requireOperator(access);
  requireMfa(session);
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
      await enqueue({ kind: "database.provision", actorId: access.userId, targetIds: [databaseId] });
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
      await enqueue({ kind: "mail.provision", actorId: access.userId, targetIds: [mailboxId] });
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
  const verify = await enqueue({ kind: "domain.verify", actorId: access.userId, targetIds: [domainId] });
  for (const endpointId of createdEndpoints) {
    await enqueue({ kind: "certificate.issue", actorId: access.userId, targetIds: [endpointId] });
  }
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

app.post("/api/domains", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = domainInput.parse(await c.req.json());
  const name = normalizeHostname(input.name);
  const id = createId("dom");
  await db.insert(domainClaims).values({
    id,
    name,
    ownershipToken: `ark-own-${createToken(16)}`,
    mailFrom: input.mailFrom ? normalizeHostname(input.mailFrom) : `bounce.${name}`,
    dmarcPolicy: input.dmarcPolicy,
  });
  await audit(access.userId, "domain.create", "domain", id, { name }, undefined, access.role);
  return c.json({ id });
});

app.post("/api/domains/:id/verify", async (c) => {
  const access = c.get("access");
  requireOperator(access);
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
  const input = projectInput.parse(await c.req.json());
  const id = createId("prj");
  await db.insert(projects).values({ id, name: input.name, slug: input.slug });
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
  const input = mailboxInput.parse(await c.req.json());
  const id = createId("mbx");
  await db.insert(mailboxes).values({
    id,
    domainId: input.domainId,
    localPart: localPart(input.localPart),
    displayName: input.displayName,
    quotaGb: input.quotaGb,
  });
  const operation = await enqueue({ kind: "mail.provision", actorId: access.userId, targetIds: [id] });
  return c.json({ id, operationId: operation.id });
});

app.post("/api/aliases", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const input = aliasInput.parse(await c.req.json());
  const existing = await db.select().from(aliases);
  const domains = await db.select().from(domainClaims);
  const graph = existing.map((item) => {
    const domain = domains.find((row) => row.id === item.domainId);
    return { address: `${item.localPart}@${domain?.name}`, targets: item.targets };
  });
  const domain = domains.find((row) => row.id === input.domainId);
  graph.push({ address: `${localPart(input.localPart)}@${domain?.name}`, targets: input.targets });
  assertAliasGraph(graph);
  const id = createId("als");
  await db.insert(aliases).values({
    id,
    domainId: input.domainId,
    localPart: localPart(input.localPart),
    description: input.description,
    targets: input.targets,
  });
  return c.json({ id });
});

app.post("/api/services", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = serviceInput.parse(await c.req.json());
  const policy = validateComposeSource(input.compose);
  if (!policy.ok)
    throw new HTTPException(422, { message: policy.violations.map((item) => item.message).join(" ") });
  const id = createId("svc");
  await db.insert(services).values({
    id,
    projectId: input.projectId,
    name: input.name,
    compose: input.compose,
    desiredRevision: createId("rev"),
    imageDigest: policy.images[0] ?? null,
    status: "registered",
    updatePolicy: input.updatePolicy,
  });
  const operation = await enqueue({
    kind: "service.deploy",
    actorId: access.userId,
    targetIds: [id],
    payload: { images: policy.images, compose: input.compose, name: input.name },
  });
  return c.json({ id, operationId: operation.id, preview: policy });
});

app.get("/api/services/discover", async (c) => {
  requireOperator(c.get("access"));
  const discovered = await discoverContainers();
  const registered = (await db.select().from(services)).map((item) => item.name);
  return c.json({ docker: dockerAvailable(), ...classifyDiscovery(discovered, registered) });
});

app.post("/api/services/adopt", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = adoptInput.parse(await c.req.json());
  const preview = adoptionPreview(input.compose);
  if (!preview.ok) throw new HTTPException(422, { message: "Unsupported compose cannot be adopted." });
  const id = createId("svc");
  await db.insert(services).values({
    id,
    projectId: input.projectId,
    name: input.name,
    compose: input.compose,
    desiredRevision: createId("rev"),
    containerId: input.containerId,
    adoptedFrom: input.containerId,
    status: "adopted",
    updatePolicy: "notify",
  });
  const operation = await enqueue({
    kind: "service.adopt",
    actorId: access.userId,
    targetIds: [id],
    payload: input,
  });
  return c.json({ id, operationId: operation.id, preview });
});

app.get("/api/services/:id/logs", async (c) => {
  requireOperator(c.get("access"));
  const [service] = await db
    .select()
    .from(services)
    .where(eq(services.id, c.req.param("id")));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  const [project] = await db.select().from(projects).where(eq(projects.id, service.projectId));
  if (!dockerAvailable()) return c.json({ lines: [], available: false });
  const lines = await serviceLogs(`ark-${project?.slug ?? "workload"}`, service.name);
  return c.json({ lines, available: true });
});

app.get("/api/services/:id/stats", async (c) => {
  requireOperator(c.get("access"));
  const [service] = await db
    .select()
    .from(services)
    .where(eq(services.id, c.req.param("id")));
  if (!service) throw new HTTPException(404, { message: "Service not found." });
  const [project] = await db.select().from(projects).where(eq(projects.id, service.projectId));
  if (!dockerAvailable()) return c.json({ available: false });
  return c.json(await serviceStats(`ark-${project?.slug ?? "workload"}`, service.name));
});

app.post("/api/services/:id/:action", async (c) => {
  const access = c.get("access");
  requireOperator(access);
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
  const operation = await enqueue({ kind, actorId: access.userId, targetIds: [c.req.param("id")] });
  await audit(access.userId, kind, "service", c.req.param("id"), {}, operation.id, access.role);
  return c.json({ operationId: operation.id });
});

app.post("/api/sql/query", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = sqlInput.parse(await c.req.json());
  const classified = classifySql(input.sql, input.readOnly);
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
  const [secret] = await db.select().from(secrets).where(eq(secrets.id, role.secretId));
  if (!secret) throw new HTTPException(404, { message: "Role secret is missing." });
  const rows = await executeWorkspaceQuery({
    database: database.name,
    username: role.name,
    password: revealSecret(secret),
    sql: input.sql,
    readOnly: input.readOnly,
  });
  await audit(
    access.userId,
    "sql.execute",
    "database",
    input.databaseId,
    { fingerprint: classified.fingerprint, role: input.role, workspaceId: input.workspaceId },
    undefined,
    access.role,
  );
  return c.json({
    databaseId: input.databaseId,
    workspaceId: input.workspaceId,
    role: input.role,
    fingerprint: classified.fingerprint,
    rows,
  });
});

app.get("/api/databases/:id/schema", async (c) => {
  requireOperator(c.get("access"));
  requireMfa(c.get("session"));
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
  const [secret] = await db.select().from(secrets).where(eq(secrets.id, role.secretId));
  if (!secret) throw new HTTPException(404, { message: "Role secret is missing." });
  return c.json(
    await inspectDatabaseSchema({
      database: database.name,
      username: role.name,
      password: revealSecret(secret),
    }),
  );
});

app.post("/api/databases/:id/rotate", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z.object({ kind: z.enum(["runtime", "readonly", "migration"]) }).parse(await c.req.json());
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
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = cidrInput.parse(await c.req.json());
  const cidrs = assertCidrs(input.sourceCidrs);
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
  return c.json({ operationId: operation.id, cidrs });
});

app.get("/api/databases/:id/admission", async (c) => {
  requireOperator(c.get("access"));
  const [database] = await db
    .select()
    .from(managedDatabases)
    .where(eq(managedDatabases.id, c.req.param("id")));
  if (!database) throw new HTTPException(404, { message: "Database not found." });
  return c.json(clientAllowed(database.sourceCidrs ?? [], String(c.req.query("ip") ?? "")));
});

app.get("/api/mail/queue", async (c) => {
  requireOperator(c.get("access"));
  const items = (await listMailQueue()).map(redactQueueItem);
  return c.json({ items });
});

app.post("/api/mail/queue", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const input = queueActionInput.parse(await c.req.json());
  const domains = (await db.select().from(domainClaims)).map((item) => item.name);
  const allowed = canMutateQueue({ action: input.action, item: input.item, localDomains: domains });
  if (!allowed.ok) throw new HTTPException(422, { message: allowed.reason });
  const operation = await enqueue({
    kind: input.action === "delete" ? "mail.queue_delete" : "mail.queue_retry",
    actorId: access.userId,
    targetIds: [input.item.id],
    payload: input.item,
  });
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
  const password = generatePassword();
  const sealed = encryptSecret(env.rootKey, password, env.rootKeyId);
  const secretId = createId("sec");
  await db
    .insert(secrets)
    .values({ id: secretId, kind: `mailbox.device.${mailbox.id}`, once: true, ...sealed });
  const id = createId("dev");
  await db.insert(mailboxDevices).values({ id, mailboxId: mailbox.id, label: input.label, secretId });
  const operation = await enqueue({
    kind: "mailbox.device",
    actorId: access.userId,
    targetIds: [mailbox.id],
    payload: { deviceId: id, label: input.label },
  });
  c.header("cache-control", "no-store");
  return c.json({ id, password, operationId: operation.id });
});

app.post("/api/devices/:id/revoke", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  await db
    .update(mailboxDevices)
    .set({ revokedAt: new Date() })
    .where(eq(mailboxDevices.id, c.req.param("id")));
  return c.json({ ok: true });
});

app.post("/api/platform/maintain", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  if (!secureEqual(c.req.header("x-maintenance-token") ?? "", env.maintenanceToken || "missing")) {
    throw new HTTPException(403, { message: "Maintenance token is invalid." });
  }
  const input = maintainInput.parse(await c.req.json());
  const operation = await enqueue({
    kind: "platform.maintain",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: input,
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/secrets/:id/reveal", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const [secret] = await db
    .select()
    .from(secrets)
    .where(eq(secrets.id, c.req.param("id")));
  if (!secret) throw new HTTPException(404, { message: "Secret not found." });
  if (secret.once && secret.revealedAt)
    throw new HTTPException(409, {
      message: "This credential was already revealed. Rotate it to obtain a new value.",
    });
  const value = revealSecret(secret);
  if (secret.once) await db.update(secrets).set({ revealedAt: new Date() }).where(eq(secrets.id, secret.id));
  await audit(
    access.userId,
    "secret.reveal",
    "secret",
    secret.id,
    { kind: secret.kind },
    undefined,
    access.role,
  );
  c.header("cache-control", "no-store");
  return c.json({ value, kind: secret.kind });
});

app.post("/api/databases/:id/credential", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const [role] = await db
    .select()
    .from(databaseRoles)
    .where(and(eq(databaseRoles.databaseId, c.req.param("id")), eq(databaseRoles.kind, "runtime")));
  if (!role?.secretId) throw new HTTPException(404, { message: "Runtime credential is not available." });
  const [secret] = await db.select().from(secrets).where(eq(secrets.id, role.secretId));
  if (!secret) throw new HTTPException(404, { message: "Runtime credential is not available." });
  if (secret.revealedAt)
    throw new HTTPException(409, {
      message: "This password was already shown. Rotate the role to generate a new one.",
    });
  const password = revealSecret(secret);
  await db.update(secrets).set({ revealedAt: new Date() }).where(eq(secrets.id, secret.id));
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
  requireOperator(access);
  const [mailbox] = await db
    .select()
    .from(mailboxes)
    .where(eq(mailboxes.id, c.req.param("id")));
  if (!mailbox?.credentialAvailable)
    throw new HTTPException(409, { message: "No one-time mailbox credential remains." });
  const [secret] = await db
    .select()
    .from(secrets)
    .where(eq(secrets.kind, `mailbox.${mailbox.id}`));
  if (!secret || secret.revealedAt)
    throw new HTTPException(409, { message: "No one-time mailbox credential remains." });
  const password = revealSecret(secret);
  await db.update(secrets).set({ revealedAt: new Date() }).where(eq(secrets.id, secret.id));
  await db.update(mailboxes).set({ credentialAvailable: false }).where(eq(mailboxes.id, mailbox.id));
  c.header("cache-control", "no-store");
  return c.json({ password });
});

app.post("/api/backups", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  const body = z.object({ kind: z.string(), targetId: z.string() }).parse(await c.req.json());
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
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z.object({ kind: z.string(), targetId: z.string() }).parse(await c.req.json());
  const operation = await enqueue({
    kind: "backup.restore_test",
    actorId: access.userId,
    targetIds: [body.targetId],
    payload: body,
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/mail/reconcile", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z.object({ mailboxId: z.string() }).parse(await c.req.json());
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
  const body = z.object({ lifecycle: z.enum(["active", "suspended", "purged"]) }).parse(await c.req.json());
  const [mailbox] = await db
    .select()
    .from(mailboxes)
    .where(eq(mailboxes.id, c.req.param("id")));
  if (!mailbox) throw new HTTPException(404, { message: "Mailbox not found." });
  if (mailbox.lifecycle === "purged")
    throw new HTTPException(409, { message: "A purged mailbox address stays reserved." });
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
  await db
    .update(alerts)
    .set({ acknowledged: true })
    .where(eq(alerts.id, c.req.param("id")));
  return c.json({ ok: true });
});

app.post("/api/updates/apply", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z.object({ serviceId: z.string(), digest: z.string() }).parse(await c.req.json());
  const operation = await enqueue({
    kind: "update.apply",
    actorId: access.userId,
    targetIds: [body.serviceId],
    payload: body,
  });
  return c.json({ operationId: operation.id });
});

app.post("/api/settings/mode", async (c) => {
  const access = c.get("access");
  requireOperator(access);
  requireMfa(c.get("session"));
  const body = z.object({ adminMode: z.enum(["public", "tailnet"]) }).parse(await c.req.json());
  const operation = await enqueue({
    kind: "admin.mode_change",
    actorId: access.userId,
    targetIds: ["platform"],
    payload: body,
  });
  return c.json({ operationId: operation.id });
});

app.put("/api/settings", async (c) => {
  const access = c.get("access");
  requireOperator(access);
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
  return c.json({ ok: true });
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
