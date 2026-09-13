import { boolean, index, integer, jsonb, pgTable, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";

export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  twoFactorEnabled: boolean("two_factor_enabled").notNull().default(false),
  mfaEnrolledAt: timestamp("mfa_enrolled_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const session = pgTable(
  "session",
  {
    id: text("id").primaryKey(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    token: text("token").notNull().unique(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
  },
  (table) => [index("session_user_id_idx").on(table.userId)],
);

export const account = pgTable(
  "account",
  {
    id: text("id").primaryKey(),
    issuer: text("issuer").notNull(),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    idToken: text("id_token"),
    accessTokenExpiresAt: timestamp("access_token_expires_at", { withTimezone: true }),
    refreshTokenExpiresAt: timestamp("refresh_token_expires_at", { withTimezone: true }),
    scope: text("scope"),
    password: text("password"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("account_issuer_account_id_idx").on(table.issuer, table.accountId),
    index("account_user_id_idx").on(table.userId),
  ],
);

export const verification = pgTable(
  "verification",
  {
    id: text("id").primaryKey(),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("verification_identifier_idx").on(table.identifier)],
);

export const twoFactor = pgTable("two_factor", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  secret: text("secret").notNull(),
  backupCodes: text("backup_codes").notNull(),
  verified: boolean("verified").default(true),
  failedVerificationCount: integer("failed_verification_count").default(0),
  lockedUntil: timestamp("locked_until", { withTimezone: true }),
});

export const platformSetup = pgTable("platform_setup", {
  id: text("id").primaryKey().default("default"),
  completed: boolean("completed").notNull().default(false),
  wizardCompleted: boolean("wizard_completed").notNull().default(false),
  bootstrapClosedAt: timestamp("bootstrap_closed_at", { withTimezone: true }),
});

export const platformAccess = pgTable("platform_access", {
  userId: text("user_id")
    .primaryKey()
    .references(() => user.id, { onDelete: "cascade" }),
  role: text("role").notNull().default("viewer"),
  projectIds: jsonb("project_ids").$type<string[]>().notNull().default([]),
  domainIds: jsonb("domain_ids").$type<string[]>().notNull().default([]),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const platformSettings = pgTable("platform_settings", {
  id: text("id").primaryKey().default("default"),
  adminMode: text("admin_mode").notNull().default("public"),
  timezone: text("timezone").notNull().default("Europe/London"),
  baseDomain: text("base_domain"),
  adminHostname: text("admin_hostname"),
  authOrigin: text("auth_origin"),
  publicIpv4: text("public_ipv4"),
  dnsProvider: text("dns_provider").notNull().default("manual"),
  defaultQuotaGb: integer("default_quota_gb").notNull().default(10),
  allowExternalForwarding: boolean("allow_external_forwarding").notNull().default(false),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const projects = pgTable("projects", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const domainClaims = pgTable("domain_claims", {
  id: text("id").primaryKey(),
  name: text("name").notNull().unique(),
  ownershipToken: text("ownership_token").notNull(),
  status: text("status").notNull().default("draft"),
  dnsProvider: text("dns_provider").notNull().default("manual"),
  mailFrom: text("mail_from"),
  dmarcPolicy: text("dmarc_policy").notNull().default("none"),
  lastError: text("last_error"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const dnsRecords = pgTable(
  "dns_records",
  {
    id: text("id").primaryKey(),
    domainId: text("domain_id")
      .notNull()
      .references(() => domainClaims.id, { onDelete: "cascade" }),
    type: text("type").notNull(),
    name: text("name").notNull(),
    relativeName: text("relative_name").notNull(),
    expectedValue: text("expected_value").notNull(),
    observedValue: text("observed_value"),
    purpose: text("purpose").notNull(),
    required: boolean("required").notNull().default(true),
    status: text("status").notNull().default("pending"),
  },
  (table) => [index("dns_records_domain_idx").on(table.domainId)],
);

export const endpoints = pgTable("endpoints", {
  id: text("id").primaryKey(),
  kind: text("kind").notNull(),
  hostname: text("hostname").notNull().unique(),
  domainId: text("domain_id").references(() => domainClaims.id, { onDelete: "restrict" }),
  exposure: text("exposure").notNull().default("public"),
  status: text("status").notNull().default("draft"),
  lastVerifiedAt: timestamp("last_verified_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const certificates = pgTable("certificates", {
  id: text("id").primaryKey(),
  endpointId: text("endpoint_id")
    .notNull()
    .references(() => endpoints.id, { onDelete: "cascade" }),
  names: jsonb("names").$type<string[]>().notNull(),
  issuer: text("issuer").notNull().default("pending"),
  fingerprint: text("fingerprint"),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  status: text("status").notNull().default("pending"),
  lastDeployedAt: timestamp("last_deployed_at", { withTimezone: true }),
});

export const databaseClusters = pgTable("database_clusters", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  major: text("major").notNull().default("17"),
  endpointId: text("endpoint_id").references(() => endpoints.id),
  status: text("status").notNull().default("provisioning"),
  observedAt: timestamp("observed_at", { withTimezone: true }),
});

export const managedDatabases = pgTable(
  "managed_databases",
  {
    id: text("id").primaryKey(),
    clusterId: text("cluster_id")
      .notNull()
      .references(() => databaseClusters.id, { onDelete: "restrict" }),
    projectId: text("project_id").references(() => projects.id),
    name: text("name").notNull(),
    exposure: text("exposure").notNull().default("public"),
    withPgvector: boolean("with_pgvector").notNull().default(false),
    withTestDatabase: boolean("with_test_database").notNull().default(false),
    sourceCidrs: jsonb("source_cidrs").$type<string[]>().notNull().default([]),
    allowlistEnforced: boolean("allowlist_enforced").notNull().default(false),
    status: text("status").notNull().default("queued"),
  },
  (table) => [uniqueIndex("managed_databases_cluster_name_idx").on(table.clusterId, table.name)],
);

export const databaseRoles = pgTable("database_roles", {
  id: text("id").primaryKey(),
  databaseId: text("database_id")
    .notNull()
    .references(() => managedDatabases.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  kind: text("kind").notNull(),
  secretId: text("secret_id"),
  connectionLimit: integer("connection_limit").notNull().default(20),
});

export const mailDomains = pgTable("mail_domains", {
  id: text("id").primaryKey(),
  domainId: text("domain_id")
    .notNull()
    .references(() => domainClaims.id, { onDelete: "restrict" }),
  inboundStatus: text("inbound_status").notNull().default("pending"),
  outboundStatus: text("outbound_status").notNull().default("paused"),
  clientStatus: text("client_status").notNull().default("pending"),
});

export const mailboxes = pgTable(
  "mailboxes",
  {
    id: text("id").primaryKey(),
    domainId: text("domain_id")
      .notNull()
      .references(() => domainClaims.id, { onDelete: "restrict" }),
    localPart: text("local_part").notNull(),
    displayName: text("display_name").notNull(),
    quotaGb: integer("quota_gb").notNull().default(10),
    lifecycle: text("lifecycle").notNull().default("active"),
    credentialAvailable: boolean("credential_available").notNull().default(true),
    nativeId: text("native_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex("mailboxes_domain_local_idx").on(table.domainId, table.localPart)],
);

export const aliases = pgTable(
  "aliases",
  {
    id: text("id").primaryKey(),
    domainId: text("domain_id")
      .notNull()
      .references(() => domainClaims.id, { onDelete: "restrict" }),
    localPart: text("local_part").notNull(),
    description: text("description"),
    targets: jsonb("targets").$type<string[]>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex("aliases_domain_local_idx").on(table.domainId, table.localPart)],
);

export const services = pgTable("services", {
  id: text("id").primaryKey(),
  projectId: text("project_id")
    .notNull()
    .references(() => projects.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  compose: text("compose").notNull(),
  imageDigest: text("image_digest"),
  desiredRevision: text("desired_revision").notNull(),
  observedRevision: text("observed_revision"),
  status: text("status").notNull().default("registered"),
  updatePolicy: text("update_policy").notNull().default("notify"),
  protected: boolean("protected").notNull().default(false),
  containerId: text("container_id"),
  adoptedFrom: text("adopted_from"),
  observedAt: timestamp("observed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const mailboxDevices = pgTable("mailbox_devices", {
  id: text("id").primaryKey(),
  mailboxId: text("mailbox_id")
    .notNull()
    .references(() => mailboxes.id, { onDelete: "cascade" }),
  label: text("label").notNull(),
  secretId: text("secret_id"),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const secrets = pgTable("secrets", {
  id: text("id").primaryKey(),
  kind: text("kind").notNull(),
  keyId: text("key_id").notNull(),
  ciphertext: text("ciphertext").notNull(),
  iv: text("iv").notNull(),
  authTag: text("auth_tag").notNull(),
  once: boolean("once").notNull().default(false),
  revealedAt: timestamp("revealed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const operations = pgTable(
  "operations",
  {
    id: text("id").primaryKey(),
    kind: text("kind").notNull(),
    status: text("status").notNull().default("queued"),
    actorId: text("actor_id"),
    idempotencyKey: text("idempotency_key").notNull(),
    planHash: text("plan_hash").notNull(),
    targetIds: jsonb("target_ids").$type<string[]>().notNull().default([]),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull().default({}),
    claimToken: text("claim_token"),
    heartbeatAt: timestamp("heartbeat_at", { withTimezone: true }),
    error: text("error"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("operations_idempotency_idx").on(table.idempotencyKey),
    index("operations_status_idx").on(table.status, table.createdAt),
  ],
);

export const operationSteps = pgTable(
  "operation_steps",
  {
    id: text("id").primaryKey(),
    operationId: text("operation_id")
      .notNull()
      .references(() => operations.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    status: text("status").notNull().default("queued"),
    evidence: jsonb("evidence").$type<Record<string, unknown>>().notNull().default({}),
    error: text("error"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("operation_steps_op_idx").on(table.operationId)],
);

export const backups = pgTable("backups", {
  id: text("id").primaryKey(),
  kind: text("kind").notNull(),
  targetId: text("target_id").notNull(),
  status: text("status").notNull().default("queued"),
  checksum: text("checksum"),
  restoreVerified: boolean("restore_verified").notNull().default(false),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const alerts = pgTable(
  "alerts",
  {
    id: text("id").primaryKey(),
    severity: text("severity").notNull(),
    title: text("title").notNull(),
    dedupKey: text("dedup_key").notNull(),
    acknowledged: boolean("acknowledged").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex("alerts_dedup_key_idx").on(table.dedupKey)],
);

export const updateCandidates = pgTable(
  "update_candidates",
  {
    id: text("id").primaryKey(),
    serviceId: text("service_id")
      .notNull()
      .references(() => services.id, { onDelete: "cascade" }),
    image: text("image").notNull(),
    currentDigest: text("current_digest"),
    candidateDigest: text("candidate_digest"),
    requiresApproval: boolean("requires_approval").notNull().default(true),
    rollbackSafe: boolean("rollback_safe").notNull().default(false),
    detectedAt: timestamp("detected_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex("update_candidates_service_idx").on(table.serviceId)],
);

export const auditEvents = pgTable("audit_events", {
  id: text("id").primaryKey(),
  actorId: text("actor_id"),
  action: text("action").notNull(),
  resourceType: text("resource_type").notNull(),
  resourceId: text("resource_id"),
  role: text("role"),
  operationId: text("operation_id"),
  detail: jsonb("detail").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const schema = {
  user,
  session,
  account,
  verification,
  twoFactor,
  platformSetup,
  platformAccess,
  platformSettings,
  projects,
  domainClaims,
  dnsRecords,
  endpoints,
  certificates,
  databaseClusters,
  managedDatabases,
  databaseRoles,
  mailDomains,
  mailboxes,
  mailboxDevices,
  aliases,
  services,
  secrets,
  operations,
  operationSteps,
  backups,
  alerts,
  updateCandidates,
  auditEvents,
};
