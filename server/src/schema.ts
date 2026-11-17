import { sql } from "drizzle-orm";
import {
  type AnyPgColumn,
  boolean,
  check,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
} from "drizzle-orm/pg-core";

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
    // No SQL default (0013): every insert names the origin. Set by the Better Auth session hook.
    origin: text("origin").$type<"admin" | "gate">().notNull(),
  },
  (table) => [
    index("session_user_id_idx").on(table.userId),
    check("session_origin_check", sql`${table.origin} IN ('admin', 'gate')`),
  ],
);

export const account = pgTable(
  "account",
  {
    id: text("id").primaryKey(),
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
  (table) => [index("account_user_id_idx").on(table.userId)],
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

export const platformSettings = pgTable(
  "platform_settings",
  {
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
    // Front door (0013). Empty allowlists deny; internet exposure needs the explicit flag.
    publicIpv6: text("public_ipv6"),
    poolerSourceCidrs: jsonb("pooler_source_cidrs").$type<string[]>().notNull().default([]),
    poolerAllowInternet: boolean("pooler_allow_internet").notNull().default(false),
    ipv6Status: text("ipv6_status")
      .$type<"unchecked" | "passed" | "failed" | "not_present">()
      .notNull()
      .default("unchecked"),
    ipv6CheckedAt: timestamp("ipv6_checked_at", { withTimezone: true }),
    ipv6Evidence: jsonb("ipv6_evidence").$type<Record<string, unknown>>(),
    gateLoginMode: text("gate_login_mode").$type<"disabled" | "public">().notNull().default("disabled"),
    gateLoginHostname: text("gate_login_hostname"),
    sniExtraPorts: jsonb("sni_extra_ports").$type<number[]>().notNull().default([]),
    tcpPortRangeStart: integer("tcp_port_range_start").notNull().default(20000),
    tcpPortRangeEnd: integer("tcp_port_range_end").notNull().default(20049),
    // Region preset (0014, FD-03). Drives suggestions only; never AWS_REGION or SES.
    region: text("region")
      .$type<"us-east" | "us-west" | "eu-west" | "eu-central">()
      .notNull()
      .default("us-east"),
    vpsRegionLabel: text("vps_region_label"),
    // Public database port per-source limits (0017, FD-18). Rendered into `inet ark_db_ingress`.
    dbIngressMaxConnections: integer("db_ingress_max_connections").notNull().default(128),
    dbIngressRatePerSecond: integer("db_ingress_rate_per_second").notNull().default(30),
    dbIngressRateBurst: integer("db_ingress_rate_burst").notNull().default(60),
  },
  (table) => [
    check(
      "platform_settings_ipv6_status_check",
      sql`${table.ipv6Status} IN ('unchecked', 'passed', 'failed', 'not_present')`,
    ),
    check("platform_settings_gate_login_mode_check", sql`${table.gateLoginMode} IN ('disabled', 'public')`),
    check(
      "platform_settings_region_check",
      sql`${table.region} IN ('us-east', 'us-west', 'eu-west', 'eu-central')`,
    ),
    check(
      "platform_settings_vps_region_label_check",
      sql`${table.vpsRegionLabel} IS NULL OR char_length(${table.vpsRegionLabel}) BETWEEN 1 AND 64`,
    ),
    check(
      "platform_settings_db_ingress_limits_check",
      sql`${table.dbIngressMaxConnections} BETWEEN 1 AND 65535 AND ${table.dbIngressRatePerSecond} BETWEEN 1 AND 10000 AND ${table.dbIngressRateBurst} BETWEEN ${table.dbIngressRatePerSecond} AND 100000`,
    ),
  ],
);

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
  // Per-domain AAAA switch (R9). Effective AAAA = aaaaEnabled AND ipv6Status = 'passed'.
  aaaaEnabled: boolean("aaaa_enabled").notNull().default(true),
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
    nativeId: text("native_id"),
    status: text("status").notNull().default("active"),
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
  stateful: boolean("stateful").notNull().default(false),
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
  nativeId: text("native_id"),
  secretId: text("secret_id"),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const secrets = pgTable("secrets", {
  id: text("id").primaryKey(),
  kind: text("kind").notNull(),
  resourceType: text("resource_type"),
  resourceId: text("resource_id"),
  purpose: text("purpose"),
  sensitivity: text("sensitivity").notNull().default("credential"),
  keyId: text("key_id").notNull(),
  ciphertext: text("ciphertext").notNull(),
  iv: text("iv").notNull(),
  authTag: text("auth_tag").notNull(),
  once: boolean("once").notNull().default(false),
  revealedAt: timestamp("revealed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const stepUpGrants = pgTable(
  "step_up_grants",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    sessionId: text("session_id").notNull(),
    action: text("action").notNull(),
    planHash: text("plan_hash"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("step_up_grants_lookup_idx").on(table.userId, table.sessionId, table.action)],
);

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

export const workerHeartbeats = pgTable("worker_heartbeats", {
  identity: text("identity").primaryKey(),
  version: text("version").notNull(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
});

export const backups = pgTable("backups", {
  id: text("id").primaryKey(),
  kind: text("kind").notNull(),
  targetId: text("target_id").notNull(),
  status: text("status").notNull().default("queued"),
  checksum: text("checksum"),
  nativeSnapshotId: text("native_snapshot_id"),
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
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    silencedUntil: timestamp("silenced_until", { withTimezone: true }),
    lastNotifiedAt: timestamp("last_notified_at", { withTimezone: true }),
    notificationAttempts: integer("notification_attempts").notNull().default(0),
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

export const deploymentRevisions = pgTable(
  "deployment_revisions",
  {
    id: text("id").primaryKey(),
    serviceId: text("service_id")
      .notNull()
      .references(() => services.id, { onDelete: "cascade" }),
    desiredRevision: text("desired_revision").notNull(),
    compose: text("compose").notNull(),
    imageDigest: text("image_digest"),
    status: text("status").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("deployment_revisions_service_idx").on(table.serviceId, table.createdAt)],
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

// ---- Front door (0013_front_door.sql, docs/design/front-door.md §3.1) ----

// Complete snapshots are independent for edge and backup observation sources.
export const tailnetSnapshots = pgTable(
  "tailnet_snapshots",
  {
    source: text("source").$type<"edge" | "backup">().primaryKey(),
    generation: text("generation").notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }).notNull(),
    validUntil: timestamp("valid_until", { withTimezone: true }).notNull(), // completed_at + 6 minutes
  },
  (table) => [check("tailnet_snapshots_source_check", sql`${table.source} IN ('edge', 'backup')`)],
);

export const tailnetNodes = pgTable(
  "tailnet_nodes",
  {
    source: text("source")
      .$type<"edge" | "backup">()
      .notNull()
      .references(() => tailnetSnapshots.source),
    generation: text("generation").notNull(),
    stableId: text("stable_id").notNull(), // tailcfg.StableNodeID
    dnsName: text("dns_name").notNull(), // MagicDNS FQDN, e.g. home.tail1234.ts.net
    hostName: text("host_name").notNull(),
    ipv4: text("ipv4"),
    ipv6: text("ipv6"),
    tags: jsonb("tags").$type<string[]>().notNull().default([]),
    isSelf: boolean("is_self").notNull().default(false),
    online: boolean("online"),
    observedAt: timestamp("observed_at", { withTimezone: true }).notNull(),
  },
  (table) => [primaryKey({ name: "tailnet_nodes_pkey", columns: [table.source, table.stableId] })],
);

// Private CAs precede front_routes, which references them.
export const privateCas = pgTable(
  "private_cas",
  {
    id: text("id").primaryKey(),
    purpose: text("purpose").$type<"db-client" | "tcp-client" | "http-client">().notNull(),
    name: text("name").notNull(),
    certPem: text("cert_pem").notNull(),
    keySecretId: text("key_secret_id")
      .notNull()
      .references(() => secrets.id),
    crlPem: text("crl_pem"),
    crlNextUpdate: timestamp("crl_next_update", { withTimezone: true }),
    notAfter: timestamp("not_after", { withTimezone: true }).notNull(),
    status: text("status").$type<"active" | "retired" | "revoked">().notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    check("private_cas_purpose_check", sql`${table.purpose} IN ('db-client', 'tcp-client', 'http-client')`),
    check("private_cas_status_check", sql`${table.status} IN ('active', 'retired', 'revoked')`),
  ],
);

export const frontRouteKinds = ["http", "tls", "postgres", "tcp"] as const;
export const frontRouteStatuses = [
  "draft",
  "awaiting_acl",
  "awaiting_dns",
  "issuing_certificate",
  "ready",
  "identity_mismatch",
  "observation_expired",
  "disabled",
  "error",
] as const;

// One row per public route. A hostname has at most one route per listener (443, each shared SNI
// port, 5432), so an HTTP and a TLS-TCP route cannot share 443; raw-TCP ports are unique globally.
export const frontRoutes = pgTable(
  "front_routes",
  {
    id: text("id").primaryKey(),
    kind: text("kind").$type<(typeof frontRouteKinds)[number]>().notNull(),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "restrict" }),
    listenPort: integer("listen_port").notNull(),
    compatPort: integer("compat_port"),
    targetInput: text("target_input").notNull(),
    targetNodeStableId: text("target_node_stable_id").notNull(),
    targetIp: text("target_ip").notNull(),
    targetPort: integer("target_port").notNull(),
    accessMode: text("access_mode").$type<"public" | "sso">().notNull().default("sso"),
    bypassPaths: jsonb("bypass_paths").$type<string[]>().notNull().default([]),
    httpOptions: jsonb("http_options").$type<Record<string, unknown>>().notNull().default({}),
    tlsMode: text("tls_mode").$type<"passthrough" | "terminate" | "terminate_mtls" | "plain">(),
    tcpOptions: jsonb("tcp_options").$type<Record<string, unknown>>().notNull().default({}),
    sourceCidrs: jsonb("source_cidrs").$type<string[]>().notNull().default([]), // empty = deny all
    allowInternet: boolean("allow_internet").notNull().default(false),
    clientCaId: text("client_ca_id").references(() => privateCas.id),
    rateLimit: jsonb("rate_limit").$type<Record<string, unknown>>(), // reserved; not rendered in v1
    enabled: boolean("enabled").notNull().default(false),
    status: text("status").$type<(typeof frontRouteStatuses)[number]>().notNull().default("draft"),
    lastError: text("last_error"),
    createdBy: text("created_by").references(() => user.id),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    check("front_routes_kind_check", sql`${table.kind} IN ('http', 'tls', 'postgres', 'tcp')`),
    check("front_routes_target_port_check", sql`${table.targetPort} BETWEEN 1 AND 65535`),
    check("front_routes_access_mode_check", sql`${table.accessMode} IN ('public', 'sso')`),
    check(
      "front_routes_tls_mode_check",
      sql`${table.tlsMode} IN ('passthrough', 'terminate', 'terminate_mtls', 'plain')`,
    ),
    uniqueIndex("front_routes_endpoint_listener")
      .on(table.endpointId, table.listenPort)
      .where(sql`kind <> 'tcp'`),
    uniqueIndex("front_routes_dedicated_port")
      .on(table.listenPort)
      .where(sql`kind = 'tcp'`),
    uniqueIndex("front_routes_compat_port")
      .on(table.compatPort)
      .where(sql`compat_port IS NOT NULL`),
  ],
);

// Individual users only (R11); no groups in v1.
export const frontRouteAccess = pgTable(
  "front_route_access",
  {
    routeId: text("route_id")
      .notNull()
      .references(() => frontRoutes.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    grantedBy: text("granted_by").references(() => user.id),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [primaryKey({ name: "front_route_access_pkey", columns: [table.routeId, table.userId] })],
);

export const gateHandoffs = pgTable("gate_handoffs", {
  id: text("id").primaryKey(),
  codeHash: text("code_hash").notNull().unique("gate_handoffs_code_hash_key"), // sha256 of a 32-byte code
  routeId: text("route_id")
    .notNull()
    .references(() => frontRoutes.id, { onDelete: "cascade" }),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  authSessionId: text("auth_session_id")
    .notNull()
    .references(() => session.id, { onDelete: "cascade" }),
  stateHash: text("state_hash").notNull(),
  returnPath: text("return_path").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(), // now() + 60s
  consumedAt: timestamp("consumed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const gateSessions = pgTable(
  "gate_sessions",
  {
    id: text("id").primaryKey(),
    tokenHash: text("token_hash").notNull().unique("gate_sessions_token_hash_key"),
    routeId: text("route_id")
      .notNull()
      .references(() => frontRoutes.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    authSessionId: text("auth_session_id")
      .notNull()
      .references(() => session.id, { onDelete: "cascade" }),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [index("gate_sessions_user_idx").on(table.userId)],
);

export const clientCertificates = pgTable(
  "client_certificates",
  {
    id: text("id").primaryKey(),
    caId: text("ca_id")
      .notNull()
      .references(() => privateCas.id, { onDelete: "cascade" }),
    subjectCn: text("subject_cn").notNull(),
    serial: text("serial").notNull(),
    fingerprintSha256: text("fingerprint_sha256").notNull(),
    notBefore: timestamp("not_before", { withTimezone: true }).notNull(),
    notAfter: timestamp("not_after", { withTimezone: true }).notNull(), // not_before + 90 days (R6)
    // 0015: the issued certificate (public). Written by modules/pki.ts; nullable for hand-made rows.
    certPem: text("cert_pem"),
    keySecretId: text("key_secret_id").references(() => secrets.id),
    status: text("status").$type<"issued" | "revoked" | "expired">().notNull().default("issued"),
    rolloverState: text("rollover_state")
      .$type<"current" | "pending" | "delivered" | "superseded" | "retired">()
      .notNull()
      .default("current"),
    supersededBy: text("superseded_by").references((): AnyPgColumn => clientCertificates.id),
    deliveredAt: timestamp("delivered_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    revokedReason: text("revoked_reason"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    // 0020 (FD-28): one-time reveal of a rollover successor, and retirement completion.
    trustAppliedAt: timestamp("trust_applied_at", { withTimezone: true }),
    revealedAt: timestamp("revealed_at", { withTimezone: true }),
    retiredAt: timestamp("retired_at", { withTimezone: true }),
  },
  (table) => [
    check("client_certificates_status_check", sql`${table.status} IN ('issued', 'revoked', 'expired')`),
    check(
      "client_certificates_rollover_state_check",
      sql`${table.rolloverState} IN ('current', 'pending', 'delivered', 'superseded', 'retired')`,
    ),
    unique("client_certificates_ca_id_serial_key").on(table.caId, table.serial),
    uniqueIndex("client_certificates_successor_unique")
      .on(table.supersededBy)
      .where(sql`superseded_by IS NOT NULL`),
    index("client_certificates_issued_not_after_idx")
      .on(table.notAfter)
      .where(sql`status = 'issued'`),
  ],
);

/**
 * 0020 (FD-28): the durable retirement task of one certificate generation (§3.10.4 step 4).
 * The timestamps are the measured fence → reload → drain → reopen timeline.
 */
export const clientCertificateRetirements = pgTable(
  "client_certificate_retirements",
  {
    certificateId: text("certificate_id")
      .primaryKey()
      .references(() => clientCertificates.id, { onDelete: "cascade" }),
    clientId: text("client_id")
      .notNull()
      .references(() => databaseClients.id, { onDelete: "cascade" }),
    role: text("role").notNull(),
    databaseName: text("database_name").notNull(),
    notAfter: timestamp("not_after", { withTimezone: true }).notNull(),
    deadline: timestamp("deadline", { withTimezone: true }).notNull(),
    attempts: integer("attempts").notNull().default(0),
    leaseUntil: timestamp("lease_until", { withTimezone: true }),
    lastError: text("last_error"),
    fencedAt: timestamp("fenced_at", { withTimezone: true }),
    reloadedAt: timestamp("reloaded_at", { withTimezone: true }),
    drainedAt: timestamp("drained_at", { withTimezone: true }),
    reopenedAt: timestamp("reopened_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    deadlineMissed: boolean("deadline_missed").notNull().default(false),
    watchdogAt: timestamp("watchdog_at", { withTimezone: true }),
    evidence: jsonb("evidence").$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("client_certificate_retirements_open_idx")
      .on(table.deadline)
      .where(sql`completed_at IS NULL`),
  ],
);

export const databaseClients = pgTable(
  "database_clients",
  {
    id: text("id").primaryKey(),
    databaseId: text("database_id")
      .notNull()
      .references(() => managedDatabases.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    environment: text("environment").notNull(),
    roleKind: text("role_kind").$type<"runtime" | "readonly">().notNull(),
    roleId: text("role_id")
      .notNull()
      .references(() => databaseRoles.id),
    caId: text("ca_id")
      .notNull()
      .references(() => privateCas.id),
    status: text("status").$type<"active" | "revoked">().notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    // 0018 (FD-17): issuance source, the one-time reveal gate and revocation history.
    keySource: text("key_source").$type<"generated" | "csr">().notNull().default("generated"),
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    // 0019: lifecycle completion, separate from admission intent.
    issuedAt: timestamp("issued_at", { withTimezone: true }).defaultNow(),
    revocationCompletedAt: timestamp("revocation_completed_at", { withTimezone: true }),
    revealedAt: timestamp("revealed_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    revokedBy: text("revoked_by").references(() => user.id, { onDelete: "set null" }),
  },
  (table) => [
    check("database_clients_role_kind_check", sql`${table.roleKind} IN ('runtime', 'readonly')`),
    check("database_clients_status_check", sql`${table.status} IN ('active', 'revoked')`),
    check("database_clients_key_source_check", sql`${table.keySource} IN ('generated', 'csr')`),
    uniqueIndex("database_clients_role_id_key").on(table.roleId),
    unique("database_clients_database_id_name_environment_key").on(
      table.databaseId,
      table.name,
      table.environment,
    ),
  ],
);

// Shared, expiring sliding-window counters for CSR submission (including rejected requests).
export const clientIssueLimits = pgTable(
  "client_issue_limits",
  {
    userId: text("user_id")
      .primaryKey()
      .references(() => user.id, { onDelete: "cascade" }),
    attempts: jsonb("attempts").$type<number[]>().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
  },
  (table) => [index("client_issue_limits_updated_at_idx").on(table.updatedAt)],
);

// Optional Vercel integration (R6), one per database client.
export const vercelIntegrations = pgTable(
  "vercel_integrations",
  {
    id: text("id").primaryKey(),
    databaseClientId: text("database_client_id")
      .notNull()
      .unique("vercel_integrations_database_client_id_key")
      .references(() => databaseClients.id, { onDelete: "cascade" }),
    vercelProjectId: text("vercel_project_id").notNull(),
    vercelTeamId: text("vercel_team_id"),
    tokenSecretId: text("token_secret_id")
      .notNull()
      .references(() => secrets.id),
    tokenExpiresAt: timestamp("token_expires_at", { withTimezone: true }),
    deployHookSecretId: text("deploy_hook_secret_id").references(() => secrets.id),
    envTarget: text("env_target").$type<"production" | "preview">().notNull(),
    gitBranch: text("git_branch"),
    lastPushAt: timestamp("last_push_at", { withTimezone: true }),
    lastPushStatus: text("last_push_status"),
    lastDeploymentId: text("last_deployment_id"),
    createdBy: text("created_by").references(() => user.id),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    check("vercel_integrations_env_target_check", sql`${table.envTarget} IN ('production', 'preview')`),
  ],
);

// Off-VPS backup destinations (R8): both kinds are required for "backups healthy".
export const backupTargets = pgTable(
  "backup_targets",
  {
    id: text("id").primaryKey(),
    kind: text("kind").$type<"s3" | "tailnet_rest">().notNull(),
    name: text("name").notNull(),
    endpoint: text("endpoint"),
    region: text("region"),
    bucket: text("bucket"),
    prefix: text("prefix").notNull().default("ark"),
    pathStyle: boolean("path_style").notNull().default(false),
    restUrl: text("rest_url"),
    targetNodeStableId: text("target_node_stable_id"), // tailnet_rest: pinned like routes (§3.2)
    credentialSecretId: text("credential_secret_id")
      .notNull()
      .references(() => secrets.id),
    appendOnlyVerified: boolean("append_only_verified").notNull().default(false),
    appendOnlyEvidence: jsonb("append_only_evidence").$type<Record<string, unknown>>(),
    lastSuccessAt: timestamp("last_success_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [check("backup_targets_kind_check", sql`${table.kind} IN ('s3', 'tailnet_rest')`)],
);

// Last generated Tailscale policy snippet per scope (0016, front door §3.7, FD-07): the diff baseline.
export const tailnetAclSnippets = pgTable(
  "tailnet_acl_snippets",
  {
    scope: text("scope").primaryKey(), // 'global' or 'route:<route id>'
    routeId: text("route_id").references(() => frontRoutes.id, { onDelete: "cascade" }),
    digest: text("digest").notNull(),
    snippet: text("snippet").notNull(),
    generatedAt: timestamp("generated_at", { withTimezone: true }).notNull().defaultNow(),
    previousDigest: text("previous_digest"),
    previousSnippet: text("previous_snippet"),
    previousGeneratedAt: timestamp("previous_generated_at", { withTimezone: true }),
  },
  (table) => [
    check(
      "tailnet_acl_snippets_scope_check",
      sql`(${table.scope} = 'global' AND ${table.routeId} IS NULL) OR (${table.routeId} IS NOT NULL AND ${table.scope} = 'route:' || ${table.routeId})`,
    ),
  ],
);

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
  stepUpGrants,
  operations,
  operationSteps,
  backups,
  alerts,
  updateCandidates,
  auditEvents,
  tailnetSnapshots,
  tailnetNodes,
  privateCas,
  frontRoutes,
  frontRouteAccess,
  gateHandoffs,
  gateSessions,
  clientCertificates,
  databaseClients,
  clientIssueLimits,
  vercelIntegrations,
  backupTargets,
  tailnetAclSnippets,
};
