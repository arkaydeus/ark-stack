export type Role = "owner" | "operator" | "viewer";

export type PlatformRegion = "us-east" | "us-west" | "eu-west" | "eu-central";

/** Mirrors `regionSummary` in shared/src/region.ts. */
export type RegionSummary = {
  region: PlatformRegion;
  label: string;
  vercelRegion: string;
  vercelLocation: string;
  backupRegionHint: string;
  docsLabel: string;
  vpsRegionLabel: string | null;
  vercelConfig: { regions: string[] };
  vercelSnippet: string;
  latencyHint: string;
  options: Array<{ region: PlatformRegion; label: string; vercelRegion: string }>;
};

export type DbIngressLimits = {
  maxConnectionsPerSource: number;
  newConnectionsPerSecond: number;
  newConnectionBurst: number;
};

type Bounds = { min: number; max: number };

/** Mirrors `dbIngressLimitsSummary` in shared/src/db-ingress.ts. */
export type DbIngressSummary = DbIngressLimits & {
  defaults: DbIngressLimits;
  bounds: Record<keyof DbIngressLimits, Bounds>;
  ipv6Grouping: "/64";
  port: number;
};

/** Mirrors `FrontAclResponse` in server/src/modules/front-acl.ts (front door §3.7). */
export type FrontAclSnippet = {
  scope: "global" | "route";
  routeId: string | null;
  tailnet: string | null;
  snippet: string;
  digest: string;
  generatedAt: string;
  sshExample: string;
  omitted: Array<{ kind: "route" | "backup"; id: string; reason: string }>;
  previous: { digest: string; generatedAt: string | null } | null;
  diff: Array<{ op: "same" | "add" | "remove"; line: string }> | null;
  routes: Array<{ id: string; kind: string; hostname: string; listenPort: number; status: string }>;
};

export type PoolerPolicyStatus =
  | "no_public_databases"
  | "invalid_policy"
  | "deny_all"
  | "unconfirmed_internet"
  | "review_required"
  | "published"
  | "fenced";

export type PoolerRequestSource =
  | { kind: "database"; id: string; name: string }
  | { kind: "vercel_client"; id: string; name: string; databaseId: string };

/** What every role sees of the pooler policy (`poolerPolicyView` in server/src/app.ts). */
export type PoolerPolicyBrief = {
  scope: "pooler-wide";
  status: PoolerPolicyStatus;
  publishable: boolean;
  message: string;
  boundary: string;
  conflict: boolean;
};

/** Mirrors `evaluatePoolerPolicy` in shared/src/pooler-policy.ts (owners and operators). */
export type PoolerPolicyFull = PoolerPolicyBrief & {
  policyPublishable: boolean;
  fence: { at: string; reason: string | null } | null;
  policy: {
    sourceCidrs: string[];
    allowInternet: boolean;
    admits: "internet" | "allowlist" | "nobody";
    rendered: string[];
    internetConfirmedAt: string | null;
    reviewedAt: string | null;
  };
  requests: Array<{ source: PoolerRequestSource; unrestricted: boolean; sourceCidrs: string[]; key: string }>;
  distinctRequests: string[];
  requestsFingerprint: string;
  conflicts: Array<{
    reason: "different_cidrs" | "restricted_with_unrestricted";
    message: string;
    sources: PoolerRequestSource[];
  }>;
  matchesRequests: boolean;
  reviewed: boolean;
};

export type PlatformState = {
  user: { id: string; name: string; email: string; role: Role; twoFactorEnabled?: boolean };
  setup: {
    completed: boolean;
    wizardCompleted: boolean;
    mfaEnrolled: boolean;
    mfaAssured: boolean;
  };
  settings: {
    adminMode: string;
    timezone: string;
    baseDomain: string | null;
    adminHostname: string | null;
    publicIpv4: string | null;
    dnsProvider: string;
    defaultQuotaGb: number;
    allowExternalForwarding: boolean;
    region?: PlatformRegion;
    vpsRegionLabel?: string | null;
  } | null;
  /** Region preset and its derived suggestions (front door §3.15). Absent on an older API. */
  region?: RegionSummary;
  /** Per-source limits on the public database port (front door §3.11). Absent on an older API. */
  dbIngress?: DbIngressSummary;
  /**
   * The one pooler-wide source policy on public 5432 (front door §3.8.3, FD-26). Owners and operators
   * get the full evaluation; viewers only the boundary and publication state. Absent on an older API.
   */
  poolerPolicy?: PoolerPolicyFull | PoolerPolicyBrief;
  domains: Array<{
    id: string;
    name: string;
    status: string;
    ownershipToken: string;
    records: Array<{
      id: string;
      type: string;
      name: string;
      relativeName: string;
      expectedValue: string;
      observedValue: string | null;
      purpose: string;
      status: string;
    }>;
  }>;
  endpoints: Array<{ id: string; kind: string; hostname: string; exposure: string; status: string }>;
  certificates: Array<{
    id: string;
    endpointId: string;
    issuer: string;
    status: string;
    expiresAt: string | null;
  }>;
  clusters: Array<{ id: string; name: string; status: string; major: string }>;
  databases: Array<{
    id: string;
    name: string;
    exposure: string;
    status: string;
    sourceCidrs?: string[];
    roles: Array<{ id: string; name: string; kind: string }>;
  }>;
  devices?: Array<{
    id: string;
    mailboxId: string;
    label: string;
    nativeId?: string | null;
    secretId?: string | null;
    revokedAt: string | null;
  }>;
  mailboxes: Array<{
    id: string;
    address: string;
    displayName: string;
    lifecycle: string;
    credentialAvailable: boolean;
    domainId: string;
  }>;
  aliases: Array<{
    id: string;
    address: string;
    targets: string[];
    description: string | null;
    status: string;
  }>;
  mailDomains: Array<{ id: string; inboundStatus: string; outboundStatus: string; clientStatus: string }>;
  projects: Array<{ id: string; name: string; slug: string }>;
  services: Array<{
    id: string;
    projectId: string;
    name: string;
    status: string;
    updatePolicy: string;
    stateful: boolean;
    observedAt: string | null;
    imageDigest: string | null;
  }>;
  operations: Array<{ id: string; kind: string; status: string; error: string | null; createdAt: string }>;
  steps: Array<{ id: string; operationId: string; name: string; status: string }>;
  backups: Array<{
    id: string;
    kind: string;
    targetId: string;
    status: string;
    restoreVerified: boolean;
    createdAt: string;
  }>;
  alerts: Array<{
    id: string;
    severity: string;
    title: string;
    acknowledged: boolean;
    resolvedAt: string | null;
    silencedUntil: string | null;
  }>;
  audit: Array<{ id: string; action: string; resourceType: string; createdAt: string }>;
  updateCandidates?: Array<{
    id: string;
    serviceId: string;
    image: string;
    currentDigest: string | null;
    candidateDigest: string | null;
    requiresApproval: boolean;
    rollbackSafe: boolean;
  }>;
  providers?: { cloudflare: boolean; ses: boolean; stalwart: boolean; alertWebhook: boolean };
};

/** `GET /api/front/routes` (FD-08, FD-14). */
export type FrontRouteSummary = {
  id: string;
  kind: "http" | "tls" | "tcp" | "postgres";
  hostname: string;
  listenPort: number;
  accessMode: string | null;
  /** HTTP routes (FD-23): requests per window per client address, or null for no limit. */
  rateLimit?: { requests: number; window: string } | null;
  /** HTTP routes (FD-23): a client certificate from the route's own CA is required. */
  mtls?: boolean;
  enabled: boolean;
  status: string;
  lastError: string | null;
  domain: { id: string; name: string; status: string; dnsProvider: string } | null;
  l4: {
    tlsMode: string | null;
    /** `postgres` passthrough routes only: the opt-in classic-SSLRequest port, or null (FD-26). */
    compatPort: number | null;
    sourceCidrs: string[];
    allowInternet: boolean;
    internetConfirmedAt: string | null;
    protocolAuthConfirmed: boolean;
    limits: { maxConn: number; perSourceConn: number; perSourceRate: number } | null;
    clientCaId: string | null;
    admits: "internet" | "allowlist" | "nobody";
  } | null;
};

/** `GET /api/front/routes/:id/client-certificates` (FD-14 terminate_mtls, FD-23 HTTP mTLS). */
export type RouteClientCertificates = {
  ca: { id: string; name: string; status: string; certPem: string; notAfter: string } | null;
  certificates: Array<{
    id: string;
    subjectCn: string;
    serial: string;
    notAfter: string;
    status: string;
    revokedAt: string | null;
    certPem: string | null;
    keySecretId: string | null;
  }>;
};

/** `GET /api/front/listeners` (§3.8.2, FD-14). */
export type FrontListeners = {
  sniRouterPort: number;
  sharedSniPorts: { available: number[]; enabled: number[] };
  tcpPorts: { start: number; end: number };
  reservedPorts: number[];
  tlsModes: string[];
  guidance: Array<{ protocol: string; tlsFirst: string; byName: string; kind: string | null; notes: string }>;
  /** Postgres routes on the 5432 router (§3.8.3, FD-26). Absent on an older API. */
  postgres?: {
    port: number;
    compatPorts: { start: number; end: number };
    checklist: Array<{ id: string; title: string; detail: string }>;
    drivers: Array<{ client: string; option: string; since: string; verified: boolean }>;
    notes: string[];
    poolerBoundary: string;
  };
};
