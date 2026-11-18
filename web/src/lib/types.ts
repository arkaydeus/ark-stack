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
  enabled: boolean;
  status: string;
  lastError: string | null;
  domain: { id: string; name: string; status: string; dnsProvider: string } | null;
  l4: {
    tlsMode: string | null;
    sourceCidrs: string[];
    allowInternet: boolean;
    internetConfirmedAt: string | null;
    protocolAuthConfirmed: boolean;
    limits: { maxConn: number; perSourceConn: number; perSourceRate: number } | null;
    clientCaId: string | null;
    admits: "internet" | "allowlist" | "nobody";
  } | null;
};

/** `GET /api/front/listeners` (§3.8.2, FD-14). */
export type FrontListeners = {
  sniRouterPort: number;
  sharedSniPorts: { available: number[]; enabled: number[] };
  tcpPorts: { start: number; end: number };
  reservedPorts: number[];
  tlsModes: string[];
  guidance: Array<{ protocol: string; tlsFirst: string; byName: string; kind: string | null; notes: string }>;
};
