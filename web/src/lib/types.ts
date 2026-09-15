export type Role = "owner" | "operator" | "viewer";

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
  } | null;
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
