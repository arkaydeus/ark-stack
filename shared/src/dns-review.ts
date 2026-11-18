export type CloudflareRecordEvidence = {
  id: string;
  type: string;
  name: string;
  content: string;
  ttl: number;
  proxied: boolean;
  priority?: number;
  comment?: string;
  modifiedOn?: string;
};

export type CloudflareOwnership = {
  zoneId: string;
  record: CloudflareRecordEvidence;
};

export type DnsReviewAction = {
  recordId: string;
  action: "keep" | "update" | "create" | "delete" | "blocked";
  before: CloudflareRecordEvidence | null;
  after: {
    type: string;
    name: string;
    content: string;
    ttl: number;
    proxied: false;
    priority?: number;
  } | null;
  reason?: string;
  deletionScope?: CloudflareOwnership;
  canAuthorizeWithdrawal?: boolean;
};

export type DnsReviewRecord = {
  id: string;
  type: string;
  name: string;
  relativeName: string;
  value: string;
  observed: string | null;
  ttl: number;
  priority?: number;
  purpose: string;
  status: string;
  providerRemoval: "review" | "automatic" | "manual" | "propagating" | null;
};

export type DomainDnsReview = {
  domainId: string;
  zone: string;
  provider: string;
  aaaaEnabled: boolean;
  automaticWithdrawalAuthorized: boolean;
  ipv6Status: "eligible" | "withdrawal_pending" | "a_only";
  lastError: string | null;
  records: DnsReviewRecord[];
  guides: Array<{ title: string; steps: string[]; url?: string }>;
  cloudflare: {
    planHash: string;
    actions: DnsReviewAction[];
  } | null;
};

export type DnsPublishStatus = {
  operationId: string;
  status: string;
  error: string | null;
  errorStatus: number | null;
  applied: number;
  total: number | null;
  verificationOperationId: string | null;
};
