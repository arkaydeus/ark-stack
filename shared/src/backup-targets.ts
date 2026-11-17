// Off-VPS backup destinations (docs/design/front-door.md §3.18, FD-21).
//
// One `backup_targets` shape covers every S3-compatible provider (AWS S3, Backblaze B2, Cloudflare R2,
// MinIO): endpoint, region (suggested by the FD-03 region preset), bucket, prefix and path style. Each
// target holds one restic repository at `<prefix>/restic`, which receives immutable snapshots of the
// staged local pgBackRest repositories and the mail/volume backups.
//
// FD-30 adds `tailnet_rest`: a restic REST repository on the owner's home machine
// (`rest-server --append-only --private-repos`), reached only through the dedicated `backup-ts`
// node's SOCKS5 proxy and pinned like a route (StableNodeID + address from backup-ts's own
// observation, §3.18.3). Health, alerts and the exporter iterate targets of any kind.
import { z } from "zod";

import { parseIpLiteral, checkTailnetAddress } from "./tailnet.ts";

export const BACKUP_TARGET_KINDS = ["s3", "tailnet_rest"] as const;
export type BackupTargetKind = (typeof BACKUP_TARGET_KINDS)[number];
/** Kinds whose fresh, append-only coverage "backups healthy" requires (R8: both destinations). */
export const REQUIRED_BACKUP_TARGET_KINDS: readonly BackupTargetKind[] = ["s3", "tailnet_rest"];

export const BACKUP_TARGET_KIND_LABELS: Record<BackupTargetKind, string> = {
  s3: "S3-compatible",
  tailnet_rest: "home (tailnet REST)",
};

export const S3_PROVIDERS = ["aws", "b2", "r2", "minio", "other"] as const;
export type S3Provider = (typeof S3_PROVIDERS)[number];

export const APPEND_ONLY_STATUSES = [
  "unverified",
  "append_only",
  "deletable",
  "unknown",
  "retention_short",
] as const;
export type AppendOnlyStatus = (typeof APPEND_ONLY_STATUSES)[number];

export const APPEND_ONLY_LABELS: Record<AppendOnlyStatus, string> = {
  unverified: "not verified yet",
  append_only: "append-only: yes",
  deletable: "deletable: a compromised server could erase backups",
  unknown: "unknown: a policy check is unsupported or unverifiable",
  retention_short: "retention is shorter than the recovery window",
};

/** Evidence older than this, or past the verified retention deadline, no longer counts (§3.18.2). */
export const APPEND_ONLY_EVIDENCE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
/** A recovery point older than three export intervals alerts (off-VPS RPO). */
export const RECOVERY_POINT_MAX_AGE_MS = 15 * 60 * 1000;
/** No successful export for this long marks a target stale. */
export const TARGET_STALE_MS = 36 * 60 * 60 * 1000;
/** Local repository/staging free space below this fraction (or below the byte floor) is critical. */
export const CAPACITY_MIN_FREE_FRACTION = 0.1;
export const CAPACITY_MIN_FREE_BYTES = 2 * 1024 ** 3;
/** Fail health before the disk fills: projected time to full below this is critical. */
export const CAPACITY_MIN_HOURS_TO_FULL = 72;

export const s3EndpointSchema = z
  .string()
  .trim()
  .min(1)
  .max(300)
  .transform((value) => (/^https?:\/\//i.test(value) ? value : `https://${value}`))
  .refine((value) => {
    try {
      const url = new URL(value);
      return (
        (url.protocol === "https:" || url.protocol === "http:") &&
        !url.username &&
        !url.password &&
        (url.pathname === "/" || url.pathname === "") &&
        !url.search &&
        !url.hash &&
        url.hostname.length > 0
      );
    } catch {
      return false;
    }
  }, "Endpoint must be https://host[:port] (http:// only for a local MinIO).")
  .transform((value) => new URL(value).origin);

// S3 bucket naming rules (lowercase, 3-63, no adjacent dots, no IP form).
export const s3BucketSchema = z
  .string()
  .trim()
  .regex(/^(?!\d+\.\d+\.\d+\.\d+$)(?!.*\.\.)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/, "Invalid bucket name.");

export const s3PrefixSchema = z
  .string()
  .trim()
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}(?:\/[A-Za-z0-9][A-Za-z0-9._-]{0,62}){0,3}$/,
    "Prefix is 1-4 path segments of letters, digits, '.', '_' or '-'.",
  )
  .default("ark");

export const s3RegionSchema = z
  .string()
  .trim()
  .regex(
    /^[a-z0-9][a-z0-9-]{0,40}$/,
    "Region is lowercase letters, digits and dashes (e.g. us-east-1 or auto).",
  );

export const s3TargetInput = z.object({
  /** Updates this target; omitted, a new target is created. */
  id: z.string().trim().min(1).max(64).optional(),
  name: z.string().trim().min(1).max(80),
  provider: z.enum(S3_PROVIDERS),
  endpoint: s3EndpointSchema,
  region: s3RegionSchema,
  bucket: s3BucketSchema,
  prefix: s3PrefixSchema,
  pathStyle: z.boolean(),
  recoveryWindowDays: z.number().int().min(1).max(3650).default(30),
  // Credentials are write-only: required when the target is created, optional (kept) on update.
  accessKeyId: z.string().trim().min(3).max(256).optional(),
  secretAccessKey: z.string().min(8).max(512).optional(),
  /** restic repository password: generated and kept off-host by the owner; Ark only seals it. */
  repositoryPassword: z.string().min(24).max(512).optional(),
  /**
   * Optional read-only verifier for provider policy metadata the writer cannot read itself, e.g. a
   * Cloudflare API token with R2 read access to inspect bucket lock rules. Never a writer credential.
   */
  verifierAccountId: z.string().trim().max(128).optional(),
  verifierToken: z.string().max(512).optional(),
});
export type S3TargetInput = z.infer<typeof s3TargetInput>;

export type S3TargetConfig = {
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  pathStyle: boolean;
};

/** restic repository path inside the bucket. */
export function resticPrefix(prefix: string) {
  return `${prefix.replace(/\/+$/, "")}/restic`;
}

/**
 * restic repository URL and options for an S3 target. The secrets go only into the restic
 * subprocess environment, never into argv.
 */
export function resticS3Repository(target: S3TargetConfig) {
  const endpoint = new URL(target.endpoint);
  return {
    repository: `s3:${endpoint.origin}/${target.bucket}/${resticPrefix(target.prefix)}`,
    options: [
      "-o",
      `s3.bucket-lookup=${target.pathStyle ? "path" : "dns"}`,
      "-o",
      `s3.region=${target.region || "us-east-1"}`,
    ],
  };
}

export function resticS3Env(
  target: S3TargetConfig,
  secrets: { accessKeyId: string; secretAccessKey: string; repositoryPassword: string },
) {
  return {
    AWS_ACCESS_KEY_ID: secrets.accessKeyId,
    AWS_SECRET_ACCESS_KEY: secrets.secretAccessKey,
    AWS_DEFAULT_REGION: target.region || "us-east-1",
    RESTIC_PASSWORD: secrets.repositoryPassword,
  };
}

// ---- Home machine over the tailnet (FD-30, §3.18.3) ----------------------------------------------

/** backup-ts's SOCKS5 listener on the internal `backup-tailnet` network. */
export const DEFAULT_BACKUP_SOCKS5_PROXY = "socks5://backup-ts:1055";
/** The local transfer watchdog re-checks identity and freshness this often during a transfer. */
export const TRANSFER_GUARD_INTERVAL_MS = 1_000;
/** Documented bound: an active REST transfer stops this soon after its identity becomes invalid. */
export const TRANSFER_STOP_BOUND_MS = 5_000;
/** Grace between SIGTERM and SIGKILL for a guarded restic subprocess (inside the bound). */
export const TRANSFER_KILL_GRACE_MS = 2_000;

/**
 * Every proxy variable Go's `ProxyFromEnvironment` (and curl-style tools) read. A restic subprocess
 * never inherits any of them: S3 runs with none, and the REST subprocess gets exactly one.
 */
export const PROXY_ENV_NAMES = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
  "NO_PROXY",
  "no_proxy",
  "REQUEST_METHOD",
] as const;

const REST_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

/**
 * The home rest-server URL as documented: `http://backup-home.<tailnet>.ts.net:8000/ark`. The host is a
 * MagicDNS name or a Tailscale address (never a public name), the port is explicit, and the first path
 * segment is the htpasswd user (`--private-repos` only lets a user reach paths under its own name).
 * No credentials, query or fragment: the htpasswd password is sealed separately.
 */
export const tailnetRestUrlSchema = z
  .string()
  .trim()
  .min(1)
  .max(300)
  .transform((value, context) => {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      context.addIssue({
        code: "custom",
        message: "Enter the REST URL, e.g. http://backup-home.tail1234.ts.net:8000/ark.",
      });
      return z.NEVER;
    }
    const problem = tailnetRestUrlProblem(url, value);
    if (problem) {
      context.addIssue({ code: "custom", message: problem });
      return z.NEVER;
    }
    return `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "")}`;
  });

function tailnetRestUrlProblem(url: URL, raw: string) {
  if (url.protocol !== "http:" && url.protocol !== "https:")
    return "The REST URL must be http:// or https://.";
  if (url.username || url.password)
    return "Do not put credentials in the URL; enter the htpasswd user and password.";
  if (url.search || url.hash || raw.includes("?") || raw.includes("#"))
    return "The REST URL has no query or fragment.";
  if (!url.port) return "Give the rest-server port explicitly, e.g. :8000.";
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const ip = parseIpLiteral(host);
  if (ip) {
    if (checkTailnetAddress(ip)) return "The REST host must be a Tailscale address or MagicDNS name.";
  } else if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host) || !host.endsWith(".ts.net")) {
    return "The REST host must be the home machine's MagicDNS name (…ts.net) or Tailscale address.";
  }
  const segments = url.pathname.replace(/\/+$/, "").split("/").slice(1);
  if (!segments.length || segments.length > 4 || segments.some((segment) => !REST_SEGMENT.test(segment)))
    return "The REST path is 1-4 segments starting with the htpasswd user, e.g. /ark.";
  return null;
}

/** The htpasswd user a `--private-repos` server requires: the first path segment. */
export function restRepositoryUser(restUrl: string) {
  return new URL(restUrl).pathname.split("/")[1] ?? "";
}

/** Host (MagicDNS name or address) and port of a validated REST URL. */
export function restUrlTarget(restUrl: string) {
  const url = new URL(restUrl);
  return {
    host: url.hostname.replace(/^\[|\]$/g, "").toLowerCase(),
    port: Number(url.port),
    https: url.protocol === "https:",
  };
}

export const tailnetRestTargetInput = z.object({
  /** Updates this target; omitted, a new target is created. */
  id: z.string().trim().min(1).max(64).optional(),
  name: z.string().trim().min(1).max(80),
  restUrl: tailnetRestUrlSchema,
  recoveryWindowDays: z.number().int().min(1).max(3650).default(30),
  // Credentials are write-only: required when the target is created, optional (kept) on update.
  password: z.string().min(8).max(512).optional(),
  repositoryPassword: z.string().min(24).max(512).optional(),
});
export type TailnetRestTargetInput = z.infer<typeof tailnetRestTargetInput>;

export type TailnetRestConfig = {
  restUrl: string;
  /** Pinned address from backup-ts's observation; substituted for the host on http:// URLs. */
  targetIp: string;
};

/** Validates the SOCKS5 proxy URL backup-ts exposes (`socks5://backup-ts:1055`). */
export function backupSocksProxy(value: string | undefined | null) {
  const raw = (value ?? "").trim() || DEFAULT_BACKUP_SOCKS5_PROXY;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("ARK_BACKUP_SOCKS5_PROXY is not a URL.");
  }
  if ((url.protocol !== "socks5:" && url.protocol !== "socks5h:") || !url.hostname || !url.port) {
    throw new Error("ARK_BACKUP_SOCKS5_PROXY must be socks5://host:port.");
  }
  if (url.username || url.password || (url.pathname && url.pathname !== "/") || url.search)
    throw new Error("ARK_BACKUP_SOCKS5_PROXY takes no credentials, path or query.");
  return { url: `${url.protocol}//${url.host}`, host: url.hostname, port: Number(url.port) };
}

/**
 * The restic REST repository for a pinned home target (§3.18.3). For http:// the validated pinned
 * Tailscale address replaces the name, so a re-pointed MagicDNS name never redirects a transfer; the
 * path (repository and `--private-repos` user) is unchanged. https:// keeps the name, which the
 * certificate binds; backup-ts resolves it from its own netmap. Credentials never go into the URL.
 */
export function resticRestRepository(config: TailnetRestConfig) {
  const url = new URL(config.restUrl);
  const pinned = parseIpLiteral(config.targetIp);
  if (!pinned || checkTailnetAddress(pinned))
    throw new Error("The pinned target is not a Tailscale address.");
  const host =
    url.protocol === "https:"
      ? url.hostname
      : pinned.version === 6
        ? `[${pinned.canonical}]`
        : pinned.canonical;
  return {
    repository: `rest:${url.protocol}//${host}:${url.port}${url.pathname.replace(/\/+$/, "")}/`,
    options: [] as string[],
  };
}

/**
 * The complete environment of the REST restic subprocess, apart from PATH/HOME/cache: htpasswd and
 * repository credentials, and exactly one matching-scheme proxy variable (HTTP_PROXY for http://,
 * HTTPS_PROXY for https://). Nothing else proxy-related is set, so inherited NO_PROXY/ALL_PROXY
 * values can never bypass or redirect it, and no other subprocess or request ever sees the proxy.
 */
export function resticRestEnv(
  config: Pick<TailnetRestConfig, "restUrl">,
  secrets: { username: string; password: string; repositoryPassword: string },
  proxy: string,
) {
  const https = new URL(config.restUrl).protocol === "https:";
  return {
    RESTIC_REST_USERNAME: secrets.username,
    RESTIC_REST_PASSWORD: secrets.password,
    RESTIC_PASSWORD: secrets.repositoryPassword,
    [https ? "HTTPS_PROXY" : "HTTP_PROXY"]: backupSocksProxy(proxy).url,
  } as Record<string, string>;
}

/** Removes every proxy variable from an environment (S3 restic, API/control calls). */
export function withoutProxyEnv(env: Record<string, string | undefined>) {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    if ((PROXY_ENV_NAMES as readonly string[]).includes(key)) continue;
    out[key] = value;
  }
  return out;
}

/** Steps for the home machine shown in the UI and docs/guides/backups.md. */
export const TAILNET_REST_RECIPE = {
  label: "Home machine (rest-server over the tailnet)",
  urlExample: "http://backup-home.tail1234.ts.net:8000/ark",
  server: [
    "Run rest-server --append-only --private-repos --listen <tailnet-ip>:8000 with an htpasswd file holding one user for Ark (the first path segment of the URL, e.g. ark).",
    "Join the home machine to the tailnet as backup-home, without any tag:ark-* tag.",
    "Add the generated tag:ark-backup grant for this target from Front door ACL (only tcp:8000 to this machine).",
  ],
  notes: [
    "Ark reaches the server only through its backup-ts node (tag:ark-backup); the edge node has no grant.",
    "Pruning runs on the home machine, never from the VPS: append-only mode refuses Ark's deletes.",
  ],
} as const;

/**
 * Prefix classes the canary must cover (§3.18.2 step 1). Every class that a bucket lock rule, IAM
 * statement or retention setting can address separately gets its own canary object. Canary names are
 * not hexadecimal IDs, so restic ignores them in its own directories.
 */
export const CANARY_POLICY_CLASSES = ["data", "index", "snapshots", "keys", "config", "ark-canary"] as const;
export type CanaryPolicyClass = (typeof CANARY_POLICY_CLASSES)[number];

export function canaryKey(prefix: string, policyClass: CanaryPolicyClass, token: string) {
  if (!/^[a-z0-9-]{8,64}$/.test(token)) throw new Error("Canary token must be 8-64 of [a-z0-9-].");
  const repo = resticPrefix(prefix);
  if (policyClass === "ark-canary") return `${prefix.replace(/\/+$/, "")}/ark-canary/${token}`;
  // A sibling tests disposable behavior only; exact config needs read-only policy proof.
  if (policyClass === "config") return `${repo}/config.ark-canary-${token}`;
  return `${repo}/${policyClass}/ark-canary-${token}`;
}

/** restic's lock directory: the only place the writer may delete (§3.18.2 step 4). */
export function locksKey(prefix: string, token: string) {
  return `${resticPrefix(prefix)}/locks/ark-canary-${token}`;
}

/**
 * The AWS-style writer policy (§3.18.2): write and read everything under the prefix, delete only
 * restic's `locks/`, and explicitly deny version deletion, retention changes or bypass, and
 * bucket-level versioning, lock, lifecycle and policy changes. MinIO accepts the same document.
 */
export function writerPolicy(bucket: string, prefix: string) {
  const base = prefix.replace(/\/+$/, "");
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ArkList",
        Effect: "Allow",
        Action: [
          "s3:ListBucket",
          "s3:ListBucketVersions",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetBucketPolicy",
          "s3:GetBucketObjectLockConfiguration",
        ],
        Resource: [`arn:aws:s3:::${bucket}`],
      },
      {
        Sid: "ArkWrite",
        Effect: "Allow",
        Action: ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"],
        Resource: [`arn:aws:s3:::${bucket}/${base}/*`],
      },
      {
        Sid: "ArkResticLocks",
        Effect: "Allow",
        Action: ["s3:DeleteObject"],
        Resource: [`arn:aws:s3:::${bucket}/${base}/restic/locks/*`],
      },
      {
        Sid: "ArkNeverErase",
        Effect: "Deny",
        Action: [
          "s3:DeleteObjectVersion",
          "s3:BypassGovernanceRetention",
          "s3:PutObjectRetention",
          "s3:PutObjectLegalHold",
          "s3:PutBucketVersioning",
          "s3:PutBucketObjectLockConfiguration",
          "s3:PutLifecycleConfiguration",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:DeleteBucket",
        ],
        Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`],
      },
    ],
  };
}

/** Attach separately as a bucket policy. Explicit all-principal denies cover exact keys too. */
export function repositoryProtectionPolicy(bucket: string, prefix: string) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ArkProtectRepositoryDependencies",
        Effect: "Deny",
        Principal: "*",
        Action: [
          "s3:DeleteObjectVersion",
          "s3:PutObjectRetention",
          "s3:BypassGovernanceRetention",
          "s3:PutObjectLegalHold",
        ],
        Resource: [`arn:aws:s3:::${bucket}/${prefix.replace(/\/+$/, "")}/*`],
      },
      {
        Sid: "ArkKeepProtectionPolicy",
        Effect: "Deny",
        Principal: "*",
        Action: ["s3:DeleteBucketPolicy"],
        Resource: [`arn:aws:s3:::${bucket}`],
      },
    ],
  };
}

export type ProviderRecipe = {
  provider: S3Provider;
  label: string;
  endpointExample: string;
  /** Path-style default: MinIO uses path style; hosted providers use virtual-host style. */
  pathStyle: boolean;
  /** Region shown when the FD-03 preset hint does not apply (R2 uses `auto`). */
  regionOverride?: string;
  immutability: string[];
  writer: string[];
  notes: string[];
};

export const PROVIDER_RECIPES: Readonly<Record<S3Provider, ProviderRecipe>> = Object.freeze({
  aws: {
    provider: "aws",
    label: "AWS S3",
    endpointExample: "https://s3.us-east-1.amazonaws.com",
    pathStyle: false,
    immutability: [
      "Create the bucket with Object Lock enabled (this turns on versioning).",
      "Set a default retention in COMPLIANCE mode, or GOVERNANCE mode with no principal holding s3:BypassGovernanceRetention, of at least the recovery window.",
    ],
    writer: [
      "Attach the generated repository protection bucket policy too (including denial of policy deletion), and permit GetBucketPolicy. Create an IAM user for Ark with only the generated writer policy: write and read under the prefix, DeleteObject only on <prefix>/restic/locks/*, and deny DeleteObjectVersion, retention changes or bypass, and bucket versioning, lock, lifecycle and policy changes.",
    ],
    notes: [
      "An overwrite or delete by the writer only adds a version or delete marker; the canary proves the recorded version still reads back.",
    ],
  },
  b2: {
    provider: "b2",
    label: "Backblaze B2",
    endpointExample: "https://s3.us-east-005.backblazeb2.com",
    pathStyle: false,
    immutability: [
      "B2 keeps file versions natively. Enable Object Lock on the bucket with a default retention of at least the recovery window.",
    ],
    writer: [
      "Create an application key scoped to the bucket without deleteFiles, bypassGovernance, writeBucketRetentions or writeBuckets. writeFiles still lets restic hide its lock files; hidden versions remain recoverable.",
    ],
    notes: [
      "The canary reads the key's own capabilities from b2_authorize_account to prove bucket-level permissions are absent.",
    ],
  },
  r2: {
    provider: "r2",
    label: "Cloudflare R2",
    endpointExample: "https://<account-id>.r2.cloudflarestorage.com",
    pathStyle: false,
    regionOverride: "auto",
    immutability: [
      "Add bucket lock rules on <prefix>/restic/data/, index/, snapshots/, keys/, config and <prefix>/ark-canary/ with Indefinite retention (finite Age or Date rules cannot protect reused objects). Do not lock <prefix>/restic/locks/.",
      "Never put a live pgBackRest repository under an R2 lock: Ark snapshots the completed local repository with restic, so the *.info history is immutable too.",
    ],
    writer: [
      "R2 tokens have no no-delete level (Object Read & Write), so the lock rules are the only control. Scope the token to this bucket.",
      "Give Ark a separate read-only Cloudflare API token (account ID + token) so the canary can verify the lock rules; without it the target stays unverified.",
    ],
    notes: [],
  },
  minio: {
    provider: "minio",
    label: "MinIO",
    endpointExample: "https://minio.example.net:9000",
    pathStyle: true,
    immutability: [
      "Create the bucket with object locking (mc mb --with-lock), which enables versioning, and set a default retention (mc retention set --default COMPLIANCE <days>d).",
    ],
    writer: [
      "Create a user with the same IAM-style policy as AWS (mc admin policy create, then attach it to the user).",
    ],
    notes: ["Use path-style addressing unless the deployment has wildcard DNS for bucket hosts."],
  },
  other: {
    provider: "other",
    label: "Other S3-compatible",
    endpointExample: "https://s3.example.net",
    pathStyle: false,
    immutability: ["Versioning plus object lock or retention of at least the recovery window."],
    writer: [
      "A credential that cannot delete object versions, shorten or bypass retention, or change bucket policy.",
    ],
    notes: ["Unsupported checks keep the target unverified, never healthy."],
  },
});

// ---- Health and alerts (§3.18.1, §3.18.4) ---------------------------------------------------------

export type HealthTarget = {
  id: string;
  name: string;
  kind: BackupTargetKind;
  enabled: boolean;
  appendOnlyStatus: AppendOnlyStatus;
  appendOnlyCheckedAt: Date | null;
  retentionUntil: Date | null;
  recoveryWindowDays: number;
  lastSuccessAt: Date | null;
  lastError: string | null;
  /**
   * tailnet_rest only: the pinned identity checked against backup-ts's current observation. Not ok
   * (expired observation, replaced or absent node) suspends transfers and is a critical alert.
   */
  identity?: { ok: boolean; message: string } | null;
};

export type HealthExport = {
  targetId: string;
  source: string;
  status: "succeeded" | "failed";
  lastRecoverableAt: Date | null;
  /** Size of the staged local repository this export uploaded (capacity projection). */
  repoBytes: number | null;
  createdAt: Date;
};

export type HealthSource = {
  source: string;
  observedAt: Date;
  freeBytes: number | null;
  totalBytes: number | null;
  /** Newest local stage's recovery point (what the VPS has, not what is off-site). */
  localRecoverableAt: Date | null;
  /** Local repository size now. */
  repoBytes: number | null;
  archiveFailing: boolean;
  configured: boolean;
};

export type BackupAlert = { dedupKey: string; severity: "warning" | "critical"; title: string };

export type BackupHealth = {
  healthy: boolean;
  reasons: string[];
  targets: Array<{
    id: string;
    name: string;
    healthy: boolean;
    reasons: string[];
    appendOnly: { status: AppendOnlyStatus; label: string; current: boolean };
    sources: Array<{ source: string; lastRecoverableAt: string | null; lastAttemptFailed: boolean }>;
  }>;
  sources: Array<{ source: string; reasons: string[]; hoursToFull: number | null }>;
  alerts: BackupAlert[];
};

export const BACKUP_ALERT_PREFIXES = [
  "backup-append-only:",
  "backup-rpo:",
  "backup-target-stale:",
  "backup-capacity:",
  "backup-source:",
  "backup-no-target",
  "backup-tailnet:",
] as const;

function age(now: Date, at: Date | null) {
  return at ? now.getTime() - at.getTime() : Number.POSITIVE_INFINITY;
}

function describeAge(ms: number) {
  if (!Number.isFinite(ms)) return "never";
  const minutes = Math.round(ms / 60_000);
  if (minutes < 120) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  return hours < 72 ? `${hours} h ago` : `${Math.round(hours / 24)} days ago`;
}

/**
 * Pure health evaluation. Healthy only when every required kind has an enabled target, every
 * enabled target has current append-only evidence, a fresh success and a fresh recovery point for
 * every PostgreSQL source, and no local source is short of capacity or failing to archive.
 */
export function evaluateBackupHealth(input: {
  targets: HealthTarget[];
  exports: HealthExport[];
  sources: HealthSource[];
  pgSources: string[];
  now: Date;
  requiredKinds?: readonly BackupTargetKind[];
}): BackupHealth {
  const { now } = input;
  const required = input.requiredKinds ?? REQUIRED_BACKUP_TARGET_KINDS;
  const alerts: BackupAlert[] = [];
  const reasons: string[] = [];
  const enabled = input.targets.filter((target) => target.enabled);
  for (const kind of required) {
    if (!enabled.some((target) => target.kind === kind)) {
      const label = BACKUP_TARGET_KIND_LABELS[kind];
      reasons.push(`No ${label} backup target is configured.`);
      alerts.push({
        // The S3 key predates FD-30; keep it so an open alert resolves rather than duplicates.
        dedupKey: kind === "s3" ? "backup-no-target" : `backup-no-target:${kind}`,
        severity: "critical",
        title: `Backups are not reaching every destination: no ${label} target is configured`,
      });
    }
  }
  const latest = new Map<string, { success?: HealthExport; attempt?: HealthExport }>();
  for (const item of input.exports) {
    const key = `${item.targetId}\u0000${item.source}`;
    const held = latest.get(key) ?? {};
    if (!held.attempt || item.createdAt > held.attempt.createdAt) held.attempt = item;
    if (item.status === "succeeded" && (!held.success || item.createdAt > held.success.createdAt))
      held.success = item;
    latest.set(key, held);
  }

  const targets = enabled.map((target) => {
    const targetReasons: string[] = [];
    // rest-server --append-only refuses deletion for as long as it runs in that mode; there is no
    // object retention deadline to cover (pruning happens on the home machine, §3.18.3).
    const retentionCovered =
      target.kind === "tailnet_rest" ||
      (target.retentionUntil ? target.retentionUntil.getTime() > now.getTime() : false);
    const current =
      target.appendOnlyStatus === "append_only" &&
      age(now, target.appendOnlyCheckedAt) <= APPEND_ONLY_EVIDENCE_MAX_AGE_MS &&
      retentionCovered;
    if (!current) {
      const why =
        target.appendOnlyStatus === "append_only"
          ? "append-only evidence expired"
          : APPEND_ONLY_LABELS[target.appendOnlyStatus];
      targetReasons.push(`${target.name}: ${why}`);
      alerts.push({
        dedupKey: `backup-append-only:${target.id}`,
        severity: target.appendOnlyStatus === "deletable" ? "critical" : "warning",
        title: `Backup target ${target.name}: ${why}`,
      });
    }
    if (target.kind === "tailnet_rest" && target.identity && !target.identity.ok) {
      targetReasons.push(`${target.name}: transfers suspended: ${target.identity.message}`);
      alerts.push({
        dedupKey: `backup-tailnet:${target.id}`,
        severity: "critical",
        title: `Backup target ${target.name}: transfers suspended: ${target.identity.message}`,
      });
    }
    if (age(now, target.lastSuccessAt) > TARGET_STALE_MS) {
      targetReasons.push(
        `${target.name}: last successful backup ${describeAge(age(now, target.lastSuccessAt))}`,
      );
      alerts.push({
        dedupKey: `backup-target-stale:${target.id}`,
        severity: "warning",
        title: `Backup target ${target.name} has no successful backup since ${describeAge(age(now, target.lastSuccessAt))}`,
      });
    }
    const sources = input.pgSources.map((source) => {
      const held = latest.get(`${target.id}\u0000${source}`) ?? {};
      const recoverable = held.success?.lastRecoverableAt ?? null;
      const recoveryAge = age(now, recoverable);
      if (recoveryAge > RECOVERY_POINT_MAX_AGE_MS) {
        targetReasons.push(
          `${target.name}: last off-VPS recovery point for ${source} ${describeAge(recoveryAge)}`,
        );
        alerts.push({
          dedupKey: `backup-rpo:${target.id}:${source}`,
          severity: "critical",
          title: `Last recoverable time for ${source} on ${target.name} is ${recoverable ? recoverable.toISOString() : "missing"} (${describeAge(recoveryAge)})`,
        });
      }
      return {
        source,
        lastRecoverableAt: recoverable ? recoverable.toISOString() : null,
        lastAttemptFailed: held.attempt?.status === "failed",
      };
    });
    if (sources.some((item) => item.lastAttemptFailed)) {
      targetReasons.push(
        `${target.name}: the last export failed${target.lastError ? `: ${target.lastError}` : ""}`,
      );
    }
    return {
      id: target.id,
      name: target.name,
      healthy: targetReasons.length === 0,
      reasons: targetReasons,
      appendOnly: {
        status: target.appendOnlyStatus,
        label: APPEND_ONLY_LABELS[target.appendOnlyStatus],
        current,
      },
      sources,
    };
  });

  const sources = input.pgSources.map((name) => {
    const source = input.sources.find((item) => item.source === name);
    const sourceReasons: string[] = [];
    let hoursToFull: number | null = null;
    if (!source || !source.configured) {
      sourceReasons.push(`${name}: WAL archiving or the backup executor is not configured`);
      alerts.push({
        dedupKey: `backup-source:${name}`,
        severity: "critical",
        title: `${name} is not being backed up: WAL archiving or the executor is not configured or unreachable`,
      });
      return { source: name, reasons: sourceReasons, hoursToFull };
    }
    if (source.archiveFailing) {
      sourceReasons.push(`${name}: WAL archiving is failing`);
      alerts.push({
        dedupKey: `backup-source:${name}`,
        severity: "critical",
        title: `${name}: WAL archiving to the local repository is failing`,
      });
    }
    // Capacity: local repo2 is never expired on the VPS, and until every destination acknowledges the
    // newest WAL the local copy is the only one. Project growth since the slowest destination's last
    // acknowledged export and fail health before the disk fills.
    const acknowledged = enabled.map((target) => latest.get(`${target.id}\u0000${name}`)?.success ?? null);
    const slowest = acknowledged.some((item) => item === null)
      ? null
      : acknowledged.reduce<HealthExport | null>(
          (min, item) =>
            !min || (item!.lastRecoverableAt?.getTime() ?? 0) < (min.lastRecoverableAt?.getTime() ?? 0)
              ? item
              : min,
          null,
        );
    const slowestAt = slowest?.lastRecoverableAt ?? null;
    const unexported =
      source.localRecoverableAt !== null &&
      enabled.length > 0 &&
      (slowestAt === null ||
        slowestAt.getTime() + RECOVERY_POINT_MAX_AGE_MS < source.localRecoverableAt.getTime());
    if (source.freeBytes !== null && source.totalBytes) {
      const low =
        source.freeBytes < CAPACITY_MIN_FREE_BYTES ||
        source.freeBytes / source.totalBytes < CAPACITY_MIN_FREE_FRACTION;
      if (
        unexported &&
        slowest?.repoBytes &&
        slowestAt &&
        source.repoBytes &&
        source.repoBytes > slowest.repoBytes
      ) {
        const elapsedHours = (now.getTime() - slowestAt.getTime()) / 3_600_000;
        // The staged copy doubles what each byte of new WAL costs on the VPS.
        const bytesPerHour = (2 * (source.repoBytes - slowest.repoBytes)) / Math.max(elapsedHours, 1 / 60);
        hoursToFull = Math.round((source.freeBytes / bytesPerHour) * 10) / 10;
      }
      if (low || (hoursToFull !== null && hoursToFull < CAPACITY_MIN_HOURS_TO_FULL)) {
        sourceReasons.push(`${name}: local backup storage is nearly full`);
        alerts.push({
          dedupKey: `backup-capacity:${name}`,
          severity: "critical",
          title: `${name}: local backup storage has ${formatBytes(source.freeBytes)} free${hoursToFull !== null ? ` (about ${hoursToFull} h to full)` : ""}; WAL is kept until every destination has it`,
        });
        return { source: name, reasons: sourceReasons, hoursToFull };
      }
    }
    if (unexported) {
      sourceReasons.push(
        `${name}: WAL is accumulating locally because a destination has not acknowledged it`,
      );
      alerts.push({
        dedupKey: `backup-capacity:${name}`,
        severity: "warning",
        title: `${name}: WAL is accumulating on the VPS (${source.freeBytes !== null ? `${formatBytes(source.freeBytes)} free` : "free space unknown"}) until every destination acknowledges it`,
      });
    }
    return { source: name, reasons: sourceReasons, hoursToFull };
  });

  for (const target of targets) reasons.push(...target.reasons);
  for (const source of sources) reasons.push(...source.reasons);
  return {
    healthy: reasons.length === 0,
    reasons,
    targets,
    sources,
    alerts: dedupeAlerts(alerts),
  };
}

function dedupeAlerts(alerts: BackupAlert[]) {
  const byKey = new Map<string, BackupAlert>();
  for (const alert of alerts) {
    const held = byKey.get(alert.dedupKey);
    if (!held || (held.severity === "warning" && alert.severity === "critical"))
      byKey.set(alert.dedupKey, alert);
  }
  return [...byKey.values()];
}

export function formatBytes(bytes: number) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}
