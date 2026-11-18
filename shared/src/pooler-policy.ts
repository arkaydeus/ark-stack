// The pooler-wide source policy for public 5432 (docs/design/front-door.md §3.8.3, FD-26).
//
// Classic PostgreSQL negotiation sends an 8-byte `SSLRequest` before TLS, and the StartupMessage that
// names the database is encrypted afterwards. HAProxy's `fe_pg5432` therefore cannot tell which Ark
// database a classic connection is for, so `be_pgbouncer` enforces exactly one explicit policy for the
// whole pooler: `platform_settings.pooler_source_cidrs`, or every source when `pooler_allow_internet`
// was saved under an owner exposure.public confirmation. Empty = deny all.
//
// A database's `source_cidrs` and its Vercel clients are *requests* for that policy, never enforced
// per database and never silently unioned. When the requests differ (two databases with different
// CIDRs, or a restricted database sharing the pooler with an unrestricted Vercel client), publication
// is refused until the owner explicitly reviews one common policy. A database that needs its own
// source isolation has to stay private or use a separate enforced listener.
import { z } from "zod";

import { clientAllowed, parseCidr } from "./cidr.ts";
import { OPEN_CIDRS, routeAllowlist } from "./edge-l4.ts";
import { sha256Hex } from "./hash.ts";

/** The boundary every API and UI status states verbatim. */
export const POOLER_POLICY_BOUNDARY =
  "Public 5432 enforces one pooler-wide source policy for every Ark database. Classic SSLRequest carries no database name, so a source admitted for one database is admitted for all of them; a database's own CIDRs are a request, not an enforced isolation. Keep a database private, or use a separate listener, if it needs its own source isolation.";

export type PoolerRequestSource =
  | { kind: "database"; id: string; name: string }
  | { kind: "vercel_client"; id: string; name: string; databaseId: string };

/** One requested policy: a database's CIDRs (empty = unrestricted), or a Vercel client (unrestricted). */
export type PoolerRequest = {
  source: PoolerRequestSource;
  unrestricted: boolean;
  sourceCidrs: string[];
  /** The normalised request: `internet`, or the sorted CIDR list joined by commas. */
  key: string;
};

export type PoolerPolicySettings = {
  sourceCidrs: string[];
  allowInternet: boolean;
  /** When the owner's exposure.public confirmation was saved with `allowInternet`. */
  internetConfirmedAt?: Date | string | null;
  /** When the owner last reviewed the policy against the requests, and the requests it covered. */
  reviewedAt?: Date | string | null;
  reviewedRequests?: string | null;
};

export type PoolerPolicyStatus =
  | "no_public_databases"
  | "invalid_policy"
  | "deny_all"
  | "unconfirmed_internet"
  | "review_required"
  | "published";

export type PoolerConflict = {
  reason: "different_cidrs" | "restricted_with_unrestricted";
  message: string;
  sources: PoolerRequestSource[];
};

function normalizedCidrs(cidrs: readonly string[]) {
  return [...new Set(cidrs.map((cidr) => cidr.trim()).filter(Boolean))]
    .map((cidr) => {
      const parsed = parseCidr(cidr);
      return parsed.ok ? parsed.cidr : cidr;
    })
    .toSorted();
}

export function poolerRequestKey(input: { unrestricted: boolean; sourceCidrs: readonly string[] }) {
  return input.unrestricted ? "internet" : normalizedCidrs(input.sourceCidrs).join(",");
}

/**
 * The requests for the pooler policy: every public database (empty CIDRs = unrestricted, as the
 * pre-FD-26 open allowlist behaved) and every active Vercel-integrated client of a public database
 * (Vercel egress has no stable addresses, so it needs an unrestricted pooler).
 */
export function poolerRequests(input: {
  databases: Array<{ id: string; name: string; exposure: string; sourceCidrs?: string[] | null }>;
  vercelClients?: Array<{ id: string; name: string; databaseId: string; status?: string }>;
}): PoolerRequest[] {
  const publicDatabases = input.databases.filter((database) => database.exposure === "public");
  const publicIds = new Set(publicDatabases.map((database) => database.id));
  const requests: PoolerRequest[] = publicDatabases.map((database) => {
    const sourceCidrs = normalizedCidrs(database.sourceCidrs ?? []);
    const unrestricted = sourceCidrs.length === 0;
    return {
      source: { kind: "database", id: database.id, name: database.name },
      unrestricted,
      sourceCidrs,
      key: poolerRequestKey({ unrestricted, sourceCidrs }),
    };
  });
  for (const client of input.vercelClients ?? []) {
    if (!publicIds.has(client.databaseId) || (client.status && client.status !== "active")) continue;
    requests.push({
      source: { kind: "vercel_client", id: client.id, name: client.name, databaseId: client.databaseId },
      unrestricted: true,
      sourceCidrs: [],
      key: "internet",
    });
  }
  return requests.toSorted((a, b) => a.source.id.localeCompare(b.source.id));
}

/** Identifies the set of distinct requests a review covered; a new distinct request needs a new review. */
export function poolerRequestsFingerprint(requests: readonly Pick<PoolerRequest, "key">[]) {
  return sha256Hex(JSON.stringify([...new Set(requests.map((request) => request.key))].toSorted())).slice(
    0,
    32,
  );
}

function sourceLabel(source: PoolerRequestSource) {
  return source.kind === "database" ? `database ${source.name}` : `Vercel client ${source.name}`;
}

export function poolerConflicts(requests: readonly PoolerRequest[]): PoolerConflict[] {
  const distinct = [...new Set(requests.map((request) => request.key))];
  if (distinct.length <= 1) return [];
  const conflicts: PoolerConflict[] = [];
  const restricted = requests.filter((request) => !request.unrestricted);
  const unrestricted = requests.filter((request) => request.unrestricted);
  if (restricted.length && unrestricted.length) {
    conflicts.push({
      reason: "restricted_with_unrestricted",
      message: `${restricted.map((request) => sourceLabel(request.source)).join(", ")} request${restricted.length === 1 ? "s" : ""} restricted sources, but ${unrestricted.map((request) => sourceLabel(request.source)).join(", ")} need${unrestricted.length === 1 ? "s" : ""} an unrestricted pooler. They would share one pooler-wide policy.`,
      sources: [...restricted, ...unrestricted].map((request) => request.source),
    });
  }
  if (new Set(restricted.map((request) => request.key)).size > 1) {
    conflicts.push({
      reason: "different_cidrs",
      message: `${restricted.map((request) => `${sourceLabel(request.source)} (${request.sourceCidrs.join(", ")})`).join("; ")} request different CIDRs. A source admitted for one would be admitted for all; adopt one reviewed common policy.`,
      sources: restricted.map((request) => request.source),
    });
  }
  return conflicts;
}

function admits(policy: Pick<PoolerPolicySettings, "sourceCidrs" | "allowInternet">) {
  return policy.allowInternet ? "internet" : policy.sourceCidrs.length ? "allowlist" : "nobody";
}

/**
 * The publication state of the pooler. PgBouncer is rendered behind `fe_pg5432` only when
 * `publishable`: a public database exists, the policy admits someone (a non-empty list, or a
 * confirmed `allowInternet`), and either every request is exactly the saved policy or the owner
 * reviewed the saved policy against the current requests.
 */
export function evaluatePoolerPolicy(input: {
  requests: readonly PoolerRequest[];
  policy: PoolerPolicySettings;
}) {
  const requests = [...input.requests];
  const policy = {
    sourceCidrs: normalizedCidrs(input.policy.sourceCidrs ?? []),
    allowInternet: Boolean(input.policy.allowInternet),
  };
  const policyKey = poolerRequestKey({ unrestricted: policy.allowInternet, sourceCidrs: policy.sourceCidrs });
  const distinct = [...new Set(requests.map((request) => request.key))].toSorted();
  const fingerprint = poolerRequestsFingerprint(requests);
  const conflicts = poolerConflicts(requests);
  const databases = requests.filter((request) => request.source.kind === "database").length;
  const matchesRequests = distinct.length === 1 && distinct[0] === policyKey;
  const reviewed = Boolean(input.policy.reviewedAt) && input.policy.reviewedRequests === fingerprint;
  const internetConfirmed = Boolean(input.policy.internetConfirmedAt);
  let invalid: string | null = null;
  try {
    checkPoolerPolicy(policy);
  } catch (error) {
    invalid = (error as Error).message;
  }
  let status: PoolerPolicyStatus;
  let message: string;
  if (!databases) {
    status = "no_public_databases";
    message =
      "No database is public, so PgBouncer is not routed on 5432 and SSLRequest connections are rejected.";
  } else if (invalid) {
    status = "invalid_policy";
    message = `The saved pooler policy cannot be rendered: ${invalid}`;
  } else if (policy.allowInternet && !internetConfirmed) {
    status = "unconfirmed_internet";
    message =
      "pooler_allow_internet was not saved with an owner exposure.public confirmation; save the pooler policy again with step-up.";
  } else if (!policy.allowInternet && !policy.sourceCidrs.length) {
    status = "deny_all";
    message = conflicts.length
      ? "The pooler policy is empty (deny all) and the databases request conflicting sources. Review and save one common pooler-wide policy."
      : "The pooler policy is empty, which denies every source. Save the pooler-wide CIDRs, or allow the internet with step-up.";
  } else if (!matchesRequests && !reviewed) {
    status = "review_required";
    message = conflicts.length
      ? "The databases request conflicting sources. Publication is refused until the owner reviews and saves one common pooler-wide policy."
      : "The saved pooler policy differs from what the databases request. Review and save it to publish.";
  } else {
    status = "published";
    message = "PgBouncer is routed on 5432 behind the pooler-wide policy.";
  }
  return {
    scope: "pooler-wide" as const,
    status,
    publishable: status === "published",
    message,
    boundary: POOLER_POLICY_BOUNDARY,
    policy: {
      ...policy,
      admits: admits(policy),
      rendered: policy.allowInternet ? [...OPEN_CIDRS] : policy.sourceCidrs,
      internetConfirmedAt: input.policy.internetConfirmedAt ?? null,
      reviewedAt: input.policy.reviewedAt ?? null,
    },
    requests,
    distinctRequests: distinct,
    requestsFingerprint: fingerprint,
    conflict: conflicts.length > 0,
    conflicts,
    matchesRequests,
    reviewed,
  };
}

export type PoolerPolicyEvaluation = ReturnType<typeof evaluatePoolerPolicy>;

/**
 * Validates a pooler policy the owner saves: the same allowlist rules as routes (no open or
 * near-open prefix without `allowInternet`). Returns the normalised list.
 */
export function checkPoolerPolicy(input: { sourceCidrs: string[]; allowInternet: boolean }) {
  routeAllowlist({ sourceCidrs: input.sourceCidrs, allowInternet: false });
  return { sourceCidrs: normalizedCidrs(input.sourceCidrs), allowInternet: Boolean(input.allowInternet) };
}

/** Whether a policy change widens who may reach the pooler (needs an exposure.public grant). */
export function poolerPolicyLoosens(
  current: Pick<PoolerPolicySettings, "sourceCidrs" | "allowInternet">,
  next: Pick<PoolerPolicySettings, "sourceCidrs" | "allowInternet">,
) {
  if (next.allowInternet && !current.allowInternet) return true;
  if (next.allowInternet) return false;
  if (current.allowInternet) return false;
  const known = new Set(normalizedCidrs(current.sourceCidrs));
  return normalizedCidrs(next.sourceCidrs).some((cidr) => !known.has(cidr));
}

/**
 * Whether a source would be admitted to PgBouncer on 5432. Always answered from the pooler-wide
 * policy: a database's own CIDRs are never reported as isolating it.
 */
export function poolerAdmission(
  evaluation: Pick<PoolerPolicyEvaluation, "publishable" | "policy" | "status">,
  ip: string,
) {
  const base = {
    scope: "pooler-wide" as const,
    databaseCidrsEnforced: false as const,
    boundary: POOLER_POLICY_BOUNDARY,
  };
  if (!evaluation.publishable) {
    return { ...base, allowed: false, reason: `pooler-${evaluation.status}` };
  }
  if (evaluation.policy.allowInternet) return { ...base, allowed: true, reason: "pooler-allow-internet" };
  const result = clientAllowed(evaluation.policy.sourceCidrs, ip);
  return {
    ...base,
    allowed: result.allowed,
    reason: result.allowed ? `pooler:${result.reason}` : "source-not-in-pooler-policy",
  };
}

/** `PUT /api/databases/pooler-policy`: the policy and the requests fingerprint the owner reviewed. */
export const poolerPolicyInput = z
  .object({
    sourceCidrs: z.array(z.string().trim().min(1).max(64)).max(64),
    allowInternet: z.boolean(),
    reviewedRequests: z
      .string()
      .regex(/^[a-f0-9]{32}$/, "reviewedRequests must be the reviewed requests fingerprint."),
  })
  .strict();
