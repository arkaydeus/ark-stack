// Append-only canary for S3-compatible backup targets (docs/design/front-door.md §3.18.2, FD-21).
//
// With the writer's deployed credentials, for every policy class (restic data/index/snapshots/keys,
// config, and ark-canary/) the canary writes a disposable object and records its hash, version and
// retention, then attempts ordinary delete and overwrite, permanent version deletion, governance
// bypass, and retention shortening on that canary only. restic's locks/ class must allow create and
// delete, separately.
//
// Bucket-level policy changes are never attempted against the real configuration. Each
// policy-changing request (PutBucketVersioning, PutObjectLockConfiguration, PutBucketLifecycle,
// PutBucketPolicy) is sent with a well-formed but invalid body: S3 authorizes before it validates, so
// AccessDenied proves the permission is absent, a validation error proves it is present, and
// NotImplemented means the check is unsupported. Nothing is ever stored. Destructive object attempts
// are judged by effect (does the original version still read back, did its retention move earlier),
// because providers answer refused WORM changes with different codes (MinIO: 400 InvalidRequest). Provider evaluation
// overrides where the S3 API cannot answer: Backblaze B2 reports the key's own capabilities, and
// Cloudflare R2 lock rules are read with an optional read-only Cloudflare API token.
//
// The verdict errs towards unhealthy: anything unknown or unsupported is `unknown`, never healthy.
import { createHash, randomBytes } from "node:crypto";

import {
  CANARY_POLICY_CLASSES,
  canaryKey,
  locksKey,
  resticPrefix,
  type AppendOnlyStatus,
  type CanaryPolicyClass,
  type S3Provider,
} from "@ark-stack/shared";

import { S3Client, contentMd5, xmlValue, type S3Response } from "./s3-client.ts";

/**
 * Well-formed but invalid configurations: every value a provider validates is illegal, so a writer
 * that holds the permission gets a validation error and nothing is stored, and one that lacks it gets
 * AccessDenied. Verified against MinIO (scripts/test-backups.ts).
 */
export const BUCKET_PROBE_BODIES = {
  versioning: `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>ArkProbeInvalid</Status></VersioningConfiguration>`,
  "object-lock": `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>ArkProbeInvalid</ObjectLockEnabled></ObjectLockConfiguration>`,
  lifecycle: `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>ark-append-only-probe</ID><Status>ArkProbeInvalid</Status><Filter><Prefix>ark-append-only-probe/</Prefix></Filter><Expiration><Days>36500</Days></Expiration></Rule></LifecycleConfiguration>`,
  policy: `{"ArkAppendOnlyProbe":"invalid policy without a Version or Statement"}`,
} as const;

export type AttemptOutcome = "refused" | "succeeded" | "unsupported" | "error";

export type Attempt = { status: number; code: string | null; outcome: AttemptOutcome };

export type ClassEvidence = {
  policyClass: CanaryPolicyClass;
  key: string;
  versionId: string | null;
  sha256: string;
  retention: { mode: string; retainUntil: string } | null;
  retentionCheck: "ok" | "none" | "unsupported" | "error";
  attempts: Record<
    | "ordinaryDelete"
    | "overwrite"
    | "permanentDelete"
    | "bypassDelete"
    | "shortenRetention"
    | "shortenRetentionBypass",
    Attempt | null
  >;
  readback: "match" | "mismatch" | "missing" | "error";
};

export type CanaryFinding = { kind: "deletable" | "unknown" | "retention"; message: string };

export type CanaryEvidence = {
  version: 1;
  checkedAt: string;
  provider: S3Provider;
  bucket: string;
  prefix: string;
  pathStyle: boolean;
  recoveryWindowDays: number;
  token: string;
  bucketVersioning: string;
  objectLock: { enabled: boolean; mode: string | null; days: number | null; years: number | null } | null;
  classes: ClassEvidence[];
  locks: { create: Attempt; delete: Attempt | null };
  bucketProbes: Record<"versioning" | "objectLock" | "lifecycle" | "policy", Attempt>;
  providerEvidence: Record<string, unknown> | null;
  retentionUntil: string | null;
  findings: CanaryFinding[];
  status: AppendOnlyStatus;
};

export type CanaryInput = {
  client: S3Client;
  provider: S3Provider;
  prefix: string;
  recoveryWindowDays: number;
  /** Writer credentials, used only for B2's own-capability lookup. */
  writer?: { accessKeyId: string; secretAccessKey: string };
  /** Optional read-only verifier (Cloudflare account ID + API token with R2 read). */
  verifier?: { accountId?: string; token?: string };
  now?: () => Date;
  fetchImpl?: typeof fetch;
};

const sha256 = (data: Uint8Array | string) => createHash("sha256").update(data).digest("hex");

function classify(response: S3Response | Error): Attempt {
  if (response instanceof Error) return { status: 0, code: response.message.slice(0, 120), outcome: "error" };
  const { status, code } = response;
  if (status >= 200 && status < 300) return { status, code, outcome: "succeeded" };
  if (status === 501 || code === "NotImplemented") return { status, code, outcome: "unsupported" };
  if (
    status === 403 ||
    code === "AccessDenied" ||
    code === "ObjectLocked" ||
    code === "InvalidRetentionPeriod"
  ) {
    return { status, code, outcome: "refused" };
  }
  if (
    status === 400 &&
    code === "InvalidRequest" &&
    /(?:WORM protected|object is locked|retention.*(?:cannot|not allowed))/i.test(response.text)
  )
    return { status, code, outcome: "refused" };
  // A lock or retention refusal some providers report as 400.
  if (status === 400 && code && /lock|retention|worm|immutable/i.test(code))
    return { status, code, outcome: "refused" };
  return { status, code, outcome: "error" };
}

/**
 * Authorization-before-validation probe: a malformed body. Denied -> refused; parsed (4xx validation
 * error) -> the permission is present ("succeeded" means "the writer holds it").
 */
function classifyProbe(response: S3Response | Error): Attempt {
  if (response instanceof Error) return { status: 0, code: response.message.slice(0, 120), outcome: "error" };
  const { status, code } = response;
  if (status === 403 || code === "AccessDenied") return { status, code, outcome: "refused" };
  if (status === 501 || code === "NotImplemented") return { status, code, outcome: "unsupported" };
  if ((status >= 200 && status < 300) || status === 400 || status === 409 || status === 411) {
    return { status, code, outcome: "succeeded" };
  }
  return { status, code, outcome: "error" };
}

/**
 * A destructive attempt judged by what it did: `changed` is true when the original version or its
 * retention changed, false when it is provably unchanged, null when the effect could not be read.
 * The provider's response code is kept as denial evidence.
 */
function byEffect(response: S3Response | Error, changed: boolean | null): Attempt {
  const seen = classify(response);
  if (changed === true) return { ...seen, outcome: "succeeded" };
  if (changed === false) return seen;
  return { ...seen, outcome: seen.outcome === "succeeded" ? "succeeded" : "error" };
}

async function attempt<T>(action: () => Promise<T>) {
  try {
    return await action();
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

const policyPatternMatches = (pattern: string, value: string) =>
  new RegExp(
    `^${pattern
      .split("*")
      .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join(".*")}$`,
  ).test(value);

/** Conservative read-only proof: only unconditional all-principal bucket Deny statements count.
 * IAM exceptions cannot override these denies. Unsupported/conditional policies stay unknown.
 */
export function protectsRepositoryPolicy(policy: unknown, bucket: string, prefix: string): boolean {
  const statements = (policy as { Statement?: unknown[] } | null)?.Statement;
  if (!Array.isArray(statements)) return false;
  const resource = `arn:aws:s3:::${bucket}/${resticPrefix(prefix)}/config`;
  return [
    ["s3:DeleteObjectVersion", resource],
    ["s3:PutObjectRetention", resource],
    ["s3:BypassGovernanceRetention", resource],
    ["s3:PutObjectLegalHold", resource],
    ["s3:DeleteBucketPolicy", `arn:aws:s3:::${bucket}`],
  ].every(([action, protectedResource]) =>
    statements.some((value) => {
      const statement = value as Record<string, unknown>;
      if (
        !statement ||
        statement.Effect !== "Deny" ||
        statement.Condition ||
        statement.NotAction ||
        statement.NotResource ||
        statement.NotPrincipal
      )
        return false;
      const principal = statement.Principal;
      if (
        principal !== "*" &&
        !(
          principal &&
          typeof principal === "object" &&
          ((principal as Record<string, unknown>).AWS === "*" ||
            (Array.isArray((principal as Record<string, unknown>).AWS) &&
              ((principal as Record<string, unknown>).AWS as unknown[]).includes("*")))
        )
      )
        return false;
      const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
      const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
      return (
        actions.some(
          (pattern) =>
            typeof pattern === "string" && policyPatternMatches(pattern.toLowerCase(), action!.toLowerCase()),
        ) &&
        resources.some(
          (pattern) => typeof pattern === "string" && policyPatternMatches(pattern, protectedResource!),
        )
      );
    }),
  );
}

export async function runAppendOnlyCanary(input: CanaryInput): Promise<CanaryEvidence> {
  const now = input.now ?? (() => new Date());
  const { client } = input;
  const startedAt = now();
  const token = `${startedAt.toISOString().slice(0, 10).replace(/-/g, "")}-${randomBytes(6).toString("hex")}`;
  const findings: CanaryFinding[] = [];
  const deletable = (message: string) => findings.push({ kind: "deletable", message });
  const unknown = (message: string) => findings.push({ kind: "unknown", message });

  // 1. Read-only bucket inspection with the writer's own credentials.
  const versioningResponse = await attempt(() =>
    client.request("GET", undefined, { query: { versioning: "" } }),
  );
  let bucketVersioning = "unknown";
  if (!(versioningResponse instanceof Error) && versioningResponse.status === 200) {
    bucketVersioning = xmlValue(versioningResponse.text, "Status") ?? "Disabled";
  }
  const lockResponse = await attempt(() =>
    client.request("GET", undefined, { query: { "object-lock": "" } }),
  );
  let objectLock: CanaryEvidence["objectLock"] = null;
  if (!(lockResponse instanceof Error) && lockResponse.status === 200) {
    const days = xmlValue(lockResponse.text, "Days");
    const years = xmlValue(lockResponse.text, "Years");
    objectLock = {
      enabled: xmlValue(lockResponse.text, "ObjectLockEnabled") === "Enabled",
      mode: xmlValue(lockResponse.text, "Mode"),
      days: days ? Number(days) : null,
      years: years ? Number(years) : null,
    };
  }
  const versioned = bucketVersioning === "Enabled";
  if (bucketVersioning === "unknown" && input.provider !== "r2") {
    unknown("bucket versioning could not be read with the writer credentials");
  }

  // 2. Per-class canaries.
  const classes: ClassEvidence[] = [];
  for (const policyClass of CANARY_POLICY_CLASSES) {
    const key = canaryKey(input.prefix, policyClass, token);
    const original = `ark append-only canary ${policyClass} ${token} ${randomBytes(16).toString("hex")}\n`;
    const evidence: ClassEvidence = {
      policyClass,
      key,
      versionId: null,
      sha256: sha256(original),
      retention: null,
      retentionCheck: "none",
      attempts: {
        ordinaryDelete: null,
        overwrite: null,
        permanentDelete: null,
        bypassDelete: null,
        shortenRetention: null,
        shortenRetentionBypass: null,
      },
      readback: "missing",
    };
    classes.push(evidence);
    const put = await attempt(() => client.request("PUT", key, { body: original }));
    if (put instanceof Error || put.status !== 200) {
      unknown(
        `${policyClass}: the writer could not create the canary (${put instanceof Error ? put.message : (put.code ?? put.status)})`,
      );
      continue;
    }
    evidence.versionId = put.headers.get("x-amz-version-id");
    if (versioned && (!evidence.versionId || evidence.versionId === "null")) {
      unknown(`${policyClass}: the provider returned no version ID on a versioned bucket`);
    }
    const versionQuery: Record<string, string> =
      evidence.versionId && evidence.versionId !== "null" ? { versionId: evidence.versionId } : {};

    // Retention as stored on the canary (default retention or bucket lock).
    const retention = await attempt(() =>
      client.request("GET", key, { query: { retention: "", ...versionQuery } }),
    );
    if (!(retention instanceof Error) && retention.status === 200) {
      const mode = xmlValue(retention.text, "Mode");
      const until = xmlValue(retention.text, "RetainUntilDate");
      if (mode && until) {
        evidence.retention = { mode, retainUntil: new Date(until).toISOString() };
        evidence.retentionCheck = "ok";
      }
    } else if (
      !(retention instanceof Error) &&
      (retention.status === 501 || retention.code === "NotImplemented")
    ) {
      evidence.retentionCheck = "unsupported";
    } else if (
      !(retention instanceof Error) &&
      (retention.status === 404 || /NoSuchObjectLockConfiguration|InvalidRequest/.test(retention.code ?? ""))
    ) {
      evidence.retentionCheck = "none";
    } else {
      evidence.retentionCheck = "error";
    }

    // Ordinary delete and overwrite: allowed or not, the original must survive.
    evidence.attempts.ordinaryDelete = classify(await attempt(() => client.request("DELETE", key)));
    evidence.attempts.overwrite = classify(
      await attempt(() =>
        client.request("PUT", key, { body: `overwritten ${randomBytes(8).toString("hex")}\n` }),
      ),
    );
    const readOriginal = async (): Promise<ClassEvidence["readback"]> => {
      const response = await attempt(() => client.request("GET", key, { query: versionQuery }));
      if (response instanceof Error) return "error";
      if (response.status === 200) return sha256(response.body) === evidence.sha256 ? "match" : "mismatch";
      return response.status === 404 ? "missing" : "error";
    };
    const readRetention = async () => {
      const response = await attempt(() =>
        client.request("GET", key, { query: { retention: "", ...versionQuery } }),
      );
      if (response instanceof Error || response.status !== 200) return null;
      const until = xmlValue(response.text, "RetainUntilDate");
      return until ? new Date(until) : null;
    };
    if (versioned && evidence.versionId && evidence.versionId !== "null") {
      // Permanent, version-specific deletion of the recorded original, plain and with the governance
      // bypass header. Judged by effect: the original version must still read back afterwards.
      for (const [name, headers] of [
        ["permanentDelete", {}],
        ["bypassDelete", { "x-amz-bypass-governance-retention": "true" }],
      ] as const) {
        const response = await attempt(() => client.request("DELETE", key, { query: versionQuery, headers }));
        const after = await readOriginal();
        evidence.attempts[name] = byEffect(response, after === "error" ? null : after !== "match");
      }
      // Shorten the canary's retention to one hour from now, plain and with bypass. Judged by effect:
      // the stored RetainUntilDate must not move earlier.
      const before = evidence.retention ? new Date(evidence.retention.retainUntil) : null;
      const shorter = `<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>GOVERNANCE</Mode><RetainUntilDate>${new Date(now().getTime() + 3_600_000).toISOString()}</RetainUntilDate></Retention>`;
      for (const [name, bypass] of [
        ["shortenRetention", false],
        ["shortenRetentionBypass", true],
      ] as const) {
        const response = await attempt(() =>
          client.request("PUT", key, {
            query: { retention: "", ...versionQuery },
            body: shorter,
            headers: {
              "content-md5": contentMd5(shorter),
              "content-type": "application/xml",
              ...(bypass ? { "x-amz-bypass-governance-retention": "true" } : {}),
            },
          }),
        );
        const after = await readRetention();
        const shortened = before ? (after ? after.getTime() < before.getTime() : null) : after !== null;
        evidence.attempts[name] = byEffect(response, shortened);
      }
    }

    // Read back the original.
    evidence.readback = await readOriginal();

    for (const [name, result] of Object.entries(evidence.attempts)) {
      if (!result) continue;
      const dangerous = [
        "permanentDelete",
        "bypassDelete",
        "shortenRetention",
        "shortenRetentionBypass",
      ].includes(name);
      if (dangerous && result.outcome === "succeeded")
        deletable(`${policyClass}: ${name} succeeded with the writer credentials`);
      if (result.outcome === "unsupported" || result.outcome === "error") {
        unknown(`${policyClass}: ${name} gave an inconclusive response (${result.code ?? result.status})`);
      }
    }
    if (evidence.readback !== "match") {
      deletable(
        `${policyClass}: the original canary is ${evidence.readback} after the writer's delete and overwrite attempts`,
      );
    }
    if (!versioned && input.provider !== "r2") {
      unknown(`${policyClass}: bucket versioning is ${bucketVersioning}; history cannot be proven immutable`);
    }
  }

  // 3. restic's locks/ class: create and delete must work, or restic backup fails.
  const lock = locksKey(input.prefix, token);
  const lockCreate = classify(
    await attempt(() => client.request("PUT", lock, { body: `ark canary lock ${token}\n` })),
  );
  const lockDelete =
    lockCreate.outcome === "succeeded" ? classify(await attempt(() => client.request("DELETE", lock))) : null;
  if (lockCreate.outcome !== "succeeded" || lockDelete?.outcome !== "succeeded") {
    unknown("restic cannot create and delete its lock files under locks/");
  }

  // 4. Bucket-level policy-changing permissions, probed without changing anything.
  const probe = (subresource: keyof typeof BUCKET_PROBE_BODIES) => {
    const body = BUCKET_PROBE_BODIES[subresource];
    return attempt(() =>
      client.request("PUT", undefined, {
        query: { [subresource]: "" },
        body,
        headers: {
          "content-md5": contentMd5(body),
          "content-type": subresource === "policy" ? "application/json" : "application/xml",
        },
      }),
    ).then(classifyProbe);
  };
  const bucketProbes = {
    versioning: await probe("versioning"),
    objectLock: await probe("object-lock"),
    lifecycle: await probe("lifecycle"),
    policy: await probe("policy"),
  };

  // 5. Provider evaluation where the S3 API cannot answer.
  let providerEvidence: Record<string, unknown> | null = null;
  let bucketLevelProven = false;
  let providerRetentionUntil: Date | null = null;
  let exactConfigProven = false;
  if (input.provider === "b2" && input.writer) {
    providerEvidence = await b2Capabilities(input.writer, input.fetchImpl ?? fetch);
    const capabilities = Array.isArray(providerEvidence.capabilities)
      ? (providerEvidence.capabilities as string[])
      : null;
    if (capabilities) {
      const forbidden = capabilities.filter((item) => B2_FORBIDDEN_CAPABILITIES.includes(item));
      if (forbidden.length) deletable(`the B2 application key holds ${forbidden.join(", ")}`);
      else {
        bucketLevelProven = true;
        exactConfigProven = true;
      }
    } else unknown("B2 key capabilities could not be read");
  }
  if (input.provider === "r2") {
    // R2 lock rules are managed only through the Cloudflare API, which an S3 key cannot authenticate
    // to; NotImplemented on the S3 probes is therefore expected. Coverage needs the read-only verifier.
    bucketLevelProven = Object.values(bucketProbes).every(
      (item) => item.outcome === "refused" || item.outcome === "unsupported",
    );
    if (input.verifier?.accountId && input.verifier.token) {
      const r2 = await r2LockRules(
        input.verifier.accountId,
        input.verifier.token,
        client.location.bucket,
        input.fetchImpl ?? fetch,
      );
      providerEvidence = r2;
      providerRetentionUntil = r2RetentionUntil(r2, input.prefix, startedAt);
      exactConfigProven = providerRetentionUntil !== null;
      if (!providerRetentionUntil)
        unknown("R2 bucket lock rules require indefinite coverage of every protected prefix");
    } else {
      unknown("R2 bucket lock rules need the read-only Cloudflare verifier token to be proven");
    }
  }
  for (const [name, result] of Object.entries(bucketProbes)) {
    if (result.outcome === "succeeded")
      deletable(`the writer holds the bucket-level ${name} permission (${result.code ?? result.status})`);
    else if (result.outcome === "error" || (result.outcome !== "refused" && !bucketLevelProven)) {
      unknown(`the bucket-level ${name} permission could not be evaluated (${result.code ?? result.status})`);
    }
  }

  // Class canaries cannot prove permissions on the singleton restic config key. Read an
  // authoritative bucket-wide Deny; it overrides IAM exceptions without touching live config.
  if (!exactConfigProven) {
    const policy = await attempt(() => client.request("GET", undefined, { query: { policy: "" } }));
    if (!(policy instanceof Error) && policy.status === 200 && versioned) {
      try {
        exactConfigProven = protectsRepositoryPolicy(
          JSON.parse(policy.text),
          client.location.bucket,
          input.prefix,
        );
      } catch {
        /* unknown */
      }
    }
    if (!exactConfigProven)
      unknown("exact restic config protection could not be proven by read-only policy evaluation");
  }

  // 6. Retention coverage.
  const window = input.recoveryWindowDays * 24 * 60 * 60 * 1000;
  let retentionUntil: Date | null = providerRetentionUntil;
  if (input.provider !== "r2") {
    for (const item of classes) {
      if (item.retentionCheck === "unsupported" || item.retentionCheck === "error") {
        unknown(`${item.policyClass}: object retention could not be read`);
        retentionUntil = null;
        break;
      }
      const until = item.retention ? new Date(item.retention.retainUntil) : null;
      if (!until) {
        retentionUntil = null;
        findings.push({ kind: "retention", message: `${item.policyClass}: the canary has no retention` });
        break;
      }
      if (!retentionUntil || until < retentionUntil) retentionUntil = until;
    }
  }
  if (retentionUntil && retentionUntil.getTime() < startedAt.getTime() + window) {
    findings.push({
      kind: "retention",
      message: `retention ends ${retentionUntil.toISOString()}, before the ${input.recoveryWindowDays}-day recovery window`,
    });
  }

  const status: AppendOnlyStatus = findings.some((item) => item.kind === "deletable")
    ? "deletable"
    : findings.some((item) => item.kind === "unknown")
      ? "unknown"
      : findings.some((item) => item.kind === "retention")
        ? "retention_short"
        : "append_only";
  return {
    version: 1,
    checkedAt: startedAt.toISOString(),
    provider: input.provider,
    bucket: client.location.bucket,
    prefix: input.prefix,
    pathStyle: client.location.pathStyle,
    recoveryWindowDays: input.recoveryWindowDays,
    token,
    bucketVersioning,
    objectLock,
    classes,
    locks: { create: lockCreate, delete: lockDelete },
    bucketProbes,
    providerEvidence,
    retentionUntil: retentionUntil?.toISOString() ?? null,
    findings,
    status,
  };
}

/** Backblaze key capabilities that would let a compromised server erase or unlock history. */
export const B2_FORBIDDEN_CAPABILITIES = [
  "deleteFiles",
  "bypassGovernance",
  "writeBucketRetentions",
  "writeBuckets",
  "deleteBuckets",
  "writeFileLegalHolds",
];

async function b2Capabilities(
  writer: { accessKeyId: string; secretAccessKey: string },
  fetchImpl: typeof fetch,
) {
  try {
    const response = await fetchImpl("https://api.backblazeb2.com/b2api/v3/b2_authorize_account", {
      headers: {
        authorization: `Basic ${Buffer.from(`${writer.accessKeyId}:${writer.secretAccessKey}`).toString("base64")}`,
      },
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok) return { error: `b2_authorize_account returned ${response.status}` };
    const body = (await response.json()) as {
      apiInfo?: {
        storageApi?: { capabilities?: string[]; bucketName?: string | null; namePrefix?: string | null };
      };
    };
    const storage = body.apiInfo?.storageApi;
    return {
      capabilities: storage?.capabilities ?? null,
      bucketName: storage?.bucketName ?? null,
      namePrefix: storage?.namePrefix ?? null,
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "b2_authorize_account failed" };
  }
}

type R2Rule = {
  id?: string;
  enabled?: boolean;
  prefix?: string;
  condition?: { type?: string; maxAgeSeconds?: number; date?: string };
};

async function r2LockRules(accountId: string, token: string, bucket: string, fetchImpl: typeof fetch) {
  try {
    const response = await fetchImpl(
      `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/r2/buckets/${encodeURIComponent(bucket)}/lock`,
      { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(20_000) },
    );
    if (!response.ok) return { error: `Cloudflare API returned ${response.status}` };
    const body = (await response.json()) as { result?: { rules?: R2Rule[] } };
    return { rules: body.result?.rules ?? [] };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "Cloudflare API request failed" };
  }
}

/** The earliest end of lock coverage across every protected prefix, or null if one is uncovered. */
export function r2RetentionUntil(evidence: Record<string, unknown>, prefix: string, _now: Date) {
  const rules = (Array.isArray(evidence.rules) ? evidence.rules : []) as R2Rule[];
  const repo = resticPrefix(prefix);
  const protectedPrefixes = [
    ...["data/", "index/", "snapshots/", "keys/"].map((item) => `${repo}/${item}`),
    `${repo}/config`,
    `${prefix.replace(/\/+$/, "")}/ark-canary/`,
  ];
  let earliest: Date | null = null;
  for (const target of protectedPrefixes) {
    let best: Date | null = null;
    for (const rule of rules) {
      if (rule.enabled === false) continue;
      const rulePrefix = rule.prefix ?? "";
      if (!target.startsWith(rulePrefix)) continue;
      // An overly broad rule that also locks locks/ breaks restic; refuse to count it.
      if (`${repo}/locks/`.startsWith(rulePrefix)) continue;
      let until: Date | null = null;
      if (rule.condition?.type === "Indefinite") until = new Date("9999-12-31T00:00:00Z");
      // Restic reuses config, keys and packs indefinitely. Finite Age/Date locks
      // cannot protect dependencies of future snapshots after their original lock expires.
      if (until && (!best || until > best)) best = until;
    }
    if (!best) return null;
    if (!earliest || best < earliest) earliest = best;
  }
  return earliest;
}
