import { describe, expect, test } from "bun:test";

import {
  PROVIDER_RECIPES,
  canaryKey,
  evaluateBackupHealth,
  locksKey,
  resticS3Repository,
  s3TargetInput,
  writerPolicy,
  type HealthExport,
  type HealthSource,
  type HealthTarget,
} from "./backup-targets.ts";

const now = new Date("2026-11-17T12:00:00Z");
const minutesAgo = (minutes: number) => new Date(now.getTime() - minutes * 60_000);

const target = (overrides: Partial<HealthTarget> = {}): HealthTarget => ({
  id: "bkt_a",
  name: "minio",
  kind: "s3",
  enabled: true,
  appendOnlyStatus: "append_only",
  appendOnlyCheckedAt: minutesAgo(60),
  retentionUntil: new Date(now.getTime() + 30 * 86_400_000),
  recoveryWindowDays: 30,
  lastSuccessAt: minutesAgo(3),
  lastError: null,
  ...overrides,
});
const exported = (overrides: Partial<HealthExport> = {}): HealthExport[] =>
  ["pg:ark-platform", "pg:ark-app"].map((source) => ({
    targetId: "bkt_a",
    source,
    status: "succeeded",
    lastRecoverableAt: minutesAgo(4),
    repoBytes: 1_000_000,
    createdAt: minutesAgo(3),
    ...overrides,
  }));
const sources = (overrides: Partial<HealthSource> = {}): HealthSource[] =>
  ["pg:ark-platform", "pg:ark-app"].map((source) => ({
    source,
    observedAt: minutesAgo(1),
    freeBytes: 400 * 1024 ** 3,
    totalBytes: 500 * 1024 ** 3,
    localRecoverableAt: minutesAgo(4),
    repoBytes: 1_000_000,
    archiveFailing: false,
    configured: true,
    ...overrides,
  }));
const pgSources = ["pg:ark-platform", "pg:ark-app"];

describe("S3 target model (FD-21)", () => {
  test("input validation normalizes the endpoint and rejects paths and credentials in it", () => {
    const parsed = s3TargetInput.parse({
      name: "b2",
      provider: "b2",
      endpoint: "s3.us-east-005.backblazeb2.com",
      region: "us-east-005",
      bucket: "ark-backups",
      pathStyle: false,
    });
    expect(parsed.endpoint).toBe("https://s3.us-east-005.backblazeb2.com");
    expect(parsed.prefix).toBe("ark");
    expect(parsed.recoveryWindowDays).toBe(30);
    for (const endpoint of [
      "https://user:pw@s3.example.com",
      "https://s3.example.com/bucket",
      "ftp://s3.example.com",
    ]) {
      expect(() => s3TargetInput.parse({ ...parsed, endpoint })).toThrow();
    }
    expect(() => s3TargetInput.parse({ ...parsed, bucket: "Bad_Bucket" })).toThrow();
    expect(() => s3TargetInput.parse({ ...parsed, prefix: "../x" })).toThrow();
    expect(() => s3TargetInput.parse({ ...parsed, repositoryPassword: "short" })).toThrow();
  });

  test("restic repository URL and addressing per path style; secrets stay out of argv", () => {
    const path = resticS3Repository({
      endpoint: "http://127.0.0.1:9000",
      region: "us-east-1",
      bucket: "b",
      prefix: "ark",
      pathStyle: true,
    });
    expect(path.repository).toBe("s3:http://127.0.0.1:9000/b/ark/restic");
    expect(path.options).toEqual(["-o", "s3.bucket-lookup=path", "-o", "s3.region=us-east-1"]);
    const dns = resticS3Repository({
      endpoint: "https://s3.amazonaws.com",
      region: "eu-west-1",
      bucket: "b",
      prefix: "x/y",
      pathStyle: false,
    });
    expect(dns.options).toContain("s3.bucket-lookup=dns");
    expect(dns.repository).toBe("s3:https://s3.amazonaws.com/b/x/y/restic");
  });

  test("the writer policy only deletes restic locks and denies every erase or unlock path", () => {
    const policy = writerPolicy("ark-backups", "ark");
    const deletes = policy.Statement.filter(
      (item) => item.Effect === "Allow" && item.Action.includes("s3:DeleteObject"),
    );
    expect(deletes.map((item) => item.Resource)).toEqual([["arn:aws:s3:::ark-backups/ark/restic/locks/*"]]);
    const denied = policy.Statement.find((item) => item.Effect === "Deny")!.Action;
    for (const action of [
      "s3:DeleteObjectVersion",
      "s3:BypassGovernanceRetention",
      "s3:PutObjectRetention",
      "s3:PutBucketVersioning",
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutLifecycleConfiguration",
      "s3:PutBucketPolicy",
    ]) {
      expect(denied).toContain(action);
    }
  });

  test("canaries cover every policy class, and only locks/ is the delete exception", () => {
    expect(canaryKey("ark", "data", "token-1234")).toBe("ark/restic/data/ark-canary-token-1234");
    expect(canaryKey("ark", "config", "token-1234")).toBe("ark/restic/config.ark-canary-token-1234");
    expect(canaryKey("ark", "ark-canary", "token-1234")).toBe("ark/ark-canary/token-1234");
    expect(locksKey("ark", "token-1234")).toBe("ark/restic/locks/ark-canary-token-1234");
    expect(() => canaryKey("ark", "data", "../../x")).toThrow();
  });

  test("every provider has a recipe; R2 never locks locks/ and needs the verifier", () => {
    expect(Object.keys(PROVIDER_RECIPES).toSorted()).toEqual(["aws", "b2", "minio", "other", "r2"]);
    expect(PROVIDER_RECIPES.minio.pathStyle).toBe(true);
    expect(PROVIDER_RECIPES.r2.regionOverride).toBe("auto");
    expect(PROVIDER_RECIPES.r2.immutability.join(" ")).toMatch(/Do not lock <prefix>\/restic\/locks\//);
  });
});

describe("backup health (FD-21, front door §3.18.4)", () => {
  test("healthy with a current append-only target and fresh recovery points", () => {
    const health = evaluateBackupHealth({
      targets: [target()],
      exports: exported(),
      sources: sources(),
      pgSources,
      now,
    });
    expect(health.reasons).toEqual([]);
    expect(health.healthy).toBe(true);
    expect(health.alerts).toEqual([]);
  });

  test("no target configured is unhealthy", () => {
    const health = evaluateBackupHealth({ targets: [], exports: [], sources: sources(), pgSources, now });
    expect(health.healthy).toBe(false);
    expect(health.alerts.map((item) => item.dedupKey)).toEqual(["backup-no-target"]);
  });

  test("deletable, unknown, short retention and expired evidence are all unhealthy", () => {
    for (const [overrides, severity] of [
      [{ appendOnlyStatus: "deletable" }, "critical"],
      [{ appendOnlyStatus: "unknown" }, "warning"],
      [{ appendOnlyStatus: "retention_short" }, "warning"],
      [{ appendOnlyCheckedAt: minutesAgo(8 * 24 * 60) }, "warning"],
      [{ retentionUntil: minutesAgo(1) }, "warning"],
    ] as const) {
      const health = evaluateBackupHealth({
        targets: [target(overrides)],
        exports: exported(),
        sources: sources(),
        pgSources,
        now,
      });
      expect(health.healthy).toBe(false);
      expect(health.alerts).toContainEqual(
        expect.objectContaining({ dedupKey: "backup-append-only:bkt_a", severity }),
      );
    }
  });

  test("a destination that stopped acknowledging raises the last-recoverable-time and capacity alerts", () => {
    const stale = exported({
      lastRecoverableAt: minutesAgo(60),
      repoBytes: 1_000_000,
      createdAt: minutesAgo(60),
    });
    const health = evaluateBackupHealth({
      targets: [target({ lastError: "dial tcp: connection refused" })],
      exports: [
        ...stale,
        ...exported({ status: "failed", lastRecoverableAt: null, createdAt: minutesAgo(1) }),
      ],
      sources: sources({ localRecoverableAt: minutesAgo(2), repoBytes: 5_000_000 }),
      pgSources,
      now,
    });
    expect(health.healthy).toBe(false);
    const keys = health.alerts.map((item) => item.dedupKey);
    expect(keys).toContain("backup-rpo:bkt_a:pg:ark-platform");
    expect(keys).toContain("backup-capacity:pg:ark-platform");
    expect(health.targets[0]!.sources[0]!.lastAttemptFailed).toBe(true);
    expect(
      health.alerts.find((item) => item.dedupKey === "backup-rpo:bkt_a:pg:ark-platform")!.title,
    ).toContain(minutesAgo(60).toISOString());
  });

  test("capacity is critical when local storage would fill before the destination recovers", () => {
    const health = evaluateBackupHealth({
      targets: [target()],
      exports: exported({ lastRecoverableAt: minutesAgo(120), repoBytes: 10 * 1024 ** 3 }),
      // 20 GiB written in two hours with 100 GiB free: about five hours to full.
      sources: sources({
        localRecoverableAt: minutesAgo(1),
        repoBytes: 30 * 1024 ** 3,
        freeBytes: 100 * 1024 ** 3,
      }),
      pgSources,
      now,
    });
    const capacity = health.alerts.find((item) => item.dedupKey === "backup-capacity:pg:ark-platform");
    expect(capacity?.severity).toBe("critical");
    expect(health.sources[0]!.hoursToFull).toBeLessThan(72);
  });

  test("low free space alone is critical; unreachable executors and failing archiving fail health", () => {
    const low = evaluateBackupHealth({
      targets: [target()],
      exports: exported(),
      sources: sources({ freeBytes: 1024 ** 3 }),
      pgSources,
      now,
    });
    expect(low.alerts).toContainEqual(
      expect.objectContaining({ dedupKey: "backup-capacity:pg:ark-app", severity: "critical" }),
    );
    const down = evaluateBackupHealth({
      targets: [target()],
      exports: exported(),
      sources: sources({ configured: false }),
      pgSources,
      now,
    });
    expect(down.alerts).toContainEqual(expect.objectContaining({ dedupKey: "backup-source:pg:ark-app" }));
    const failing = evaluateBackupHealth({
      targets: [target()],
      exports: exported(),
      sources: sources({ archiveFailing: true }),
      pgSources,
      now,
    });
    expect(failing.healthy).toBe(false);
  });

  test("a disabled target is ignored, but at least one enabled target of each required kind is needed", () => {
    const health = evaluateBackupHealth({
      targets: [target({ enabled: false })],
      exports: exported(),
      sources: sources(),
      pgSources,
      now,
    });
    expect(health.alerts.map((item) => item.dedupKey)).toContain("backup-no-target");
  });
});
