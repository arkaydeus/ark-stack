import { describe, expect, test } from "bun:test";

import {
  PROVIDER_RECIPES,
  REQUIRED_BACKUP_TARGET_KINDS,
  backupSocksProxy,
  canaryKey,
  evaluateBackupHealth,
  locksKey,
  restRepositoryUser,
  resticRestEnv,
  resticRestRepository,
  resticS3Repository,
  s3TargetInput,
  tailnetRestTargetInput,
  withoutProxyEnv,
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
// FD-30: the home target, healthy unless a test overrides it.
const home = (overrides: Partial<HealthTarget> = {}): HealthTarget =>
  target({
    id: "bkt_home",
    name: "home",
    kind: "tailnet_rest",
    retentionUntil: null,
    identity: { ok: true, message: "pinned" },
    ...overrides,
  });
const homeExports = (overrides: Partial<HealthExport> = {}) =>
  exported({ targetId: "bkt_home", ...overrides });

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
  test("healthy with a current append-only target of each kind and fresh recovery points", () => {
    const health = evaluateBackupHealth({
      targets: [target(), home()],
      exports: [...exported(), ...homeExports()],
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
    expect(health.alerts.map((item) => item.dedupKey)).toEqual([
      "backup-no-target",
      "backup-no-target:tailnet_rest",
    ]);
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

describe("both destinations are required (FD-30, §3.18.4)", () => {
  test("S3 and the home target are both required kinds", () => {
    expect([...REQUIRED_BACKUP_TARGET_KINDS].toSorted()).toEqual(["s3", "tailnet_rest"]);
  });

  test("an S3 target alone is not healthy: the home destination is missing", () => {
    const health = evaluateBackupHealth({
      targets: [target()],
      exports: exported(),
      sources: sources(),
      pgSources,
      now,
    });
    expect(health.healthy).toBe(false);
    expect(health.targets[0]!.healthy).toBe(true);
    expect(health.reasons).toEqual(["No home (tailnet REST) backup target is configured."]);
    expect(health.alerts.map((item) => item.dedupKey)).toEqual(["backup-no-target:tailnet_rest"]);
  });

  test("either target stale makes backups unhealthy and alerts", () => {
    for (const [stale, key] of [
      ["s3", "backup-target-stale:bkt_a"],
      ["tailnet_rest", "backup-target-stale:bkt_home"],
    ] as const) {
      const old = minutesAgo(40 * 60);
      const health = evaluateBackupHealth({
        targets: [
          target(stale === "s3" ? { lastSuccessAt: old } : {}),
          home(stale === "tailnet_rest" ? { lastSuccessAt: old } : {}),
        ],
        exports: [
          ...exported(stale === "s3" ? { createdAt: old, lastRecoverableAt: old } : {}),
          ...homeExports(stale === "tailnet_rest" ? { createdAt: old, lastRecoverableAt: old } : {}),
        ],
        sources: sources(),
        pgSources,
        now,
      });
      expect(health.healthy).toBe(false);
      const keys = health.alerts.map((item) => item.dedupKey);
      expect(keys).toContain(key);
      const id = stale === "s3" ? "bkt_a" : "bkt_home";
      expect(keys).toContain(`backup-rpo:${id}:pg:ark-platform`);
      expect(health.targets.find((item) => item.id === id)!.healthy).toBe(false);
      expect(health.targets.find((item) => item.id !== id)!.healthy).toBe(true);
    }
  });

  test("an invalid home identity suspends transfers and is a critical alert", () => {
    const health = evaluateBackupHealth({
      targets: [target(), home({ identity: { ok: false, message: "backup-ts's observation has expired" } })],
      exports: [...exported(), ...homeExports()],
      sources: sources(),
      pgSources,
      now,
    });
    expect(health.healthy).toBe(false);
    expect(health.alerts).toContainEqual(
      expect.objectContaining({ dedupKey: "backup-tailnet:bkt_home", severity: "critical" }),
    );
  });

  test("rest-server append-only evidence has no object-retention deadline but still expires", () => {
    const fresh = evaluateBackupHealth({
      targets: [target(), home()],
      exports: [...exported(), ...homeExports()],
      sources: sources(),
      pgSources,
      now,
    });
    expect(fresh.targets.find((item) => item.id === "bkt_home")!.appendOnly.current).toBe(true);
    const expired = evaluateBackupHealth({
      targets: [target(), home({ appendOnlyCheckedAt: minutesAgo(8 * 24 * 60) })],
      exports: [...exported(), ...homeExports()],
      sources: sources(),
      pgSources,
      now,
    });
    expect(expired.alerts).toContainEqual(
      expect.objectContaining({ dedupKey: "backup-append-only:bkt_home" }),
    );
  });
});

describe("tailnet REST target model (FD-30)", () => {
  test("accepts the documented URL and derives the private-repos user", () => {
    const input = tailnetRestTargetInput.parse({
      name: "home",
      restUrl: "http://backup-home.tail1234.ts.net:8000/ark/",
      password: "htpasswd-secret",
      repositoryPassword: "x".repeat(32),
    });
    expect(input.restUrl).toBe("http://backup-home.tail1234.ts.net:8000/ark");
    expect(restRepositoryUser(input.restUrl)).toBe("ark");
    expect(
      tailnetRestTargetInput.parse({ name: "ip", restUrl: "http://100.66.2.9:8000/ark/vps1" }).restUrl,
    ).toBe("http://100.66.2.9:8000/ark/vps1");
  });

  test("rejects public hosts, credentials in the URL, missing ports and odd paths", () => {
    for (const restUrl of [
      "http://backup.example.com:8000/ark",
      "http://8.8.8.8:8000/ark",
      "http://ark:pw@backup-home.tail1234.ts.net:8000/ark",
      "http://backup-home.tail1234.ts.net/ark",
      "http://backup-home.tail1234.ts.net:8000/",
      "http://backup-home.tail1234.ts.net:8000/ark?x=1",
      "ftp://backup-home.tail1234.ts.net:8000/ark",
      "http://100.100.100.100:8000/ark",
    ]) {
      expect(tailnetRestTargetInput.safeParse({ name: "home", restUrl }).success).toBe(false);
    }
  });

  test("http:// substitutes the pinned address; https:// keeps the certificate's name", () => {
    expect(
      resticRestRepository({ restUrl: "http://backup-home.tail1234.ts.net:8000/ark", targetIp: "100.66.2.9" })
        .repository,
    ).toBe("rest:http://100.66.2.9:8000/ark/");
    expect(
      resticRestRepository({
        restUrl: "http://backup-home.tail1234.ts.net:8000/ark",
        targetIp: "fd7a:115c:a1e0::1:2",
      }).repository,
    ).toBe("rest:http://[fd7a:115c:a1e0::1:2]:8000/ark/");
    expect(
      resticRestRepository({
        restUrl: "https://backup-home.tail1234.ts.net:8000/ark",
        targetIp: "100.66.2.9",
      }).repository,
    ).toBe("rest:https://backup-home.tail1234.ts.net:8000/ark/");
    expect(() =>
      resticRestRepository({ restUrl: "http://backup-home.tail1234.ts.net:8000/ark", targetIp: "10.0.0.1" }),
    ).toThrow();
  });

  test("the REST subprocess gets exactly one matching-scheme proxy and no other proxy setting", () => {
    const keys = { username: "ark", password: "pw", repositoryPassword: "repo" };
    const http = resticRestEnv(
      { restUrl: "http://backup-home.tail1234.ts.net:8000/ark" },
      keys,
      "socks5://backup-ts:1055",
    );
    expect(http).toEqual({
      RESTIC_REST_USERNAME: "ark",
      RESTIC_REST_PASSWORD: "pw",
      RESTIC_PASSWORD: "repo",
      HTTP_PROXY: "socks5://backup-ts:1055",
    });
    const https = resticRestEnv({ restUrl: "https://backup-home.tail1234.ts.net:8000/ark" }, keys, "");
    expect(https.HTTPS_PROXY).toBe("socks5://backup-ts:1055");
    expect(https.HTTP_PROXY).toBeUndefined();
    expect(() => backupSocksProxy("http://backup-ts:1055")).toThrow();
    expect(() => backupSocksProxy("socks5://user:pw@backup-ts:1055")).toThrow();
  });

  test("proxy variables are stripped from any inherited environment", () => {
    expect(
      withoutProxyEnv({
        PATH: "/bin",
        HTTP_PROXY: "socks5://decoy:1",
        https_proxy: "http://decoy:2",
        ALL_PROXY: "x",
        NO_PROXY: "*",
        no_proxy: "*",
      }),
    ).toEqual({ PATH: "/bin" });
  });
});
