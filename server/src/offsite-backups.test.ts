// FD-21 off-VPS backups against the migrated platform database (DATABASE_URL): sealed write-only target
// credentials, per-destination export manifests from a fake executor and a fake restic, local backups
// becoming `uploaded`, and per-target alerts raised and resolved.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { fakeS3 } from "./modules/test-backup-s3.ts";
import { createId } from "@ark-stack/shared";
import { and, eq, inArray, like } from "drizzle-orm";

const { db } = await import("./db.ts");
const { alerts, backupExports, backupSources, backupTargets, backups, secrets, operations } =
  await import("./schema.ts");
const offsite = await import("./modules/offsite-backups.ts");

const prefix = `fd21t${Date.now().toString(36)}`;
let work = "";
let executor: ReturnType<typeof Bun.serve>;
const executorCalls: string[] = [];
let observedBackups: Array<{ type: string; stoppedAt: string }> = [];
let resticMode: "ok" | "fail" = "ok";
const ENV_KEYS = [
  "ARK_RESTIC_BIN",
  "ARK_BACKUP_EXECUTE",
  "ARK_RESTORE_RUNNER",
  "ARK_MAIL_SNAPSHOT_READY",
  "ARK_PG_STAGE_ROOT",
  "ARK_PLATFORM_PG_EXECUTOR_URL",
  "ARK_PLATFORM_PG_EXECUTOR_TOKEN",
  "ARK_APP_PG_EXECUTOR_URL",
  "ARK_APP_PG_EXECUTOR_TOKEN",
] as const;
const savedEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));

beforeAll(async () => {
  work = await mkdtemp(join(tmpdir(), "ark-fd21-"));
  for (const stanza of ["ark-platform", "ark-app"])
    await mkdir(join(work, "stages", stanza, "20261117T120000Z-abc123"), { recursive: true });
  // restic stand-in: exit 10 (no repository) once, then init, then a JSON backup summary.
  const restic = join(work, "restic");
  await writeFile(
    restic,
    `#!/bin/sh
for arg in "$@"; do last="$arg"; done
case "$*" in
  *"/fail-only/"*) echo "destination refused" >&2; exit 1 ;;
  *"cat config"*) [ -f "${work}/initialised" ] && exit 0; exit 10 ;;
  *" init"*) touch "${work}/initialised"; exit 0 ;;
esac
echo "$*" >> "${work}/restic-args"
printf '%s:%s:%s' "$AWS_ACCESS_KEY_ID" "$RESTIC_PASSWORD" "$ARK_ROOT_KEY" > "${work}/restic-env"
if [ -f "${work}/block" ] && echo "$*" | grep -q "backup"; then touch "${work}/blocked"; while [ -f "${work}/block" ]; do sleep 0.01; done; fi
if [ -f "${work}/fail" ]; then echo "Fatal: unable to open repository: dial tcp: connection refused" >&2; exit 1; fi
echo '{"message_type":"status","percent_done":1}'
echo "{\\"message_type\\":\\"summary\\",\\"snapshot_id\\":\\"snap$(date +%s%N)\\",\\"path\\":\\"$last\\"}"
`,
  );
  await chmod(restic, 0o755);
  executor = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const action = new URL(request.url).pathname.replace("/v1/", "");
      const stanza = request.headers.get("host")?.includes("127.0.0.1") ? "ark-platform" : "ark-app";
      executorCalls.push(action);
      if (action === "stage") {
        return Response.json({
          reused: false,
          manifest: {
            version: 1,
            stanza,
            stageId: "20261117T120000Z-abc123",
            createdAt: new Date().toISOString(),
            lastRecoverableAt: new Date(Date.now() - 30_000).toISOString(),
            walSegment: "000000010000000000000009",
            archive: { min: "000000010000000000000001", max: "000000010000000000000009" },
            backups: [
              {
                label: `${prefix}-F`,
                type: "full",
                startedAt: "",
                stoppedAt: "",
                walStart: null,
                walStop: null,
              },
            ],
            repoBytes: 4096,
            pgbackrestVersion: "2.60.0",
          },
        });
      }
      if (action === "status") {
        return Response.json({
          info: { backups: observedBackups },
          archiver: { archiveMode: "on", lastArchivedAt: new Date().toISOString() },
          repoBytes: 4096,
          repoFs: { totalBytes: 100 * 1024 ** 3, freeBytes: 90 * 1024 ** 3 },
          stagingFs: { totalBytes: 100 * 1024 ** 3, freeBytes: 90 * 1024 ** 3 },
          newestStage: null,
        });
      }
      return Response.json({ kept: 1, removed: [] });
    },
  });
  Object.assign(process.env, {
    ARK_RESTIC_BIN: restic,
    ARK_PG_STAGE_ROOT: join(work, "stages"),
    ARK_PLATFORM_PG_EXECUTOR_URL: `http://127.0.0.1:${executor.port}`,
    ARK_PLATFORM_PG_EXECUTOR_TOKEN: "platform-token-0123456789-abcdef",
    ARK_APP_PG_EXECUTOR_URL: `http://localhost:${executor.port}`,
    ARK_APP_PG_EXECUTOR_TOKEN: "app-token-0123456789-abcdef",
  });
});

afterAll(async () => {
  executor?.stop(true);
  const targets = await db
    .select()
    .from(backupTargets)
    .where(like(backupTargets.name, `${prefix}%`));
  const secretIds = targets
    .flatMap((item) => [item.credentialSecretId, item.repositorySecretId, item.verifierSecretId])
    .filter(Boolean) as string[];
  await db.delete(backupTargets).where(like(backupTargets.name, `${prefix}%`));
  if (secretIds.length) await db.delete(secrets).where(inArray(secrets.id, secretIds));
  await db.delete(backups).where(like(backups.nativeSnapshotId, `${prefix}%`));
  await db.delete(backupSources).where(inArray(backupSources.source, offsite.PG_SOURCES));
  await db.delete(alerts).where(like(alerts.dedupKey, "backup-%"));
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
  await rm(work, { recursive: true, force: true });
});

const input = (overrides: Record<string, unknown> = {}) => ({
  name: `${prefix}-minio`,
  provider: "minio" as const,
  endpoint: "http://127.0.0.1:9",
  region: "us-east-1",
  bucket: "ark-test",
  prefix: "ark",
  pathStyle: true,
  recoveryWindowDays: 7,
  accessKeyId: "ark-writer",
  secretAccessKey: "writer-secret-key-0123456789",
  repositoryPassword: "repository-password-0123456789",
  ...overrides,
});

describe("off-VPS backup targets (FD-21)", () => {
  test("credentials and the repository password are sealed and never returned", async () => {
    const target = await offsite.saveS3Target(input());
    const view = offsite.publicTarget(target);
    expect(JSON.stringify(view)).not.toContain("writer-secret-key");
    expect(JSON.stringify(view)).not.toContain("repository-password");
    const rows = await db
      .select()
      .from(secrets)
      .where(inArray(secrets.id, [target.credentialSecretId, target.repositorySecretId!]));
    expect(rows.map((row) => row.kind).toSorted()).toEqual([
      "backup.restic.password",
      "backup.s3.credential",
    ]);
    for (const row of rows) expect(row.ciphertext).not.toContain("writer-secret-key");
    const opened = await offsite.targetSecrets(target);
    expect(opened.secretAccessKey).toBe("writer-secret-key-0123456789");
    expect(opened.repositoryPassword).toBe("repository-password-0123456789");
  });

  test("the repository password cannot change, and new credentials reset the append-only verdict", async () => {
    const [target] = await db
      .select()
      .from(backupTargets)
      .where(eq(backupTargets.name, `${prefix}-minio`));
    await db
      .update(backupTargets)
      .set({ appendOnlyStatus: "append_only", appendOnlyVerified: true, appendOnlyCheckedAt: new Date() })
      .where(eq(backupTargets.id, target!.id));
    await expect(
      offsite.saveS3Target(input({ id: target!.id, repositoryPassword: "another-password-0123456789" })),
    ).rejects.toThrow(/cannot change/);
    // Every save creates a new verification revision.
    const unchanged = await offsite.saveS3Target(
      input({
        id: target!.id,
        accessKeyId: undefined,
        secretAccessKey: undefined,
        repositoryPassword: undefined,
      }),
    );
    expect(unchanged.appendOnlyStatus).toBe("unverified");
    expect(unchanged.configRevision).not.toBe(target!.configRevision);
    const replaced = await offsite.saveS3Target(
      input({
        id: target!.id,
        accessKeyId: "other-writer",
        secretAccessKey: "other-secret-0123456789",
        repositoryPassword: undefined,
      }),
    );
    expect(replaced.appendOnlyStatus).toBe("unverified");
    expect(replaced.appendOnlyVerified).toBe(false);
    await expect(
      offsite.saveS3Target(
        input({
          id: target!.id,
          accessKeyId: "only-the-id",
          secretAccessKey: undefined,
          repositoryPassword: undefined,
        }),
      ),
    ).rejects.toThrow(/together/);
  });

  test("an export records a per-destination manifest for each cluster and ships local backups", async () => {
    const [target] = await db
      .select()
      .from(backupTargets)
      .where(eq(backupTargets.name, `${prefix}-minio`));
    await db.insert(backups).values({
      id: createId("bak"),
      kind: "platform-postgres",
      targetId: "platform",
      status: "local",
      nativeSnapshotId: `${prefix}-F`,
    });
    resticMode = "ok";
    const result = await offsite.exportTarget(target!.id);
    expect(result.sources.map((item) => [item.source, item.ok])).toEqual([
      ["pg:ark-platform", true],
      ["pg:ark-app", true],
    ]);
    expect(executorCalls).toContain("stage");
    expect(executorCalls).not.toContain("expire");
    const rows = await db.select().from(backupExports).where(eq(backupExports.targetId, target!.id));
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.status).toBe("succeeded");
      expect(row.stageId).toBe("20261117T120000Z-abc123");
      expect(row.resticSnapshotId).toMatch(/^snap/);
      expect(row.walSegment).toBe("000000010000000000000009");
      expect(row.lastRecoverableAt).toBeInstanceOf(Date);
    }
    const [local] = await db
      .select()
      .from(backups)
      .where(eq(backups.nativeSnapshotId, `${prefix}-F`));
    expect(local!.status).toBe("uploaded");
    const [after] = await db.select().from(backupTargets).where(eq(backupTargets.id, target!.id));
    expect(after!.lastSuccessAt).toBeInstanceOf(Date);
    expect(after!.lastError).toBeNull();
  });

  test("an unavailable destination fails the export without a recovery point and raises alerts", async () => {
    const [target] = await db
      .select()
      .from(backupTargets)
      .where(eq(backupTargets.name, `${prefix}-minio`));
    resticMode = "fail";
    await writeFile(join(work, "fail"), "");
    await expect(offsite.exportTarget(target!.id)).rejects.toThrow(/connection refused/);
    const failed = (
      await db.select().from(backupExports).where(eq(backupExports.targetId, target!.id))
    ).filter((row) => row.status === "failed");
    expect(failed).toHaveLength(2);
    expect(failed.every((row) => row.lastRecoverableAt === null && row.resticSnapshotId === null)).toBe(true);
    const health = await offsite.evaluateBackupAlerts(new Date(Date.now() + 20 * 60_000));
    expect(health?.healthy).toBe(false);
    const open = (await db.select().from(alerts).where(like(alerts.dedupKey, "backup-%")))
      .filter((row) => !row.resolvedAt)
      .map((row) => row.dedupKey);
    expect(open).toContain(`backup-rpo:${target!.id}:pg:ark-platform`);
    expect(open).toContain(`backup-append-only:${target!.id}`);
    // Back online and verified: the target's alerts resolve.
    await rm(join(work, "fail"));
    resticMode = "ok";
    await offsite.exportTarget(target!.id);
    await db
      .update(backupTargets)
      .set({
        appendOnlyStatus: "append_only",
        appendOnlyCheckedAt: new Date(),
        retentionUntil: new Date(Date.now() + 30 * 86_400_000),
      })
      .where(eq(backupTargets.id, target!.id));
    await offsite.evaluateBackupAlerts();
    const still = (
      await db
        .select()
        .from(alerts)
        .where(like(alerts.dedupKey, `backup-%${target!.id}%`))
    ).filter((row) => !row.resolvedAt);
    expect(still).toEqual([]);
    expect(resticMode).toBe("ok");
  });
  test("a previous verification cannot bless replacement credentials and each revision queues independently", async () => {
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let first = true;
    const { server, endpoint } = fakeS3([], undefined, undefined, async () => {
      if (first) {
        first = false;
        entered();
        await gate;
      }
    });
    try {
      const target = await offsite.saveS3Target(input({ name: `${prefix}-race`, endpoint, bucket: "bkt" }));
      const { enqueue } = await import("./coordinator.ts");
      const oldJob = await enqueue({
        kind: "backup.verify_target",
        targetIds: [target.id],
        payload: { revision: target.configRevision },
      });
      const verifying = offsite.verifyTarget(target.id, target.configRevision);
      await started;
      const rotated = await offsite.saveS3Target(
        input({
          id: target.id,
          name: target.name,
          endpoint,
          bucket: "bkt",
          accessKeyId: "replacement-writer",
          repositoryPassword: undefined,
        }),
      );
      const newJob = await enqueue({
        kind: "backup.verify_target",
        targetIds: [target.id],
        payload: { revision: rotated.configRevision },
      });
      expect(newJob.id).not.toBe(oldJob.id);
      release();
      expect((await verifying).status).toBe("append_only");
      const [after] = await db.select().from(backupTargets).where(eq(backupTargets.id, target.id));
      expect(after!.appendOnlyStatus).toBe("unverified");
      expect(after!.appendOnlyEvidence).toBeNull();
      await expect(offsite.verifyTarget(target.id, target.configRevision)).rejects.toThrow(
        /configuration changed/,
      );
      await db.delete(operations).where(inArray(operations.id, [oldJob.id, newJob.id]));
    } finally {
      release();
      server.stop(true);
    }
  });

  test("a repository move excludes old and in-flight export evidence from current health", async () => {
    const target = await offsite.saveS3Target(input({ name: `${prefix}-move` }));
    await offsite.exportTarget(target.id);
    const block = join(work, "block");
    const blocked = join(work, "blocked");
    await writeFile(block, "");
    const pending = offsite.exportTarget(target.id);
    const settled = pending.catch(() => undefined);
    let moved: Awaited<ReturnType<typeof offsite.saveS3Target>>;
    try {
      const deadline = Date.now() + 5_000;
      while (!existsSync(blocked) && Date.now() < deadline) await Bun.sleep(10);
      if (!existsSync(blocked)) throw new Error("The in-flight backup never reached restic.");
      moved = await offsite.saveS3Target(
        input({ id: target.id, name: target.name, prefix: "empty", repositoryPassword: undefined }),
      );
    } finally {
      // Release and join the export even if the repository move or readiness check fails.
      await rm(block, { force: true });
      await settled;
    }
    await pending;
    expect(moved.repositoryRevision).not.toBe(target.repositoryRevision);
    const [after] = await db.select().from(backupTargets).where(eq(backupTargets.id, target.id));
    expect(after!.lastSuccessAt).toBeNull();
    const health = await offsite.backupHealth();
    expect(health.healthy).toBe(false);
    const rows = await db
      .select()
      .from(backupExports)
      .where(
        and(
          eq(backupExports.targetId, target.id),
          eq(backupExports.repositoryRevision, moved.repositoryRevision),
        ),
      );
    expect(rows).toHaveLength(0);
    await offsite.exportTarget(target.id);
    const [exported] = await db.select().from(backupTargets).where(eq(backupTargets.id, target.id));
    expect(exported!.lastSuccessAt).toBeInstanceOf(Date);
  }, 20_000);

  test("scheduler enqueues due backups, per-target exports and revision-bound weekly verification", async () => {
    const jobs: Array<{ kind: string; targetIds: string[]; payload?: Record<string, unknown> }> = [];
    const target = await offsite.saveS3Target(input({ name: `${prefix}-scheduled` }));
    await offsite.backupScheduleTick(async (job) => {
      jobs.push(job);
    });
    expect(jobs.filter((job) => job.kind === "backup.create").map((job) => job.payload?.type)).toEqual([
      "full",
      "full",
    ]);
    expect(jobs.some((job) => job.kind === "backup.export" && job.targetIds[0] === target.id)).toBe(true);
    expect(
      jobs.find((job) => job.kind === "backup.verify_target" && job.targetIds[0] === target.id)?.payload
        ?.revision,
    ).toBe(target.configRevision);
    await db
      .update(backupTargets)
      .set({ appendOnlyCheckedAt: new Date() })
      .where(eq(backupTargets.id, target.id));
    observedBackups = [{ type: "full", stoppedAt: new Date(Date.now() - 2 * 86400000).toISOString() }];
    jobs.length = 0;
    await offsite.backupScheduleTick(async (job) => {
      jobs.push(job);
    });
    expect(jobs.filter((job) => job.kind === "backup.create").map((job) => job.payload?.type)).toEqual([
      "diff",
      "diff",
    ]);
    observedBackups = [];
    const old = process.env.ARK_APP_PG_EXECUTOR_URL;
    process.env.ARK_APP_PG_EXECUTOR_URL = "http://127.0.0.1:9";
    jobs.length = 0;
    try {
      await offsite.backupScheduleTick(async (job) => {
        jobs.push(job);
      });
    } finally {
      process.env.ARK_APP_PG_EXECUTOR_URL = old;
    }
    expect(jobs.filter((job) => job.kind === "backup.create")).toHaveLength(1);
    expect(jobs.some((job) => job.kind === "backup.verify_target" && job.targetIds[0] === target.id)).toBe(
      false,
    );
  });

  test("schedule interval starts immediately, reports failures and continues retrying", async () => {
    const clock = { ticks: 0 };
    const errors: string[] = [];
    const timer = offsite.startBackupSchedule({
      intervalMs: 10,
      enqueue: async () => {
        clock.ticks++;
        throw new Error("fixture enqueue unavailable");
      },
      log: (message) => errors.push(message),
    });
    try {
      const deadline = Date.now() + 3000;
      while (clock.ticks < 2 && Date.now() < deadline) await Bun.sleep(10);
      expect(clock.ticks).toBeGreaterThanOrEqual(2);
      expect(errors.some((message) => message.includes("fixture enqueue unavailable"))).toBe(true);
    } finally {
      clearInterval(timer);
    }
  });

  test("file exports continue across target failures and exact snapshots restore with sealed environment", async () => {
    await rm(join(work, "restic-args"), { force: true });
    // This case only needs one successful and one failing destination.
    await db
      .update(backupTargets)
      .set({ enabled: false })
      .where(like(backupTargets.name, `${prefix}%`));
    const bad = await offsite.saveS3Target(input({ name: `${prefix}-files-fail`, prefix: "fail-only" }));
    const good = await offsite.saveS3Target(input({ name: `${prefix}-files-good`, prefix: "files-only" }));
    const results = await offsite.exportFiles("mail", work, []);
    expect(results.find((row) => row.targetId === bad.id)?.error).toContain("destination refused");
    await db.update(backupTargets).set({ enabled: false }).where(eq(backupTargets.id, bad.id));
    const snapshotId = results.find((row) => row.targetId === good.id)?.snapshotId;
    if (!snapshotId) throw new Error("The healthy destination did not return a snapshot.");
    const restored = await offsite.restoreFiles("mail", snapshotId, join(work, "restored"));
    expect(restored.argv.join(" ")).toContain("s3:");
    expect(restored.argv).toContain(snapshotId);
    expect(restored.argv.join(" ")).not.toContain("writer-secret");
    process.env.ARK_BACKUP_EXECUTE = "1";
    process.env.ARK_RESTORE_RUNNER = "1";
    process.env.ARK_MAIL_SNAPSHOT_READY = "1";
    const { runBackup, runRestoreTest } = await import("./modules/backups.ts");
    for (const kind of ["mail", "volume"] as const) {
      const backup = await runBackup(kind, "fixture");
      expect(backup.status).toBe("uploaded");
      const restoredSnapshot = await runRestoreTest(kind, "fixture", backup.snapshotId);
      expect(restoredSnapshot.status).toBe("integrity_ok");
      expect(restoredSnapshot.argv.join(" ")).toContain("s3:");
      expect(restoredSnapshot.argv).toContain(backup.snapshotId!);
      const captured = await Bun.file(join(work, "restic-env")).text();
      expect(captured).toContain("repository-password-0123456789");
      expect(captured).not.toContain(process.env.ARK_ROOT_KEY!);
      await rm(restoredSnapshot.restoreRoot!, { recursive: true, force: true });
    }
    await expect(offsite.restoreFiles("volume:wrong", snapshotId, join(work, "wrong"))).rejects.toThrow(
      /No successful export/,
    );
  });
});
