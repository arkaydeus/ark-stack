// FD-21 off-VPS backups against the migrated platform database (DATABASE_URL): sealed write-only target
// credentials, per-destination export manifests from a fake executor and a fake restic, local backups
// becoming `uploaded`, and per-target alerts raised and resolved.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createId } from "@ark-stack/shared";
import { eq, inArray, like } from "drizzle-orm";

const { db } = await import("./db.ts");
const { alerts, backupExports, backupSources, backupTargets, backups, secrets } = await import("./schema.ts");
const offsite = await import("./modules/offsite-backups.ts");

const prefix = `fd21t${Date.now().toString(36)}`;
let work = "";
let executor: ReturnType<typeof Bun.serve>;
const executorCalls: string[] = [];
let resticMode: "ok" | "fail" = "ok";
const ENV_KEYS = [
  "ARK_RESTIC_BIN",
  "ARK_PLATFORM_PG_EXECUTOR_URL",
  "ARK_PLATFORM_PG_EXECUTOR_TOKEN",
  "ARK_APP_PG_EXECUTOR_URL",
  "ARK_APP_PG_EXECUTOR_TOKEN",
] as const;
const savedEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));

beforeAll(async () => {
  work = await mkdtemp(join(tmpdir(), "ark-fd21-"));
  // restic stand-in: exit 10 (no repository) once, then init, then a JSON backup summary.
  const restic = join(work, "restic");
  await writeFile(
    restic,
    `#!/bin/sh
for arg in "$@"; do last="$arg"; done
case "$*" in
  *"cat config"*) [ -f "${work}/initialised" ] && exit 0; exit 10 ;;
  *" init"*) touch "${work}/initialised"; exit 0 ;;
esac
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
          info: { backups: [] },
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
    // Same settings, no credentials: the verdict stands.
    const unchanged = await offsite.saveS3Target(
      input({
        id: target!.id,
        accessKeyId: undefined,
        secretAccessKey: undefined,
        repositoryPassword: undefined,
      }),
    );
    expect(unchanged.appendOnlyStatus).toBe("append_only");
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
});
