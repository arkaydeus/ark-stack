// Off-VPS backups to S3-compatible targets (docs/design/front-door.md §3.18, FD-21).
//
// - The PostgreSQL executors (workers/src/pg-executor.ts) keep an encrypted local pgBackRest repo2 per
//   cluster and stage completed copies of it under an exclusive lock.
// - `backup.export` (backup worker, per target, every 5 minutes) asks each executor for a stage at
//   most four minutes old, uploads it as an immutable restic snapshot to that target only, and
//   records the per-destination manifest (stage, labels, WAL segment, last recoverable time) in
//   `backup_exports`. Targets are exported independently: one failing never blocks another.
// - `backup.verify_target` runs the append-only canary (backup-canary.ts) with the deployed writer
//   credentials, weekly and whenever a target is saved.
// - Health and alerts come from evaluateBackupHealth (shared/src/backup-targets.ts).
//
// pgBackRest `expire` is never run from here (scripts/backup-no-expire.test.ts).
import {
  BACKUP_ALERT_PREFIXES,
  PG_CLUSTERS,
  PG_EXPORT_INTERVAL_MS,
  PG_STAGE_MOUNT_ROOT,
  createId,
  decryptSecret,
  dueBackupType,
  encryptSecret,
  evaluateBackupHealth,
  pgSnapshotTags,
  resticS3Env,
  resticS3Repository,
  type BackupHealth,
  type PgCluster,
  type S3Provider,
  type S3TargetInput,
  type StageManifest,
  type StagedBackup,
} from "@ark-stack/shared";
import { and, desc, eq, inArray, isNull, like, or } from "drizzle-orm";

import { db } from "../db.ts";
import { alerts, backupExports, backupSources, backupTargets, backups, secrets } from "../schema.ts";
import { raiseAlert } from "./alerts.ts";
import { runAppendOnlyCanary, type CanaryEvidence } from "./backup-canary.ts";
import { callExecutor, executorConfig } from "./pg-executor-client.ts";
import { S3Client } from "./s3-client.ts";

export { callExecutor, executorConfig };

export type BackupTargetRow = typeof backupTargets.$inferSelect;

function rootKey() {
  const key = process.env.ARK_ROOT_KEY ?? "";
  if (key.length < 32) throw new Error("ARK_ROOT_KEY is required to open backup credentials.");
  return key;
}

export const PG_SOURCES = Object.values(PG_CLUSTERS).map((profile) => `pg:${profile.stanza}`);

// ---- Secrets and targets --------------------------------------------------------------------------

async function openSecret(id: string | null) {
  if (!id) return null;
  const [row] = await db.select().from(secrets).where(eq(secrets.id, id));
  return row ? decryptSecret(rootKey(), row) : null;
}

export async function targetSecrets(target: BackupTargetRow) {
  const credential = await openSecret(target.credentialSecretId);
  const repositoryPassword = await openSecret(target.repositorySecretId);
  if (!credential || !repositoryPassword)
    throw new Error(`Backup target ${target.name} has no sealed credentials.`);
  const parsed = JSON.parse(credential) as { accessKeyId: string; secretAccessKey: string };
  const verifier = await openSecret(target.verifierSecretId);
  return {
    accessKeyId: parsed.accessKeyId,
    secretAccessKey: parsed.secretAccessKey,
    repositoryPassword,
    verifier: verifier ? (JSON.parse(verifier) as { accountId?: string; token?: string }) : null,
  };
}

function s3Config(target: BackupTargetRow) {
  if (target.kind !== "s3" || !target.endpoint || !target.bucket || !target.region) {
    throw new Error(`Backup target ${target.name} is not a complete S3 target.`);
  }
  return {
    endpoint: target.endpoint,
    region: target.region,
    bucket: target.bucket,
    prefix: target.prefix,
    pathStyle: target.pathStyle,
  };
}

async function sealSecret(
  executor: Pick<typeof db, "insert">,
  kind: string,
  targetId: string,
  value: string,
) {
  const id = createId("sec");
  await executor.insert(secrets).values({
    id,
    kind,
    once: false,
    resourceType: "backup_target",
    resourceId: targetId,
    purpose: "backup",
    sensitivity: "credential",
    ...encryptSecret(rootKey(), value, process.env.ARK_ROOT_KEY_ID ?? "k1"),
  });
  return id;
}

/**
 * Creates (no `id`) or updates an S3 target (PUT /api/backups/targets/s3). Credentials are write-only;
 * the repository password can be set once, because changing it would orphan the restic repository.
 * Any change to where or how backups are written resets the append-only verdict.
 */
export async function saveS3Target(input: S3TargetInput) {
  const [existing] = input.id
    ? await db
        .select()
        .from(backupTargets)
        .where(and(eq(backupTargets.id, input.id), eq(backupTargets.kind, "s3")))
    : [];
  if (input.id && !existing) throw new Error("Backup target not found.");
  const id = existing?.id ?? createId("bkt");
  if (!existing && (!input.accessKeyId || !input.secretAccessKey || !input.repositoryPassword)) {
    throw new Error("A new S3 target needs the access key, secret key and repository password.");
  }
  if (existing?.repositorySecretId && input.repositoryPassword) {
    const current = await openSecret(existing.repositorySecretId);
    if (current !== input.repositoryPassword) {
      throw new Error("The repository password cannot change; use a new prefix for a new repository.");
    }
  }
  if (existing && (input.accessKeyId === undefined) !== (input.secretAccessKey === undefined)) {
    throw new Error("Replace the access key and secret key together.");
  }
  const moved =
    !existing ||
    existing.endpoint !== input.endpoint ||
    existing.bucket !== input.bucket ||
    existing.prefix !== input.prefix ||
    existing.pathStyle !== input.pathStyle ||
    existing.region !== input.region ||
    existing.provider !== input.provider ||
    existing.recoveryWindowDays !== input.recoveryWindowDays;
  const values = {
    kind: "s3" as const,
    name: input.name,
    provider: input.provider,
    endpoint: input.endpoint,
    region: input.region,
    bucket: input.bucket,
    prefix: input.prefix,
    pathStyle: input.pathStyle,
    recoveryWindowDays: input.recoveryWindowDays,
    updatedAt: new Date(),
  };
  // A different location is a different restic repository; it reuses the sealed password.
  return db.transaction(async (tx) => {
    const credentialSecretId =
      input.accessKeyId && input.secretAccessKey
        ? await sealSecret(
            tx,
            "backup.s3.credential",
            id,
            JSON.stringify({ accessKeyId: input.accessKeyId, secretAccessKey: input.secretAccessKey }),
          )
        : existing!.credentialSecretId;
    const repositorySecretId =
      existing?.repositorySecretId ??
      (await sealSecret(tx, "backup.restic.password", id, input.repositoryPassword!));
    const verifierSecretId =
      input.verifierToken !== undefined
        ? input.verifierToken
          ? await sealSecret(
              tx,
              "backup.s3.verifier",
              id,
              JSON.stringify({ accountId: input.verifierAccountId ?? "", token: input.verifierToken }),
            )
          : null
        : (existing?.verifierSecretId ?? null);
    const reset =
      moved ||
      credentialSecretId !== existing?.credentialSecretId ||
      verifierSecretId !== existing?.verifierSecretId
        ? {
            appendOnlyStatus: "unverified" as const,
            appendOnlyVerified: false,
            appendOnlyCheckedAt: null,
            retentionUntil: null,
          }
        : {};
    const [row] = existing
      ? await tx
          .update(backupTargets)
          .set({ ...values, credentialSecretId, repositorySecretId, verifierSecretId, ...reset })
          .where(eq(backupTargets.id, id))
          .returning()
      : await tx
          .insert(backupTargets)
          .values({ id, ...values, credentialSecretId, repositorySecretId, verifierSecretId })
          .returning();
    return row!;
  });
}

/** Public view of a target: never credentials or the repository password. */
export function publicTarget(target: BackupTargetRow) {
  return {
    id: target.id,
    kind: target.kind,
    name: target.name,
    provider: target.provider,
    endpoint: target.endpoint,
    region: target.region,
    bucket: target.bucket,
    prefix: target.prefix,
    pathStyle: target.pathStyle,
    enabled: target.enabled,
    recoveryWindowDays: target.recoveryWindowDays,
    hasVerifier: Boolean(target.verifierSecretId),
    appendOnlyStatus: target.appendOnlyStatus,
    appendOnlyVerified: target.appendOnlyVerified,
    appendOnlyCheckedAt: target.appendOnlyCheckedAt,
    appendOnlyEvidence: target.appendOnlyEvidence,
    retentionUntil: target.retentionUntil,
    lastSuccessAt: target.lastSuccessAt,
    lastAttemptAt: target.lastAttemptAt,
    lastError: target.lastError,
  };
}

// ---- restic ---------------------------------------------------------------------------------------

export type ResticResult = { status: number; stdout: string; stderr: string; timedOut: boolean };

/**
 * Runs restic with a minimal environment: the target's credentials and repository password only.
 * No inherited proxy settings (FD-30 sets HTTP_PROXY only for its REST subprocess), no root key.
 */
export async function runRestic(
  target: BackupTargetRow,
  keys: { accessKeyId: string; secretAccessKey: string; repositoryPassword: string },
  args: string[],
  timeoutMs = 6 * 60 * 60 * 1000,
): Promise<ResticResult> {
  const config = s3Config(target);
  const { repository, options } = resticS3Repository(config);
  const cacheDir = process.env.ARK_RESTIC_CACHE_DIR;
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
    HOME: process.env.ARK_RESTIC_HOME ?? "/tmp",
    ...resticS3Env(config, keys),
    ...(cacheDir ? { RESTIC_CACHE_DIR: cacheDir } : {}),
  };
  for (const name of ["ARK_TEST_RESTIC_DOCKER_ARGS"]) if (process.env[name]) env[name] = process.env[name]!;
  const binary = process.env.ARK_RESTIC_BIN || "restic";
  const argv = [binary, "-r", repository, ...options, ...(cacheDir ? [] : ["--no-cache"]), ...args];
  const child = Bun.spawn(argv, { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGTERM");
  }, timeoutMs);
  try {
    const [status, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    return { status, stdout, stderr, timedOut };
  } finally {
    clearTimeout(timer);
  }
}

function resticError(what: string, result: ResticResult) {
  const detail = (result.stderr || result.stdout).trim().split("\n").filter(Boolean).slice(-3).join(" | ");
  const why = result.timedOut ? "timed out; the destination is unavailable" : `failed (${result.status})`;
  return new Error(`restic ${what} ${why}: ${detail.slice(0, 600)}`);
}

/**
 * restic retries an unreachable backend for about 15 minutes and has no option to shorten that, so
 * the first request of every export is bounded: an unavailable destination fails fast, is recorded
 * and retried at the next interval, and never delays the other targets.
 */
function probeTimeoutMs() {
  const value = Number(process.env.ARK_RESTIC_PROBE_TIMEOUT_MS ?? 120_000);
  return Number.isFinite(value) && value >= 1000 ? value : 120_000;
}

/** Opens the target's restic repository, initialising it on first use (exit code 10: no repository). */
export async function ensureResticRepository(
  target: BackupTargetRow,
  keys: { accessKeyId: string; secretAccessKey: string; repositoryPassword: string },
) {
  const probe = await runRestic(target, keys, ["cat", "config"], probeTimeoutMs());
  if (probe.status === 0) return { initialised: false };
  if (probe.timedOut || probe.status !== 10) throw resticError("cat config", probe);
  const init = await runRestic(target, keys, ["init"], probeTimeoutMs());
  if (init.status !== 0) throw resticError("init", init);
  return { initialised: true };
}

export function resticSummarySnapshot(stdout: string) {
  for (const line of stdout.split("\n").toReversed()) {
    try {
      const parsed = JSON.parse(line) as { message_type?: string; snapshot_id?: string };
      if (parsed.message_type === "summary" && parsed.snapshot_id) return parsed.snapshot_id;
    } catch {
      continue;
    }
  }
  return null;
}

/** restic backup of one path with tags; returns the snapshot ID. */
export async function resticBackup(
  target: BackupTargetRow,
  keys: { accessKeyId: string; secretAccessKey: string; repositoryPassword: string },
  path: string,
  tags: string[],
) {
  const result = await runRestic(target, keys, [
    "backup",
    "--json",
    "--host",
    "ark",
    ...tags.flatMap((tag) => ["--tag", tag]),
    path,
  ]);
  const snapshotId = resticSummarySnapshot(result.stdout);
  if (result.status !== 0 || !snapshotId) throw resticError("backup", result);
  return snapshotId;
}

// ---- Export (backup.export) -----------------------------------------------------------------------

function stagePath(stanza: string, stage: string) {
  return `${process.env.ARK_PG_STAGE_ROOT ?? PG_STAGE_MOUNT_ROOT}/${stanza}/${stage}`;
}

/**
 * Observes one executor and records the local source: archiving, capacity, newest stage. Throws
 * nothing: an unreachable executor is recorded as not configured, which fails health.
 */
export async function observeSource(cluster: PgCluster) {
  const { profile } = executorConfig(cluster);
  const source = `pg:${profile.stanza}`;
  try {
    const status = await callExecutor<{
      info: { backups?: StagedBackup[]; error?: string };
      archiver: {
        archiveMode?: string;
        failedCount?: number;
        lastFailedAt?: string | null;
        lastArchivedAt?: string | null;
        error?: string;
      };
      repoBytes: number;
      repoFs: { totalBytes: number; freeBytes: number };
      stagingFs: { totalBytes: number; freeBytes: number };
      newestStage: StageManifest | null;
    }>(cluster, "status", {}, 10 * 60 * 1000);
    const backupsList = status.info.backups ?? [];
    const fulls = backupsList.filter((item) => item.type === "full");
    const lastFailed = status.archiver.lastFailedAt ? new Date(status.archiver.lastFailedAt).getTime() : 0;
    const lastArchived = status.archiver.lastArchivedAt
      ? new Date(status.archiver.lastArchivedAt).getTime()
      : 0;
    const values = {
      configured: status.archiver.archiveMode === "on" && !status.info.error,
      archiveFailing: lastFailed > lastArchived && Date.now() - lastFailed < 15 * 60 * 1000,
      repoBytes: status.repoBytes,
      // Repository and staging usually share a filesystem; take the tighter of the two.
      freeBytes: Math.min(status.repoFs.freeBytes, status.stagingFs.freeBytes),
      totalBytes: status.repoFs.totalBytes,
      lastStageId: status.newestStage?.stageId ?? null,
      localRecoverableAt: status.newestStage?.lastRecoverableAt
        ? new Date(status.newestStage.lastRecoverableAt)
        : null,
      lastFullAt: fulls.at(-1) ? new Date(fulls.at(-1)!.stoppedAt) : null,
      lastBackupAt: backupsList.at(-1) ? new Date(backupsList.at(-1)!.stoppedAt) : null,
      detail: {
        archiver: status.archiver,
        backups: backupsList.length,
        infoError: status.info.error ?? null,
      },
      observedAt: new Date(),
    };
    await db
      .insert(backupSources)
      .values({ source, ...values })
      .onConflictDoUpdate({ target: backupSources.source, set: values });
    return { source, ok: true as const, backups: backupsList };
  } catch (error) {
    const message = error instanceof Error ? error.message : "executor unreachable";
    const values = { configured: false, detail: { error: message.slice(0, 500) }, observedAt: new Date() };
    await db
      .insert(backupSources)
      .values({ source, ...values })
      .onConflictDoUpdate({ target: backupSources.source, set: values });
    return { source, ok: false as const, error: message };
  }
}

export type ExportResult = {
  targetId: string;
  sources: Array<
    | {
        source: string;
        ok: true;
        stageId: string;
        snapshotId: string;
        lastRecoverableAt: string | null;
        reusedStage: boolean;
      }
    | { source: string; ok: false; error: string }
  >;
};

/**
 * Exports every PostgreSQL source to one target. Each source is independent; failures are recorded
 * per destination and rethrown after the others ran, so the operation fails (and alerts) without
 * stopping the other sources or targets.
 */
export async function exportTarget(
  targetId: string,
  options: { fresh?: boolean; now?: () => Date } = {},
): Promise<ExportResult> {
  const now = options.now ?? (() => new Date());
  const [target] = await db.select().from(backupTargets).where(eq(backupTargets.id, targetId));
  if (!target) throw new Error("Backup target not found.");
  if (!target.enabled) throw new Error(`Backup target ${target.name} is disabled.`);
  await db.update(backupTargets).set({ lastAttemptAt: now() }).where(eq(backupTargets.id, target.id));
  const result: ExportResult = { targetId, sources: [] };
  let secretsForTarget: Awaited<ReturnType<typeof targetSecrets>> | null = null;
  let repositoryError: string | null = null;
  try {
    secretsForTarget = await targetSecrets(target);
    await ensureResticRepository(target, secretsForTarget);
  } catch (error) {
    repositoryError = error instanceof Error ? error.message : "restic repository unavailable";
  }
  for (const cluster of Object.keys(PG_CLUSTERS) as PgCluster[]) {
    const { profile } = executorConfig(cluster);
    const source = `pg:${profile.stanza}`;
    try {
      if (repositoryError || !secretsForTarget) throw new Error(repositoryError ?? "no credentials");
      // A scheduled export reuses a stage at most four minutes old, so targets exporting in the same
      // interval upload the same completed copy. An export right after a backup stages afresh.
      const staged = await callExecutor<{ reused: boolean; manifest: StageManifest }>(cluster, "stage", {
        maxAgeSeconds: options.fresh ? 0 : Math.floor((PG_EXPORT_INTERVAL_MS * 0.8) / 1000),
      });
      const manifest = staged.manifest;
      const snapshotId = await resticBackup(
        target,
        secretsForTarget,
        stagePath(profile.stanza, manifest.stageId),
        pgSnapshotTags(profile.stanza, manifest.stageId),
      );
      await db.insert(backupExports).values({
        id: createId("bex"),
        targetId: target.id,
        source,
        status: "succeeded",
        stageId: manifest.stageId,
        resticSnapshotId: snapshotId,
        backupLabels: manifest.backups.map((item) => item.label),
        walSegment: manifest.walSegment,
        lastRecoverableAt: manifest.lastRecoverableAt ? new Date(manifest.lastRecoverableAt) : null,
        repoBytes: manifest.repoBytes,
      });
      await markUploaded(
        profile.backupKind,
        manifest.backups.map((item) => item.label),
      );
      result.sources.push({
        source,
        ok: true,
        stageId: manifest.stageId,
        snapshotId,
        lastRecoverableAt: manifest.lastRecoverableAt,
        reusedStage: staged.reused,
      });
      // Older stages are subsets of the newest one (repo2 is never expired on the VPS); keep two so
      // an export still reading the previous stage is not disturbed.
      await callExecutor(cluster, "prune-stages", { keep: 2 }, 10 * 60 * 1000).catch(() => undefined);
    } catch (error) {
      const message = (error instanceof Error ? error.message : "export failed").slice(0, 1000);
      await db
        .insert(backupExports)
        .values({ id: createId("bex"), targetId: target.id, source, status: "failed", error: message });
      result.sources.push({ source, ok: false, error: message });
    }
    await observeSource(cluster);
  }
  const failures = result.sources.filter((item) => !item.ok);
  await db
    .update(backupTargets)
    .set(
      failures.length
        ? {
            lastError: failures
              .map((item) => `${item.source}: ${"error" in item ? item.error : ""}`)
              .join("; ")
              .slice(0, 1000),
          }
        : { lastError: null, lastSuccessAt: now() },
    )
    .where(eq(backupTargets.id, target.id));
  await evaluateBackupAlerts().catch(() => undefined);
  if (failures.length) {
    throw new Error(
      `Export to ${target.name} failed for ${failures.map((item) => item.source).join(", ")}: ${"error" in failures[0]! ? failures[0].error : ""}`,
    );
  }
  return result;
}

/** Local backups become `uploaded` once a stage containing them reached an off-VPS target. */
async function markUploaded(kind: string, labels: string[]) {
  if (!labels.length) return;
  await db
    .update(backups)
    .set({ status: "uploaded" })
    .where(
      and(eq(backups.kind, kind), eq(backups.status, "local"), inArray(backups.nativeSnapshotId, labels)),
    );
}

// ---- Files (mail and reviewed volumes) -----------------------------------------------------------

/** restic backup of a mail snapshot or reviewed volume path to every enabled S3 target. */
export async function exportFiles(source: string, path: string, tags: string[]) {
  const targets = await db.select().from(backupTargets).where(eq(backupTargets.enabled, true));
  if (!targets.length) throw new Error("No backup target is configured for mail and volume backups.");
  const results: Array<{ targetId: string; snapshotId?: string; error?: string }> = [];
  for (const target of targets) {
    try {
      const secretsForTarget = await targetSecrets(target);
      await ensureResticRepository(target, secretsForTarget);
      const snapshotId = await resticBackup(target, secretsForTarget, path, [
        "ark",
        `source=${source}`,
        ...tags,
      ]);
      await db.insert(backupExports).values({
        id: createId("bex"),
        targetId: target.id,
        source,
        status: "succeeded",
        resticSnapshotId: snapshotId,
      });
      results.push({ targetId: target.id, snapshotId });
    } catch (error) {
      const message = (error instanceof Error ? error.message : "export failed").slice(0, 1000);
      await db
        .insert(backupExports)
        .values({ id: createId("bex"), targetId: target.id, source, status: "failed", error: message });
      results.push({ targetId: target.id, error: message });
    }
  }
  return results;
}

// ---- Append-only canary (backup.verify_target) ----------------------------------------------------

export async function verifyTarget(targetId: string): Promise<CanaryEvidence> {
  const [target] = await db.select().from(backupTargets).where(eq(backupTargets.id, targetId));
  if (!target) throw new Error("Backup target not found.");
  const config = s3Config(target);
  const secretsForTarget = await targetSecrets(target);
  const client = new S3Client(
    { endpoint: config.endpoint, region: config.region, bucket: config.bucket, pathStyle: config.pathStyle },
    { accessKeyId: secretsForTarget.accessKeyId, secretAccessKey: secretsForTarget.secretAccessKey },
  );
  const evidence = await runAppendOnlyCanary({
    client,
    provider: target.provider as S3Provider,
    prefix: target.prefix,
    recoveryWindowDays: target.recoveryWindowDays,
    writer: { accessKeyId: secretsForTarget.accessKeyId, secretAccessKey: secretsForTarget.secretAccessKey },
    verifier: secretsForTarget.verifier ?? undefined,
  });
  await db
    .update(backupTargets)
    .set({
      appendOnlyStatus: evidence.status,
      appendOnlyVerified: evidence.status === "append_only",
      appendOnlyEvidence: evidence as unknown as Record<string, unknown>,
      appendOnlyCheckedAt: new Date(evidence.checkedAt),
      retentionUntil: evidence.retentionUntil ? new Date(evidence.retentionUntil) : null,
    })
    .where(eq(backupTargets.id, target.id));
  await evaluateBackupAlerts().catch(() => undefined);
  return evidence;
}

// ---- Health and alerts ----------------------------------------------------------------------------

export async function backupHealth(now = new Date()): Promise<BackupHealth> {
  const [targets, exportsRows, sources] = await Promise.all([
    db.select().from(backupTargets),
    db
      .select()
      .from(backupExports)
      .where(or(...PG_SOURCES.map((source) => eq(backupExports.source, source))))
      .orderBy(desc(backupExports.createdAt))
      .limit(2000),
    db.select().from(backupSources),
  ]);
  return evaluateBackupHealth({
    now,
    pgSources: PG_SOURCES,
    targets: targets.map((target) => ({
      id: target.id,
      name: target.name,
      kind: target.kind,
      enabled: target.enabled,
      appendOnlyStatus: target.appendOnlyStatus,
      appendOnlyCheckedAt: target.appendOnlyCheckedAt,
      retentionUntil: target.retentionUntil,
      recoveryWindowDays: target.recoveryWindowDays,
      lastSuccessAt: target.lastSuccessAt,
      lastError: target.lastError,
    })),
    exports: exportsRows.map((row) => ({
      targetId: row.targetId,
      source: row.source,
      status: row.status,
      lastRecoverableAt: row.lastRecoverableAt,
      repoBytes: row.repoBytes,
      createdAt: row.createdAt,
    })),
    sources: sources.map((row) => ({
      source: row.source,
      observedAt: row.observedAt,
      freeBytes: row.freeBytes,
      totalBytes: row.totalBytes,
      localRecoverableAt: row.localRecoverableAt,
      repoBytes: row.repoBytes,
      archiveFailing: row.archiveFailing,
      // An observation older than 15 minutes means the executor stopped answering.
      configured: row.configured && now.getTime() - row.observedAt.getTime() < 15 * 60 * 1000,
    })),
  });
}

/**
 * Raises the per-target and per-source backup alerts and resolves the ones that cleared. Backups are
 * only evaluated once something is configured (a target or an observed source), so a fresh install
 * that has not set up backups yet is not flooded; `backup-no-target` covers that case once a source
 * exists.
 */
export async function evaluateBackupAlerts(now = new Date()) {
  const [anyTarget] = await db.select({ id: backupTargets.id }).from(backupTargets).limit(1);
  const [anySource] = await db.select({ source: backupSources.source }).from(backupSources).limit(1);
  const health = anyTarget || anySource ? await backupHealth(now) : null;
  const active = new Set<string>();
  for (const alert of health?.alerts ?? []) {
    active.add(alert.dedupKey);
    await raiseAlert(alert);
  }
  const open = await db
    .select()
    .from(alerts)
    .where(
      and(
        isNull(alerts.resolvedAt),
        or(...BACKUP_ALERT_PREFIXES.map((prefix) => like(alerts.dedupKey, `${prefix}%`))),
      ),
    );
  for (const alert of open) {
    if (!active.has(alert.dedupKey)) {
      await db.update(alerts).set({ resolvedAt: now }).where(eq(alerts.id, alert.id));
    }
  }
  return health;
}

// ---- Schedules (backup worker) --------------------------------------------------------------------

type Enqueue = (input: {
  kind: "backup.create" | "backup.export" | "backup.verify_target";
  targetIds: string[];
  payload?: Record<string, unknown>;
}) => Promise<unknown>;

/** Re-verify append-only evidence a little before it expires (weekly, §3.18.2). */
const VERIFY_EVERY_MS = 6.5 * 24 * 60 * 60 * 1000;

/**
 * One schedule tick: observe both executors, enqueue a full (weekly) or differential (daily) backup
 * when due, enqueue an export per enabled target (independent operations, so one unavailable target
 * never delays another), and re-run the canary when its evidence is about to expire.
 */
export async function backupScheduleTick(enqueue: Enqueue, now = new Date()) {
  for (const cluster of Object.keys(PG_CLUSTERS) as PgCluster[]) {
    const observed = await observeSource(cluster);
    if (!observed.ok) continue;
    const type = dueBackupType(observed.backups, now);
    if (type) {
      await enqueue({
        kind: "backup.create",
        targetIds: [cluster],
        payload: { kind: PG_CLUSTERS[cluster].backupKind, targetId: cluster, type, scheduled: true },
      });
    }
  }
  const targets = await db.select().from(backupTargets).where(eq(backupTargets.enabled, true));
  for (const target of targets) {
    if (target.kind !== "s3") continue; // FD-30 adds the tailnet REST exporter.
    await enqueue({ kind: "backup.export", targetIds: [target.id] });
    if (
      !target.appendOnlyCheckedAt ||
      now.getTime() - target.appendOnlyCheckedAt.getTime() > VERIFY_EVERY_MS
    ) {
      await enqueue({ kind: "backup.verify_target", targetIds: [target.id] });
    }
  }
}

export function startBackupSchedule(input: {
  enqueue: Enqueue;
  intervalMs?: number;
  log?: (line: string) => void;
}) {
  const tick = () =>
    void backupScheduleTick(input.enqueue).catch((error: Error) =>
      input.log?.(`backup schedule tick failed: ${error.message}`),
    );
  tick();
  return setInterval(tick, input.intervalMs ?? PG_EXPORT_INTERVAL_MS);
}
