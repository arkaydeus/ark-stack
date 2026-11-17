// Off-VPS backups to S3-compatible targets (docs/design/front-door.md §3.18, FD-21) and to the
// owner's home machine over the tailnet (§3.18.3, FD-30).
//
// - The PostgreSQL executors (workers/src/pg-executor.ts) keep an encrypted local pgBackRest repo2 per
//   cluster and stage completed copies of it under an exclusive lock.
// - `backup.export` (backup worker, per target, every 5 minutes) asks each executor for a stage at
//   most four minutes old, uploads it as an immutable restic snapshot to that target only, and
//   records the per-destination manifest (stage, labels, WAL segment, last recoverable time) in
//   `backup_exports`. Targets are exported independently: one failing never blocks another.
// - `backup.verify_target` runs the append-only canary (backup-canary.ts) with the deployed writer
//   credentials, weekly and whenever a target is saved.
// - Health and alerts come from evaluateBackupHealth (shared/src/backup-targets.ts); "healthy" needs
//   both an S3 and a home target.
// - A `tailnet_rest` (home) target is pinned from backup-ts's own observation (backup-observe.ts).
//   Its restic subprocess, and only that subprocess, gets `HTTP_PROXY=socks5://backup-ts:1055`
//   (HTTPS_PROXY for https://) and the pinned address; every transfer checks identity and freshness
//   first and runs under the local watchdog, which kills it within the documented bound when either
//   fails. S3 subprocesses and API/executor calls never see a proxy setting.
//
// pgBackRest `expire` is never run from here (scripts/backup-no-expire.test.ts).
import {
  BACKUP_ALERT_PREFIXES,
  PG_CLUSTERS,
  PG_EXPORT_INTERVAL_MS,
  PG_STAGE_MOUNT_ROOT,
  TRANSFER_KILL_GRACE_MS,
  backupSocksProxy,
  createId,
  decryptSecret,
  dueBackupType,
  encryptSecret,
  evaluateBackupHealth,
  pgSnapshotTags,
  restRepositoryUser,
  resticRestEnv,
  resticRestRepository,
  resticS3Env,
  resticS3Repository,
  withoutProxyEnv,
  type BackupHealth,
  type PgCluster,
  type S3Provider,
  type S3TargetInput,
  type StageManifest,
  type StagedBackup,
  type TailnetRestTargetInput,
} from "@ark-stack/shared";
import { and, desc, eq, inArray, isNull, like, or } from "drizzle-orm";

import { db } from "../db.ts";
import { alerts, backupExports, backupSources, backupTargets, backups, secrets } from "../schema.ts";
import { raiseAlert } from "./alerts.ts";
import { runAppendOnlyCanary, type CanaryEvidence } from "./backup-canary.ts";
import {
  checkTailnetIdentity,
  currentTailnetIdentity,
  guardTransfer,
  loadBackupSnapshot,
  pinTailnetTarget,
} from "./backup-observe.ts";
import { callExecutor, executorConfig } from "./pg-executor-client.ts";
import { runRestCanary, type RestCanaryEvidence } from "./rest-canary.ts";
import { S3Client } from "./s3-client.ts";
import { socks5HttpRequest } from "./socks5-http.ts";

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

/** Credentials for one restic invocation: S3 keys, or the home rest-server's htpasswd user. */
export type ResticKeys = {
  repositoryPassword: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  username?: string;
  password?: string;
};

export async function targetSecrets(target: BackupTargetRow) {
  const credential = await openSecret(target.credentialSecretId);
  const repositoryPassword = await openSecret(target.repositorySecretId);
  if (!credential || !repositoryPassword)
    throw new Error(`Backup target ${target.name} has no sealed credentials.`);
  if (target.kind === "tailnet_rest") {
    const rest = JSON.parse(credential) as { username: string; password: string };
    return {
      accessKeyId: "",
      secretAccessKey: "",
      username: rest.username,
      password: rest.password,
      repositoryPassword,
      verifier: null,
    };
  }
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
    configRevision: createId("rev"),
    repositoryRevision: moved ? createId("repo") : existing!.repositoryRevision,
    ...(moved ? { lastSuccessAt: null, lastAttemptAt: null, lastError: null } : {}),
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
    const reset = {
      appendOnlyStatus: "unverified" as const,
      appendOnlyVerified: false,
      appendOnlyCheckedAt: null,
      retentionUntil: null,
      appendOnlyEvidence: null,
    };
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

/**
 * Creates (no `id`) or updates the home target (PUT /api/backups/targets/tailnet_rest). The URL's host
 * is pinned from backup-ts's own current observation (StableNodeID + address), like a route. The
 * htpasswd password is write-only; the repository password can be set once. Changing the URL re-pins
 * and starts a new repository revision; any change resets the append-only verdict.
 */
export async function saveTailnetRestTarget(input: TailnetRestTargetInput) {
  const [existing] = input.id
    ? await db
        .select()
        .from(backupTargets)
        .where(and(eq(backupTargets.id, input.id), eq(backupTargets.kind, "tailnet_rest")))
    : [];
  if (input.id && !existing) throw new Error("Backup target not found.");
  const id = existing?.id ?? createId("bkt");
  if (!existing && (!input.password || !input.repositoryPassword)) {
    throw new Error("A new home target needs the htpasswd password and the repository password.");
  }
  if (existing?.repositorySecretId && input.repositoryPassword) {
    const current = await openSecret(existing.repositorySecretId);
    if (current !== input.repositoryPassword) {
      throw new Error("The repository password cannot change; use a new URL path for a new repository.");
    }
  }
  const pin = await pinTailnetTarget(input.restUrl);
  const moved =
    !existing ||
    existing.restUrl !== input.restUrl ||
    existing.targetNodeStableId !== pin.stableId ||
    existing.recoveryWindowDays !== input.recoveryWindowDays;
  const values = {
    kind: "tailnet_rest" as const,
    provider: "rest_server" as const,
    name: input.name,
    restUrl: input.restUrl,
    prefix: restRepositoryUser(input.restUrl),
    targetNodeStableId: pin.stableId,
    targetIp: pin.ip,
    recoveryWindowDays: input.recoveryWindowDays,
    configRevision: createId("rev"),
    repositoryRevision: moved ? createId("repo") : existing!.repositoryRevision,
    ...(moved ? { lastSuccessAt: null, lastAttemptAt: null, lastError: null } : {}),
    updatedAt: new Date(),
  };
  return db.transaction(async (tx) => {
    const credentialSecretId = input.password
      ? await sealSecret(
          tx,
          "backup.rest.credential",
          id,
          JSON.stringify({ username: restRepositoryUser(input.restUrl), password: input.password }),
        )
      : existing!.credentialSecretId;
    if (
      !input.password &&
      existing &&
      restRepositoryUser(existing.restUrl ?? "") !== restRepositoryUser(input.restUrl)
    ) {
      throw new Error("The URL's user changed; enter that user's htpasswd password too.");
    }
    const repositorySecretId =
      existing?.repositorySecretId ??
      (await sealSecret(tx, "backup.restic.password", id, input.repositoryPassword!));
    const reset = {
      appendOnlyStatus: "unverified" as const,
      appendOnlyVerified: false,
      appendOnlyCheckedAt: null,
      retentionUntil: null,
      appendOnlyEvidence: null,
    };
    const [row] = existing
      ? await tx
          .update(backupTargets)
          .set({ ...values, credentialSecretId, repositorySecretId, ...reset })
          .where(eq(backupTargets.id, id))
          .returning()
      : await tx
          .insert(backupTargets)
          .values({ id, ...values, credentialSecretId, repositorySecretId })
          .returning();
    return row!;
  });
}

function withoutUserinfo(value: string | null) {
  if (!value) return null;
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}

/** Public view of a target: never credentials or the repository password. */
export function publicTarget(target: BackupTargetRow) {
  return {
    id: target.id,
    kind: target.kind,
    name: target.name,
    provider: target.provider,
    restUrl: target.kind === "tailnet_rest" ? withoutUserinfo(target.restUrl) : null,
    pinned:
      target.kind === "tailnet_rest" ? { stableId: target.targetNodeStableId, ip: target.targetIp } : null,
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
    configRevision: target.configRevision,
    lastSuccessAt: target.lastSuccessAt,
    lastAttemptAt: target.lastAttemptAt,
    lastError: target.lastError,
  };
}

// ---- restic ---------------------------------------------------------------------------------------

export type ResticResult = {
  status: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Set when the transfer watchdog stopped the subprocess. */
  aborted?: string | null;
};

function restConfig(target: BackupTargetRow) {
  if (target.kind !== "tailnet_rest" || !target.restUrl || !target.targetIp) {
    throw new Error(`Backup target ${target.name} is not a pinned tailnet REST target.`);
  }
  return { restUrl: target.restUrl, targetIp: target.targetIp };
}

/** restic repository and per-kind environment (credentials, and the REST proxy only for REST). */
export function resticInvocation(target: BackupTargetRow, keys: ResticKeys) {
  if (target.kind === "tailnet_rest") {
    const config = restConfig(target);
    if (!keys.username || !keys.password)
      throw new Error(`Backup target ${target.name} has no htpasswd credentials.`);
    return {
      ...resticRestRepository(config),
      env: resticRestEnv(
        config,
        { username: keys.username, password: keys.password, repositoryPassword: keys.repositoryPassword },
        backupSocksProxy(process.env.ARK_BACKUP_SOCKS5_PROXY).url,
      ),
    };
  }
  const config = s3Config(target);
  if (!keys.accessKeyId || !keys.secretAccessKey)
    throw new Error(`Backup target ${target.name} has no S3 keys.`);
  return {
    ...resticS3Repository(config),
    env: resticS3Env(config, {
      accessKeyId: keys.accessKeyId,
      secretAccessKey: keys.secretAccessKey,
      repositoryPassword: keys.repositoryPassword,
    }),
  };
}

/**
 * Runs restic with a minimal environment built from scratch: the target's credentials and repository
 * password, plus (home targets only) the one matching-scheme proxy variable. Nothing is inherited, so
 * an HTTP_PROXY/NO_PROXY/ALL_PROXY set on the worker can never reach an S3 subprocess or redirect the
 * REST one, and no root key leaks. With `signal`, an abort (the transfer watchdog) stops the
 * subprocess: SIGTERM, then SIGKILL after TRANSFER_KILL_GRACE_MS.
 */
export async function runRestic(
  target: BackupTargetRow,
  keys: ResticKeys,
  args: string[],
  timeoutMs = 6 * 60 * 60 * 1000,
  cwd?: string,
  options: { signal?: AbortSignal } = {},
): Promise<ResticResult> {
  const { repository, options: repositoryOptions, env: targetEnv } = resticInvocation(target, keys);
  const cacheDir = process.env.ARK_RESTIC_CACHE_DIR;
  const env: Record<string, string> = withoutProxyEnv({
    PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
    HOME: process.env.ARK_RESTIC_HOME ?? "/tmp",
    ...(cacheDir ? { RESTIC_CACHE_DIR: cacheDir } : {}),
    ...(cwd ? { ARK_RESTIC_CWD: cwd } : {}),
  });
  Object.assign(env, targetEnv);
  // Test harness hooks (scripts/backup-test/restic-docker.sh); never set in production.
  for (const [name, value] of Object.entries(process.env))
    if (name.startsWith("ARK_TEST_RESTIC_") && value) env[name] = value;
  const binary = process.env.ARK_RESTIC_BIN || "restic";
  const argv = [binary, "-r", repository, ...repositoryOptions, ...(cacheDir ? [] : ["--no-cache"]), ...args];
  if (options.signal?.aborted) {
    const reason = String((options.signal.reason as Error | undefined)?.message ?? "aborted");
    return { status: -1, stdout: "", stderr: reason, timedOut: false, aborted: reason };
  }
  const child = Bun.spawn(argv, {
    env,
    ...(cwd && !process.env.ARK_TEST_RESTIC_DOCKER_ARGS ? { cwd } : {}),
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  let timedOut = false;
  let aborted: string | null = null;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const stop = () => {
    child.kill("SIGTERM");
    killTimer = setTimeout(() => child.kill("SIGKILL"), TRANSFER_KILL_GRACE_MS);
  };
  const timer = setTimeout(() => {
    timedOut = true;
    stop();
  }, timeoutMs);
  const onAbort = () => {
    aborted = String((options.signal?.reason as Error | undefined)?.message ?? "aborted");
    stop();
  };
  options.signal?.addEventListener("abort", onAbort, { once: true });
  try {
    const [status, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    return { status, stdout, stderr, timedOut, aborted };
  } finally {
    clearTimeout(timer);
    clearTimeout(killTimer);
    options.signal?.removeEventListener("abort", onAbort);
  }
}

function resticError(what: string, result: ResticResult) {
  const detail = (result.stderr || result.stdout).trim().split("\n").filter(Boolean).slice(-3).join(" | ");
  if (result.aborted) return new Error(`restic ${what} stopped by the transfer watchdog: ${result.aborted}`);
  const why = result.timedOut ? "timed out; the destination is unavailable" : `failed (${result.status})`;
  return new Error(`restic ${what} ${why}: ${detail.slice(0, 600)}`);
}

/**
 * Runs `work` as one transfer to `target`. For a home target the pinned identity and backup-ts's
 * lease are checked first (a failure means the transfer never starts) and then every second while it
 * runs (a failure aborts the signal, which kills restic). S3 transfers run unguarded.
 */
export async function withTransfer<T>(
  target: BackupTargetRow,
  work: (signal: AbortSignal | undefined) => Promise<T>,
): Promise<T> {
  if (target.kind !== "tailnet_rest") return work(undefined);
  const identity = await currentTailnetIdentity(target.id);
  if (!identity.ok) throw new Error(`Transfer to ${target.name} not started: ${identity.message}`);
  if (identity.ip !== target.targetIp)
    throw new Error(`Transfer to ${target.name} not started: the pinned address changed; retry.`);
  const guard = guardTransfer(target.id, { pinnedIp: identity.ip });
  try {
    const result = await work(guard.signal);
    const reason = guard.reason();
    if (reason) throw new Error(reason);
    return result;
  } finally {
    guard.stop();
  }
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
  keys: ResticKeys,
  signal?: AbortSignal,
) {
  const probe = await runRestic(target, keys, ["cat", "config"], probeTimeoutMs(), undefined, { signal });
  if (probe.status === 0) return { initialised: false };
  if (probe.timedOut || probe.aborted || probe.status !== 10) throw resticError("cat config", probe);
  const init = await runRestic(target, keys, ["init"], probeTimeoutMs(), undefined, { signal });
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
  keys: ResticKeys,
  path: string,
  tags: string[],
  stage?: { parent?: string | null },
  signal?: AbortSignal,
) {
  const result = await runRestic(
    target,
    keys,
    [
      "backup",
      "--json",
      "--host",
      "ark",
      ...tags.flatMap((tag) => ["--tag", tag]),
      ...(stage
        ? ["--ignore-inode", ...(stage.parent ? ["--parent", stage.parent] : []), "repo2", "manifest.json"]
        : [path]),
    ],
    undefined,
    stage ? path : undefined,
    { signal },
  );
  const snapshotId = resticSummarySnapshot(result.stdout);
  if (result.aborted || result.status !== 0 || !snapshotId) throw resticError("backup", result);
  let summary: Record<string, number> = {};
  for (const line of result.stdout.split("\n")) {
    try {
      const parsed = JSON.parse(line);
      if (parsed.message_type === "summary")
        summary = {
          filesUnmodified: parsed.files_unmodified ?? 0,
          bytesProcessed: parsed.total_bytes_processed ?? 0,
          bytesAdded: parsed.data_added ?? 0,
        };
    } catch {
      /* progress output */
    }
  }
  return { snapshotId, summary };
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
    }>(cluster, "status", {}, 15_000);
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
        stats: Record<string, number>;
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
  try {
    await withTransfer(target, async (signal) => {
      await exportSources(target, result, signal, options);
    });
  } catch (error) {
    // A home target whose identity or observation is invalid never starts a transfer: every source
    // gets a failed attempt (and no recovery point).
    const message = (error instanceof Error ? error.message : "transfer refused").slice(0, 1000);
    const done = new Set(result.sources.map((item) => item.source));
    for (const cluster of Object.keys(PG_CLUSTERS) as PgCluster[]) {
      const source = `pg:${executorConfig(cluster).profile.stanza}`;
      if (done.has(source)) continue;
      await db.insert(backupExports).values({
        id: createId("bex"),
        targetId: target.id,
        repositoryRevision: target.repositoryRevision,
        source,
        status: "failed",
        error: message,
      });
      result.sources.push({ source, ok: false, error: message });
    }
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
    .where(and(eq(backupTargets.id, target.id), eq(backupTargets.configRevision, target.configRevision)));
  await evaluateBackupAlerts().catch(() => undefined);
  if (failures.length) {
    throw new Error(
      `Export to ${target.name} failed for ${failures.map((item) => item.source).join(", ")}: ${"error" in failures[0]! ? failures[0].error : ""}`,
    );
  }
  return result;
}

/** Stages and uploads every PostgreSQL source to one target (inside the transfer guard). */
async function exportSources(
  target: BackupTargetRow,
  result: ExportResult,
  signal: AbortSignal | undefined,
  options: { fresh?: boolean },
) {
  let secretsForTarget: Awaited<ReturnType<typeof targetSecrets>> | null = null;
  let repositoryError: string | null = null;
  try {
    secretsForTarget = await targetSecrets(target);
    await ensureResticRepository(target, secretsForTarget, signal);
  } catch (error) {
    repositoryError = error instanceof Error ? error.message : "restic repository unavailable";
  }
  for (const cluster of Object.keys(PG_CLUSTERS) as PgCluster[]) {
    const { profile } = executorConfig(cluster);
    const source = `pg:${profile.stanza}`;
    try {
      if (repositoryError || !secretsForTarget) throw new Error(repositoryError ?? "no credentials");
      if (signal?.aborted)
        throw new Error(String((signal.reason as Error | undefined)?.message ?? "aborted"));
      // A scheduled export reuses a stage at most four minutes old, so targets exporting in the same
      // interval upload the same completed copy. An export right after a backup stages afresh.
      const staged = await callExecutor<{ reused: boolean; manifest: StageManifest; leaseId?: string }>(
        cluster,
        "stage",
        {
          maxAgeSeconds: options.fresh ? 0 : Math.floor((PG_EXPORT_INTERVAL_MS * 0.8) / 1000),
          leaseSeconds: 6 * 3600 + 900,
        },
      );
      const manifest = staged.manifest;
      const [previous] = await db
        .select()
        .from(backupExports)
        .where(
          and(
            eq(backupExports.targetId, target.id),
            eq(backupExports.repositoryRevision, target.repositoryRevision),
            eq(backupExports.source, source),
            eq(backupExports.status, "succeeded"),
          ),
        )
        .orderBy(desc(backupExports.createdAt))
        .limit(1);
      const { snapshotId, summary } = await (async () => {
        try {
          return await resticBackup(
            target,
            secretsForTarget!,
            stagePath(profile.stanza, manifest.stageId),
            [...pgSnapshotTags(profile.stanza, manifest.stageId), "layout=relative-v1"],
            { parent: previous?.resticSnapshotId },
            signal,
          );
        } finally {
          if (staged.leaseId)
            await callExecutor(
              cluster,
              "release-stage",
              { stageId: manifest.stageId, leaseId: staged.leaseId },
              10_000,
            ).catch(() => undefined);
        }
      })();
      await db.insert(backupExports).values({
        id: createId("bex"),
        targetId: target.id,
        repositoryRevision: target.repositoryRevision,
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
        stats: summary,
      });
      // Older stages are subsets of the newest one (repo2 is never expired on the VPS); keep two so
      // active exports also hold persisted leases so a stalled reader is never pruned.
      await callExecutor(cluster, "prune-stages", { keep: 2 }, 10 * 60 * 1000).catch(() => undefined);
    } catch (error) {
      const message = (error instanceof Error ? error.message : "export failed").slice(0, 1000);
      await db.insert(backupExports).values({
        id: createId("bex"),
        targetId: target.id,
        repositoryRevision: target.repositoryRevision,
        source,
        status: "failed",
        error: message,
      });
      result.sources.push({ source, ok: false, error: message });
    }
    await observeSource(cluster);
  }
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

/** restic backup of a mail snapshot or reviewed volume path to every enabled target (S3 and home). */
export async function exportFiles(source: string, path: string, tags: string[]) {
  const targets = await db.select().from(backupTargets).where(eq(backupTargets.enabled, true));
  if (!targets.length) throw new Error("No backup target is configured for mail and volume backups.");
  const results: Array<{ targetId: string; snapshotId?: string; error?: string }> = [];
  for (const target of targets) {
    try {
      const { snapshotId } = await withTransfer(target, async (signal) => {
        const secretsForTarget = await targetSecrets(target);
        await ensureResticRepository(target, secretsForTarget, signal);
        return resticBackup(
          target,
          secretsForTarget,
          path,
          ["ark", `source=${source}`, ...tags],
          undefined,
          signal,
        );
      });
      await db.insert(backupExports).values({
        id: createId("bex"),
        targetId: target.id,
        repositoryRevision: target.repositoryRevision,
        source,
        status: "succeeded",
        resticSnapshotId: snapshotId,
      });
      results.push({ targetId: target.id, snapshotId });
    } catch (error) {
      const message = (error instanceof Error ? error.message : "export failed").slice(0, 1000);
      await db.insert(backupExports).values({
        id: createId("bex"),
        targetId: target.id,
        repositoryRevision: target.repositoryRevision,
        source,
        status: "failed",
        error: message,
      });
      results.push({ targetId: target.id, error: message });
    }
  }
  return results;
}

/** Restore only a recorded successful snapshot from the current repository revision. */
export async function restoreFiles(source: string, snapshotId: string, restoreRoot: string) {
  const rows = await db
    .select({ target: backupTargets })
    .from(backupExports)
    .innerJoin(
      backupTargets,
      and(
        eq(backupTargets.id, backupExports.targetId),
        eq(backupTargets.repositoryRevision, backupExports.repositoryRevision),
      ),
    )
    .where(
      and(
        eq(backupExports.source, source),
        eq(backupExports.resticSnapshotId, snapshotId),
        eq(backupExports.status, "succeeded"),
      ),
    )
    .orderBy(desc(backupExports.createdAt))
    .limit(1);
  const target = rows[0]?.target;
  if (!target)
    throw new Error("No successful export of this exact snapshot exists in a current target repository.");
  const argv = ["restore", snapshotId, "--target", restoreRoot];
  const keys = await targetSecrets(target);
  const result = await withTransfer(target, (signal) =>
    runRestic(target, keys, argv, 180_000, undefined, { signal }),
  );
  if (result.aborted || result.status !== 0) throw resticError("restore", result);
  return { ...result, argv: ["restic", "-r", resticInvocation(target, keys).repository, ...argv] };
}

// ---- Append-only canary (backup.verify_target) ----------------------------------------------------

/**
 * The home target's canary (rest-canary.ts): its repository is opened (or initialised) first, then
 * the canary runs with the deployed htpasswd credentials through backup-ts's SOCKS5 proxy to the
 * pinned address, under the same identity checks and watchdog as a backup.
 */
async function verifyRestTarget(target: BackupTargetRow): Promise<RestCanaryEvidence> {
  const keys = await targetSecrets(target);
  const config = restConfig(target);
  const proxy = backupSocksProxy(process.env.ARK_BACKUP_SOCKS5_PROXY).url;
  const base = new URL(`${config.restUrl}/`);
  return withTransfer(target, async (signal) => {
    await ensureResticRepository(target, keys, signal);
    const authorization = `Basic ${Buffer.from(`${keys.username}:${keys.password}`).toString("base64")}`;
    return runRestCanary({
      restUrl: config.restUrl,
      pinned: { stableId: target.targetNodeStableId!, ip: config.targetIp },
      request: async ({ method, path, body, auth }) => {
        if (signal?.aborted)
          throw new Error(String((signal.reason as Error | undefined)?.message ?? "aborted"));
        const response = await socks5HttpRequest({
          proxy,
          url: new URL(path, base).toString(),
          connectHost: base.protocol === "https:" ? undefined : config.targetIp,
          method,
          body,
          headers: {
            ...(auth === false ? {} : { authorization }),
            accept: "application/vnd.x.restic.rest.v2",
            ...(body ? { "content-type": "application/octet-stream" } : {}),
          },
          timeoutMs: 30_000,
        });
        return { status: response.status, body: response.body };
      },
    });
  });
}

/** Append-only evidence of either kind; callers verifying a home target ask for RestCanaryEvidence. */
export type TargetEvidence = CanaryEvidence | RestCanaryEvidence;

export async function verifyTarget<E extends TargetEvidence = CanaryEvidence>(
  targetId: string,
  revision?: string,
): Promise<E> {
  const [target] = await db.select().from(backupTargets).where(eq(backupTargets.id, targetId));
  if (!target) throw new Error("Backup target not found.");
  if (revision && revision !== target.configRevision)
    throw new Error("Backup target configuration changed; verify its current revision.");
  if (target.kind === "tailnet_rest") {
    const evidence = await verifyRestTarget(target);
    await db
      .update(backupTargets)
      .set({
        appendOnlyStatus: evidence.status,
        appendOnlyVerified: evidence.status === "append_only",
        appendOnlyEvidence: evidence as unknown as Record<string, unknown>,
        appendOnlyCheckedAt: new Date(evidence.checkedAt),
        retentionUntil: null,
      })
      .where(and(eq(backupTargets.id, target.id), eq(backupTargets.configRevision, target.configRevision)));
    await evaluateBackupAlerts().catch(() => undefined);
    return evidence as E;
  }
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
    .where(and(eq(backupTargets.id, target.id), eq(backupTargets.configRevision, target.configRevision)));
  await evaluateBackupAlerts().catch(() => undefined);
  return evidence as E;
}

// ---- Health and alerts ----------------------------------------------------------------------------

export async function backupHealth(now = new Date()): Promise<BackupHealth> {
  const [targets, exportsRows, sources, backupSnapshot] = await Promise.all([
    db.select().from(backupTargets),
    db
      .select()
      .from(backupExports)
      .where(or(...PG_SOURCES.map((source) => eq(backupExports.source, source))))
      .orderBy(desc(backupExports.createdAt))
      .limit(2000),
    db.select().from(backupSources),
    loadBackupSnapshot(),
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
      identity:
        target.kind === "tailnet_rest"
          ? (() => {
              const identity = checkTailnetIdentity(target, backupSnapshot, now);
              return { ok: identity.ok, message: identity.ok ? "pinned" : identity.message };
            })()
          : null,
    })),
    exports: exportsRows
      .filter((row) =>
        targets.some(
          (target) => target.id === row.targetId && target.repositoryRevision === row.repositoryRevision,
        ),
      )
      .map((row) => ({
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
  const targets = await db.select().from(backupTargets).where(eq(backupTargets.enabled, true));
  for (const target of targets) {
    await enqueue({ kind: "backup.export", targetIds: [target.id] });
    if (
      !target.appendOnlyCheckedAt ||
      now.getTime() - target.appendOnlyCheckedAt.getTime() > VERIFY_EVERY_MS
    ) {
      await enqueue({
        kind: "backup.verify_target",
        targetIds: [target.id],
        payload: { revision: target.configRevision },
      });
    }
  }
  await Promise.all(
    (Object.keys(PG_CLUSTERS) as PgCluster[]).map(async (cluster) => {
      const observed = await observeSource(cluster);
      if (!observed.ok) return;
      const type = dueBackupType(observed.backups, now);
      if (type) {
        await enqueue({
          kind: "backup.create",
          targetIds: [cluster],
          payload: { kind: PG_CLUSTERS[cluster].backupKind, targetId: cluster, type, scheduled: true },
        });
      }
    }),
  );
}

export function startBackupSchedule(input: {
  enqueue: Enqueue;
  intervalMs?: number;
  log?: (line: string) => void;
}) {
  let running = false;
  const tick = () => {
    if (running) return;
    running = true;
    void backupScheduleTick(input.enqueue)
      .catch((error: Error) => input.log?.(`backup schedule tick failed: ${error.message}`))
      .finally(() => {
        running = false;
      });
  };
  tick();
  return setInterval(tick, input.intervalMs ?? PG_EXPORT_INTERVAL_MS);
}
