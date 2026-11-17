// pgBackRest executor, run inside each PostgreSQL container (docs/design/front-door.md §3.18.1, FD-21).
//
// It runs as the `postgres` user next to PGDATA and the local Unix socket, and answers a fixed set of
// token-authenticated actions on the internal `backup-management` network: status, stanza-create,
// check, backup (full/diff/incr) into the encrypted posix repo2, stage, release-stage, and prune-stages. There is no
// generic command, no shell and no Docker socket, and pgBackRest `expire` is never run.
//
// Locking: every repo2 writer holds the executor lock. archive-push (archive_command) and backup take
// it shared; staging takes it exclusive, so a stage is a copy of a repository whose `.info` files are
// not being rewritten. While a stage is copied, archive-push waits (PostgreSQL retries and keeps WAL
// in pg_wal), so WAL is fenced, never dropped.
//
// Bundled on its own (Dockerfile `pg-executor-build`), so it imports nothing outside this file and
// shared/src/pg-backup.ts.
import { lookup } from "node:dns/promises";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readdir, readFile, rename, rm, stat, statfs, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  PG_EXECUTOR_LOCK,
  PG_EXECUTOR_PORT,
  PG_REPO2_PATH,
  PG_REPO_ROOT,
  PG_STAGING_ROOT,
  STAGE_ID,
  assertStanza,
  parsePgbackrestInfo,
  pgbackrestArgv,
  stageId,
  stageRecoverableAt,
  type PgBackupType,
  type StageManifest,
} from "../../shared/src/pg-backup.ts";

const config = {
  stanza: assertStanza(process.env.ARK_PG_STANZA ?? "ark-platform"),
  token: process.env.ARK_PG_EXECUTOR_TOKEN ?? "",
  port: Number(process.env.ARK_PG_EXECUTOR_PORT ?? PG_EXECUTOR_PORT),
  repoRoot: process.env.ARK_PG_REPO_ROOT ?? PG_REPO_ROOT,
  repo2: process.env.PGBACKREST_REPO2_PATH ?? PG_REPO2_PATH,
  lock: process.env.ARK_PG_EXECUTOR_LOCK ?? PG_EXECUTOR_LOCK,
  staging: process.env.ARK_PG_STAGING_DIR ?? PG_STAGING_ROOT,
  socket: process.env.PGBACKREST_PG1_SOCKET_PATH ?? "/var/run/postgresql",
  user: process.env.PGBACKREST_PG1_USER ?? process.env.POSTGRES_USER ?? "postgres",
  database: process.env.POSTGRES_DB ?? process.env.POSTGRES_USER ?? "postgres",
  archiveWaitMs: Number(process.env.ARK_PG_ARCHIVE_WAIT_MS ?? 120_000),
  stageLockWaitSeconds: Number(process.env.ARK_PG_STAGE_LOCK_WAIT_SECONDS ?? 600),
  backupLockWaitSeconds: Number(process.env.ARK_PG_BACKUP_LOCK_WAIT_SECONDS ?? 3600),
};

type Run = { status: number; stdout: string; stderr: string };

async function run(argv: string[], timeoutMs = 6 * 60 * 60 * 1000): Promise<Run> {
  const child = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe", stdin: "ignore", env: process.env });
  const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
  try {
    const [status, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    return { status, stdout, stderr };
  } finally {
    clearTimeout(timer);
  }
}

function failed(what: string, result: Run): never {
  const detail = (result.stderr || result.stdout).trim().split("\n").slice(-6).join("\n");
  throw new Error(`${what} failed (${result.status}): ${detail.slice(0, 1500)}`);
}

async function pgbackrest(argv: string[], lock: "shared" | "none" = "none") {
  const command =
    lock === "shared"
      ? ["flock", "-s", "-w", String(config.backupLockWaitSeconds), config.lock, ...argv]
      : argv;
  const result = await run(command);
  if (result.status !== 0) failed(argv.slice(0, 3).join(" "), result);
  return result.stdout;
}

async function psql(query: string) {
  const result = await run(
    [
      "psql",
      "-X",
      "-A",
      "-t",
      "-v",
      "ON_ERROR_STOP=1",
      "-h",
      config.socket,
      "-U",
      config.user,
      "-d",
      config.database,
      "-c",
      query,
    ],
    60_000,
  );
  if (result.status !== 0) failed("psql", result);
  return result.stdout.trim();
}

/** True once pgBackRest has stored `segment` in repo2 (`archive/<stanza>/<db id>/<first 16>/<segment>-<sha1>...`). */
async function segmentInRepo(segment: string) {
  const archiveRoot = join(config.repo2, "archive", config.stanza);
  for (const dbId of await readdir(archiveRoot).catch(() => [] as string[])) {
    const files = await readdir(join(archiveRoot, dbId, segment.slice(0, 16))).catch(() => [] as string[]);
    if (files.some((name) => name.startsWith(`${segment}-`))) return true;
  }
  return false;
}

// pg_stat_archiver.last_archived_wal can name a backup history or timeline file, so the proof that a
// segment is archived is the segment itself in repo2.
async function waitForArchive(segment: string) {
  const deadline = Date.now() + config.archiveWaitMs;
  while (true) {
    if (await segmentInRepo(segment)) return segment;
    if (Date.now() > deadline) {
      const row = await psql("SELECT coalesce(last_archived_wal, '') FROM pg_stat_archiver").catch(() => "");
      throw new Error(
        `WAL ${segment} was not archived within ${config.archiveWaitMs / 1000} s (last archived: ${row || "none"}).`,
      );
    }
    await Bun.sleep(250);
  }
}

async function directoryBytes(path: string) {
  const result = await run(["du", "-s", "-B1", path], 10 * 60 * 1000);
  if (result.status !== 0) return 0;
  return Number(result.stdout.split(/\s+/)[0] ?? 0);
}

async function listStages() {
  await mkdir(config.staging, { recursive: true });
  const names = await readdir(config.staging);
  return names.filter((name) => STAGE_ID.test(name)).toSorted();
}

async function readManifest(stage: string) {
  return JSON.parse(await readFile(join(config.staging, stage, "manifest.json"), "utf8")) as StageManifest;
}

async function reportStatus() {
  const info = await pgbackrest(pgbackrestArgv("info", config.stanza)).then(
    (text) => parsePgbackrestInfo(text, config.stanza),
    (error: Error) => ({ error: error.message }),
  );
  const repoFs = await statfs(config.repoRoot);
  const stageFs = await statfs(config.staging).catch(() => repoFs);
  const archiver = await psql(
    "SELECT json_build_object('archiveMode', current_setting('archive_mode'), 'lastArchivedWal', last_archived_wal, 'lastArchivedAt', last_archived_time, 'failedCount', failed_count, 'lastFailedWal', last_failed_wal, 'lastFailedAt', last_failed_time)::text FROM pg_stat_archiver",
  ).then(
    (text) => JSON.parse(text) as Record<string, unknown>,
    (error: Error) => ({ error: error.message }),
  );
  const stages = await listStages();
  const newest = stages.at(-1);
  return {
    stanza: config.stanza,
    info,
    archiver,
    repoBytes: await directoryBytes(config.repo2),
    repoFs: { totalBytes: repoFs.blocks * repoFs.bsize, freeBytes: repoFs.bavail * repoFs.bsize },
    stagingFs: { totalBytes: stageFs.blocks * stageFs.bsize, freeBytes: stageFs.bavail * stageFs.bsize },
    stages,
    newestStage: newest ? await readManifest(newest).catch(() => null) : null,
  };
}

async function backup(type: PgBackupType) {
  const before = parsePgbackrestInfo(await pgbackrest(pgbackrestArgv("info", config.stanza)), config.stanza);
  const output = await pgbackrest(pgbackrestArgv("backup", config.stanza, { type }), "shared");
  const after = parsePgbackrestInfo(await pgbackrest(pgbackrestArgv("info", config.stanza)), config.stanza);
  const created = after.backups.filter((item) => !before.backups.some((old) => old.label === item.label));
  const label = created.at(-1)?.label;
  if (!label) throw new Error("pgBackRest finished without a new backup label.");
  return { label, type, backup: created.at(-1), output: output.slice(-1500) };
}

/**
 * Switch WAL, wait until the switched segment is archived, then copy the completed repo2 under the
 * exclusive executor lock. The manifest claims a recovery point only for what the copy contains.
 */
export async function stageRepository(maxAgeSeconds: number) {
  const existing = await listStages();
  const newest = existing.at(-1);
  if (newest && maxAgeSeconds > 0) {
    const manifest = await readManifest(newest).catch(() => null);
    if (manifest && Date.now() - new Date(manifest.createdAt).getTime() <= maxAgeSeconds * 1000) {
      return { reused: true, manifest };
    }
  }
  const switchedAt = new Date(await psql("SELECT to_json(clock_timestamp())#>>'{}'"));
  // On an idle cluster pg_switch_wal() does nothing and the "switched" segment stays open until
  // background activity and archive_timeout close it (up to a minute or more). One tiny WAL record
  // first guarantees the switch completes the segment that holds everything committed so far.
  // Commit a WAL marker *before* switching, in its own transaction. Its commit timestamp is
  // after switchedAt, so PostgreSQL can reach the default time target even on an idle cluster.
  await psql("SELECT pg_logical_emit_message(true, 'ark-backup-stage', '') IS NOT NULL");
  const switched = await psql("SELECT pg_walfile_name(pg_switch_wal())");
  const segment = switched.split("\n").at(-1)!.trim();
  if (!/^[0-9A-F]{24}$/.test(segment)) throw new Error(`Unexpected WAL segment name: ${segment}`);
  await waitForArchive(segment);
  const id = stageId(
    new Date(),
    Math.random()
      .toString(36)
      .slice(2, 8)
      .padEnd(6, "0")
      .replace(/[^a-z0-9]/g, "0"),
  );
  const partial = join(config.staging, `.${id}.partial`);
  await rm(partial, { recursive: true, force: true });
  await mkdir(partial, { recursive: true, mode: 0o750 });
  // cp --reflink=auto clones when the filesystem supports it and copies otherwise. Either way the
  // whole copy happens under the exclusive lock, never as concurrent partial metadata copies.
  const copy = await run(
    [
      "flock",
      "-x",
      "-w",
      String(config.stageLockWaitSeconds),
      config.lock,
      "cp",
      "-a",
      "--reflink=auto",
      config.repo2,
      join(partial, "repo2"),
    ],
    60 * 60 * 1000,
  );
  if (copy.status !== 0) {
    await rm(partial, { recursive: true, force: true });
    failed("staging copy", copy);
  }
  const info = parsePgbackrestInfo(
    await pgbackrest(pgbackrestArgv("info", config.stanza, { repoPath: join(partial, "repo2") })),
    config.stanza,
  );
  const manifest: StageManifest = {
    version: 1,
    stanza: config.stanza,
    stageId: id,
    createdAt: new Date().toISOString(),
    lastRecoverableAt: stageRecoverableAt({ switchedAt, walSegment: segment, info }),
    walSegment: segment,
    archive: info.archive,
    backups: info.backups,
    repoBytes: await directoryBytes(join(partial, "repo2")),
    pgbackrestVersion: info.version,
  };
  await writeFile(join(partial, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o640 });
  await rename(partial, join(config.staging, id));
  return { reused: false, manifest };
}

/** Keeps the newest `keep` stages. A newer stage is a superset: repo2 itself is never expired here. */
export async function pruneStages(keep: number) {
  const leased = new Set<string>();
  const leaseDir = join(config.staging, ".leases");
  for (const name of await readdir(leaseDir).catch(() => [])) {
    const stage = name.split(".")[0]!;
    if (!STAGE_ID.test(stage)) continue;
    const expires = Number(await readFile(join(leaseDir, name), "utf8").catch(() => "NaN"));
    if (!Number.isFinite(expires) || expires > Date.now()) leased.add(stage);
    else await rm(join(leaseDir, name), { force: true });
  }
  const stages = await listStages();
  const removed: string[] = [];
  for (const name of stages.slice(0, Math.max(0, stages.length - keep))) {
    if (leased.has(name)) continue;
    await rm(join(config.staging, name), { recursive: true, force: true });
    removed.push(name);
  }
  for (const name of await readdir(config.staging)) {
    if (!name.startsWith(".") || !name.endsWith(".partial")) continue;
    const info = await stat(join(config.staging, name)).catch(() => null);
    if (info && Date.now() - info.mtimeMs > 60 * 60 * 1000) {
      await rm(join(config.staging, name), { recursive: true, force: true });
      removed.push(name);
    }
  }
  return { kept: (await listStages()).length, removed };
}

// One mutating action at a time; status is always allowed.
let busy: Promise<unknown> = Promise.resolve();
function serialized<T>(action: () => Promise<T>) {
  const next = busy.then(action, action);
  busy = next.catch(() => undefined);
  return next;
}

async function handle(action: string, body: Record<string, unknown>) {
  if (action === "status") return reportStatus();
  if (action === "stanza-create")
    return serialized(() =>
      pgbackrest(pgbackrestArgv("stanza-create", config.stanza)).then(() => ({ ok: true })),
    );
  if (action === "check")
    return serialized(() => pgbackrest(pgbackrestArgv("check", config.stanza)).then(() => ({ ok: true })));
  if (action === "backup") {
    const type = body.type;
    if (type !== "full" && type !== "diff" && type !== "incr")
      throw new TypeError("type must be full, diff or incr.");
    return serialized(() => backup(type));
  }
  if (action === "stage") {
    const maxAge = Number(body.maxAgeSeconds ?? 0);
    if (!Number.isInteger(maxAge) || maxAge < 0 || maxAge > 86_400)
      throw new TypeError("maxAgeSeconds must be 0..86400.");
    const leaseSeconds = Number(body.leaseSeconds ?? 0);
    if (!Number.isInteger(leaseSeconds) || leaseSeconds < 0 || leaseSeconds > 25200)
      throw new TypeError("leaseSeconds must be 0..25200.");
    return serialized(async () => {
      const result = await stageRepository(maxAge);
      if (!leaseSeconds) return result;
      const leaseId = randomBytes(16).toString("hex");
      await mkdir(join(config.staging, ".leases"), { recursive: true });
      await writeFile(
        join(config.staging, ".leases", `${result.manifest.stageId}.${leaseId}`),
        String(Date.now() + leaseSeconds * 1000),
        { mode: 0o600 },
      );
      return { ...result, leaseId };
    });
  }
  if (action === "release-stage") {
    if (
      typeof body.stageId !== "string" ||
      !STAGE_ID.test(body.stageId) ||
      typeof body.leaseId !== "string" ||
      !/^[a-f0-9]{32}$/.test(body.leaseId)
    )
      throw new TypeError("Invalid stage lease.");
    await rm(join(config.staging, ".leases", `${body.stageId}.${body.leaseId}`), { force: true });
    return { released: true };
  }
  if (action === "prune-stages") {
    const keep = Number(body.keep ?? 2);
    if (!Number.isInteger(keep) || keep < 1 || keep > 10) throw new TypeError("keep must be 1..10.");
    return serialized(() => pruneStages(keep));
  }
  return null;
}

async function prepareStanza() {
  // The stanza needs a running server; retry until it exists. Until then archive-push fails and
  // PostgreSQL keeps the WAL and retries, so nothing is lost.
  for (let attempt = 0; ; attempt += 1) {
    const ready = await run(
      ["pg_isready", "-q", "-h", config.socket, "-U", config.user, "-d", config.database],
      10_000,
    );
    if (ready.status === 0) {
      const created = await run(pgbackrestArgv("stanza-create", config.stanza));
      if (created.status === 0) {
        console.log(`ark-pg-executor: stanza ${config.stanza} ready`);
        return;
      }
      if (attempt % 10 === 0)
        console.error(`ark-pg-executor: stanza-create pending: ${created.stderr.trim().split("\n").at(-1)}`);
    }
    await Bun.sleep(2000);
  }
}

export function executorHandler(token: string, actionHandler = handle) {
  return async (request: Request) => {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return new Response("ok");
    const supplied = Buffer.from(request.headers.get("authorization") ?? "");
    const expected = Buffer.from(`Bearer ${token}`);
    if (!token || supplied.length !== expected.length || !timingSafeEqual(supplied, expected))
      return Response.json({ error: "unauthorized" }, { status: 401 });
    const match = /^\/v1\/([a-z-]+)$/.exec(url.pathname);
    if (!match || request.method !== "POST") return Response.json({ error: "not found" }, { status: 404 });
    try {
      const body = await request.json();
      if (!body || typeof body !== "object" || Array.isArray(body))
        throw new TypeError("Expected an object body.");
      const result = await actionHandler(match[1]!, body);
      if (result === null) return Response.json({ error: "unknown action" }, { status: 404 });
      return Response.json(result);
    } catch (error) {
      return Response.json(
        { error: error instanceof Error ? error.message : "executor error" },
        { status: error instanceof TypeError || error instanceof SyntaxError ? 400 : 500 },
      );
    }
  };
}

if (import.meta.main) {
  if (config.token.length < 24) {
    console.error(
      "ark-pg-executor: ARK_PG_EXECUTOR_TOKEN is missing or shorter than 24 characters; not listening.",
    );
    process.exit(78);
  }
  await mkdir(config.staging, { recursive: true });
  void prepareStanza();
  const address = (await lookup(process.env.ARK_PG_EXECUTOR_BIND_HOST ?? "127.0.0.1", { family: 4 })).address;
  Bun.serve({ port: config.port, hostname: address, fetch: executorHandler(config.token) });
  console.log(`ark-pg-executor: ${config.stanza} listening on ${address}:${config.port}`);
}
