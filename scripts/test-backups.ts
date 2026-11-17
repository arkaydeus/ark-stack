import { workerSmoke } from "./backup-test/worker-smoke.ts";
import { S3Client } from "../server/src/modules/s3-client.ts";
// FD-21 acceptance suite: S3-compatible off-VPS backups, append-only, run locally against MinIO
// (docs/design/front-door.md §3.18, §5 FD-21). No provider credentials are needed; hosted providers
// run the same scenario opt-in through scripts/test-backups-hosted.ts.
//
// It starts a pinned MinIO (path-style), a throwaway control database and the actual `postgres` and
// `app-postgres` Compose services with their pgBackRest executors, then drives the production backup
// worker code (server/src/modules/offsite-backups.ts) in-process, then runs the deployed Compose
// backup-worker as bun with group 999, its stage/cache mounts, API claims and actual restic. The
// in-process cases use scripts/backup-test/restic-docker.sh with the worker's minimal environment.
//
// 1. Append-only policy classes: a versioning-only bucket with a full-access writer fails (and
//    permanent deletion succeeds there); a locked bucket with the AWS-style no-delete writer passes
//    with permanent version deletion and retention change/bypass refused; the same bucket with a
//    full-access key is "deletable" and marks backups unhealthy; retention shorter than the recovery
//    window is unhealthy. (Unsupported checks are covered by server/src/modules/backup-canary.test.ts.)
// 2. R2 lock recipe, emulated with MinIO object lock: two backup + WAL cycles, both recovery points
//    restore, both *.info histories are kept, and locks never block later writes.
// 3. Unavailable destination: an unreachable endpoint and a missing bucket fail while the healthy
//    target still exports; no WAL is dropped; health fails; capacity and last-recoverable-time alerts.
// 4. Full recovery: data in both clusters, backups, more WAL, export, every VPS-local copy deleted,
//    then a chosen PITR timestamp restored per cluster in isolated containers with independent
//    read-only recovery credentials and only the MinIO destination.
import { randomBytes } from "node:crypto";

import {
  PG_CLUSTERS,
  resticS3Repository,
  repositoryProtectionPolicy,
  writerPolicy,
  type PgCluster,
} from "@ark-stack/shared";

import {
  assert,
  recorder,
  resticDockerArgs,
  startClusters,
  startControlDb,
  type Clusters,
  type ControlDb,
} from "./backup-test/harness.ts";
import { fullAccessPolicy, readOnlyPolicy, run, startMinio, type MinioFixture } from "./backup-test/minio.ts";
import { offsiteRestore } from "./offsite-restore.ts";

const { record, summary } = recorder();
const keep = process.env.ARK_TEST_KEEP === "1";
const repositoryPassword = randomBytes(24).toString("base64url");
const r2Password = randomBytes(24).toString("base64url");

const state: { minio?: MinioFixture; control?: ControlDb; clusters?: Clusters } = {};
const restored: Array<{ cleanup: () => Promise<void> }> = [];

async function main() {
  console.log("Starting MinIO, the control database and the Compose clusters…");
  [state.minio, state.control] = await Promise.all([startMinio("suite"), startControlDb("suite")]);
  state.clusters = await startClusters("suite");
  const m = state.minio;
  const c = state.clusters;
  const control = state.control;

  // Buckets and identities.
  await m.mc(["mb", "--with-lock", "ark/pitr"]);
  await m.mc(["retention", "set", "--default", "COMPLIANCE", "2d", "ark/pitr"]);
  await m.mc(["mb", "--with-versioning", "ark/versioned"]);
  await m.mc(["mb", "--with-lock", "ark/short"]);
  await m.mc(["retention", "set", "--default", "GOVERNANCE", "1d", "ark/short"]);
  await m.mc(["mb", "--with-lock", "ark/r2emu"]);
  await m.mc(["retention", "set", "--default", "COMPLIANCE", "2d", "ark/r2emu"]);
  const writer = await m.createUser("ark-writer", "ark-writer", writerPolicy("pitr", "ark"));
  const pitrFull = await m.createUser("ark-pitr-full", "ark-pitr-full", fullAccessPolicy("pitr"));
  const versionedFull = await m.createUser(
    "ark-versioned-full",
    "ark-versioned-full",
    fullAccessPolicy("versioned"),
  );
  const shortWriter = await m.createUser(
    "ark-short-writer",
    "ark-short-writer",
    writerPolicy("short", "ark"),
  );
  // R2 tokens have no no-delete level: "Object Read & Write" on the bucket, locks are the only control.
  const r2Token = await m.createUser("ark-r2-token", "ark-r2-token", fullAccessPolicy("r2emu"));
  // Independent recovery credentials: list and read only.
  const recovery = await m.createUser("ark-recovery", "ark-recovery", readOnlyPolicy("pitr", "ark"));
  const r2Recovery = await m.createUser("ark-r2-recovery", "ark-r2-recovery", readOnlyPolicy("r2emu", "ark"));

  Object.assign(process.env, {
    DATABASE_URL: control.url,
    ARK_ROOT_KEY: randomBytes(32).toString("base64url"),
    ARK_ROOT_KEY_ID: "k1",
    ARK_RUNTIME_ROLE: "worker",
    // restic retries a dead endpoint for ~15 minutes; the worker bounds its probe (default 2 min).
    ARK_RESTIC_PROBE_TIMEOUT_MS: "20000",
    ARK_TEST_RESTIC_DOCKER_ARGS: resticDockerArgs(c, `container:${m.container}`),
    ...c.workerEnv(),
  });
  const backups = await import("../server/src/modules/offsite-backups.ts");
  const { sql } = await import("../server/src/db.ts");
  const removeTarget = async (id: string) => void (await sql`DELETE FROM backup_targets WHERE id = ${id}`);

  const s3 = (
    bucket: string,
    name: string,
    keys: { accessKeyId: string; secretAccessKey: string },
    extra: Record<string, unknown> = {},
  ) => ({
    name,
    provider: "minio" as const,
    endpoint: m.endpoint,
    region: "us-east-1",
    bucket,
    prefix: "ark",
    pathStyle: true,
    recoveryWindowDays: 1,
    accessKeyId: keys.accessKeyId,
    secretAccessKey: keys.secretAccessKey,
    repositoryPassword,
    ...extra,
  });
  const openAlerts = async () =>
    (await sql<Array<{ dedup_key: string }>>`SELECT dedup_key FROM alerts WHERE resolved_at IS NULL`).map(
      (row) => row.dedup_key,
    );

  // ---- 1. Append-only policy classes ----------------------------------------------------------------
  const versionedTarget = await backups.saveS3Target(s3("versioned", "versioned-full-access", versionedFull));
  const versioned = await backups.verifyTarget(versionedTarget.id);
  assert(
    versioned.status === "deletable",
    `versioning-only + full access must fail, got ${versioned.status}`,
  );
  const versionedData = versioned.classes.find((item) => item.policyClass === "data")!;
  assert(
    versionedData.attempts.ordinaryDelete?.outcome === "succeeded",
    "ordinary delete on the versioned bucket succeeds",
  );
  assert(
    versionedData.attempts.permanentDelete?.outcome === "succeeded",
    "permanent deletion succeeds in the negative fixture",
  );
  record(
    "Versioning-only bucket, full-access writer",
    `canary "${versioned.status}"; ordinary delete kept history but permanent version deletion succeeded (${versioned.findings.length} findings)`,
  );
  await removeTarget(versionedTarget.id);

  const protect = async (bucket: string) => {
    const client = new S3Client(
      { endpoint: m.endpoint, region: "us-east-1", bucket, pathStyle: true },
      { accessKeyId: m.rootUser, secretAccessKey: m.rootPassword },
    );
    const response = await client.request("PUT", undefined, {
      query: { policy: "" },
      body: JSON.stringify(repositoryProtectionPolicy(bucket, "ark")),
    });
    assert(
      response.status === 204 || response.status === 200,
      `bucket policy installed: ${response.status} ${response.text}`,
    );
  };
  await protect("short");

  const shortTarget = await backups.saveS3Target(
    s3("short", "short-retention", shortWriter, { recoveryWindowDays: 7 }),
  );
  const short = await backups.verifyTarget(shortTarget.id);
  assert(
    short.status === "retention_short",
    `1-day retention vs 7-day window must be unhealthy, got ${short.status}: ${JSON.stringify(short.findings)}`,
  );
  record(
    "Retention shorter than the recovery window",
    `canary "${short.status}": ${short.findings.at(-1)?.message}`,
  );
  await removeTarget(shortTarget.id);

  // Full-access key on the locked bucket: deletable, and backups are unhealthy.
  const fullOnLocked = await backups.saveS3Target(s3("pitr", "minio-pitr", pitrFull));
  const fullVerdict = await backups.verifyTarget(fullOnLocked.id);
  assert(fullVerdict.status === "deletable", `full-access key must be deletable, got ${fullVerdict.status}`);
  let health = await backups.backupHealth();
  assert(!health.healthy, "a deletable target makes backups unhealthy");
  assert(health.targets[0]?.appendOnly.label.startsWith("deletable"), "target is shown as deletable");
  await backups.evaluateBackupAlerts();
  assert((await openAlerts()).includes(`backup-append-only:${fullOnLocked.id}`), "append-only alert raised");
  record(
    "Full-access key on the locked bucket",
    `canary "${fullVerdict.status}" ("${health.targets[0]!.appendOnly.label}"); backups unhealthy and alert raised`,
  );

  await protect("pitr");
  // The AWS-style no-delete writer plus independently evaluated bucket denial covers exact config.
  const pitr = await backups.saveS3Target({ ...s3("pitr", "minio-pitr", writer), id: fullOnLocked.id });
  const locked = await backups.verifyTarget(pitr.id);
  assert(
    locked.status === "append_only",
    `restricted locked writer must pass, got ${locked.status}: ${JSON.stringify(locked.findings)}`,
  );
  for (const item of locked.classes) {
    assert(
      item.attempts.permanentDelete?.outcome === "refused",
      `${item.policyClass}: permanent version deletion refused`,
    );
    assert(
      item.attempts.bypassDelete?.outcome === "refused",
      `${item.policyClass}: governance bypass refused`,
    );
    assert(
      item.attempts.shortenRetention?.outcome === "refused",
      `${item.policyClass}: retention change refused`,
    );
    assert(
      item.attempts.shortenRetentionBypass?.outcome === "refused",
      `${item.policyClass}: retention bypass refused`,
    );
    assert(item.readback === "match", `${item.policyClass}: original hash retrievable`);
  }
  assert(
    Object.values(locked.bucketProbes).every((item) => item.outcome === "refused"),
    "bucket-level policy changes refused",
  );
  assert(
    locked.locks.create.outcome === "succeeded" && locked.locks.delete?.outcome === "succeeded",
    "restic locks/ create+delete allowed",
  );
  record(
    "Restricted locked writer (AWS-style policy, delete only on locks/)",
    `canary "${locked.status}" → append-only: yes; ${locked.classes.length} policy classes, permanent deletion, bypass and retention change refused (${locked.classes[0]!.attempts.permanentDelete!.code}, ${locked.classes[0]!.attempts.shortenRetention!.code}); retention until ${locked.retentionUntil}`,
  );

  // ---- 2. R2 lock recipe, emulated -------------------------------------------------------------------
  const r2 = await backups.saveS3Target({
    ...s3("r2emu", "r2-emulated", r2Token),
    provider: "r2",
    repositoryPassword: r2Password,
  });
  const cycles: Array<{ label: string; t: string; snapshot: string }> = [];
  for (const [cycle, type] of [
    [1, "full"],
    [2, "diff"],
  ] as const) {
    await c.psql(
      "platform",
      `CREATE TABLE IF NOT EXISTS fd21_r2 (cycle int, note text); INSERT INTO fd21_r2 VALUES (${cycle}, 'before-backup')`,
    );
    const backup = await backups.callExecutor<{ label: string }>("platform", "backup", { type });
    await Bun.sleep(1500);
    await c.psql("platform", `INSERT INTO fd21_r2 VALUES (${cycle}, 'recovery-point')`);
    const t = await c.psql("platform", "SELECT to_json(clock_timestamp())#>>'{}'");
    await Bun.sleep(1200);
    await c.psql("platform", `INSERT INTO fd21_r2 VALUES (${cycle}, 'after-recovery-point')`);
    const exported = await backups.exportTarget(r2.id, { fresh: true });
    const platform = exported.sources.find((item) => item.source === "pg:ark-platform");
    assert(platform?.ok, `cycle ${cycle}: export to the R2-emulated target succeeded`);
    cycles.push({ label: backup.label, t, snapshot: platform.ok ? platform.snapshotId : "" });
  }
  // Both recovery points restore, each from its own snapshot.
  for (const [index, cycle] of cycles.entries()) {
    const restore = await offsiteRestore({
      endpoint: m.endpoint,
      region: "us-east-1",
      bucket: "r2emu",
      prefix: "ark",
      pathStyle: true,
      ...r2Recovery,
      resticPassword: r2Password,
      cluster: "platform",
      cipherPass: c.cipherPasses.platform,
      targetTime: cycle.t,
      snapshot: cycle.snapshot,
      image: c.images.platform,
      resticNetwork: `container:${m.container}`,
      name: `ark-fd21-r2-${index + 1}-${randomBytes(2).toString("hex")}`,
    });
    restored.push(restore);
    const rows = await restore.query(
      "SELECT string_agg(cycle || ':' || note, ',' ORDER BY cycle, note) FROM fd21_r2",
    );
    const expected = cycles
      .slice(0, index + 1)
      .flatMap((_, i) =>
        i < index
          ? [`${i + 1}:after-recovery-point`, `${i + 1}:before-backup`, `${i + 1}:recovery-point`]
          : [`${i + 1}:before-backup`, `${i + 1}:recovery-point`],
      )
      .toSorted()
      .join(",");
    assert(rows === expected, `R2 recovery point ${index + 1}: expected ${expected}, got ${rows}`);
    // The snapshot's backup.info lists every backup up to that cycle: the metadata history is kept.
    const info = JSON.parse(
      await run([
        "docker",
        "exec",
        "--user",
        "postgres",
        "--env",
        `PGBACKREST_REPO2_CIPHER_PASS=${c.cipherPasses.platform}`,
        restore.container,
        "pgbackrest",
        "--stanza=ark-platform",
        "--repo=2",
        "--repo2-path=/restore/repo2",
        "--output=json",
        "info",
      ]).then((result) => result.stdout),
    ) as Array<{ backup: Array<{ label: string }> }>;
    const labels = new Set(info[0]!.backup.map((item) => item.label));
    for (const previous of cycles.slice(0, index + 1))
      assert(labels.has(previous.label), `snapshot ${index + 1} backup.info lists ${previous.label}`);
    assert(!labels.has(cycles[1]!.label) || index === 1, "snapshot 1 predates cycle 2");
    await restore.cleanup();
  }
  // The two snapshots hold different backup.info and archive.info versions (immutable history).
  const r2Repo = resticS3Repository({
    endpoint: m.endpoint,
    region: "us-east-1",
    bucket: "r2emu",
    prefix: "ark",
    pathStyle: true,
  });
  const infoHash = async (snapshot: string, file: string) => {
    const env = {
      AWS_ACCESS_KEY_ID: r2Recovery.accessKeyId,
      AWS_SECRET_ACCESS_KEY: r2Recovery.secretAccessKey,
      AWS_DEFAULT_REGION: "us-east-1",
      RESTIC_PASSWORD: r2Password,
    };
    const ls = await run(
      [
        "docker",
        "run",
        "--rm",
        "--network",
        `container:${m.container}`,
        ...Object.keys(env).flatMap((key) => ["-e", key]),
        "restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510",
        "--no-lock",
        "--no-cache",
        "-r",
        r2Repo.repository,
        ...r2Repo.options,
        "ls",
        "--json",
        snapshot,
      ],
      { env },
    );
    const node = ls.stdout
      .split("\n")
      .map((line) => JSON.parse(line) as { path?: string; mtime?: string; size?: number })
      .find((item) => item.path?.endsWith(`/repo2/${file}`));
    assert(node, `${file} is in snapshot ${snapshot}`);
    return `${node.size}:${node.mtime}`;
  };
  const backupInfo = await Promise.all(
    cycles.map((cycle) => infoHash(cycle.snapshot, "backup/ark-platform/backup.info")),
  );
  await Promise.all(cycles.map((cycle) => infoHash(cycle.snapshot, "archive/ark-platform/archive.info")));
  assert(backupInfo[0] !== backupInfo[1], "backup.info differs between the two snapshots");
  record(
    "R2 lock recipe emulated (MinIO object lock, Object Read & Write token)",
    `two backup/WAL cycles (${cycles.map((item) => item.label).join(", ")}) restored to both recovery points; each snapshot keeps its own backup.info/archive.info; locks did not block the second cycle's backup, index or snapshot writes`,
  );
  const r2Check = await backups.runRestic(
    r2,
    {
      accessKeyId: r2Token.accessKeyId,
      secretAccessKey: r2Token.secretAccessKey,
      repositoryPassword: r2Password,
    },
    ["check"],
  );
  assert(r2Check.status === 0, `restic check on the locked repository: ${r2Check.stderr}`);
  await removeTarget(r2.id);

  // ---- 3. Unavailable destination -------------------------------------------------------------------
  const deadPort = (await import("./backup-test/minio.ts")).freePort;
  const unreachable = await backups.saveS3Target({
    ...s3("pitr", "unreachable", writer),
    endpoint: `http://127.0.0.1:${await deadPort()}`,
  });
  const missingBucket = await backups.saveS3Target(s3("no-such-bucket", "missing-bucket", writer));
  const archiveBefore = await backups.callExecutor<{
    info: { archive: { min: string; max: string } };
    archiver: { failedCount: number };
  }>("platform", "status");
  await c.psql(
    "platform",
    "CREATE TABLE IF NOT EXISTS fd21_outage (note text); INSERT INTO fd21_outage VALUES ('during-outage')",
  );
  const outcomes: Record<string, string> = {};
  for (const target of [unreachable, missingBucket, pitr]) {
    try {
      const result = await backups.exportTarget(target.id);
      outcomes[target.name] = `ok (${result.sources.length} sources)`;
    } catch (error) {
      outcomes[target.name] = `failed: ${(error as Error).message.slice(0, 90)}`;
    }
  }
  assert(outcomes.unreachable!.startsWith("failed"), "the unreachable target fails");
  assert(outcomes["missing-bucket"]!.startsWith("failed"), "the missing repository fails");
  assert(
    outcomes["minio-pitr"]!.startsWith("ok"),
    `the healthy target still exports: ${outcomes["minio-pitr"]}`,
  );
  const archiveAfter = await backups.callExecutor<{
    info: { archive: { min: string; max: string } };
    archiver: { failedCount: number };
  }>("platform", "status");
  assert(
    archiveAfter.info.archive.min === archiveBefore.info.archive.min,
    "no archived WAL was removed from repo2",
  );
  assert(archiveAfter.info.archive.max >= archiveBefore.info.archive.max, "WAL archiving continued");
  assert(
    archiveAfter.archiver.failedCount === archiveBefore.archiver.failedCount,
    "no archive_command failures",
  );
  const failedRows = await sql<Array<{ status: string; last_recoverable_at: Date | null }>>`
    SELECT status, last_recoverable_at FROM backup_exports WHERE target_id = ${unreachable.id}`;
  assert(
    failedRows.length > 0 &&
      failedRows.every((row) => row.status === "failed" && row.last_recoverable_at === null),
    "failed exports claim no recovery point",
  );
  // The unavailable targets hold no recovery point at all: the newest local WAL exists only on the VPS.
  health = await backups.backupHealth();
  assert(!health.healthy, "backup health fails while a destination is unavailable");
  await backups.evaluateBackupAlerts();
  const alertKeys = await openAlerts();
  assert(
    alertKeys.includes("backup-capacity:pg:ark-platform"),
    `capacity alert fires: ${alertKeys.join(", ")}`,
  );
  assert(
    alertKeys.includes(`backup-rpo:${unreachable.id}:pg:ark-platform`),
    "last-recoverable-time alert fires",
  );
  record(
    "Unavailable repository and egress target",
    `${Object.entries(outcomes)
      .map(([name, outcome]) => `${name}: ${outcome.split(":")[0]}`)
      .join(
        "; ",
      )}; repo2 WAL ${archiveBefore.info.archive.min}…${archiveAfter.info.archive.max} intact; health failed; alerts: ${alertKeys.filter((key) => key.startsWith("backup-capacity") || key.startsWith("backup-rpo")).length} capacity/last-recoverable-time`,
  );
  await removeTarget(unreachable.id);
  await removeTarget(missingBucket.id);

  // ---- 4. Full recovery against the actual Compose clusters ------------------------------------------
  const targets: Partial<Record<PgCluster, string>> = {};
  for (const cluster of ["platform", "app"] as const) {
    await c.psql(
      cluster,
      "CREATE TABLE fd21_pitr (note text); INSERT INTO fd21_pitr VALUES ('before-backup')",
    );
    await backups.callExecutor(cluster, "backup", { type: "full" });
  }
  await Bun.sleep(1500);
  for (const cluster of ["platform", "app"] as const) {
    await c.psql(cluster, "INSERT INTO fd21_pitr VALUES ('after-backup'); SELECT pg_switch_wal()");
    targets[cluster] = await c.psql(cluster, "SELECT to_json(clock_timestamp())#>>'{}'");
  }
  await Bun.sleep(1200);
  for (const cluster of ["platform", "app"] as const) {
    // More WAL after the chosen point; the restore must stop before it.
    await c.psql(cluster, "INSERT INTO fd21_pitr SELECT 'after-target' FROM generate_series(1, 2000)");
  }
  const final = await backups.exportTarget(pitr.id, { fresh: true });
  for (const source of final.sources)
    assert(
      source.ok && source.stats.filesUnmodified! > 0,
      `${source.source}: restic reused unchanged parent files`,
    );
  record(
    "Restic parent reuse",
    "freshly copied stage retains unchanged-file detection through a relative tree, an explicit per-source parent and ignore-inode",
  );
  for (const item of final.sources)
    assert(item.ok && item.lastRecoverableAt, `${item.source} exported with a recovery point`);
  health = await backups.backupHealth();
  const pitrHealth = health.targets.find((item) => item.id === pitr.id)!;
  assert(
    pitrHealth.healthy,
    `the append-only target is healthy after export: ${pitrHealth.reasons.join("; ")}`,
  );
  // Default manifest-time recovery must also work with no user writes after the backup.
  const idleExport = await backups.exportTarget(pitr.id, { fresh: true });
  const idleSource = idleExport.sources.find((item) => item.source === "pg:ark-platform");
  assert(idleSource?.ok && idleSource.lastRecoverableAt, "idle source has a recovery point");
  const idle = await offsiteRestore({
    endpoint: m.endpoint,
    region: "us-east-1",
    bucket: "pitr",
    prefix: "ark",
    pathStyle: true,
    ...recovery,
    resticPassword: repositoryPassword,
    cluster: "platform",
    cipherPass: c.cipherPasses.platform,
    image: c.images.platform,
    resticNetwork: `container:${m.container}`,
    snapshot: idleSource.snapshotId,
  });
  restored.push(idle);
  assert(idle.targetTime === idleSource.lastRecoverableAt, "default recovery preserves the manifest time");
  assert(
    (await idle.query("SELECT count(*) FROM fd21_pitr")) ===
      (await c.psql("platform", "SELECT count(*) FROM fd21_pitr")),
    "idle cluster default recovery includes all committed rows",
  );
  await idle.cleanup();
  record(
    "Idle default recovery",
    "no explicit target; manifest-time recovery completed and recovered every committed row",
  );

  // Two actual commits inside one millisecond expose any rounding-up of a PITR target.
  // Async commit avoids fsync latency in this fixture connection only; staging
  // switches and archives WAL durably before recovery, including both real commit records.
  await c.psql(
    "platform",
    "CREATE TABLE fd21_precision (note text, xid text); CREATE PROCEDURE fd21_precision_pair() LANGUAGE plpgsql AS $$ BEGIN PERFORM set_config('synchronous_commit', 'off', false); INSERT INTO fd21_precision VALUES ('first', pg_current_xact_id()::text); COMMIT; INSERT INTO fd21_precision VALUES ('second', pg_current_xact_id()::text); COMMIT; END $$",
  );
  let preciseTarget = "";
  for (let attempt = 0; attempt < 100 && !preciseTarget; attempt++) {
    await c.psql("platform", "TRUNCATE fd21_precision");
    await c.psql("platform", "CALL fd21_precision_pair()");
    preciseTarget = await c.psql(
      "platform",
      "WITH commits AS (SELECT max(pg_xact_commit_timestamp(xid::xid)) FILTER (WHERE note='first') AS a, max(pg_xact_commit_timestamp(xid::xid)) FILTER (WHERE note='second') AS b FROM fd21_precision) SELECT CASE WHEN b>a AND date_trunc('milliseconds', a)=date_trunc('milliseconds', b) THEN to_json(a+(b-a)/2)#>>'{}' ELSE '' END FROM commits",
    );
  }
  assert(preciseTarget, "obtained two distinct commits within the same millisecond");
  const preciseExport = await backups.exportTarget(pitr.id, { fresh: true });
  const preciseSource = preciseExport.sources.find((item) => item.source === "pg:ark-platform");
  assert(preciseSource?.ok, "precision fixture exported");
  const precise = await offsiteRestore({
    endpoint: m.endpoint,
    region: "us-east-1",
    bucket: "pitr",
    prefix: "ark",
    pathStyle: true,
    ...recovery,
    resticPassword: repositoryPassword,
    cluster: "platform",
    cipherPass: c.cipherPasses.platform,
    image: c.images.platform,
    resticNetwork: `container:${m.container}`,
    snapshot: preciseSource.snapshotId,
    targetTime: preciseTarget,
  });
  restored.push(precise);
  assert(
    (await precise.query("SELECT string_agg(note, ',') FROM fd21_precision")) === "first",
    "sub-millisecond PITR excludes the later commit",
  );
  await precise.cleanup();
  record(
    "Microsecond recovery boundary",
    "two commits within one millisecond; exact target restored the first and excluded the second",
  );

  await workerSmoke(c, control, m, writer, repositoryPassword);
  record(
    "Deployed backup worker",
    "bun user/group 999, read-only stages, cache, two healthy exports during blocked full backup and mid-upload stall; mail and volume exact snapshots restored with content assertions; executor inaccessible on control interface",
  );
  // Lose every VPS-local copy: PGDATA, repo2 and staged copies of both clusters.
  await c.destroy();
  const leftovers = await run(["docker", "volume", "ls", "--quiet", "--filter", `name=${c.project}_`]);
  assert(leftovers.stdout === "", `no VPS-local volume remains: ${leftovers.stdout}`);
  for (const cluster of ["platform", "app"] as const) {
    const restore = await offsiteRestore({
      endpoint: m.endpoint,
      region: "us-east-1",
      bucket: "pitr",
      prefix: "ark",
      pathStyle: true,
      ...recovery,
      resticPassword: repositoryPassword,
      cluster,
      cipherPass: c.cipherPasses[cluster],
      targetTime: targets[cluster],
      image: c.images[cluster],
      resticNetwork: `container:${m.container}`,
      name: `ark-fd21-pitr-${cluster}-${randomBytes(2).toString("hex")}`,
    });
    restored.push(restore);
    const rows = await restore.query("SELECT string_agg(note, ',' ORDER BY note) FROM fd21_pitr");
    assert(rows === "after-backup,before-backup", `${cluster}: PITR to ${targets[cluster]} returned ${rows}`);
    record(
      `Full off-VPS recovery: ${PG_CLUSTERS[cluster].stanza}`,
      `all VPS-local copies deleted; restored ${targets[cluster]} from snapshot ${restore.snapshotId.slice(0, 8)} (MinIO path-style) with a read-only recovery key; rows before the target present, after it absent`,
    );
    await restore.cleanup();
  }
  await sql.end({ timeout: 5 });
}

try {
  await main();
  summary();
  console.log("\nFD-21 backup suite passed.");
} finally {
  if (!keep) {
    for (const item of restored) await item.cleanup().catch(() => undefined);
    await state.clusters?.teardown().catch(() => undefined);
    await state.minio?.stop().catch(() => undefined);
    await state.control?.stop().catch(() => undefined);
  } else {
    console.log(`Kept: ${state.clusters?.project}, ${state.minio?.container}, ${state.control?.container}`);
  }
}
