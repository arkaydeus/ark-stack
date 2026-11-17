// FD-21 opt-in hosted-provider test (docs/design/front-door.md §3.18, §5 FD-21): the same backup and
// off-VPS PITR restore scenario as scripts/test-backups.ts, against a real AWS S3, Backblaze B2 or
// Cloudflare R2 bucket addressed virtual-host style. It runs only when credentials are supplied and
// otherwise exits 0 with a skip message. Nothing is deleted from the bucket: locked objects cannot
// be, and the test only adds a restic repository under a unique prefix.
//
//   ARK_TEST_S3_PROVIDER=aws|b2|r2                (required)
//   ARK_TEST_S3_ENDPOINT=https://s3.us-east-1.amazonaws.com
//   ARK_TEST_S3_REGION=us-east-1                  (R2: auto)
//   ARK_TEST_S3_BUCKET=ark-fd21-test              (versioned + object lock / R2 lock rules per recipe)
//   ARK_TEST_S3_ACCESS_KEY_ID / ARK_TEST_S3_SECRET_ACCESS_KEY            writer (recipe policy)
//   ARK_TEST_S3_RECOVERY_ACCESS_KEY_ID / ..._SECRET_ACCESS_KEY            optional read-only key
//   ARK_TEST_S3_PREFIX_BASE=ark-fd21              (a unique suffix is added per run)
//   ARK_TEST_S3_RECOVERY_WINDOW_DAYS=1
//   ARK_TEST_R2_ACCOUNT_ID / ARK_TEST_R2_VERIFIER_TOKEN                   optional, R2 lock-rule verifier
import { randomBytes } from "node:crypto";

import type { PgCluster, S3Provider } from "@ark-stack/shared";

import {
  assert,
  recorder,
  resticDockerArgs,
  startClusters,
  startControlDb,
  type Clusters,
  type ControlDb,
} from "./backup-test/harness.ts";
import { offsiteRestore } from "./offsite-restore.ts";

const required = [
  "ARK_TEST_S3_PROVIDER",
  "ARK_TEST_S3_ENDPOINT",
  "ARK_TEST_S3_BUCKET",
  "ARK_TEST_S3_ACCESS_KEY_ID",
  "ARK_TEST_S3_SECRET_ACCESS_KEY",
];
const missing = required.filter((name) => !process.env[name]);
if (missing.length) {
  console.log(
    `SKIP: hosted-provider backup test (FD-21) needs ${missing.join(", ")}. It is opt-in; the required suite is \`mise run test:backups\` against MinIO.`,
  );
  process.exit(0);
}
const provider = process.env.ARK_TEST_S3_PROVIDER as S3Provider;
if (!["aws", "b2", "r2"].includes(provider)) throw new Error("ARK_TEST_S3_PROVIDER must be aws, b2 or r2.");

const { record, summary } = recorder();
const state: { control?: ControlDb; clusters?: Clusters } = {};
const restores: Array<{ cleanup: () => Promise<void> }> = [];
const prefix = `${process.env.ARK_TEST_S3_PREFIX_BASE ?? "ark-fd21"}-${Date.now().toString(36)}`;
const repositoryPassword = randomBytes(24).toString("base64url");
const region = process.env.ARK_TEST_S3_REGION ?? (provider === "r2" ? "auto" : "us-east-1");

try {
  [state.control, state.clusters] = await Promise.all([startControlDb("hosted"), startClusters("hosted")]);
  const c = state.clusters;
  Object.assign(process.env, {
    DATABASE_URL: state.control.url,
    ARK_ROOT_KEY: randomBytes(32).toString("base64url"),
    ARK_RUNTIME_ROLE: "worker",
    ARK_TEST_RESTIC_DOCKER_ARGS: resticDockerArgs(c, "bridge"),
    ...c.workerEnv(),
  });
  const backups = await import("../server/src/modules/offsite-backups.ts");
  const target = await backups.saveS3Target({
    name: `hosted-${provider}`,
    provider,
    endpoint: process.env.ARK_TEST_S3_ENDPOINT!,
    region,
    bucket: process.env.ARK_TEST_S3_BUCKET!,
    prefix,
    pathStyle: false,
    recoveryWindowDays: Number(process.env.ARK_TEST_S3_RECOVERY_WINDOW_DAYS ?? "1"),
    accessKeyId: process.env.ARK_TEST_S3_ACCESS_KEY_ID!,
    secretAccessKey: process.env.ARK_TEST_S3_SECRET_ACCESS_KEY!,
    repositoryPassword,
    verifierAccountId: process.env.ARK_TEST_R2_ACCOUNT_ID,
    verifierToken: process.env.ARK_TEST_R2_VERIFIER_TOKEN,
  });
  const canary = await backups.verifyTarget(target.id);
  record(
    `Append-only canary on ${provider} (virtual-host)`,
    `${canary.status}; ${canary.findings.map((item) => item.message).join("; ") || "no findings"}`,
  );

  const times: Partial<Record<PgCluster, string>> = {};
  for (const cluster of ["platform", "app"] as const) {
    await c.psql(
      cluster,
      "CREATE TABLE fd21_hosted (note text); INSERT INTO fd21_hosted VALUES ('before-backup')",
    );
    await backups.callExecutor(cluster, "backup", { type: "full" });
  }
  await Bun.sleep(1500);
  for (const cluster of ["platform", "app"] as const) {
    await c.psql(cluster, "INSERT INTO fd21_hosted VALUES ('after-backup')");
    times[cluster] = await c.psql(cluster, "SELECT to_json(clock_timestamp())#>>'{}'");
  }
  await Bun.sleep(1200);
  for (const cluster of ["platform", "app"] as const)
    await c.psql(cluster, "INSERT INTO fd21_hosted VALUES ('after-target')");
  const exported = await backups.exportTarget(target.id, { fresh: true });
  assert(
    exported.sources.every((item) => item.ok),
    `export to ${provider}: ${JSON.stringify(exported.sources)}`,
  );
  await c.destroy();
  for (const cluster of ["platform", "app"] as const) {
    const restore = await offsiteRestore({
      endpoint: process.env.ARK_TEST_S3_ENDPOINT!,
      region,
      bucket: process.env.ARK_TEST_S3_BUCKET!,
      prefix,
      pathStyle: false,
      accessKeyId: process.env.ARK_TEST_S3_RECOVERY_ACCESS_KEY_ID ?? process.env.ARK_TEST_S3_ACCESS_KEY_ID!,
      secretAccessKey:
        process.env.ARK_TEST_S3_RECOVERY_SECRET_ACCESS_KEY ?? process.env.ARK_TEST_S3_SECRET_ACCESS_KEY!,
      resticPassword: repositoryPassword,
      cluster,
      cipherPass: c.cipherPasses[cluster],
      targetTime: times[cluster],
      image: c.images[cluster],
    });
    restores.push(restore);
    const rows = await restore.query("SELECT string_agg(note, ',' ORDER BY note) FROM fd21_hosted");
    assert(rows === "after-backup,before-backup", `${cluster}: PITR returned ${rows}`);
    record(
      `Backup and off-VPS PITR restore via ${provider}: ${cluster}`,
      `restored ${times[cluster]} from ${restore.snapshotId.slice(0, 8)}`,
    );
    await restore.cleanup();
  }
  summary();
  console.log(`\nHosted-provider backup test passed (prefix ${prefix} left in the bucket under its lock).`);
} finally {
  for (const item of restores) await item.cleanup().catch(() => undefined);
  await state.clusters?.teardown().catch(() => undefined);
  await state.control?.stop().catch(() => undefined);
}
