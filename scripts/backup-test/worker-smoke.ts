import { writerPolicy } from "@ark-stack/shared";
// Exercise the deployed backup-worker service, its bun identity, group 999, cache and stage mounts.
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Clusters, ControlDb } from "./harness.ts";
import { assert } from "./harness.ts";
import { RESTIC_IMAGE, run, type MinioFixture } from "./minio.ts";

const wait = async (predicate: () => Promise<boolean> | boolean, label: string, timeout = 120_000) => {
  const until = Date.now() + timeout;
  while (!(await predicate())) {
    if (Date.now() > until) throw new Error(`Worker smoke timed out: ${label}`);
    await Bun.sleep(200);
  }
};

export async function workerSmoke(
  c: Clusters,
  control: ControlDb,
  m: MinioFixture,
  keys: { accessKeyId: string; secretAccessKey: string },
  password: string,
) {
  const offsite = await import("../../server/src/modules/offsite-backups.ts");
  const { enqueue } = await import("../../server/src/coordinator.ts");
  const { app } = await import("../../server/src/app.ts");
  const { sql } = await import("../../server/src/db.ts");
  const enabled = await sql<Array<{ id: string }>>`SELECT id FROM backup_targets WHERE enabled`;
  await sql`UPDATE backup_targets SET enabled = false`;
  const api = Bun.serve({ hostname: "0.0.0.0", port: 0, fetch: app.fetch });
  let releaseUpload!: () => void;
  let releaseBackup!: () => void;
  const uploadGate = new Promise<void>((resolve) => {
    releaseUpload = resolve;
  });
  const backupGate = new Promise<void>((resolve) => {
    releaseBackup = resolve;
  });
  let uploadBlocked = false,
    backupBlocked = false;
  const storage = Bun.serve({
    hostname: "0.0.0.0",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const body =
        request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer();
      if (request.method === "PUT" && url.pathname.includes("/worker-stalled/ark/restic/data/")) {
        uploadBlocked = true;
        await uploadGate;
      }
      const headers = new Headers(request.headers);
      // Preserve the signed Host while relaying to this fixture's MinIO.
      headers.set("host", url.host);
      // Go adds gzip after SigV4 signing. Request identity so Bun cannot decompress a MinIO
      // list response while leaving its Content-Encoding header for restic to decode again.
      headers.set("accept-encoding", "identity");
      for (const header of ["connection", "transfer-encoding", "expect"]) headers.delete(header);
      return fetch(`${m.endpoint}${url.pathname}${url.search}`, {
        method: request.method,
        headers,
        body,
        redirect: "manual",
      });
    },
  });
  const executor = Bun.serve({
    hostname: "0.0.0.0",
    port: 0,
    async fetch(request) {
      if (new URL(request.url).pathname === "/v1/backup") {
        backupBlocked = true;
        await backupGate;
      }
      return fetch(`${c.executorUrls.platform}${new URL(request.url).pathname}`, {
        method: request.method,
        headers: request.headers,
        body: (await request.text()) || "{}",
      });
    },
  });
  const target = (name: string, credential: { accessKeyId: string; secretAccessKey: string }) =>
    offsite.saveS3Target({
      name,
      provider: "minio",
      endpoint: `http://host.docker.internal:${storage.port}`,
      region: "us-east-1",
      bucket: name,
      prefix: "ark",
      pathStyle: true,
      recoveryWindowDays: 1,
      ...credential,
      repositoryPassword: password,
    });
  const name = `${c.project}-worker-smoke`;
  let workerId = "";
  const sourceVolume = `${c.project}_worker-files`;
  let sourceCreated = false;
  const finished = async (id: string) => {
    const [row] = await sql`SELECT status, error FROM operations WHERE id=${id}`;
    if (row?.status === "failed") throw new Error(`Worker job failed: ${row.error}`);
    return row?.status === "succeeded";
  };
  try {
    const credentials: Record<string, { accessKeyId: string; secretAccessKey: string }> = {};
    for (const bucket of ["worker-stalled", "worker-healthy"]) {
      await m.mc(["mb", "--with-lock", `ark/${bucket}`]);
      await m.mc(["retention", "set", "--default", "COMPLIANCE", "2d", `ark/${bucket}`]);
      credentials[bucket] = await m.createUser(bucket, bucket, writerPolicy(bucket, "ark"));
    }
    const stalled = await target("worker-stalled", credentials["worker-stalled"]!);
    const healthy = await target("worker-healthy", credentials["worker-healthy"]!);
    const cache = join(c.work, "cache");
    await mkdir(cache);
    await chmod(cache, 0o777);
    await run(["docker", "volume", "create", "--label", `ark.worker-smoke=${c.project}`, sourceVolume]);
    sourceCreated = true;
    await run([
      "docker",
      "run",
      "--rm",
      "--network",
      "none",
      "--user",
      "0",
      "--volume",
      `${sourceVolume}:/data`,
      "--entrypoint",
      "/bin/sh",
      RESTIC_IMAGE,
      "-c",
      'printf "off-VPS file recovery sentinel\\n" > /data/sentinel; chmod 0644 /data/sentinel',
    ]);
    const databaseUrl = new URL(control.url);
    databaseUrl.hostname = "host.docker.internal";
    const diagnosticRunner = join(c.work, "restic-smoke.sh");
    await writeFile(
      diagnosticRunner,
      '#!/bin/sh\nrestic "$@" 2>/tmp/ark-restic-$$.stderr\nstatus=$?\ncat /tmp/ark-restic-$$.stderr >&2\nexit "$status"\n',
      { mode: 0o755 },
    );
    const override = join(c.work, "worker-smoke.json");
    await writeFile(
      override,
      JSON.stringify({
        volumes: { [sourceVolume]: { external: true, name: sourceVolume } },
        services: {
          "backup-worker": {
            environment: {
              ARK_API_URL: `http://host.docker.internal:${api.port}`,
              ARK_WORKER_TOKEN: process.env.ARK_BACKUP_WORKER_TOKEN,
              DATABASE_URL: databaseUrl.toString(),
              ARK_ROOT_KEY: process.env.ARK_ROOT_KEY,
              ARK_BACKUP_EXECUTE: "1",
              ARK_BACKUP_SCHEDULE: "0",
              ARK_MAIL_SNAPSHOT_READY: "1",
              ARK_RESTORE_RUNNER: "1",
              ARK_RESTIC_BIN: "/tmp/ark-restic-smoke",
              ARK_PLATFORM_PG_EXECUTOR_URL: `http://host.docker.internal:${executor.port}`,
              ARK_RESTIC_PROBE_TIMEOUT_MS: "10000",
            },
            volumes: [
              `${diagnosticRunner}:/tmp/ark-restic-smoke:ro`,
              `${cache}:/var/lib/ark/backups`,
              `${sourceVolume}:/var/lib/stalwart-snapshot:ro`,
              `${sourceVolume}:/var/lib/ark/volumes/reviewed:ro`,
            ],
          },
        },
      }),
    );
    await chmod(override, 0o600);
    await c.compose(["build", "backup-worker"]);
    workerId = (
      await c.compose(["-f", override, "run", "--no-deps", "--detach", "--name", name, "backup-worker"])
    ).stdout
      .split("\n")
      .at(-1)!;
    const uid = await run(["docker", "exec", workerId, "id"]);
    assert(/uid=1000/.test(uid.stdout) && /999/.test(uid.stdout), `deployed worker identity: ${uid.stdout}`);
    assert(
      (await run(["docker", "exec", workerId, "cat", "/var/lib/stalwart-snapshot/sentinel"])).stdout ===
        "off-VPS file recovery sentinel",
      "bun can read the native file fixture",
    );
    // The control interface must refuse executor traffic while the backup interface works.
    const network = JSON.parse((await run(["docker", "inspect", await c.container("platform")])).stdout)[0]
      .NetworkSettings.Networks;
    const controlIp = network[`${c.project}_control`].IPAddress;
    const backupIp = network[`${c.project}_backup-management`].IPAddress;
    const reach = await run([
      "docker",
      "exec",
      workerId,
      "bun",
      "-e",
      `const probe=async(ip)=>fetch('http://'+ip+':8432/healthz',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok,()=>false);if(await probe(${JSON.stringify(controlIp)})||!await probe(${JSON.stringify(backupIp)}))process.exit(1);console.log('backup interface only');`,
    ]);
    assert(reach.status === 0, "executor listens only on backup-management");
    const full = await enqueue({
      kind: "backup.create",
      targetIds: ["platform"],
      payload: { kind: "platform-postgres", targetId: "platform" },
    });
    const stalledJob = await enqueue({ kind: "backup.export", targetIds: [stalled.id] });
    const export1 = await enqueue({ kind: "backup.export", targetIds: [healthy.id] });
    await wait(async () => {
      await finished(stalledJob.id);
      await finished(full.id);
      return backupBlocked && uploadBlocked;
    }, "blocked backup and mid-upload destination");
    await wait(() => finished(export1.id), "first healthy export while other jobs are blocked");
    const export2 = await enqueue({ kind: "backup.export", targetIds: [healthy.id] });
    await wait(() => finished(export2.id), "second healthy export while other jobs are blocked");
    assert(backupBlocked && uploadBlocked, "both blocked lanes remain occupied");
    releaseBackup();
    releaseUpload();
    await wait(() => finished(full.id), "released full backup");
    await sql`UPDATE backup_targets SET enabled=false WHERE id=${stalled.id}`;
    for (const [kind, resource] of [
      ["mail", "mail-fixture"],
      ["volume", "reviewed"],
    ]) {
      const job = await enqueue({
        kind: "backup.create",
        targetIds: [resource!],
        payload: { kind, targetId: resource },
      });
      await wait(() => finished(job.id), `${kind} backup`);
      const [backup] =
        await sql`SELECT id FROM backups WHERE kind=${kind!} AND target_id=${resource!} ORDER BY created_at DESC LIMIT 1`;
      const restore = await enqueue({
        kind: "backup.restore_test",
        targetIds: [resource!],
        payload: { kind, backupId: backup!.id },
      });
      await wait(() => finished(restore.id), `${kind} exact-snapshot restore`);
      const [step] =
        await sql`SELECT evidence FROM operation_steps WHERE operation_id=${restore.id} AND name='restore-test'`;
      const path = `${step!.evidence.restoreRoot}${kind === "mail" ? "/var/lib/stalwart-snapshot" : "/var/lib/ark/volumes/reviewed"}/sentinel`;
      const recovered = await run(["docker", "exec", workerId, "cat", path]);
      assert(
        recovered.stdout === "off-VPS file recovery sentinel",
        `${kind}: recovered exact snapshot contents`,
      );
    }
    const logs = await run(["docker", "logs", workerId]);
    assert(
      !logs.stdout.includes(keys.secretAccessKey) && !logs.stderr.includes(password),
      "worker logs contain no credentials",
    );
  } catch (error) {
    if (workerId) {
      const diagnostics = await run(
        ["docker", "exec", workerId, "sh", "-c", "cat /tmp/ark-restic-*.stderr"],
        { allowFailure: true },
      );
      const logs = await run(["docker", "logs", "--tail", "40", workerId], { allowFailure: true });
      console.error(`Deployed worker diagnostics: ${logs.stdout} ${logs.stderr}`);
      console.error(`Deployed restic diagnostics: ${diagnostics.stdout.slice(-6000)}`);
    }
    throw error;
  } finally {
    releaseBackup();
    releaseUpload();
    if (workerId) await run(["docker", "rm", "--force", workerId], { allowFailure: true });
    if (sourceCreated) {
      const volume = await run(["docker", "volume", "inspect", sourceVolume], { allowFailure: true });
      if (volume.status === 0 && JSON.parse(volume.stdout)[0].Labels?.["ark.worker-smoke"] === c.project)
        await run(["docker", "volume", "rm", sourceVolume], { allowFailure: true });
    }
    api.stop(true);
    storage.stop(true);
    executor.stop(true);
    await sql`DELETE FROM backup_targets WHERE name IN ('worker-stalled', 'worker-healthy')`;
    if (enabled.length)
      await sql`UPDATE backup_targets SET enabled=true WHERE id IN ${sql(enabled.map((row) => row.id))}`;
    for (const network of [`${c.project}_test-monitoring`, `${c.project}_test-mail-management`]) {
      const inspected = await run(["docker", "network", "inspect", network], { allowFailure: true });
      if (
        inspected.status === 0 &&
        JSON.parse(inspected.stdout)[0].Labels?.["com.docker.compose.project"] === c.project
      )
        await run(["docker", "network", "rm", network], { allowFailure: true });
    }
    await run(["docker", "image", "rm", `ark-backup-worker:${c.version}`], { allowFailure: true });
  }
}
