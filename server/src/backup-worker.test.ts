// Exercise the actual worker entry point and coordinator through the internal claim API.
import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve as resolvePath } from "node:path";
import { eq, inArray } from "drizzle-orm";
import { MockLocalApi } from "./mock-localapi.ts";
import { db, sql } from "./db.ts";
import { backupTargets, operations, secrets } from "./schema.ts";
import { app } from "./app.ts";
import { enqueue } from "./coordinator.ts";
import { saveS3Target } from "./modules/offsite-backups.ts";
import { observeBackupTailnet } from "./modules/backup-observe.ts";
import { mockStatusDocument } from "./mock-localapi.ts";

async function waitFor(predicate: () => Promise<boolean> | boolean) {
  const deadline = Date.now() + 12_000;
  while (!(await predicate())) {
    if (Date.now() >= deadline) throw new Error("deployed worker did not make progress");
    await Bun.sleep(30);
  }
}

test("two blocked verification jobs cannot starve a due backup observation", async () => {
  const work = await mkdtemp(join(tmpdir(), "ark-worker-lanes-"));
  const local = new MockLocalApi({
    backendState: "Running",
    suffix: ".tail-worker.ts.net",
    self: { id: "nBACKUPLANES", name: "ark-backup", ips: ["100.64.9.1"], tags: ["tag:ark-backup"] },
    peers: [],
    reachable: new Set(),
  });
  const socket = await local.listen(join(work, "tailscaled.sock"));
  await observeBackupTailnet({
    api: { status: async () => mockStatusDocument(local.state) },
    validityMs: 12_000,
  });
  const [before] = await sql`SELECT generation, valid_until FROM tailnet_snapshots WHERE source='backup'`;
  const blocked = new Set<string>();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const storage = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      blocked.add(new URL(request.url).pathname.split("/")[1]!);
      await gate;
      return new Response("AccessDenied", { status: 403 });
    },
  });
  const ids: string[] = [];
  const jobs: string[] = [];
  const api = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      if (new URL(request.url).pathname === "/api/internal/jobs") {
        const prefixes = request.headers.get("x-ark-worker-kinds")?.split(",") ?? [];
        const rows = jobs.length
          ? await db.select().from(operations).where(inArray(operations.id, jobs))
          : [];
        if (
          !rows.some(
            (row) => row.status === "queued" && prefixes.some((prefix) => row.kind.startsWith(prefix)),
          )
        ) {
          return Response.json({ jobs: [] });
        }
      }
      return app.fetch(request);
    },
  });
  let worker: Bun.Subprocess<"ignore", "pipe", "pipe"> | undefined;
  let output: Promise<string> | undefined;
  try {
    for (const bucket of ["lane-one", "lane-two"]) {
      const target = await saveS3Target({
        name: bucket,
        provider: "minio",
        endpoint: storage.url.origin,
        region: "us-east-1",
        bucket,
        prefix: "ark",
        pathStyle: true,
        recoveryWindowDays: 1,
        accessKeyId: "fixture-access-key",
        secretAccessKey: "fixture-secret-key",
        repositoryPassword: "fixture-repository-password-0123456789",
      });
      ids.push(target.id);
      const job = await enqueue({
        kind: "backup.verify_target",
        targetIds: [target.id],
        payload: { revision: target.configRevision },
      });
      jobs.push(job.id);
      // Keep these jobs ahead of unrelated fixtures left by other unit files.
      await db
        .update(operations)
        .set({ createdAt: new Date(0) })
        .where(eq(operations.id, job.id));
    }
    worker = Bun.spawn(
      [process.execPath, "--no-env-file", resolvePath(import.meta.dir, "../../workers/src/backup.ts")],
      {
        env: {
          ...process.env,
          ARK_API_URL: api.url.origin,
          ARK_WORKER_TOKEN: process.env.ARK_BACKUP_WORKER_TOKEN!,
          ARK_BACKUP_SCHEDULE: "0",
          ARK_BACKUP_TS_SOCKET: socket,
          ARK_RUNTIME_ROLE: "worker",
        },
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    output = new Response(worker.stderr).text();
    await waitFor(() => blocked.size === 2);
    const observation = await enqueue({
      kind: "backup.observe",
      targetIds: ["tailnet:backup"],
      payload: { nonce: work },
    });
    jobs.push(observation.id);
    await db
      .update(operations)
      .set({ createdAt: new Date(0) })
      .where(eq(operations.id, observation.id));
    await waitFor(async () => {
      const [row] = await db.select().from(operations).where(eq(operations.id, observation.id));
      if (row?.status === "failed") throw new Error(row.error ?? "observation failed");
      return row?.status === "succeeded";
    });
    const [after] = await sql`SELECT generation, valid_until FROM tailnet_snapshots WHERE source='backup'`;
    expect(after!.generation).not.toBe(before!.generation);
    expect(new Date(after!.valid_until).getTime()).toBeGreaterThan(new Date(before!.valid_until).getTime());
    expect(Date.now()).toBeLessThan(new Date(before!.valid_until).getTime());
    const canaries = await db
      .select()
      .from(operations)
      .where(inArray(operations.id, jobs.slice(0, 2)));
    expect(canaries.map((row) => row.status)).toEqual(["running", "running"]);
    expect(blocked.size).toBe(2);
  } catch (error) {
    worker?.kill("SIGKILL");
    await worker?.exited;
    throw new Error(`${(error as Error).message}\n${(await output) ?? ""}`, { cause: error });
  } finally {
    worker?.kill("SIGKILL");
    await worker?.exited;
    release();
    api.stop(true);
    storage.stop(true);
    local.stop();
    if (jobs.length)
      await db
        .update(operations)
        .set({ status: "failed", claimToken: null })
        .where(inArray(operations.id, jobs));
    if (ids.length) {
      const targets = await db.select().from(backupTargets).where(inArray(backupTargets.id, ids));
      await db.delete(backupTargets).where(inArray(backupTargets.id, ids));
      await db.delete(secrets).where(
        inArray(
          secrets.id,
          targets.flatMap((target) => [target.credentialSecretId, target.repositorySecretId!]),
        ),
      );
    }
    await rm(work, { recursive: true, force: true });
  }
}, 20_000);
