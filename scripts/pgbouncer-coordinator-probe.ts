// Live FD-28 coordinator/scheduler regression. The admin socket and PgBouncer are real;
// only the host ingress peer is simulated, acknowledging exact policy bytes after a delay.
import { createHash } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { createId } from "@ark-stack/shared";

import { queueDailyRollover, runOperation, startRolloverScheduler } from "../server/src/coordinator.ts";
import { sql } from "../server/src/db.ts";

const spec = JSON.parse(await Bun.file(process.argv[2]!).text()) as {
  certificateId: string;
  databaseId: string;
};
const dir = process.env.ARK_PGBOUNCER_DIR!;
let acknowledgements = 0;
let watching = false;
let previous = "";
let stopScheduler: (() => void) | undefined;
const watchdog: string[] = [];
// Remember only the job inserted by this probe, so cleanup never removes a pre-existing daily
// operation and the scheduler cannot leave a global queue row behind its database fixture.
const daily = await queueDailyRollover(new Date());
const startedAt = new Date().toISOString();
// A separate peer emulates the host ingress reconciler, including policy-hash matching. The
// coordinator must await this exchange; it cannot use the development bypass. (Since FD-26 there
// is no exposure toggle: whether PgBouncer is reachable on 5432 is the edge's be_pgbouncer.)
const watcher = setInterval(() => {
  if (watching) return;
  watching = true;
  void (async () => {
    const rules = await readFile(join(dir, "allowlist.nft"), "utf8").catch(() => "");
    if (!rules || (previous === rules && (await Bun.file(join(dir, "allowlist.status")).exists()))) return;
    await Bun.sleep(150);
    await writeFile(
      join(dir, "allowlist.status"),
      `policy_hash=${createHash("sha256").update(rules).digest("hex")}\napplied=true\n`,
    );
    previous = rules;
    acknowledgements++;
  })().finally(() => {
    watching = false;
  });
}, 20);
try {
  const id = createId("op");
  const [operation] =
    await sql`INSERT INTO operations (id, kind, target_ids, payload, idempotency_key, plan_hash, status)
    VALUES (${id}, 'pgbouncer.reload', ${JSON.stringify([spec.databaseId])}::jsonb, '{}'::jsonb, ${id}, 'live-probe', 'running') RETURNING *`;
  await runOperation("pgbouncer.reload", {
    ...operation!,
    id,
    kind: "pgbouncer.reload",
    status: "running",
    actorId: null,
    idempotencyKey: id,
    planHash: "live-probe",
    targetIds: [spec.databaseId],
    payload: {},
    createdAt: new Date(),
    updatedAt: new Date(),
  } as Parameters<typeof runOperation>[1]);
  await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${id}`;
  // Require a fresh peer response during retirement as well as the initial reload.
  await rm(join(dir, "allowlist.status"), { force: true });
  stopScheduler = startRolloverScheduler(50, {
    watchdog: {
      fence: async () => {
        watchdog.push("fence");
        throw Error("Unexpected missed live drain deadline");
      },
      stop: async () => {
        watchdog.push("stop");
        throw Error("Unexpected missed live drain deadline");
      },
      fenceListener: async () => {
        watchdog.push("listener");
        throw Error("Unexpected missed live drain deadline");
      },
    },
  });
  const timeout = Date.now() + 120_000;
  for (;;) {
    const [task] =
      await sql`SELECT * FROM client_certificate_retirements WHERE certificate_id = ${spec.certificateId}`;
    if (task?.completed_at) {
      if (task.deadline_missed || watchdog.length || acknowledgements < 2)
        throw Error(`Coordinator acceptance failed: ${JSON.stringify({ task, watchdog, acknowledgements })}`);
      const [step] =
        await sql`SELECT evidence FROM operation_steps WHERE operation_id = ${id} AND name = 'pgbouncer-reload'`;
      if (!step?.evidence.applied || !step.evidence.reloaded)
        throw Error("Production reload did not await ingress acknowledgement");
      console.log(
        JSON.stringify({
          ok: true,
          acknowledgements,
          watchdog,
          fencedAt: new Date(task.fenced_at).getTime(),
          reloadedAt: new Date(task.reloaded_at).getTime(),
          drainedAt: new Date(task.drained_at).getTime(),
          reopenedAt: new Date(task.reopened_at).getTime(),
          deadline: new Date(task.deadline).getTime(),
        }),
      );
      break;
    }
    if (Date.now() > timeout) throw Error(`Coordinator retirement did not complete: ${JSON.stringify(task)}`);
    await Bun.sleep(25);
  }
} finally {
  stopScheduler?.();
  clearInterval(watcher);
  for (let attempt = 0; attempt < 100; attempt++) {
    if (!watching) break;
    await Bun.sleep(5);
  }
  if (daily) await sql`DELETE FROM operations WHERE id = ${daily.id}`;
  // pgbouncer.reload queues edge.l4_apply for the domain worker (FD-26); none runs here.
  await sql`DELETE FROM operations WHERE kind = 'edge.l4_apply' AND status = 'queued'
    AND created_at >= ${startedAt}::timestamptz`;
  await sql.end({ timeout: 2 });
}
