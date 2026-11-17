import { redactLogLine, redactValue } from "@ark-stack/shared";

export type WorkerJob = {
  id: string;
  kind: string;
  status: string;
  claimToken: string;
  targetIds: string[];
  payload: Record<string, unknown>;
  error: string | null;
  planHash: string;
  actorId: string | null;
  idempotencyKey: string;
  createdAt: string | Date;
  updatedAt: string | Date;
  heartbeatAt: string | Date | null;
  [key: string]: unknown;
};

function config() {
  const token = process.env.ARK_WORKER_TOKEN ?? process.env.ARK_INTERNAL_TOKEN;
  const base = process.env.ARK_API_URL ?? "http://api:3000";
  if (!token) throw new Error("ARK_WORKER_TOKEN is required for workers.");
  return { token, base };
}

export async function poll(prefixes: string[]) {
  const { token, base } = config();
  const heartbeat = await fetch(`${base}/api/internal/heartbeat`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ version: "ts-worker-v1" }),
  });
  if (!heartbeat.ok) throw new Error(`Worker heartbeat failed: ${heartbeat.status}`);
  const response = await fetch(`${base}/api/internal/jobs`, {
    headers: {
      authorization: `Bearer ${token}`,
      "x-ark-worker-kinds": prefixes.join(","),
    },
  });
  if (!response.ok) throw new Error(`Worker poll failed: ${response.status}`);
  const body = (await response.json()) as { jobs: WorkerJob[] };
  return body.jobs;
}

async function post(job: WorkerJob, suffix: "heartbeat" | "complete", body: Record<string, unknown>) {
  const { token, base } = config();
  const response = await fetch(`${base}/api/internal/jobs/${job.id}/${suffix}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`Worker ${suffix} failed: ${response.status}`);
}

export async function executeOne(
  job: WorkerJob,
  executor: (job: WorkerJob) => Promise<void | { complete: boolean; evidence?: Record<string, unknown> }>,
) {
  let heartbeatFailed = false;
  let mutationCompleted = false;
  const heartbeat = setInterval(() => {
    void post(job, "heartbeat", { claimToken: job.claimToken }).catch(() => {
      heartbeatFailed = true;
    });
  }, 15_000);
  try {
    const outcome = await executor(job);
    if (outcome && !outcome.complete) return;
    if (heartbeatFailed) throw new Error("Worker lease heartbeat failed during execution.");
    mutationCompleted = true;
    await post(job, "complete", {
      status: "succeeded",
      claimToken: job.claimToken,
      evidence: redactValue({
        worker: process.env.ARK_WORKER_NAME ?? "module",
        contractVersion: 1,
        ...outcome?.evidence,
      }),
    });
  } catch (error) {
    if (mutationCompleted) {
      throw new Error(
        `needs_recovery: worker completion failed after a mutation: ${error instanceof Error ? error.message : "unknown"}`,
        { cause: error },
      );
    }
    const message = redactLogLine(error instanceof Error ? error.message : "Worker execution failed.");
    await post(job, "complete", {
      status: "failed",
      claimToken: job.claimToken,
      error: message.slice(0, 1000),
      evidence: redactValue({ worker: process.env.ARK_WORKER_NAME ?? "module", contractVersion: 1 }),
    });
  } finally {
    clearInterval(heartbeat);
  }
}

export async function runWorker(
  name: string,
  prefixes: string[],
  executor: (job: WorkerJob) => Promise<void | { complete: boolean; evidence?: Record<string, unknown> }>,
  options: { concurrency?: number; signal?: AbortSignal; pollMs?: number } = {},
) {
  process.env.ARK_WORKER_NAME = name;
  let stopped = false;
  const stop = () => {
    stopped = true;
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  const running = new Set<Promise<void>>();
  const concurrency = Math.max(1, Math.min(16, options.concurrency ?? 1));
  while (true) {
    if (stopped || options.signal?.aborted) break;
    try {
      if (running.size < concurrency) {
        for (const job of await poll(prefixes)) {
          const task = executeOne(job, executor)
            .catch((error) => {
              console.error(redactLogLine(error instanceof Error ? error.message : "worker job failed"));
            })
            .finally(() => running.delete(task));
          running.add(task);
        }
      }
    } catch (error) {
      console.error(redactLogLine(error instanceof Error ? error.message : "worker tick failed"));
    }
    await Bun.sleep(options.pollMs ?? 2_000);
  }
  await Promise.allSettled(running);
  process.off("SIGTERM", stop);
  process.off("SIGINT", stop);
}
