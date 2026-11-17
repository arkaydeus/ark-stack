import { describe, expect, test } from "bun:test";

import { redactLogLine } from "@ark-stack/shared";

import { executeOne, type WorkerJob } from "./runtime.ts";

describe("worker log redaction", () => {
  test("strips canary secrets and control characters", () => {
    expect(redactLogLine("password=super-secret\u0007", ["super-secret"])).toBe("password=<redacted>");
  });
});

describe("worker completion fence", () => {
  test("treats a failed complete after a mutation as needs_recovery", async () => {
    const previousUrl = process.env.ARK_API_URL;
    const previousToken = process.env.ARK_WORKER_TOKEN;
    process.env.ARK_API_URL = "http://127.0.0.1:9";
    process.env.ARK_WORKER_TOKEN = "worker-token";
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { status?: string };
      if (body.status === "succeeded") return new Response("conflict", { status: 409 });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }) as typeof fetch;
    const job = {
      id: "op_1",
      kind: "backup.create",
      status: "running",
      claimToken: "claim",
      targetIds: ["t"],
      payload: {},
      error: null,
      planHash: "x",
      actorId: null,
      idempotencyKey: "k",
      createdAt: new Date(),
      updatedAt: new Date(),
      heartbeatAt: new Date(),
    } satisfies WorkerJob;
    try {
      await expect(executeOne(job, async () => undefined)).rejects.toThrow(/needs_recovery/);
    } finally {
      globalThis.fetch = originalFetch;
      if (previousUrl === undefined) delete process.env.ARK_API_URL;
      else process.env.ARK_API_URL = previousUrl;
      if (previousToken === undefined) delete process.env.ARK_WORKER_TOKEN;
      else process.env.ARK_WORKER_TOKEN = previousToken;
    }
  });
});

test("actual worker loop keeps healthy exports running during a blocked upload", async () => {
  const { runWorker } = await import("./runtime.ts");
  const previous = { url: process.env.ARK_API_URL, token: process.env.ARK_WORKER_TOKEN };
  const controller = new AbortController();
  const completed: string[] = [];
  let claimed = 0;
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const api = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const path = new URL(request.url).pathname;
      if (path.endsWith("/jobs")) {
        const id = claimed++;
        return Response.json({
          jobs:
            id < 4
              ? [{ id: String(id), kind: "backup.export", claimToken: "token", targetIds: [String(id)] }]
              : [],
        });
      }
      if (path.endsWith("/complete")) completed.push(path.split("/").at(-2)!);
      return Response.json({ ok: true });
    },
  });
  process.env.ARK_API_URL = `http://127.0.0.1:${api.port}`;
  process.env.ARK_WORKER_TOKEN = "token";
  const running = runWorker(
    "backup",
    ["backup.export"],
    async (job) => {
      if (job.id === "0") await blocked;
    },
    { concurrency: 2, pollMs: 1, signal: controller.signal },
  );
  try {
    const deadline = Date.now() + 3000;
    while (completed.length < 3 && Date.now() < deadline) await Bun.sleep(10);
    expect(completed).toEqual(["1", "2", "3"]);
    expect(completed).not.toContain("0");
  } finally {
    controller.abort();
    release();
    await running;
    api.stop(true);
    if (previous.url === undefined) delete process.env.ARK_API_URL;
    else process.env.ARK_API_URL = previous.url;
    if (previous.token === undefined) delete process.env.ARK_WORKER_TOKEN;
    else process.env.ARK_WORKER_TOKEN = previous.token;
  }
});
