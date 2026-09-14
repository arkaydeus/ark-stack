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
