import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { eq } from "drizzle-orm";

import { createId, parseEnvFile } from "@ark-stack/shared";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { db } = await import("./db.ts");
const { operations } = await import("./schema.ts");

describe("internal worker boundary", () => {
  test("agent token cannot complete a non-service operation", async () => {
    const id = createId("op");
    await db.insert(operations).values({
      id,
      kind: "backup.restore_test",
      status: "running",
      idempotencyKey: `test-${id}`,
      planHash: "x",
      targetIds: ["t1"],
      payload: {},
    });
    const response = await app.request(`/api/internal/jobs/${id}/complete`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${process.env.ARK_AGENT_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ status: "succeeded" }),
    });
    expect(response.status).toBe(403);
    const [row] = await db.select().from(operations).where(eq(operations.id, id));
    expect(row?.status).toBe("running");
  });
});
