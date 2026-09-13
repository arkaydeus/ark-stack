import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";

import { parseEnvFile } from "@ark-stack/shared";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { evaluateAlerts, raiseAlert } = await import("./alerts.ts");
const { db } = await import("../db.ts");
const { alerts, operations } = await import("../schema.ts");
const { createId } = await import("@ark-stack/shared");
const { eq } = await import("drizzle-orm");

describe("alert acknowledgement", () => {
  test("does not re-raise or re-notify an acknowledged condition", async () => {
    const key = `op-failed:${createId("op")}`;
    const first = await raiseAlert({ severity: "warning", title: "Operation failed", dedupKey: key });
    await db.update(alerts).set({ acknowledged: true }).where(eq(alerts.id, first.id));
    const calls: string[] = [];
    const previous = process.env.ARK_ALERT_WEBHOOK;
    process.env.ARK_ALERT_WEBHOOK = "http://127.0.0.1:9/missing";
    try {
      await raiseAlert({ severity: "warning", title: "Operation failed", dedupKey: key });
      await evaluateAlerts();
      const rows = await db.select().from(alerts).where(eq(alerts.dedupKey, key));
      expect(rows).toHaveLength(1);
      expect(rows[0]?.acknowledged).toBe(true);
      expect(calls).toHaveLength(0);
    } finally {
      if (previous === undefined) delete process.env.ARK_ALERT_WEBHOOK;
      else process.env.ARK_ALERT_WEBHOOK = previous;
    }
  });

  test("evaluateAlerts does not insert a second row for a failed operation", async () => {
    const id = createId("op");
    await db.insert(operations).values({
      id,
      kind: "backup.create",
      status: "failed",
      idempotencyKey: `fail-${id}`,
      planHash: "x",
      targetIds: ["t"],
      payload: {},
    });
    await evaluateAlerts();
    await evaluateAlerts();
    const rows = await db
      .select()
      .from(alerts)
      .where(eq(alerts.dedupKey, `op-failed:${id}`));
    expect(rows).toHaveLength(1);
  });
});
