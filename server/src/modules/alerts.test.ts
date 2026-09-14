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

  test("keeps older failed operations unresolved once more than 100 have failed", async () => {
    const oldest = createId("op");
    await db.insert(operations).values({
      id: oldest,
      kind: "backup.create",
      status: "failed",
      idempotencyKey: `fail-${oldest}`,
      planHash: "x",
      targetIds: ["t"],
      payload: {},
    });
    await evaluateAlerts();
    await db
      .update(operations)
      .set({ updatedAt: new Date(Date.now() - 86_400_000) })
      .where(eq(operations.id, oldest));
    for (let index = 0; index < 100; index++) {
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
    }
    await evaluateAlerts();
    await evaluateAlerts();
    const [row] = await db
      .select()
      .from(alerts)
      .where(eq(alerts.dedupKey, `op-failed:${oldest}`));
    expect(row).toBeDefined();
    expect(row?.resolvedAt).toBeNull();
  });

  test("failed webhook deliveries do not consume the retry budget", async () => {
    const previous = process.env.ARK_ALERT_WEBHOOK;
    const originalFetch = globalThis.fetch;
    let calls = 0;
    process.env.ARK_ALERT_WEBHOOK = "http://127.0.0.1:9/alerts";
    globalThis.fetch = (async () => {
      calls += 1;
      if (calls < 5) return new Response("down", { status: 503 });
      return new Response("ok", { status: 200 });
    }) as unknown as typeof fetch;
    const key = `op-failed:${createId("op")}`;
    try {
      const first = await raiseAlert({ severity: "critical", title: "Operation failed", dedupKey: key });
      expect(first.notificationAttempts).toBe(0);
      expect(first.lastNotifiedAt).toBeNull();
      for (let index = 0; index < 3; index++) {
        await raiseAlert({ severity: "critical", title: "Operation failed", dedupKey: key });
      }
      const [afterFailures] = await db.select().from(alerts).where(eq(alerts.dedupKey, key));
      expect(afterFailures?.notificationAttempts).toBe(0);
      expect(afterFailures?.lastNotifiedAt).toBeNull();
      await raiseAlert({ severity: "critical", title: "Operation failed", dedupKey: key });
      const [success] = await db.select().from(alerts).where(eq(alerts.dedupKey, key));
      expect(success?.notificationAttempts).toBe(1);
      expect(success?.lastNotifiedAt).toBeInstanceOf(Date);
      expect(calls).toBe(5);
    } finally {
      globalThis.fetch = originalFetch;
      if (previous === undefined) delete process.env.ARK_ALERT_WEBHOOK;
      else process.env.ARK_ALERT_WEBHOOK = previous;
    }
  });
});
