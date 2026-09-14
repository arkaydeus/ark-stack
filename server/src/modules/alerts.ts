import { createId } from "@ark-stack/shared";
import { desc, eq, isNull } from "drizzle-orm";

import { db } from "../db.ts";
import { alerts, backups, certificates, operations } from "../schema.ts";

export async function raiseAlert(input: {
  severity: "warning" | "critical" | "info";
  title: string;
  dedupKey: string;
}) {
  const existing = await db.select().from(alerts).where(eq(alerts.dedupKey, input.dedupKey));
  if (existing[0]) {
    const row = existing[0];
    if (row.resolvedAt) {
      const [reopened] = await db
        .update(alerts)
        .set({ resolvedAt: null, acknowledged: false, severity: input.severity, title: input.title })
        .where(eq(alerts.id, row.id))
        .returning();
      if (reopened) await maybeNotify(reopened);
      return reopened ?? row;
    }
    await maybeNotify(row);
    return row;
  }
  const [row] = await db
    .insert(alerts)
    .values({
      id: createId("alt"),
      severity: input.severity,
      title: input.title,
      dedupKey: input.dedupKey,
    })
    .onConflictDoNothing({ target: alerts.dedupKey })
    .returning();
  if (!row) return existing[0];
  await maybeNotify(row);
  return row;
}

async function maybeNotify(row: typeof alerts.$inferSelect) {
  const now = new Date();
  if (
    row.acknowledged ||
    row.resolvedAt ||
    (row.silencedUntil && row.silencedUntil > now) ||
    row.notificationAttempts >= 5 ||
    (row.lastNotifiedAt && now.getTime() - row.lastNotifiedAt.getTime() < 5 * 60_000)
  ) {
    return;
  }
  await notifyExternal(row.title, row.severity);
  await db
    .update(alerts)
    .set({
      lastNotifiedAt: now,
      notificationAttempts: row.notificationAttempts + 1,
    })
    .where(eq(alerts.id, row.id));
}

export async function evaluateAlerts() {
  const activeKeys = new Set<string>();
  const failed = await db
    .select()
    .from(operations)
    .where(eq(operations.status, "failed"))
    .orderBy(desc(operations.updatedAt))
    .limit(100);
  for (const operation of failed) {
    activeKeys.add(`op-failed:${operation.id}`);
    await raiseAlert({
      severity: "warning",
      title: `Operation ${operation.kind} failed`,
      dedupKey: `op-failed:${operation.id}`,
    });
  }
  const certs = await db.select().from(certificates);
  const soon = Date.now() + 14 * 24 * 60 * 60 * 1000;
  for (const cert of certs) {
    if (cert.expiresAt && cert.expiresAt.getTime() < soon) {
      activeKeys.add(`cert:${cert.id}`);
      await raiseAlert({
        severity: "critical",
        title: `Certificate for ${cert.names.join(", ")} expires soon`,
        dedupKey: `cert:${cert.id}`,
      });
    }
  }
  const recentBackups = await db.select().from(backups);
  const stale = recentBackups.filter(
    (item) =>
      Date.now() - item.createdAt.getTime() > 36 * 60 * 60 * 1000 &&
      item.status !== "restore_verified" &&
      !item.restoreVerified,
  );
  if (stale.length) {
    activeKeys.add("backup-stale");
    await raiseAlert({
      severity: "warning",
      title: "Backup freshness or restore proof is stale",
      dedupKey: "backup-stale",
    });
  }
  const managedAlerts = await db.select().from(alerts).where(isNull(alerts.resolvedAt));
  for (const alert of managedAlerts) {
    if (
      (alert.dedupKey.startsWith("op-failed:") ||
        alert.dedupKey.startsWith("cert:") ||
        alert.dedupKey === "backup-stale") &&
      !activeKeys.has(alert.dedupKey)
    ) {
      await db.update(alerts).set({ resolvedAt: new Date() }).where(eq(alerts.id, alert.id));
    }
  }
}

export async function notifyExternal(title: string, severity: string) {
  const webhook = process.env.ARK_ALERT_WEBHOOK;
  if (!webhook) return false;
  return fetch(webhook, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ title, severity, source: "ark-stack" }),
  })
    .then((response) => response.ok)
    .catch(() => false);
}
