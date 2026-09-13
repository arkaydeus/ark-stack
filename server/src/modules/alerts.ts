import { createId } from "@ark-stack/shared";
import { and, eq } from "drizzle-orm";

import { db } from "../db.ts";
import { alerts, backups, certificates, operations } from "../schema.ts";

export async function raiseAlert(input: {
  severity: "warning" | "critical" | "info";
  title: string;
  dedupKey: string;
}) {
  const existing = await db
    .select()
    .from(alerts)
    .where(and(eq(alerts.dedupKey, input.dedupKey), eq(alerts.acknowledged, false)));
  if (existing[0]) return existing[0];
  const [row] = await db
    .insert(alerts)
    .values({
      id: createId("alt"),
      severity: input.severity,
      title: input.title,
      dedupKey: input.dedupKey,
    })
    .returning();
  await notifyExternal(input.title, input.severity);
  return row;
}

export async function evaluateAlerts() {
  const failed = await db.select().from(operations).where(eq(operations.status, "failed"));
  for (const operation of failed.slice(0, 20)) {
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
      Date.now() - item.createdAt.getTime() > 36 * 60 * 60 * 1000 && item.status !== "restore_verified",
  );
  if (stale.length) {
    await raiseAlert({
      severity: "warning",
      title: "Backup freshness or restore proof is stale",
      dedupKey: "backup-stale",
    });
  }
}

async function notifyExternal(title: string, severity: string) {
  const webhook = process.env.ARK_ALERT_WEBHOOK;
  if (!webhook) return;
  await fetch(webhook, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ title, severity, source: "ark-stack" }),
  }).catch(() => undefined);
}
