import { createId } from "@ark-stack/shared";
import { and, desc, eq, isNull, ne } from "drizzle-orm";

import { db } from "../db.ts";
import { alerts, backups, certificates, operations } from "../schema.ts";

const SEVERITY_RANK: Record<string, number> = { info: 0, warning: 1, critical: 2 };

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
    if (row.severity !== input.severity || row.title !== input.title) {
      // An open alert keeps its identity while its severity moves (the FD-28 rollover alert goes
      // info → warning → critical). An escalation is news: clear the acknowledgement and the
      // notification throttle so it is delivered again.
      const escalated = (SEVERITY_RANK[input.severity] ?? 0) > (SEVERITY_RANK[row.severity] ?? 0);
      const [updated] = await db
        .update(alerts)
        .set({
          severity: input.severity,
          title: input.title,
          ...(escalated ? { acknowledged: false, lastNotifiedAt: null, notificationAttempts: 0 } : {}),
        })
        .where(eq(alerts.id, row.id))
        .returning();
      if (updated) await maybeNotify(updated);
      return updated ?? row;
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
  const delivered = await notifyExternal(row.title, row.severity);
  if (!delivered) return;
  await db
    .update(alerts)
    .set({
      lastNotifiedAt: now,
      notificationAttempts: row.notificationAttempts + 1,
    })
    .where(eq(alerts.id, row.id));
}

/** Resolve every open alert with exactly this dedup key. */
export async function resolveAlert(dedupKey: string, at = new Date()) {
  await db
    .update(alerts)
    .set({ resolvedAt: at })
    .where(and(eq(alerts.dedupKey, dedupKey), isNull(alerts.resolvedAt)));
}

export async function evaluateAlerts() {
  // The per-client Vercel alert spans retries and resolves after either delivery path succeeds.
  const vercelPushKind = "integration.vercel_push";
  const activeKeys = new Set<string>();
  const failed = await db
    .select()
    .from(operations)
    .where(and(eq(operations.status, "failed"), ne(operations.kind, vercelPushKind)))
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
  // Renewal inserts a new row per endpoint and keeps the old ones, so only the newest
  // certificate for each endpoint describes what is actually served. Alerting on superseded
  // rows would make the alert permanent from the first renewal onwards.
  // A renewal still `awaiting_reload` (database endpoint, §3.14) is not served yet, so the
  // previous certificate's expiry keeps alerting until PgBouncer confirms the new one.
  const certs = (await db.select().from(certificates)).filter((cert) => cert.status !== "awaiting_reload");
  const current = new Map<string, (typeof certs)[number]>();
  for (const cert of certs) {
    const held = current.get(cert.endpointId);
    if (!held || (cert.expiresAt?.getTime() ?? 0) > (held.expiresAt?.getTime() ?? 0)) {
      current.set(cert.endpointId, cert);
    }
  }
  const soon = Date.now() + 14 * 24 * 60 * 60 * 1000;
  for (const cert of current.values()) {
    if (cert.expiresAt && cert.expiresAt.getTime() < soon) {
      activeKeys.add(`cert:${cert.id}`);
      await raiseAlert({
        severity: "critical",
        title: `Certificate for ${cert.names.join(", ")} expires soon`,
        dedupKey: `cert:${cert.id}`,
      });
    }
  }
  // Freshness is a property of a backup target, not of every row ever written for it: an old
  // backup is expected once a newer one exists.
  const recentBackups = await db.select().from(backups);
  const newestPerTarget = new Map<string, (typeof recentBackups)[number]>();
  for (const item of recentBackups) {
    // A `local` PostgreSQL backup has not left the VPS yet (FD-21), so it is not freshness evidence.
    if (item.status === "failed" || item.status === "planned" || item.status === "local") continue;
    const key = `${item.kind}:${item.targetId}`;
    const held = newestPerTarget.get(key);
    if (!held || item.createdAt.getTime() > held.createdAt.getTime()) newestPerTarget.set(key, item);
  }
  const stale = [...newestPerTarget.values()].filter(
    (item) => Date.now() - item.createdAt.getTime() > 36 * 60 * 60 * 1000,
  );
  if (stale.length) {
    activeKeys.add("backup-stale");
    await raiseAlert({
      severity: "warning",
      title: "Backup freshness or restore proof is stale",
      dedupKey: "backup-stale",
    });
  }
  // Per-target and per-source off-VPS backup alerts (FD-21, front door §3.18.4). Imported lazily:
  // offsite-backups raises its alerts through this module.
  await import("./offsite-backups.ts")
    .then((module) => module.evaluateBackupAlerts())
    .catch((error: Error) => console.error(`backup alert evaluation failed: ${error.message}`));
  const managedAlerts = await db.select().from(alerts).where(isNull(alerts.resolvedAt));
  for (const alert of managedAlerts) {
    if (alert.dedupKey.startsWith("op-failed:")) {
      const operationId = alert.dedupKey.slice("op-failed:".length);
      const [operation] = await db.select().from(operations).where(eq(operations.id, operationId));
      if (!operation || operation.status !== "failed" || operation.kind === vercelPushKind) {
        await db.update(alerts).set({ resolvedAt: new Date() }).where(eq(alerts.id, alert.id));
      }
      continue;
    }
    if (
      (alert.dedupKey.startsWith("cert:") || alert.dedupKey === "backup-stale") &&
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
    signal: AbortSignal.timeout(10_000),
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ title, severity, source: "ark-stack" }),
  })
    .then((response) => response.ok)
    .catch(() => false);
}
