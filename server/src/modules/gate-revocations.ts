// Gate revocation journal (docs/design/front-door.md §3.9.3, FD-11).
//
// Upgraded connections (WebSockets) are never re-checked by `forward_auth`, so revoking a user's
// authorization must also end the connections they already hold. Every revocation (access removal,
// user deletion, session deletion or sign-out, logout everywhere, MFA reset, route logout, a mode
// change and tightening a route's gate) writes a `gate_revocations` row and queues a forced-reload
// `edge.drain` in the revoking transaction. The SQL side lives in migrations 0026 and 0028: the
// `ark_gate_revoke` function and triggers on `gate_sessions`, `front_route_access` and the MFA
// fields on `user`, so a revocation made by Better Auth, a cascade or a script is journalled exactly like one made here.
//
// - The drain snapshots pending rows, fences and drains the affected HAProxy backends before
//   and after a forced Caddy load, then marks those rows applied. A queued apply restores Caddy
//   handlers and HAProxy admission after the watchdog has enforced the applied journal revision.
// - Claims retry pending work with exponential backoff from 10 s to 5 min.
// - A row pending longer than 5 s takes its route out of the watchdog lease. The watchdog
//   fences the backend and closes its existing sessions, and the API raises a critical alert.

import {
  GATE_REVOCATION_DEADLINE_MS,
  routesAfterRevocations,
  sha256Hex,
  type EdgeLeaseDocument,
  type EdgeWatchdogHealth,
  type PendingGateRevocation,
} from "@ark-stack/shared";

import { sql } from "../db.ts";
import { raiseAlert } from "./alerts.ts";
import { edgePolicy } from "./edge-observe.ts";

export const GATE_REVOCATION_ALERT = "gate-revocation-overdue";

/** Read the pending revocations and the latest applied revision from a single database snapshot. */
export async function gateRevocationState() {
  const rows = await sql`
    SELECT id, route_id, created_at, false AS applied FROM gate_revocations
    WHERE applied_at IS NULL
    UNION ALL (
      SELECT id, route_id, created_at, true AS applied FROM gate_revocations
      WHERE applied_at IS NOT NULL ORDER BY applied_at DESC, id DESC LIMIT 1
    )
    ORDER BY created_at
  `;
  const latest = rows.find((row) => row.applied);
  return {
    revision: latest ? sha256Hex(String(latest.id)) : null,
    pending: rows
      .filter((row) => !row.applied)
      .map((row): PendingGateRevocation => ({
        id: String(row.id),
        routeId: String(row.route_id),
        createdAt: new Date(row.created_at as string).toISOString(),
      })),
  };
}

/** Wait until neither proxy can be working on an allowlist that predates this drain. */
export async function waitForGateRecovery(revision: string, watchdogUrl: string, scoped: boolean) {
  const url = new URL("/v1/health", watchdogUrl);
  const deadline = performance.now() + 10_000;
  const proxies = scoped ? ["caddy", "haproxy"] : ["caddy"];
  for (let remaining = 10_000; remaining > 0; remaining = Math.floor(deadline - performance.now())) {
    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(Math.min(1_000, remaining)),
      });
      if (response.ok) {
        const health = (await response.json()) as EdgeWatchdogHealth;
        if (
          proxies.every((name) => {
            const pass = health.proxies?.[name]?.lastTick;
            return pass?.verified && pass.policy?.leaseValid && pass.policy.gateRecovery === revision;
          })
        )
          return;
      }
    } catch {
      // A restarted or temporarily unavailable watchdog must acknowledge the revision before admission.
    }
    await Bun.sleep(Math.max(0, Math.min(100, deadline - performance.now())));
  }
  throw new Error("The edge watchdog did not verify the applied gate revocation policy.");
}

/** Marks revocations applied after the affected sessions have closed and Caddy has loaded. */
export async function markGateRevocationsApplied(ids: string[], appliedBy: string) {
  if (!ids.length) return 0;
  const rows = await sql`
    UPDATE gate_revocations SET applied_at = now(), applied_by = ${appliedBy}
    WHERE id = ANY(${ids}::text[]) AND applied_at IS NULL
    RETURNING id
  `;
  return rows.length;
}

/**
 * Durable retry: queue a forced-reload drain whenever revocations are pending and no drain is in
 * flight (a failed drain, or one lost with its worker). Called before every claim; failures back off
 * from 10 seconds to 5 minutes while the independent 5-second withdrawal deadline stays in force.
 */
export async function ensureGateRevocationDrain() {
  const [row] = await sql`SELECT ark_gate_ensure_drain() AS id`;
  return row?.id ? String(row.id) : null;
}

/**
 * `GET /api/internal/edge/lease`: the lease policy (FD-06) minus routes with an overdue gate
 * revocation. Overdue revocations raise one critical alert each time a new one passes its deadline.
 */
export async function edgeLeaseDocument(now = new Date()): Promise<EdgeLeaseDocument> {
  const policy = await edgePolicy(now);
  const { pending, revision } = await gateRevocationState();
  const { routes, overdue } = routesAfterRevocations(policy.routes, pending, now);
  if (overdue.length) {
    const late = await sql`
      UPDATE gate_revocations SET alerted_at = now()
      WHERE applied_at IS NULL AND alerted_at IS NULL
        AND created_at < ${new Date(now.getTime() - GATE_REVOCATION_DEADLINE_MS).toISOString()}::timestamptz
      RETURNING route_id
    `;
    if (late.length) {
      await raiseAlert({
        severity: "critical",
        title: `Gate revocation not applied within 5 s; the edge withdrew route(s) ${[...new Set(late.map((row) => String(row.route_id)))].join(", ")} until the drain and config load succeed`,
        dedupKey: GATE_REVOCATION_ALERT,
      }).catch(() => undefined);
    }
  }
  return {
    ...policy,
    routes,
    gateRecovery: revision,
    revocations: pending.map((item) => ({
      ...item,
      overdue: overdue.includes(item.routeId),
    })),
  };
}
