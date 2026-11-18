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
// - The drain (and any `edge.apply`) snapshots the pending rows, forces a Caddy `/load` with
//   `Cache-Control: must-revalidate` even for identical text, and marks the rows applied only after
//   it succeeded. The old handlers close their upgraded connections after `stream_close_delay`,
//   which is at most 5m on an SSO route, so every socket is gone by revocation + 305 s.
// - A failed or interrupted drain leaves the rows pending. `ensureGateRevocationDrain` re-queues the
//   work on claims with exponential backoff (10 s to 5 min), so it survives worker restarts and failures.
// - A row pending for more than 5 s takes its route out of the lease the edge-local watchdog
//   enforces (`edgeLeaseDocument`): the watchdog withdraws it (zero stream-close delay, or a Caddy
//   stop when the old handler keeps streams open) and a critical alert is raised. The route comes
//   back once a forced reload has applied the revocation.

import {
  GATE_REVOCATION_DEADLINE_MS,
  routesAfterRevocations,
  type EdgeLeaseDocument,
  type PendingGateRevocation,
} from "@ark-stack/shared";

import { sql } from "../db.ts";
import { raiseAlert } from "./alerts.ts";
import { edgePolicy } from "./edge-observe.ts";

export const GATE_REVOCATION_ALERT = "gate-revocation-overdue";

/** Revocations whose forced reload has not succeeded yet, oldest first. */
export async function pendingGateRevocations(): Promise<PendingGateRevocation[]> {
  const rows = await sql`
    SELECT id, route_id, created_at FROM gate_revocations
    WHERE applied_at IS NULL
    ORDER BY created_at
  `;
  return rows.map((row) => ({
    id: String(row.id),
    routeId: String(row.route_id),
    createdAt: new Date(row.created_at as string).toISOString(),
  }));
}

/** Marks revocations applied by a forced reload that began after they committed. */
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
  const pending = await pendingGateRevocations();
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
        title: `Gate revocation not applied within 5 s; the edge withdrew route(s) ${[...new Set(late.map((row) => String(row.route_id)))].join(", ")} until a forced reload succeeds`,
        dedupKey: GATE_REVOCATION_ALERT,
      }).catch(() => undefined);
    }
  }
  return {
    ...policy,
    routes,
    revocations: pending.map((item) => ({
      ...item,
      overdue: overdue.includes(item.routeId),
    })),
  };
}
