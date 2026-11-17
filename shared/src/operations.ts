export const operationStates = [
  "queued",
  "awaiting_approval",
  "running",
  "waiting_external",
  "succeeded",
  "failed",
  "cancelled",
  "needs_recovery",
] as const;

export type OperationState = (typeof operationStates)[number];

const allowed: Record<OperationState, OperationState[]> = {
  queued: ["awaiting_approval", "running", "cancelled"],
  awaiting_approval: ["queued", "cancelled"],
  running: ["waiting_external", "succeeded", "failed", "cancelled", "needs_recovery"],
  waiting_external: ["running", "cancelled", "failed"],
  succeeded: [],
  failed: ["queued"],
  cancelled: [],
  needs_recovery: ["queued", "cancelled"],
};

export function canTransition(from: OperationState, to: OperationState) {
  return allowed[from].includes(to);
}

export function transition(from: OperationState, to: OperationState) {
  if (!canTransition(from, to)) {
    throw new Error(`Operation cannot move from ${from} to ${to}.`);
  }
  return to;
}

export function isTerminal(state: OperationState) {
  return state === "succeeded" || state === "cancelled";
}

export function isInFlight(state: string) {
  return (
    state === "queued" || state === "running" || state === "awaiting_approval" || state === "waiting_external"
  );
}

export function staleObservation(observedAt: Date | null, now = new Date(), maxAgeMs = 90_000) {
  if (!observedAt) return true;
  return now.getTime() - observedAt.getTime() > maxAgeMs;
}

export type OperationKind =
  | "domain.verify"
  | "certificate.issue"
  | "certificate.renew"
  | "database.provision"
  | "database.rotate"
  | "database.query"
  | "database.schema"
  | "mail.provision"
  | "mail.reconcile"
  | "service.deploy"
  | "service.start"
  | "service.stop"
  | "service.restart"
  | "service.logs"
  | "service.stats"
  | "service.discover"
  | "backup.create"
  | "backup.restore_test"
  | "backup.export"
  | "update.apply"
  | "update.detect"
  | "admin.mode_change"
  | "dns.publish"
  | "ses.reconcile"
  | "pgbouncer.reload"
  | "edge.apply"
  | "edge.observe"
  | "edge.l4_apply"
  | "edge.drain"
  | "domain.ipv6_preflight"
  | "integration.vercel_push"
  | "database.client_issue"
  | "database.client_rollover"
  | "database.client_retire"
  | "database.client_revoke"
  | "backup.observe"
  | "backup.verify_target"
  | "import.scan"
  | "service.adopt"
  | "mail.queue_retry"
  | "mail.queue_delete"
  | "mailbox.device"
  | "platform.maintain";
