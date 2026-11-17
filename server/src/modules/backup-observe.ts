// backup-ts observer, home-target pinning and the transfer watchdog (docs/design/front-door.md
// §3.18.3, FD-30).
//
// - `backup.observe` (backup worker, every five minutes) reads **backup-ts's own** LocalAPI status
//   through `ark_backup_ts_socket`, mounted read-only into the backup worker only, and commits a
//   complete `source = 'backup'` generation with a six-minute lease. The edge snapshot, the edge
//   socket and edge grants are never used: route reach and backup reach never share an identity.
// - A `tailnet_rest` target is pinned like a route (§3.2): StableNodeID plus one Tailscale address,
//   both taken from the backup generation when the target is saved. Every observation re-validates
//   the pin; an address change for the same identity is followed, a replaced or absent identity or an
//   expired observation is not.
// - `guardTransfer` is the local watchdog: while a REST transfer runs it re-checks identity and
//   freshness every second and aborts the restic subprocess as soon as either fails, so active
//   transfers stop within `TRANSFER_STOP_BOUND_MS` without waiting for the next scheduled backup or
//   any manual step.
import {
  BACKUP_OBSERVE_INTERVAL_MS,
  TRANSFER_GUARD_INTERVAL_MS,
  createId,
  leaseValidityMs,
  parseLocalApiStatus,
  redactValue,
  restUrlTarget,
  revalidateRouteTarget,
  tailnetSuffixOf,
  tailnetRestUrlSchema,
  validateRouteTarget,
} from "@ark-stack/shared";
import { and, desc, eq } from "drizzle-orm";

import { db } from "../db.ts";
import { auditEvents, backupTargets, operations } from "../schema.ts";
import { readLocalApiStatus } from "./tailnet-localapi.ts";
import {
  commitTailnetGeneration,
  loadTailnetSnapshot,
  snapshotLeaseValid,
  type LoadedSnapshot,
} from "./tailnet-snapshot.ts";

export const BACKUP_OBSERVE_TARGET = "tailnet:backup";

/** backup-ts's LocalAPI, read-only: status only (no dial, no writes). */
export type BackupLocalApi = { status(): Promise<unknown> };

export function backupSocketPath(env: Record<string, string | undefined> = process.env) {
  return env.ARK_BACKUP_TS_SOCKET?.trim() || null;
}

export function backupLocalApi(socket: string): BackupLocalApi {
  return { status: () => readLocalApiStatus(socket) };
}

type Enqueue = (input: {
  kind: "backup.observe";
  targetIds: string[];
  payload?: Record<string, unknown>;
}) => Promise<unknown>;

export function loadBackupSnapshot() {
  return loadTailnetSnapshot("backup");
}

export type TailnetIdentity =
  | { ok: true; stableId: string; ip: string; ipChanged: boolean }
  | {
      ok: false;
      status: "observation_expired" | "identity_mismatch" | "awaiting_acl" | "error";
      reason: string;
      message: string;
    };

type PinnedTarget = Pick<
  typeof backupTargets.$inferSelect,
  "id" | "name" | "kind" | "restUrl" | "targetNodeStableId" | "targetIp"
>;

/**
 * Checks a pinned home target against backup-ts's own latest generation (§3.2 rule 6 with
 * `source = 'backup'`): the lease must be valid, the pinned StableNodeID present, and the URL's name
 * (if it is a name) must still identify that same node.
 */
export function checkTailnetIdentity(
  target: PinnedTarget,
  loaded: LoadedSnapshot,
  now: Date,
): TailnetIdentity {
  if (target.kind !== "tailnet_rest" || !target.restUrl || !target.targetNodeStableId || !target.targetIp) {
    return {
      ok: false,
      status: "error",
      reason: "not_pinned",
      message: "The target is not a pinned tailnet target.",
    };
  }
  if (!tailnetRestUrlSchema.safeParse(target.restUrl).success) {
    return {
      ok: false,
      status: "error",
      reason: "unsupported_transport",
      message: "Home REST targets require http:// over the encrypted tailnet.",
    };
  }
  const check = revalidateRouteTarget({
    route: {
      targetInput: restUrlTarget(target.restUrl).host,
      targetNodeStableId: target.targetNodeStableId,
      targetIp: target.targetIp,
    },
    peers: loaded.peers,
    snapshot: loaded.snapshot,
    self: loaded.self,
    now,
    tailnetSuffix: loaded.self ? tailnetSuffixOf(loaded.self) : "",
    source: "backup",
  });
  if (check.ok) return check;
  const message =
    check.status === "observation_expired"
      ? `backup-ts's tailnet observation is missing or expired (${check.message})`
      : check.status === "awaiting_acl"
        ? "the pinned home machine is not in backup-ts's current tailnet view"
        : check.message;
  return { ...check, message };
}

/** The identity of one target now, read fresh from the database (the watchdog's per-tick check). */
export async function currentTailnetIdentity(targetId: string, now = new Date()): Promise<TailnetIdentity> {
  const [target] = await db.select().from(backupTargets).where(eq(backupTargets.id, targetId));
  if (!target)
    return { ok: false, status: "error", reason: "missing", message: "The backup target was removed." };
  if (!target.enabled)
    return { ok: false, status: "error", reason: "disabled", message: "The backup target is disabled." };
  // The pinned address only moves with an observation; guardTransfer compares it with the address
  // the transfer started with.
  return checkTailnetIdentity(target, await loadBackupSnapshot(), now);
}

/**
 * Pins a new home target from backup-ts's current generation (§3.2 rules 1-5, `source = 'backup'`):
 * the URL's host must be exactly one observed peer, not backup-ts itself and not an Ark-tagged node.
 */
export async function pinTailnetTarget(restUrl: string, now = new Date()) {
  const loaded = await loadBackupSnapshot();
  const { host, port } = restUrlTarget(restUrl);
  const result = validateRouteTarget({
    target: host,
    port,
    peers: loaded.peers,
    snapshot: loaded.snapshot,
    self: loaded.self,
    now,
    tailnetSuffix: loaded.self ? tailnetSuffixOf(loaded.self) : "",
    source: "backup",
  });
  if (!result.ok) {
    const hint =
      result.reason === "snapshot_incomplete" || result.reason === "snapshot_expired"
        ? " Make sure backup-ts is logged in (tag:ark-backup), then observe the backup tailnet again."
        : result.reason === "peer_not_found"
          ? " Check that the home machine is online and that the tag:ark-backup grant from Front door ACL is in the tailnet policy."
          : "";
    throw new Error(`${result.message}${hint}`);
  }
  return { stableId: result.stableId, ip: result.ip };
}

async function audit(
  action: string,
  targetId: string,
  detail: Record<string, unknown>,
  operationId?: string,
) {
  await db.insert(auditEvents).values({
    id: createId("aud"),
    action,
    resourceType: "backup_target",
    resourceId: targetId,
    operationId,
    detail: redactValue(detail) as Record<string, unknown>,
  });
}

/**
 * One `backup.observe` run. Throws on a failed or partial observation (the lease is not renewed and
 * the stored generation is untouched, so it expires and suspends transfers). On success every home
 * target is re-validated; a new address for the same identity replaces the pinned one.
 */
export async function observeBackupTailnet(input: {
  api: BackupLocalApi;
  now?: () => Date;
  operationId?: string;
  validityMs?: number;
}) {
  const clock = input.now ?? (() => new Date());
  const startedAt = clock();
  const generation = createId("gen");
  let parsed: ReturnType<typeof parseLocalApiStatus>;
  try {
    parsed = parseLocalApiStatus(await input.api.status(), { generation, source: "backup" });
  } catch (error) {
    parsed = { ok: false, reason: `LocalAPI status could not be read: ${(error as Error).message}` };
  }
  if (!parsed.ok) throw new Error(`Backup observation failed; the lease was not renewed. ${parsed.reason}`);
  if (!parsed.self.tags.includes("tag:ark-backup")) {
    // Not fatal for the lease (a node may be tagged later), but surfaced: grants are keyed on the tag.
    await audit(
      "backup.tailnet.untagged",
      BACKUP_OBSERVE_TARGET,
      { tags: parsed.self.tags },
      input.operationId,
    );
  }
  const validUntil = new Date(
    startedAt.getTime() + (input.validityMs ?? leaseValidityMs(process.env, "backup")),
  );
  await commitTailnetGeneration("backup", {
    generation,
    self: parsed.self,
    peers: parsed.peers,
    completedAt: startedAt,
    validUntil,
  });
  const loaded = await loadBackupSnapshot();
  const now = clock();
  const targets = await db.select().from(backupTargets).where(eq(backupTargets.kind, "tailnet_rest"));
  const outcomes = [];
  for (const target of targets) {
    const identity = checkTailnetIdentity(target, loaded, now);
    if (identity.ok && identity.ipChanged) {
      const changed = await db
        .update(backupTargets)
        .set({ targetIp: identity.ip, updatedAt: now })
        .where(
          and(
            eq(backupTargets.id, target.id),
            eq(backupTargets.configRevision, target.configRevision),
            eq(backupTargets.targetNodeStableId, identity.stableId),
          ),
        )
        .returning({ id: backupTargets.id });
      if (changed.length)
        await audit(
          "backup.target_ip_changed",
          target.id,
          { stableId: identity.stableId, from: target.targetIp, to: identity.ip },
          input.operationId,
        );
    }
    outcomes.push({
      id: target.id,
      name: target.name,
      identity: identity.ok ? (identity.ipChanged ? "ip_changed" : "ok") : identity.status,
      message: identity.ok ? null : identity.message,
    });
  }
  return {
    generation,
    completedAt: startedAt.toISOString(),
    validUntil: validUntil.toISOString(),
    self: { stableId: parsed.self.stableId, dnsName: parsed.self.dnsName, tags: parsed.self.tags },
    peers: parsed.peers.length,
    targets: outcomes,
  };
}

export type TransferGuard = {
  signal: AbortSignal;
  /** Why the transfer was stopped, once it was. */
  reason: () => string | null;
  stop: () => void;
};

/**
 * The local transfer watchdog (§3.18.3): checks the target's identity and backup-ts's lease every
 * `intervalMs` (never slower than a second) and at the instant the lease runs out, and aborts the
 * signal on the first failure. The restic runner kills its subprocess on abort.
 */
export function guardTransfer(
  targetId: string,
  options: {
    /** The address the transfer dials; a re-pinned address stops it too. */
    pinnedIp?: string;
    intervalMs?: number;
    now?: () => Date;
    onStop?: (reason: string) => void;
    /** Injectable control read for deterministic deadline tests. */
    readState?: () => Promise<{ identity: TailnetIdentity; validUntil: Date | null }>;
  } = {},
): TransferGuard {
  const controller = new AbortController();
  const clock = options.now ?? (() => new Date());
  const intervalMs = Math.min(options.intervalMs ?? TRANSFER_GUARD_INTERVAL_MS, TRANSFER_GUARD_INTERVAL_MS);
  let stopped: string | null = null;
  let disposed = false;
  let expiryTimer: ReturnType<typeof setTimeout> | undefined;
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  let running = false;
  const readState =
    options.readState ??
    (async () => {
      const [target] = await db.select().from(backupTargets).where(eq(backupTargets.id, targetId));
      const loaded = await loadBackupSnapshot();
      return {
        identity: target?.enabled
          ? checkTailnetIdentity(target, loaded, clock())
          : {
              ok: false as const,
              status: "error" as const,
              reason: "missing",
              message: "Backup target not found.",
            },
        validUntil: loaded.row?.validUntil ?? null,
      };
    });
  const abort = (reason: string) => {
    if (disposed || stopped) return;
    stopped = reason;
    clearInterval(timer);
    clearTimeout(expiryTimer);
    clearTimeout(deadlineTimer);
    controller.abort(new Error(reason));
    options.onStop?.(reason);
  };
  const check = async () => {
    if (running || disposed || stopped) return;
    running = true;
    // Independent of the query promise: 1 s polling + 1.5 s read budget + 2 s kill grace < 5 s.
    deadlineTimer = setTimeout(() => abort("Transfer stopped: the identity check timed out"), 1_500);
    try {
      const { identity, validUntil } = await readState();
      if (disposed || stopped) return;
      if (!identity.ok) return abort(`Transfer stopped: ${identity.message}`);
      if (options.pinnedIp && identity.ip !== options.pinnedIp)
        return abort(`Transfer stopped: the home machine's address changed to ${identity.ip}`);
      const remaining = (validUntil?.getTime() ?? 0) - clock().getTime();
      if (remaining <= 0) return abort("Transfer stopped: the backup observation expired");
      // Expiry aborts directly, even while a subsequent database read is hung.
      clearTimeout(expiryTimer);
      expiryTimer = setTimeout(() => abort("Transfer stopped: the backup observation expired"), remaining);
    } catch (error) {
      abort(`Transfer stopped: the identity check failed (${(error as Error).message})`);
    } finally {
      clearTimeout(deadlineTimer);
      running = false;
    }
  };
  const timer = setInterval(() => void check(), intervalMs);
  void check();
  return {
    signal: controller.signal,
    reason: () => stopped,
    stop: () => {
      disposed = true;
      clearInterval(timer);
      clearTimeout(expiryTimer);
      clearTimeout(deadlineTimer);
    },
  };
}

function publicNode(item: {
  stableId: string;
  dnsName: string;
  hostName: string;
  ipv4: string | null;
  ipv6: string | null;
  tags: string[];
  online: boolean | null;
}) {
  return {
    stableId: item.stableId,
    dnsName: item.dnsName,
    hostName: item.hostName,
    ipv4: item.ipv4,
    ipv6: item.ipv6,
    tags: item.tags,
    online: item.online,
  };
}

/** `GET /api/backups/tailnet`: backup-ts's latest generation and every home target's identity. */
export async function backupTailnetOverview(now = new Date()) {
  const loaded = await loadBackupSnapshot();
  const [lastRun] = await db
    .select({
      id: operations.id,
      status: operations.status,
      error: operations.error,
      updatedAt: operations.updatedAt,
    })
    .from(operations)
    .where(eq(operations.kind, "backup.observe"))
    .orderBy(desc(operations.createdAt))
    .limit(1);
  const targets = await db.select().from(backupTargets).where(eq(backupTargets.kind, "tailnet_rest"));
  return {
    generation: loaded.row
      ? {
          id: loaded.row.generation,
          completedAt: loaded.row.completedAt.toISOString(),
          validUntil: loaded.row.validUntil.toISOString(),
          leaseValid: snapshotLeaseValid(loaded, now),
        }
      : null,
    self: loaded.self ? publicNode(loaded.self) : null,
    tailnetSuffix: loaded.self ? tailnetSuffixOf(loaded.self) : null,
    peers: loaded.peers.map(publicNode).toSorted((a, b) => a.dnsName.localeCompare(b.dnsName)),
    lastObservation: lastRun
      ? {
          operationId: lastRun.id,
          status: lastRun.status,
          error: lastRun.error,
          at: lastRun.updatedAt.toISOString(),
        }
      : null,
    targets: targets.map((target) => {
      const identity = checkTailnetIdentity(target, loaded, now);
      return {
        id: target.id,
        name: target.name,
        restUrl: target.restUrl,
        pinned: { stableId: target.targetNodeStableId, ip: target.targetIp },
        identity: identity.ok ? (identity.ipChanged ? "ip_changed" : "ok") : identity.status,
        identityMessage: identity.ok ? null : identity.message,
      };
    }),
  };
}

/**
 * Enqueues `backup.observe` now and every five minutes. Run by the backup worker when backup-ts's
 * socket is mounted (and by the embedded coordinator in development); a queued or running
 * observation is reused.
 */
export function startBackupObserveSchedule(input: {
  enqueue: Enqueue;
  intervalMs?: number;
  log?: (line: string) => void;
}) {
  const run = () =>
    void input
      .enqueue({ kind: "backup.observe", targetIds: [BACKUP_OBSERVE_TARGET] })
      .catch((error: Error) => input.log?.(`backup.observe could not be scheduled: ${error.message}`));
  run();
  return setInterval(run, input.intervalMs ?? BACKUP_OBSERVE_INTERVAL_MS);
}
