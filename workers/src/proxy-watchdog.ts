import { EdgeWatchdog, type WatchdogOptions } from "@ark-stack/shared";

/** A verified pass is fresh for this long; the launch guard stops the proxy after two misses. */
export const VERIFIED_FRESH_MS = 2_000;
/** Enforcement freshness plus guard polling/transport/kill must fit the five-second deadline.
 * A busy pass has 3 s from its observation start; the guard reserves at most 1.5 s to stop it.
 * Caddy keeps the original freshness window and does not inherit the L4 grace.
 */
export const PASS_BUDGET_MS = 3_000;

/** One independently scheduled proxy. A stalled adapter cannot delay another proxy's heartbeat. */
export class ProxyWatchdog {
  readonly watchdog: EdgeWatchdog;
  lastVerifiedAt = Number.NEGATIVE_INFINITY;
  /** Start of the pass in progress, or null between passes. */
  passStartedAt: number | null = null;
  lastTick: { at: string; withdrawn: string[]; errors: string[] } | null = null;

  private readonly extendPass: boolean;

  constructor(options: WatchdogOptions) {
    this.extendPass = options.adapters.some((adapter) => adapter.proxy === "haproxy");
    this.watchdog = new EdgeWatchdog(options);
  }

  healthy(now = performance.now()) {
    if (now - this.lastVerifiedAt <= VERIFIED_FRESH_MS) return true;
    // A pass still inside the withdrawal budget that began while the proxy was verified. A failed or
    // unverifiable pass resets `lastVerifiedAt`, so it never extends itself; a wedged pass expires.
    return (
      this.extendPass &&
      this.passStartedAt !== null &&
      this.passStartedAt - this.lastVerifiedAt <= VERIFIED_FRESH_MS &&
      now - this.lastVerifiedAt <= PASS_BUDGET_MS
    );
  }

  async tick() {
    this.passStartedAt = performance.now();
    try {
      const results = await this.watchdog.tick(300);
      // An unreachable proxy is never verified, not even while it restarts after a deliberate stop.
      this.lastVerifiedAt = results.some((result) => result.error || result.unreachable)
        ? Number.NEGATIVE_INFINITY
        : this.passStartedAt;
      this.lastTick = {
        at: new Date().toISOString(),
        withdrawn: results.flatMap((result) => result.withdrawn),
        errors: results.flatMap((result) => (result.error ? [`${result.proxy}: ${result.error}`] : [])),
      };
    } catch (error) {
      this.lastVerifiedAt = Number.NEGATIVE_INFINITY;
      throw error;
    } finally {
      this.passStartedAt = null;
    }
  }
}
