import { EdgeWatchdog, type WatchdogOptions } from "@ark-stack/shared";

/** One independently scheduled proxy. A stalled adapter cannot delay another proxy's heartbeat. */
export class ProxyWatchdog {
  readonly watchdog: EdgeWatchdog;
  lastVerifiedAt = Number.NEGATIVE_INFINITY;
  lastTick: { at: string; withdrawn: string[]; errors: string[] } | null = null;

  constructor(options: WatchdogOptions) {
    this.watchdog = new EdgeWatchdog(options);
  }

  healthy(now = performance.now()) {
    return now - this.lastVerifiedAt <= 2_000;
  }

  async tick() {
    try {
      const results = await this.watchdog.tick(300);
      // An unreachable proxy is never verified, not even while it restarts after a deliberate stop.
      this.lastVerifiedAt = results.some((result) => result.error || result.unreachable)
        ? Number.NEGATIVE_INFINITY
        : performance.now();
      this.lastTick = {
        at: new Date().toISOString(),
        withdrawn: results.flatMap((result) => result.withdrawn),
        errors: results.flatMap((result) => (result.error ? [`${result.proxy}: ${result.error}`] : [])),
      };
    } catch (error) {
      this.lastVerifiedAt = Number.NEGATIVE_INFINITY;
      throw error;
    }
  }
}
