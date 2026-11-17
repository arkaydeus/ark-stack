/** Invalid or out-of-range deployment settings use the safe production defaults. */
export function watchdogConfig(env: Record<string, string | undefined>) {
  const integer = (name: string, fallback: number, min: number, max: number) => {
    const value = Number(env[name]);
    return env[name]?.trim() && Number.isInteger(value) && value >= min && value <= max ? value : fallback;
  };
  return {
    intervalMs: integer("ARK_EDGE_WATCHDOG_INTERVAL_MS", 1_000, 100, 1_000),
    staleMs: integer("ARK_EDGE_WATCHDOG_STALE_MS", 5_000, 500, 5_000),
    port: integer("ARK_EDGE_WATCHDOG_PORT", 2021, 1, 65535),
  };
}
