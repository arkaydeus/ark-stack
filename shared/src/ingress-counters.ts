// Named host nftables counters exposed by /api/metrics/prometheus (§3.11).
export const DB_INGRESS_TABLE = "ark_db_ingress";
export const DB_INGRESS_LIMITS_CHAIN = "ark_db_limits";
export const FRONT_TABLE = "ark_front";
export const FRONT_SHARED_CHAIN = "shared_limits";
export const FRONT_DEDICATED_CHAIN = "dedicated_ports";

function limitCounters(chain: string) {
  return {
    drop_conn4: { chain, reason: "concurrent", family: "ipv4" },
    drop_conn6: { chain, reason: "concurrent", family: "ipv6" },
    drop_rate4: { chain, reason: "rate", family: "ipv4" },
    drop_rate6: { chain, reason: "rate", family: "ipv6" },
  };
}

export const DB_INGRESS_COUNTERS = limitCounters(DB_INGRESS_LIMITS_CHAIN);
export const FRONT_COUNTERS = {
  ...limitCounters(FRONT_SHARED_CHAIN),
  drop_dedicated_conn4: { chain: FRONT_DEDICATED_CHAIN, reason: "concurrent", family: "ipv4" },
  drop_dedicated_conn6: { chain: FRONT_DEDICATED_CHAIN, reason: "concurrent", family: "ipv6" },
  drop_dedicated_rate4: { chain: FRONT_DEDICATED_CHAIN, reason: "rate", family: "ipv4" },
  drop_dedicated_rate6: { chain: FRONT_DEDICATED_CHAIN, reason: "rate", family: "ipv6" },
  drop_closed: { chain: FRONT_DEDICATED_CHAIN, reason: "closed", family: "any" },
  drop_allowlist: { chain: FRONT_DEDICATED_CHAIN, reason: "allowlist", family: "any" },
};

type CounterLabels = { chain: string; reason: string; family: string };
type IngressTable = typeof DB_INGRESS_TABLE | typeof FRONT_TABLE;
const counterLabels: Record<IngressTable, Record<string, CounterLabels>> = {
  [DB_INGRESS_TABLE]: DB_INGRESS_COUNTERS,
  [FRONT_TABLE]: FRONT_COUNTERS,
};

export type IngressCounterSnapshot = {
  table: IngressTable;
  observedAt: string;
  counters: { name: string; packets: number; bytes: number }[];
};

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** Filter nft's JSON to the named counters in the requested table. */
export function parseNftCounters(
  json: string,
  observedAt = new Date(),
  table: IngressTable = DB_INGRESS_TABLE,
): IngressCounterSnapshot {
  const parsed = JSON.parse(json) as { nftables?: Array<Record<string, unknown>> };
  const counters: IngressCounterSnapshot["counters"] = [];
  for (const item of parsed.nftables ?? []) {
    const counter = item.counter as Record<string, unknown> | undefined;
    if (!counter || counter.table !== table || counter.family !== "inet") continue;
    if (typeof counter.name !== "string" || !Object.hasOwn(counterLabels[table], counter.name)) continue;
    if (!isCount(counter.packets) || !isCount(counter.bytes)) continue;
    counters.push({ name: counter.name, packets: counter.packets, bytes: counter.bytes });
  }
  return { table, observedAt: observedAt.toISOString(), counters };
}

/** Keep the FD-18 snapshot at the root. The reconciler adds the front table under `front`. */
export function ingressCounterMetrics(snapshot: unknown, now = new Date()) {
  const value = snapshot as (IngressCounterSnapshot & { front?: IngressCounterSnapshot }) | null;
  const present: string[] = [];
  const age: string[] = [];
  const drops: string[] = [];
  for (const [table, data] of [
    [DB_INGRESS_TABLE, value],
    [FRONT_TABLE, value?.front],
  ] as const) {
    const observedAt = typeof data?.observedAt === "string" ? Date.parse(data.observedAt) : Number.NaN;
    const valid = data?.table === table && Array.isArray(data.counters) && !Number.isNaN(observedAt);
    present.push(`ark_nft_counters_present{table="${table}"} ${valid ? 1 : 0}`);
    if (!valid) continue;
    age.push(
      `ark_nft_counters_age_seconds{table="${table}"} ${Math.max(0, Math.round((now.getTime() - observedAt) / 1000))}`,
    );
    const seen = new Set<string>();
    for (const sample of data.counters) {
      if (typeof sample?.name !== "string" || !isCount(sample.packets) || seen.has(sample.name)) continue;
      if (!Object.hasOwn(counterLabels[table], sample.name)) continue;
      const labels = counterLabels[table][sample.name]!;
      seen.add(sample.name);
      drops.push(
        `ark_nft_drop_packets_total{table="${table}",chain="${labels.chain}",reason="${labels.reason}",family="${labels.family}"} ${sample.packets}`,
      );
    }
  }
  return [
    "# HELP ark_nft_counters_present Whether the host nftables counter snapshot was readable.",
    "# TYPE ark_nft_counters_present gauge",
    ...present,
    "# HELP ark_nft_counters_age_seconds Age of the host nftables counter snapshot.",
    "# TYPE ark_nft_counters_age_seconds gauge",
    ...age,
    "# HELP ark_nft_drop_packets_total Packets dropped by Ark's nftables rules, by table, chain and reason.",
    "# TYPE ark_nft_drop_packets_total counter",
    ...drops,
  ];
}
