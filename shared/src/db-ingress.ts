// The public database port's nftables policy (docs/design/front-door.md §3.11, FD-18).
//
// `inet ark_db_ingress` matches TCP 5432 on both the `input` hook (a host-namespace listener,
// today's `database-ingress` proxy) and the `forward` hook (Docker DNAT to a published port, the
// FD-26 Postgres router), so the same rules hold before and after that change. It carries:
//
// - the per-database CIDR allowlist, until FD-26 moves it into HAProxy's `be_pgbouncer`;
// - per-source limits: a concurrent-connection cap (`ct count`) and a new-connection rate
//   (`limit rate`). IPv4 sources are keyed per address and IPv6 sources per /64, so a client
//   cannot dodge the limits by rotating through its own /64.
//
// Every drop has a named counter. The host-namespace reconciler reads them back and the API
// exports them on `/api/metrics/prometheus` as `ark_nft_drop_packets_total`.
import { z } from "zod";

import { parseCidr } from "./cidr.ts";

export const DB_INGRESS_TABLE = "ark_db_ingress";
export const DB_INGRESS_LIMITS_CHAIN = "ark_db_limits";
export const DB_INGRESS_ALLOW_CHAIN = "ark_db_allow";

/**
 * §3.11 defaults. Vercel egress comes from shared AWS addresses, so many function instances can
 * share one source IP; the defaults are deliberately generous.
 */
export const DB_INGRESS_LIMIT_DEFAULTS = {
  maxConnectionsPerSource: 128,
  newConnectionsPerSecond: 30,
  newConnectionBurst: 60,
} as const;

/** Bounds the API, the database CHECKs (0016) and the renderer all enforce. */
export const DB_INGRESS_LIMIT_BOUNDS = {
  maxConnectionsPerSource: { min: 1, max: 65_535 },
  newConnectionsPerSecond: { min: 1, max: 10_000 },
  newConnectionBurst: { min: 1, max: 100_000 },
} as const;

export type DbIngressLimits = {
  maxConnectionsPerSource: number;
  newConnectionsPerSecond: number;
  newConnectionBurst: number;
};

function bounded(name: keyof DbIngressLimits, label: string) {
  const { min, max } = DB_INGRESS_LIMIT_BOUNDS[name];
  return z
    .number()
    .int(`${label} must be a whole number.`)
    .min(min, `${label} must be at least ${min}.`)
    .max(max, `${label} must be at most ${max}.`);
}

export const dbIngressLimitsInput = z
  .object({
    maxConnectionsPerSource: bounded("maxConnectionsPerSource", "Concurrent connections per source"),
    newConnectionsPerSecond: bounded("newConnectionsPerSecond", "New connections per second"),
    newConnectionBurst: bounded("newConnectionBurst", "New-connection burst"),
  })
  .strict()
  .refine((value) => value.newConnectionBurst >= value.newConnectionsPerSecond, {
    message: "The new-connection burst must be at least the per-second rate.",
    path: ["newConnectionBurst"],
  });

function withinBounds(name: keyof DbIngressLimits, value: unknown) {
  const { min, max } = DB_INGRESS_LIMIT_BOUNDS[name];
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
}

/**
 * The effective limits for a platform settings row. Missing or out-of-range values (an older
 * schema, a hand-edited row) fall back to the safe defaults one field at a time, so the policy is
 * always renderable and never silently unlimited.
 */
export function dbIngressLimits(
  settings: Partial<Record<keyof DbIngressLimits, number | null | undefined>> | null | undefined,
): DbIngressLimits {
  const pick = (name: keyof DbIngressLimits) =>
    withinBounds(name, settings?.[name]) ? (settings?.[name] as number) : DB_INGRESS_LIMIT_DEFAULTS[name];
  const newConnectionsPerSecond = pick("newConnectionsPerSecond");
  return {
    maxConnectionsPerSource: pick("maxConnectionsPerSource"),
    newConnectionsPerSecond,
    // A burst below the rate would never let a full second's worth through.
    newConnectionBurst: Math.max(pick("newConnectionBurst"), newConnectionsPerSecond),
  };
}

/** The effective limits for a `platform_settings` row (columns from 0016). */
export function platformDbIngressLimits(
  settings:
    | {
        dbIngressMaxConnections?: number | null;
        dbIngressRatePerSecond?: number | null;
        dbIngressRateBurst?: number | null;
      }
    | null
    | undefined,
) {
  return dbIngressLimits({
    maxConnectionsPerSource: settings?.dbIngressMaxConnections,
    newConnectionsPerSecond: settings?.dbIngressRatePerSecond,
    newConnectionBurst: settings?.dbIngressRateBurst,
  });
}

/** What the API reports for the setting: the effective limits, the defaults and the bounds. */
export function dbIngressLimitsSummary(settings: Parameters<typeof platformDbIngressLimits>[0]) {
  return {
    ...platformDbIngressLimits(settings),
    defaults: { ...DB_INGRESS_LIMIT_DEFAULTS },
    bounds: DB_INGRESS_LIMIT_BOUNDS,
    ipv6Grouping: "/64" as const,
    port: 5432,
  };
}

/**
 * Named counters in the table, one per drop rule. `reason` and `family` become metric labels.
 * The allowlist counter exists only while an allowlist is rendered.
 */
export const DB_INGRESS_COUNTERS = {
  drop_conn4: { chain: DB_INGRESS_LIMITS_CHAIN, reason: "concurrent", family: "ipv4" },
  drop_conn6: { chain: DB_INGRESS_LIMITS_CHAIN, reason: "concurrent", family: "ipv6" },
  drop_rate4: { chain: DB_INGRESS_LIMITS_CHAIN, reason: "rate", family: "ipv4" },
  drop_rate6: { chain: DB_INGRESS_LIMITS_CHAIN, reason: "rate", family: "ipv6" },
  drop_allowlist: { chain: DB_INGRESS_ALLOW_CHAIN, reason: "allowlist", family: "any" },
} as const;

export type DbIngressCounterName = keyof typeof DB_INGRESS_COUNTERS;

/** Marks whether the rendered file enforces a CIDR allowlist; the reconcilers report it. */
export const DB_INGRESS_ENFORCED_MARKER = "# ark-db-ingress: allowlist=enforced";
const OPEN_MARKER = "# ark-db-ingress: allowlist=open";

/** IPv6 sources are grouped by /64 for both limits (§3.11). */
const V6_PREFIX_MASK = "ffff:ffff:ffff:ffff::";

export function nftAllowlist(
  cidrs: string[],
  port = 5432,
  limits: DbIngressLimits = DB_INGRESS_LIMIT_DEFAULTS,
) {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error(`Invalid database port ${port}.`);
  const parsed = dbIngressLimitsInput.safeParse(limits);
  if (!parsed.success) {
    throw new Error(
      `Invalid database ingress limits: ${parsed.error.issues.map((item) => item.message).join(" ")}`,
    );
  }
  const {
    maxConnectionsPerSource: conn,
    newConnectionsPerSecond: rate,
    newConnectionBurst: burst,
  } = parsed.data;
  const valid = cidrs.map((item) => parseCidr(item)).filter((item) => item.ok);
  const v4 = valid.filter((item) => item.version === 4).map((item) => `    ip saddr ${item.cidr} return`);
  const v6 = valid.filter((item) => item.version === 6).map((item) => `    ip6 saddr ${item.cidr} return`);
  const enforced = valid.length > 0;
  // The allowlist runs first, so sources it drops never take a slot in the per-source sets.
  // An empty allowlist still emits a real table: the reconcilers read it back and treat a
  // missing table as a failed apply.
  const jumps = (match: string) =>
    [
      ...(enforced ? [`    ${match} jump ${DB_INGRESS_ALLOW_CHAIN}`] : []),
      `    ${match} jump ${DB_INGRESS_LIMITS_CHAIN}`,
    ].join("\n");
  const allowChain = enforced
    ? `  chain ${DB_INGRESS_ALLOW_CHAIN} {
${[...v4, ...v6].join("\n")}
    counter name "drop_allowlist" drop
  }
`
    : "";
  const counters = (Object.keys(DB_INGRESS_COUNTERS) as DbIngressCounterName[])
    .filter((name) => enforced || name !== "drop_allowlist")
    .map((name) => `  counter ${name} {}`)
    .join("\n");
  return `#!/usr/sbin/nft -f
# Generated public database source policy (docs/design/front-door.md §3.11).
${enforced ? DB_INGRESS_ENFORCED_MARKER : OPEN_MARKER}
# ${enforced ? `CIDR allowlist enforced on tcp/${port}; other sources are dropped.` : `Empty allowlist: any authenticated client may reach tcp/${port}.`}
# Per-source limits on tcp/${port}: ${conn} concurrent, ${rate}/second (burst ${burst}) new connections. IPv6 sources are grouped by /64.
# input covers a host-namespace listener; forward covers Docker DNAT to a published port.
table inet ${DB_INGRESS_TABLE}
delete table inet ${DB_INGRESS_TABLE}
table inet ${DB_INGRESS_TABLE} {
${counters}
  set conn4 { type ipv4_addr; size 65535; flags dynamic; }
  set conn6 { type ipv6_addr; size 65535; flags dynamic; }
  set rate4 { type ipv4_addr; size 65535; flags dynamic; timeout 2m; }
  set rate6 { type ipv6_addr; size 65535; flags dynamic; timeout 2m; }
  chain input {
    type filter hook input priority -1; policy accept;
${jumps(`tcp dport ${port}`)}
  }
  chain forward {
    type filter hook forward priority -1; policy accept;
${jumps(`ct status dnat tcp dport ${port}`)}
  }
${allowChain}  chain ${DB_INGRESS_LIMITS_CHAIN} {
    ct state new add @conn4 { ip saddr ct count over ${conn} } counter name "drop_conn4" drop
    ct state new add @conn6 { ip6 saddr and ${V6_PREFIX_MASK} ct count over ${conn} } counter name "drop_conn6" drop
    ct state new update @rate4 { ip saddr limit rate over ${rate}/second burst ${burst} packets } counter name "drop_rate4" drop
    ct state new update @rate6 { ip6 saddr and ${V6_PREFIX_MASK} limit rate over ${rate}/second burst ${burst} packets } counter name "drop_rate6" drop
  }
}
`;
}

/** True when a rendered policy file enforces a CIDR allowlist (rather than only the limits). */
export function dbIngressAllowlistEnforced(rules: string) {
  return rules.split("\n").some((line) => line.trim() === DB_INGRESS_ENFORCED_MARKER);
}

export type DbIngressCounterSample = { name: DbIngressCounterName; packets: number; bytes: number };

export type DbIngressCounterSnapshot = {
  table: typeof DB_INGRESS_TABLE;
  observedAt: string;
  counters: DbIngressCounterSample[];
};

function isCounterName(value: unknown): value is DbIngressCounterName {
  return typeof value === "string" && Object.hasOwn(DB_INGRESS_COUNTERS, value);
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/**
 * Reads `nft -j list counters table inet ark_db_ingress` output. Only the known named counters
 * of this table are kept; anything else is ignored.
 */
export function parseNftCounters(json: string, observedAt = new Date()): DbIngressCounterSnapshot {
  const parsed = JSON.parse(json) as { nftables?: Array<Record<string, unknown>> };
  const counters: DbIngressCounterSample[] = [];
  for (const item of parsed.nftables ?? []) {
    const counter = item.counter as Record<string, unknown> | undefined;
    if (!counter || counter.table !== DB_INGRESS_TABLE || counter.family !== "inet") continue;
    if (!isCounterName(counter.name) || !isCount(counter.packets) || !isCount(counter.bytes)) continue;
    counters.push({ name: counter.name, packets: counter.packets, bytes: counter.bytes });
  }
  return { table: DB_INGRESS_TABLE, observedAt: observedAt.toISOString(), counters };
}

/** Counter snapshots older than this are reported stale (the reconciler writes every 15 s). */
export const DB_INGRESS_COUNTERS_STALE_SECONDS = 120;

/**
 * Prometheus lines for a counter snapshot written by the host-namespace reconciler. `snapshot`
 * is untrusted file content: unknown names and malformed values are dropped, and labels come
 * only from `DB_INGRESS_COUNTERS`. A missing snapshot reports `ark_nft_counters_present 0`.
 */
export function dbIngressCounterMetrics(snapshot: unknown, now = new Date()) {
  const table = DB_INGRESS_TABLE;
  const lines = [
    "# HELP ark_nft_counters_present Whether the host nftables counter snapshot was readable.",
    "# TYPE ark_nft_counters_present gauge",
  ];
  const value = snapshot as Partial<DbIngressCounterSnapshot> | null | undefined;
  const observedAt = typeof value?.observedAt === "string" ? Date.parse(value.observedAt) : Number.NaN;
  if (!value || value.table !== table || !Array.isArray(value.counters) || Number.isNaN(observedAt)) {
    lines.push(`ark_nft_counters_present{table="${table}"} 0`);
    return lines;
  }
  lines.push(`ark_nft_counters_present{table="${table}"} 1`);
  lines.push(
    "# HELP ark_nft_counters_age_seconds Age of the host nftables counter snapshot.",
    "# TYPE ark_nft_counters_age_seconds gauge",
    `ark_nft_counters_age_seconds{table="${table}"} ${Math.max(0, Math.round((now.getTime() - observedAt) / 1000))}`,
    "# HELP ark_nft_drop_packets_total Packets dropped by Ark's nftables rules, by table, chain and reason.",
    "# TYPE ark_nft_drop_packets_total counter",
  );
  const seen = new Set<string>();
  for (const sample of value.counters as unknown[]) {
    const item = sample as Partial<DbIngressCounterSample> | null;
    if (!item || !isCounterName(item.name) || !isCount(item.packets) || seen.has(item.name)) continue;
    seen.add(item.name);
    const labels = DB_INGRESS_COUNTERS[item.name];
    lines.push(
      `ark_nft_drop_packets_total{table="${table}",chain="${labels.chain}",reason="${labels.reason}",family="${labels.family}"} ${item.packets}`,
    );
  }
  return lines;
}
