// The public database port's nftables policy (docs/design/front-door.md §3.11, FD-18).
//
// `inet ark_db_ingress` limits public TCP 5432 on the input hook (host listeners) and the
// forward hook (DNAT to the FD-26 router). IPv4 sources are keyed per address and IPv6 sources
// per /64. The pooler and each PostgreSQL route enforce their CIDRs in HAProxy.
//
// Every drop has a named counter. The host-namespace reconciler reads them back and the API
// exports them on `/api/metrics/prometheus` as `ark_nft_drop_packets_total`.
import { z } from "zod";

import { DB_INGRESS_COUNTERS, DB_INGRESS_LIMITS_CHAIN, DB_INGRESS_TABLE } from "./ingress-counters.ts";

/**
 * §3.11 defaults. Vercel egress comes from shared AWS addresses, so many function instances can
 * share one source IP; the defaults are deliberately generous.
 */
export const DB_INGRESS_LIMIT_DEFAULTS = {
  maxConnectionsPerSource: 128,
  newConnectionsPerSecond: 30,
  newConnectionBurst: 60,
} as const;

/** Bounds the API, the database CHECKs (0017) and the renderer all enforce. */
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

/** The effective limits for a `platform_settings` row (columns from 0017). */
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

/** IPv6 sources are grouped by /64 for both limits (§3.11). */
const V6_PREFIX_MASK = "ffff:ffff:ffff:ffff::";

export function renderDbIngress(limits: DbIngressLimits = DB_INGRESS_LIMIT_DEFAULTS, previousRules = "") {
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
  // Stateful expressions are copied into each dynamic element when it is first created.
  // Replacing a rule cannot change an existing element's cap or token bucket. Use a set
  // generation per configured value. Retain older conncount sets and deny their sources
  // until they drain (the kernel garbage-collects empty conncount elements). This keeps
  // idle established connections accounted for without terminating them on a cap change.
  const connectionSets = new Set(
    [...previousRules.matchAll(/^  set (conn[46](?:_[0-9]+)?) \{/gm)].map((match) => match[1]!),
  );
  const conn4 = `conn4_${conn}`;
  const conn6 = `conn6_${conn}`;
  connectionSets.add(conn4);
  connectionSets.add(conn6);
  const setDeclarations = [...connectionSets]
    .flatMap((name) => {
      const type = name.startsWith("conn4") ? "ipv4_addr" : "ipv6_addr";
      return [name, name.replace("conn", "active")].map(
        (set) => `  set ${set} { type ${type}; size 65535; flags dynamic; }`,
      );
    })
    .join("\n");
  const drainingRules = [...connectionSets]
    .filter((name) => name !== conn4 && name !== conn6)
    .map((name) =>
      name.startsWith("conn4")
        ? `    ct state new ip saddr @${name.replace("conn", "active")} counter name "drop_conn4" drop`
        : `    ct state new ip6 saddr and ${V6_PREFIX_MASK} @${name.replace("conn", "active")} counter name "drop_conn6" drop`,
    )
    .join("\n");
  const rate4 = `rate4_${rate}_${burst}`;
  const rate6 = `rate6_${rate}_${burst}`;
  const counters = Object.keys(DB_INGRESS_COUNTERS)
    .map((name) => `  counter ${name} {}`)
    .join("\n");
  return `#!/usr/sbin/nft -f
# Generated public database limits (docs/design/front-door.md §3.11).
# Per-source limits on tcp/5432: ${conn} concurrent, ${rate}/second (burst ${burst}) new connections. IPv6 sources are grouped by /64.
# input covers a host-namespace listener; forward covers Docker DNAT to a published port.
table inet ${DB_INGRESS_TABLE}
# Declare objects without deleting live conncount state or named counters. Flushing only
# chains removes old jumps/rules (including a legacy allowlist) in this same transaction.
add chain inet ${DB_INGRESS_TABLE} input { type filter hook input priority -1; policy accept; }
add chain inet ${DB_INGRESS_TABLE} forward { type filter hook forward priority -1; policy accept; }
add chain inet ${DB_INGRESS_TABLE} ${DB_INGRESS_LIMITS_CHAIN}
flush chain inet ${DB_INGRESS_TABLE} input
flush chain inet ${DB_INGRESS_TABLE} forward
flush chain inet ${DB_INGRESS_TABLE} ${DB_INGRESS_LIMITS_CHAIN}
# Retire the old allowlist objects, including on upgrades from a pre-FD-26 policy.
add chain inet ${DB_INGRESS_TABLE} ark_db_allow
flush chain inet ${DB_INGRESS_TABLE} ark_db_allow
delete chain inet ${DB_INGRESS_TABLE} ark_db_allow
add counter inet ${DB_INGRESS_TABLE} drop_allowlist
delete counter inet ${DB_INGRESS_TABLE} drop_allowlist
table inet ${DB_INGRESS_TABLE} {
${counters}
${setDeclarations}
  set ${rate4} { type ipv4_addr; size 65535; flags dynamic; timeout 2m; }
  set ${rate6} { type ipv6_addr; size 65535; flags dynamic; timeout 2m; }
  chain input {
    type filter hook input priority -1; policy accept;
    tcp dport 5432 jump ${DB_INGRESS_LIMITS_CHAIN}
  }
  chain forward {
    type filter hook forward priority -1; policy accept;
    ct direction original ct status dnat tcp dport 5432 jump ${DB_INGRESS_LIMITS_CHAIN}
  }
  chain ${DB_INGRESS_LIMITS_CHAIN} {
${drainingRules ? `${drainingRules}\n` : ""}    # Presence trackers use count over 0: a set lookup evaluates its element expression,
    # so looking up the capped conn sets would only match sources already over the OLD cap.
    ct state new add @active4_${conn} { ip saddr ct count over 0 }
    ct state new add @active6_${conn} { ip6 saddr and ${V6_PREFIX_MASK} ct count over 0 }
    ct state new add @${conn4} { ip saddr ct count over ${conn} } counter name "drop_conn4" drop
    ct state new add @${conn6} { ip6 saddr and ${V6_PREFIX_MASK} ct count over ${conn} } counter name "drop_conn6" drop
    ct state new update @${rate4} { ip saddr limit rate over ${rate}/second burst ${burst} packets } counter name "drop_rate4" drop
    ct state new update @${rate6} { ip6 saddr and ${V6_PREFIX_MASK} limit rate over ${rate}/second burst ${burst} packets } counter name "drop_rate6" drop
  }
}
`;
}
