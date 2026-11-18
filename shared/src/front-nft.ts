// Host nftables rules for public HTTP, SNI, raw TCP and PostgreSQL compatibility ports (§3.11).

import { parseCidr } from "./cidr.ts";
import { dbIngressLimitsInput, type DbIngressLimits } from "./db-ingress.ts";
import {
  SNI_ROUTER_PORT,
  TCP_ROUTE_PORTS,
  isSharedSniPort,
  isTcpRoutePort,
  l4Limits,
  routeAllowlist,
  type L4Limits,
} from "./edge-l4.ts";
import { ValidationError } from "./errors.ts";
import {
  FRONT_COUNTERS,
  FRONT_DEDICATED_CHAIN,
  FRONT_SHARED_CHAIN,
  FRONT_TABLE,
} from "./ingress-counters.ts";

export const FRONT_SHARED_LIMIT_DEFAULTS: Readonly<DbIngressLimits> = {
  maxConnectionsPerSource: 256,
  newConnectionsPerSecond: 50,
  newConnectionBurst: 100,
};

type FrontDedicatedRoute = {
  id: string;
  listenPort: number;
  sourceCidrs: string[];
  allowInternet?: boolean;
  limits?: Partial<L4Limits>;
};

const V6_PREFIX_MASK = "ffff:ffff:ffff:ffff::";
export const FRONT_RAW_RANGE = `${TCP_ROUTE_PORTS.start}-${TCP_ROUTE_PORTS.end}`;

export function frontSharedPorts(sniPorts: number[]) {
  for (const port of sniPorts) {
    if (!isSharedSniPort(port)) throw new ValidationError(`Shared SNI port ${port} is not supported.`);
  }
  return [80, SNI_ROUTER_PORT, ...[...new Set(sniPorts)].toSorted((a, b) => a - b)];
}

function frontPortMarker(port: number, policy: "closed" | "deny-all" | "allowlist" | "internet") {
  return `# ark-front: port=${port} policy=${policy}`;
}

function meterKeys(key: string, limits: DbIngressLimits, defaults: DbIngressLimits) {
  const { maxConnectionsPerSource: conn, newConnectionsPerSecond: rate, newConnectionBurst: burst } = limits;
  return {
    conn: conn === defaults.maxConnectionsPerSource ? key : `${key}_${conn}`,
    rate:
      rate === defaults.newConnectionsPerSecond && burst === defaults.newConnectionBurst
        ? key
        : `${key}_${rate}_${burst}`,
  };
}

function meterSets(keys: { conn: string; rate: string }) {
  return [
    `  set conn4_${keys.conn} { type ipv4_addr; size 65535; flags dynamic; }`,
    `  set conn6_${keys.conn} { type ipv6_addr; size 65535; flags dynamic; }`,
    `  set rate4_${keys.rate} { type ipv4_addr; size 65535; flags dynamic; timeout 2m; }`,
    `  set rate6_${keys.rate} { type ipv6_addr; size 65535; flags dynamic; timeout 2m; }`,
  ];
}

function meterRules(
  keys: { conn: string; rate: string },
  conn: number,
  rate: string,
  burst: number,
  drop: string,
) {
  return [
    `    ct state new add @conn4_${keys.conn} { ip saddr ct count over ${conn} } counter name "${drop}_conn4" drop`,
    `    ct state new add @conn6_${keys.conn} { ip6 saddr and ${V6_PREFIX_MASK} ct count over ${conn} } counter name "${drop}_conn6" drop`,
    `    ct state new update @rate4_${keys.rate} { ip saddr limit rate over ${rate} burst ${burst} packets } counter name "${drop}_rate4" drop`,
    `    ct state new update @rate6_${keys.rate} { ip6 saddr and ${V6_PREFIX_MASK} limit rate over ${rate} burst ${burst} packets } counter name "${drop}_rate6" drop`,
  ];
}

export function renderFrontIngress(
  routes: FrontDedicatedRoute[],
  sniPorts: number[] = [],
  limits: DbIngressLimits = FRONT_SHARED_LIMIT_DEFAULTS,
) {
  const shared = frontSharedPorts(sniPorts);
  const {
    maxConnectionsPerSource: conn,
    newConnectionsPerSecond: rate,
    newConnectionBurst: burst,
  } = dbIngressLimitsInput.parse(limits);
  const byPort = new Map<number, FrontDedicatedRoute>();
  for (const route of routes) {
    if (!/^rt_[a-z0-9]+$/.test(route.id)) throw new ValidationError(`Route id ${route.id} is invalid.`);
    if (!isTcpRoutePort(route.listenPort)) {
      throw new ValidationError(`Route ${route.id}: port ${route.listenPort} is not a raw TCP port.`);
    }
    if (byPort.has(route.listenPort)) {
      throw new ValidationError(`Port ${route.listenPort} has more than one raw TCP route.`);
    }
    byPort.set(route.listenPort, route);
  }
  const markers: string[] = [];
  // Dynamic elements remember their original limits. Keep their names when the settings
  // are unchanged and use fresh sets for new thresholds.
  const sharedKeys = meterKeys("shared", limits, FRONT_SHARED_LIMIT_DEFAULTS);
  const sets = meterSets(sharedKeys);
  const rules: string[] = [];
  const defaultPortLimits = l4Limits("tcp");
  for (let port = TCP_ROUTE_PORTS.start; port <= TCP_ROUTE_PORTS.end; port++) {
    const route = byPort.get(port);
    if (!route) {
      markers.push(frontPortMarker(port, "closed"));
      continue;
    }
    const cidrs = routeAllowlist(route);
    const open = Boolean(route.allowInternet);
    markers.push(frontPortMarker(port, open ? "internet" : cidrs.length ? "allowlist" : "deny-all"));
    const portLimits = l4Limits("tcp", route.limits);
    const v4 = cidrs.filter((cidr) => parseCidr(cidr).version === 4);
    const v6 = cidrs.filter((cidr) => parseCidr(cidr).version === 6);
    const chain = `port_${port}`;
    const keys = meterKeys(
      String(port),
      {
        maxConnectionsPerSource: portLimits.perSourceConn,
        newConnectionsPerSecond: portLimits.perSourceRate,
        newConnectionBurst: portLimits.perSourceRate,
      },
      {
        maxConnectionsPerSource: defaultPortLimits.perSourceConn,
        newConnectionsPerSecond: defaultPortLimits.perSourceRate,
        newConnectionBurst: defaultPortLimits.perSourceRate,
      },
    );
    sets.push(...meterSets(keys));
    // HAProxy counts the rate per 10 s; the kernel bucket allows the same per minute (x6).
    const perMinute = portLimits.perSourceRate * 6;
    rules.push(
      `  chain ${chain} {`,
      `    # ${route.id}: ${open ? "allowInternet (explicit, exposure.public)" : cidrs.length ? `${cidrs.length} allowed CIDR(s)` : "empty allowlist = deny all"}`,
      ...(open
        ? []
        : [
            // One rule per CIDR, so overlapping prefixes never conflict.
            ...v4.map((cidr) => `    ip saddr ${cidr} goto ${chain}_limits`),
            ...v6.map((cidr) => `    ip6 saddr ${cidr} goto ${chain}_limits`),
            '    counter name "drop_allowlist" drop',
          ]),
      ...(open ? [`    goto ${chain}_limits`] : []),
      "  }",
      `  chain ${chain}_limits {`,
      ...meterRules(
        keys,
        portLimits.perSourceConn,
        `${perMinute}/minute`,
        portLimits.perSourceRate,
        "drop_dedicated",
      ),
      // Admitted: end this table's evaluation before the dedicated-range fallback drop.
      "    accept",
      "  }",
    );
  }
  const enabledPorts = [...byPort.keys()].toSorted((a, b) => a - b);
  const vmap = enabledPorts.length
    ? `    tcp dport vmap { ${enabledPorts.map((port) => `${port} : jump port_${port}`).join(", ")} }\n`
    : "";
  const dispatch = (match: string) =>
    [
      `    ${match}tcp dport { ${shared.join(", ")} } jump ${FRONT_SHARED_CHAIN}`,
      `    ${match}tcp dport ${FRONT_RAW_RANGE} jump ${FRONT_DEDICATED_CHAIN}`,
    ].join("\n");
  return `#!/usr/sbin/nft -f
# Generated public front-door port policy (docs/design/front-door.md §3.11).
${markers.join("\n")}
# input covers a host-namespace listener; forward covers Docker DNAT to a published port.
# Retire the FD-14/FD-26 table in the same transaction as its replacement.
table inet ark_front_raw
delete table inet ark_front_raw
table inet ${FRONT_TABLE}
# Replace dispatch and policy rules while retaining unchanged meters and named counters.
flush table inet ${FRONT_TABLE}
table inet ${FRONT_TABLE} {
${Object.keys(FRONT_COUNTERS)
  .map((name) => `  counter ${name} {}`)
  .join("\n")}
${sets.join("\n")}
  chain input {
    type filter hook input priority -1; policy accept;
${dispatch("")}
  }
  chain forward {
    type filter hook forward priority -1; policy accept;
${dispatch("ct direction original ct status dnat ")}
  }
  chain ${FRONT_SHARED_CHAIN} {
${meterRules(sharedKeys, conn, `${rate}/second`, burst, "drop").join("\n")}
  }
  chain ${FRONT_DEDICATED_CHAIN} {
${vmap}    counter name "drop_closed" drop
  }
${rules.join("\n")}
}
`;
}

/** The effective policy per raw port, read back from a rendered or applied file. */
export function frontPortPolicies(rules: string) {
  const policies = new Map<number, string>();
  for (const match of rules.matchAll(/^# ark-front: port=(\d+) policy=([a-z-]+)$/gm)) {
    policies.set(Number(match[1]), match[2]!);
  }
  return policies;
}
