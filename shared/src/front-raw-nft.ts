// Host nftables rules for raw-TCP route ports (docs/design/front-door.md §3.8.6, §3.11, FD-14).
//
// The same style as `ark_db_ingress` (FD-18): one `inet` table with `input` (host listener) and
// `forward` (Docker DNAT to a published port) hooks, the allowlist before the per-source limits, IPv6
// sources grouped by /64. Every port of the dedicated range is covered: a port without an enabled
// route drops all traffic, an enabled route with an empty allowlist drops all traffic (deny all), and
// only an explicit `allowInternet` renders no source restriction. The general `ark_front` table for
// the shared ports, and applying it through the `database-ingress` reconciler, are FD-15; this table
// is the raw-port part it absorbs.

import { parseCidr } from "./cidr.ts";
import { TCP_ROUTE_PORTS, isTcpRoutePort, l4Limits, routeAllowlist, type L4Limits } from "./edge-l4.ts";
import { ValidationError } from "./errors.ts";

export const FRONT_RAW_TABLE = "ark_front_raw";

export type FrontRawPortRoute = {
  id: string;
  listenPort: number;
  sourceCidrs: string[];
  allowInternet?: boolean;
  limits?: Partial<L4Limits>;
};

const V6_PREFIX_MASK = "ffff:ffff:ffff:ffff::";

/** Marker lines the reconciler and tests read back: one per port, with its effective policy. */
export function frontRawPortMarker(port: number, policy: "closed" | "deny-all" | "allowlist" | "internet") {
  return `# ark-front-raw: port=${port} policy=${policy}`;
}

/**
 * Renders the raw-port table for the enabled `tcp` routes. Ports outside the range or used twice are
 * refused; an empty allowlist is rendered as a drop rule, never as an open port.
 */
export function renderFrontRawPorts(routes: FrontRawPortRoute[]) {
  const byPort = new Map<number, FrontRawPortRoute>();
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
  const sets: string[] = [];
  const rules: string[] = [];
  for (let port = TCP_ROUTE_PORTS.start; port <= TCP_ROUTE_PORTS.end; port++) {
    const route = byPort.get(port);
    if (!route) {
      markers.push(frontRawPortMarker(port, "closed"));
      continue;
    }
    const cidrs = routeAllowlist(route);
    const open = Boolean(route.allowInternet);
    markers.push(frontRawPortMarker(port, open ? "internet" : cidrs.length ? "allowlist" : "deny-all"));
    const limits = l4Limits("tcp", route.limits);
    const v4 = cidrs.filter((cidr) => parseCidr(cidr).version === 4);
    const v6 = cidrs.filter((cidr) => parseCidr(cidr).version === 6);
    const chain = `port_${port}`;
    const set = (name: string, type: string, extra = "") =>
      `  set ${name}_${port} { type ${type}; size 65535; flags dynamic;${extra} }`;
    sets.push(
      set("conn4", "ipv4_addr"),
      set("conn6", "ipv6_addr"),
      set("rate4", "ipv4_addr", " timeout 2m;"),
      set("rate6", "ipv6_addr", " timeout 2m;"),
    );
    // HAProxy counts the rate per 10 s; the kernel bucket allows the same per minute (x6).
    const perMinute = limits.perSourceRate * 6;
    rules.push(
      `  chain ${chain} {`,
      `    # ${route.id}: ${open ? "allowInternet (explicit, exposure.public)" : cidrs.length ? `${cidrs.length} allowed CIDR(s)` : "empty allowlist = deny all"}`,
      ...(open
        ? []
        : [
            // One rule per CIDR (as ark_db_ingress does): overlapping prefixes never conflict.
            ...v4.map((cidr) => `    ip saddr ${cidr} goto ${chain}_limits`),
            ...v6.map((cidr) => `    ip6 saddr ${cidr} goto ${chain}_limits`),
            '    counter name "drop_allowlist" drop',
          ]),
      ...(open ? [`    goto ${chain}_limits`] : []),
      "  }",
      `  chain ${chain}_limits {`,
      `    ct state new add @conn4_${port} { ip saddr ct count over ${limits.perSourceConn} } counter name "drop_conn" drop`,
      `    ct state new add @conn6_${port} { ip6 saddr and ${V6_PREFIX_MASK} ct count over ${limits.perSourceConn} } counter name "drop_conn" drop`,
      `    ct state new update @rate4_${port} { ip saddr limit rate over ${perMinute}/minute burst ${limits.perSourceRate} packets } counter name "drop_rate" drop`,
      `    ct state new update @rate6_${port} { ip6 saddr and ${V6_PREFIX_MASK} limit rate over ${perMinute}/minute burst ${limits.perSourceRate} packets } counter name "drop_rate" drop`,
      // Admitted: end this table's evaluation, so the base chain's closed-range drop never sees it.
      "    accept",
      "  }",
    );
  }
  const enabledPorts = [...byPort.keys()].toSorted((a, b) => a - b);
  const range = `${TCP_ROUTE_PORTS.start}-${TCP_ROUTE_PORTS.end}`;
  const vmap = enabledPorts.length
    ? `tcp dport vmap { ${enabledPorts.map((port) => `${port} : jump port_${port}`).join(", ")} }`
    : "";
  const dispatch = (match: string) =>
    [
      ...(vmap ? [`    ${match}${vmap}`] : []),
      // Every other range port has no enabled route: drop.
      `    ${match}tcp dport ${range} counter name "drop_closed" drop`,
    ].join("\n");
  return `#!/usr/sbin/nft -f
# Generated raw TCP route ports policy (docs/design/front-door.md §3.8.6, §3.11, FD-14).
${markers.join("\n")}
# input covers a host-namespace listener; forward covers Docker DNAT to a published port.
table inet ${FRONT_RAW_TABLE}
delete table inet ${FRONT_RAW_TABLE}
table inet ${FRONT_RAW_TABLE} {
  counter drop_closed {}
  counter drop_allowlist {}
  counter drop_conn {}
  counter drop_rate {}
${sets.join("\n")}
  chain input {
    type filter hook input priority -1; policy accept;
${dispatch("")}
  }
  chain forward {
    type filter hook forward priority -1; policy accept;
${dispatch("ct direction original ct status dnat ")}
  }
${rules.join("\n")}
}
`;
}

/** The effective policy per raw port, read back from a rendered or applied file. */
export function frontRawPortPolicies(rules: string) {
  const policies = new Map<number, string>();
  for (const match of rules.matchAll(/^# ark-front-raw: port=(\d+) policy=([a-z-]+)$/gm)) {
    policies.set(Number(match[1]), match[2]!);
  }
  return policies;
}
