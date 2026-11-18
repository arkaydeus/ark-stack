import { POSTGRES_ROUTER_PORT, TCP_ROUTE_PORTS, isTcpRoutePort } from "./edge-l4.ts";
import { frontPortPolicies, frontSharedPorts } from "./front-nft.ts";

export const HOST_FIREWALL_TABLE = "ark_host";
export const MAIL_PUBLIC_TCP = [25, 465, 587, 993] as const;
export const HOST_TAILSCALE_UDP = 41641;
export const EDGE_TAILSCALE_UDP = 41642;

export type RawPortPolicy = "internet" | "allowlist" | "deny-all";
export type HostPortConfig = {
  mailEnabled: boolean;
  sniPorts: number[];
  routes?: { port: number; policy: RawPortPolicy }[];
};

export function mailEnabled(value: string | undefined) {
  if (value === undefined || value === "" || value === "1") return true;
  if (value === "0") return false;
  throw new Error("ARK_MAIL_ENABLED must be 0 or 1.");
}

export function hostRoutesFromFront(rules: string): NonNullable<HostPortConfig["routes"]> {
  const routes: NonNullable<HostPortConfig["routes"]> = [];
  const policies = frontPortPolicies(rules);
  for (let port = TCP_ROUTE_PORTS.start; port <= TCP_ROUTE_PORTS.end; port++) {
    const policy = policies.get(port);
    if (policy === "closed") continue;
    if (policy !== "internet" && policy !== "allowlist" && policy !== "deny-all") {
      throw new Error(`Public front policy has no valid entry for TCP ${port}.`);
    }
    routes.push({ port, policy });
  }
  return routes;
}

export function publicHostPorts(config: HostPortConfig) {
  const web = frontSharedPorts(config.sniPorts);
  if (typeof config.mailEnabled !== "boolean") throw new Error("Missing mail configuration.");
  const mail = config.mailEnabled ? [...MAIL_PUBLIC_TCP] : [];
  const raw = new Set<number>();
  for (const { port, policy } of config.routes ?? []) {
    if (!isTcpRoutePort(port) || !["internet", "allowlist", "deny-all"].includes(policy) || raw.has(port)) {
      throw new Error(`Invalid public route port ${port}.`);
    }
    raw.add(port);
  }
  return {
    tcp: [...web, POSTGRES_ROUTER_PORT, ...mail, ...raw].toSorted((a, b) => a - b),
    udp: [HOST_TAILSCALE_UDP, EDGE_TAILSCALE_UDP],
  };
}

export function providerFirewallRules(config: HostPortConfig) {
  const ports = publicHostPorts(config);
  return (["tcp", "udp"] as const).map((protocol) => ({
    protocol,
    ports: ports[protocol],
    sourceCidrs: ["0.0.0.0/0", "::/0"],
  }));
}

function hostFirewallTable(config: HostPortConfig) {
  const { tcp, udp } = publicHostPorts(config);
  return `table inet ${HOST_FIREWALL_TABLE} {
  set public_tcp {
    type inet_service
    elements = { ${tcp.join(", ")} }
  }
  set public_udp {
    type inet_service
    elements = { ${udp.join(", ")} }
  }
  chain input {
    type filter hook input priority -5; policy drop;
    ct state established,related accept
    iifname "lo" accept
    iifname "tailscale0" accept
    meta l4proto { icmp, ipv6-icmp } accept
    tcp dport @public_tcp accept
    udp dport @public_udp accept
  }
  chain forward {
    type filter hook forward priority -5; policy accept;
    ct direction original ct status dnat jump published
  }
  chain published {
    meta l4proto tcp ct original proto-dst @public_tcp return
    meta l4proto udp ct original proto-dst @public_udp return
    drop
  }
}
`;
}

export function renderHostFirewall(config: HostPortConfig) {
  return `table inet ${HOST_FIREWALL_TABLE}\ndelete table inet ${HOST_FIREWALL_TABLE}\n${hostFirewallTable(config)}`;
}

function normalizeFirewall(rules: string) {
  // nft aligns set elements across lines and may sort members of anonymous sets.
  return rules
    .replace(
      /\{\s*([\w-]+(?:\s*,\s*[\w-]+)*)\s*\}/g,
      (_set, elements: string) =>
        `{${elements
          .split(",")
          .map((part) => part.trim())
          .toSorted()
          .join(",")}}`,
    )
    .replace(/\s+/g, "");
}

export function assertHostFirewall(installed: string, config: HostPortConfig) {
  if (normalizeFirewall(installed) !== normalizeFirewall(hostFirewallTable(config))) {
    throw new Error("Installed ark_host rules differ from the enabled-service inventory or baseline.");
  }
}

export function rebootRequiredMetrics(marker: string | null) {
  if (marker !== "" && marker !== "/run/reboot-required\n") return [];
  return ["# TYPE ark_host_reboot_required gauge", `ark_host_reboot_required ${marker ? 1 : 0}`];
}
