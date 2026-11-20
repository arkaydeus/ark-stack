import { isIP } from "node:net";

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
export type HostSshAccess = { ports: number[]; source?: string };

function sshAccessRules(access?: HostSshAccess) {
  const family = access?.source ? isIP(access.source) : undefined;
  if (family === 0 || access?.source?.includes("%"))
    throw new Error("SSH recovery source must be a single IP address.");
  return (access?.ports ?? []).map((port) => {
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid SSH listener port.");
    const source = access?.source ? `${family === 4 ? "ip" : "ip6"} saddr ${access.source} ` : "";
    return `${source}tcp dport ${port} accept`;
  });
}

/** The SSH chain is administered by host setup, independently of the edge port sets. */
export function readHostSshAccess(rules: string): HostSshAccess {
  const body = /^\s*chain ssh_access \{\n([\s\S]*?)^[ \t]*}/m.exec(rules)?.[1]?.trim();
  const access: HostSshAccess = { ports: [] };
  for (const line of body ? body.split("\n") : []) {
    const entry = /^(?:(ip6?) saddr ([\da-f:.]+) )?tcp dport (\d+) accept$/i.exec(line.trim());
    if (!entry || (entry[2] && isIP(entry[2]) !== (entry[1] === "ip" ? 4 : 6))) {
      throw new Error("Unexpected rule in the host SSH access chain.");
    }
    if (access.ports.length && access.source !== entry[2]) throw new Error("Mixed SSH recovery sources.");
    access.source = entry[2];
    access.ports.push(Number(entry[3]));
  }
  return access;
}

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

function hostFirewallTable(config: HostPortConfig, ssh?: HostSshAccess, legacy = false) {
  const { tcp, udp } = publicHostPorts(config);
  const sshRules = sshAccessRules(ssh)
    .map((rule) => `    ${rule}\n`)
    .join("");
  return `table inet ${HOST_FIREWALL_TABLE} {
  set public_tcp {
    type inet_service
    elements = { ${tcp.join(", ")} }
  }
  set public_udp {
    type inet_service
    elements = { ${udp.join(", ")} }
  }
  ${legacy ? "" : `chain ssh_access {\n${sshRules}  }\n  `}chain input {
    type filter hook input priority -5; policy drop;
    ct state established,related accept
    iifname "lo" accept
    iifname "tailscale0" accept
    meta l4proto { icmp, ipv6-icmp } accept
    ip6 daddr fe80::/10 udp sport 547 udp dport 546 accept
    ${legacy ? "" : "jump ssh_access\n    "}tcp dport @public_tcp accept
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

export function renderHostFirewall(config: HostPortConfig, ssh?: HostSshAccess) {
  return `table inet ${HOST_FIREWALL_TABLE}\ndelete table inet ${HOST_FIREWALL_TABLE}\n${hostFirewallTable(config, ssh)}`;
}

export function updateHostFirewallPorts(config: HostPortConfig) {
  const ports = publicHostPorts(config);
  return (["tcp", "udp"] as const)
    .map((protocol) => {
      const set = `inet ${HOST_FIREWALL_TABLE} public_${protocol}`;
      return `flush set ${set}\nadd element ${set} { ${ports[protocol].join(", ")} }\n`;
    })
    .join("");
}

export function updateHostSshAccess(access: HostSshAccess) {
  const chain = `inet ${HOST_FIREWALL_TABLE} ssh_access`;
  return (
    `flush chain ${chain}\n` +
    sshAccessRules(access)
      .map((rule) => `add rule ${chain} ${rule}\n`)
      .join("")
  );
}

/** Update just the inputs for the SSH chain in the boot rules, leaving the baseline policy intact. */
export function replaceHostSshAccess(rules: string, access: HostSshAccess) {
  const replacement = sshAccessRules(access)
    .map((rule) => `    ${rule}\n`)
    .join("");
  const updated = rules.replace(/(^[ \t]*chain ssh_access \{\n)[\s\S]*?(^[ \t]*})/m, `$1${replacement}$2`);
  if (updated === rules && !/^[ \t]*chain ssh_access \{/m.test(rules)) {
    throw new Error("Missing SSH access chain in the boot firewall.");
  }
  return updated;
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
    .replace(
      /\b(ip6?) saddr ([\da-f:.]+)(?=\s)/gi,
      (_match, family: string, address: string) =>
        `${family} saddr ${family === "ip6" ? new URL(`http://[${address}]/`).hostname.slice(1, -1) : address}`,
    )
    .replace(/\s+/g, "");
}

export function assertHostFirewall(installed: string, config: HostPortConfig, ssh?: HostSshAccess) {
  const actual = normalizeFirewall(installed);
  if (
    actual !== normalizeFirewall(hostFirewallTable(config, ssh)) &&
    !(ssh === undefined && actual === normalizeFirewall(hostFirewallTable(config, undefined, true)))
  ) {
    throw new Error("Installed ark_host rules differ from the enabled-service inventory or baseline.");
  }
}

export function rebootRequiredMetrics(marker: string | null) {
  if (marker !== "" && marker !== "/run/reboot-required\n") return [];
  return ["# TYPE ark_host_reboot_required gauge", `ark_host_reboot_required ${marker ? 1 : 0}`];
}
