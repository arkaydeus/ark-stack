import { isIP } from "node:net";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import {
  HOST_FIREWALL_TABLE,
  assertHostFirewall,
  isTcpRoutePort,
  providerFirewallRules,
  publicHostPorts,
  readHostSshAccess,
  type HostPortConfig,
} from "@ark-stack/shared";

import { auditExternal, readExternalInventory } from "./host-audit-external.ts";
import { appliedHostConfig } from "./host-inventory.ts";
import { hostCommand, hostFirewallPath } from "./install-host-hardening.ts";

type Protocol = "tcp" | "udp";
type PublishedPort = {
  container: string;
  arkEdge?: boolean;
  protocol: Protocol;
  address: string;
  port: number;
  target: number;
};

function unbracket(address: string) {
  return address.replace(/^\[([^\]]+)\](%.*)?$/, "$1$2").replace(/^::ffff:(?=\d+\.)/, "");
}

function privateBind(address: string, tailnet: Set<string>) {
  const ip = unbracket(address).split("%")[0]!;
  return ip === "::1" || (isIP(ip) === 4 && ip.startsWith("127.")) || tailnet.has(ip);
}

function dhcpClientSocket(protocol: Protocol, address: string, port: number, line: string) {
  const ip = unbracket(address).split("%")[0]!;
  const family = port === 68 ? 4 : port === 546 ? 6 : 0;
  if (protocol !== "udp" || !family || (ip !== "*" && isIP(ip) !== family)) return false;
  const owners = [...line.matchAll(/\("([^"]+)",pid=\d+,fd=\d+\)/g)];
  return owners.length > 0 && owners.every(([, owner]) => /^(?:systemd-networkd?|dhclient)$/.test(owner!));
}

function endpoint(address: string, port: number) {
  const ip = unbracket(address);
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

function edgeReservation(item: PublishedPort) {
  return item.arkEdge && item.protocol === "tcp" && item.port === item.target && isTcpRoutePort(item.port);
}

export function unexpectedPorts(
  config: HostPortConfig,
  sockets: string,
  published: PublishedPort[],
  tailnet = new Set<string>(),
  retainedSsh: number[] = [],
) {
  const expected = publicHostPorts(config);
  const problems = [];
  // edge-ts reserves its entire raw range in Compose. ark_host and ark_front
  // gate it per route. Docker may hold the socket in dockerd or docker-proxy.
  const reserved = new Set(
    published.filter(edgeReservation).map((item) => endpoint(item.address, item.port)),
  );
  for (const item of published) {
    if (
      !privateBind(item.address, tailnet) &&
      !expected[item.protocol].includes(item.port) &&
      !edgeReservation(item)
    ) {
      problems.push(
        `Unexpected ${item.protocol.toUpperCase()} ${endpoint(item.address, item.port)} published by ${item.container}.`,
      );
    }
  }
  for (const line of sockets.trim().split("\n")) {
    if (!line) continue;
    const match = /^(tcp|udp)\s+\S+\s+\d+\s+\d+\s+(\S+):(\d+)\s/.exec(line);
    if (!match) throw new Error(`Unrecognised ss record: ${line}`);
    const protocol = match[1] as Protocol;
    const address = unbracket(match[2]!);
    const port = Number(match[3]);
    const owners = [...line.matchAll(/\("([^"]+)",pid=(\d+),fd=\d+\)/g)];
    const retainedOpenSsh =
      protocol === "tcp" &&
      retainedSsh.includes(port) &&
      owners.length > 0 &&
      owners.every(
        ([, owner, pid]) => /^sshd(?:-session)?$/.test(owner!) || (owner === "systemd" && pid === "1"),
      );
    const dockerReservation =
      protocol === "tcp" &&
      /"(?:dockerd|docker-proxy)"/.test(line) &&
      (reserved.has(endpoint(address, port)) || (address === "*" && reserved.has(endpoint("::", port))));
    if (
      !privateBind(address, tailnet) &&
      !expected[protocol].includes(port) &&
      !dockerReservation &&
      !retainedOpenSsh &&
      !dhcpClientSocket(protocol, address, port, line)
    ) {
      problems.push(`Unexpected ${protocol.toUpperCase()} ${endpoint(address, port)} listening on the host.`);
    }
  }
  return problems;
}

async function dockerPublications() {
  const localDocker = ["--host", "unix:///var/run/docker.sock"];
  const ids = (await hostCommand("docker", [...localDocker, "ps", "-q"])).trim().split(/\s+/).filter(Boolean);
  if (!ids.length) return [];
  const rows = await hostCommand("docker", [
    ...localDocker,
    "inspect",
    "--format",
    "{{json .Name}}\t{{json .Config.Labels}}\t{{json .NetworkSettings.Ports}}",
    ...ids,
  ]);
  const publications: PublishedPort[] = [];
  for (const row of rows.trim().split("\n")) {
    const [name, labels, ports] = row.split("\t").map((field) => JSON.parse(field));
    const arkEdge =
      labels?.["com.docker.compose.project"] === "ark-platform" &&
      labels?.["com.docker.compose.service"] === "edge-ts";
    for (const [key, mappings] of Object.entries(ports ?? {})) {
      const [target, protocol] = key.split("/");
      for (const { HostIp, HostPort } of (mappings ?? []) as { HostIp: string; HostPort: string }[]) {
        if (protocol !== "tcp" && protocol !== "udp") {
          throw new Error(`Unexpected ${protocol} port ${HostIp}:${HostPort} published by ${name}.`);
        }
        publications.push({
          container: name,
          arkEdge,
          protocol,
          address: HostIp,
          port: Number(HostPort),
          target: Number(target),
        });
      }
    }
  }
  return publications;
}

async function tailscaleAddresses() {
  const links = JSON.parse(await hostCommand("ip", ["-j", "address", "show"])) as {
    ifname: string;
    addr_info: { local: string }[];
  }[];
  return new Set(links.find((link) => link.ifname === "tailscale0")?.addr_info.map((addr) => addr.local));
}

export async function auditLocal(config: HostPortConfig, retainSsh = false) {
  if (process.platform !== "linux" || process.getuid?.() !== 0) {
    throw new Error("Run the local audit as root on the Linux VPS.");
  }
  const [rules, sockets, publications, tailnet] = await Promise.all([
    hostCommand("nft", ["-s", "-y", "list", "table", "inet", HOST_FIREWALL_TABLE]),
    hostCommand("ss", ["-H", "-lntup"]),
    dockerPublications(),
    tailscaleAddresses(),
  ]);
  const access = retainSsh ? readHostSshAccess(await readFile(hostFirewallPath, "utf8")) : undefined;
  assertHostFirewall(rules, config, access);
  const problems = unexpectedPorts(config, sockets, publications, tailnet, access?.ports);
  if (problems.length) throw new Error(problems.join("\n"));
}

async function main(args: string[]) {
  if (args[0] === "--external" && args.length >= 3) {
    const config = await readExternalInventory(args[1]!);
    await Promise.all(args.slice(2).map((address) => auditExternal(config, address)));
    return;
  }
  if (args.length > 1 || (args.length === 1 && !["--inventory", "--retain-ssh"].includes(args[0]!))) {
    throw new Error("Usage: host:audit [--inventory | --retain-ssh | --external INVENTORY.json IP [IP...]]");
  }
  const config = await appliedHostConfig(join(import.meta.dir, ".."));
  if (args[0] === "--inventory") {
    console.log(JSON.stringify({ config, providerRules: providerFirewallRules(config) }, null, 2));
    return;
  }
  await auditLocal(config, args[0] === "--retain-ssh");
  console.log("Host listeners, Docker publications and ark_host match the public inventory.");
}

if (import.meta.main) await main(process.argv.slice(2));
