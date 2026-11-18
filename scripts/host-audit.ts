import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { join } from "node:path";

import {
  HOST_FIREWALL_TABLE,
  assertHostFirewall,
  isTcpRoutePort,
  providerFirewallRules,
  publicHostPorts,
  type HostPortConfig,
} from "@ark-stack/shared";

import { appliedHostConfig } from "./host-inventory.ts";
import { hostCommand } from "./install-host-hardening.ts";

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
  return address.replace(/^\[(.*)\]$/, "$1").replace(/^::ffff:(?=\d+\.)/, "");
}

function privateBind(address: string, tailnet: Set<string>) {
  const ip = unbracket(address).split("%")[0]!;
  return ip === "::1" || ip.startsWith("127.") || tailnet.has(ip);
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
    const dockerReservation =
      protocol === "tcp" && /"(?:dockerd|docker-proxy)"/.test(line) && reserved.has(endpoint(address, port));
    if (!privateBind(address, tailnet) && !expected[protocol].includes(port) && !dockerReservation) {
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

export async function auditLocal(config: HostPortConfig) {
  if (process.platform !== "linux" || process.getuid?.() !== 0) {
    throw new Error("Run the local audit as root on the Linux VPS.");
  }
  const [rules, sockets, publications, tailnet] = await Promise.all([
    hostCommand("nft", ["-s", "-y", "list", "table", "inet", HOST_FIREWALL_TABLE]),
    hostCommand("ss", ["-H", "-lntup"]),
    dockerPublications(),
    tailscaleAddresses(),
  ]);
  assertHostFirewall(rules, config);
  const problems = unexpectedPorts(config, sockets, publications, tailnet);
  if (problems.length) throw new Error(problems.join("\n"));
}

async function nmapPorts(address: string, args: string[]) {
  const output = await hostCommand("nmap", [
    ...(isIP(address) === 6 ? ["-6"] : []),
    "-n",
    "-Pn",
    "--max-retries",
    "1",
    "-oG",
    "-",
    ...args,
    address,
  ]);
  if (!output.includes("1 host up")) throw new Error(`Nmap could not scan ${address}.`);
  return [...output.matchAll(/(\d+)\/(open\|filtered|open|closed|filtered)\/(tcp|udp)\//g)].map((match) => ({
    port: Number(match[1]),
    state: match[2]!,
  }));
}

export async function auditExternal(config: HostPortConfig, address: string) {
  if (!isIP(address) || address.includes("%")) throw new Error("Provide an IPv4 or IPv6 address literal.");
  const { tcp, udp } = publicHostPorts(config);
  const restricted = new Map(config.routes?.map(({ port, policy }) => [port, policy]));
  const privatePorts = [22, 2019, 3000, 15432];
  // Probe the inventory at normal timing before the full-range scan. In particular,
  // a flood of unanswered SYNs can delay unrelated replies on an IPv6 scan.
  const tcpCheck = await nmapPorts(address, ["-sS", "-p", [...tcp, ...privatePorts].join(",")]);
  const udpResults = await nmapPorts(address, ["-sU", "-p", [...udp, ...privatePorts].join(",")]);
  const tcpSweep = await nmapPorts(address, ["-sS", "-p-", "--open", "--min-rate", "2000"]);
  const openTcp = new Set(
    [...tcpCheck, ...tcpSweep].filter(({ state }) => state === "open").map(({ port }) => port),
  );
  const unexpected = [...openTcp].filter(
    (port) => !tcp.includes(port) || restricted.get(port) === "deny-all",
  );
  const missing = tcp.filter(
    (port) => (restricted.get(port) ?? "internet") === "internet" && !openTcp.has(port),
  );
  const missingUdp = udp.filter(
    (port) =>
      !udpResults.some((entry) => entry.port === port && ["open", "open|filtered"].includes(entry.state)),
  );
  const unexpectedUdp = udpResults.filter(({ port, state }) => state === "open" && !udp.includes(port));
  if (unexpected.length || missing.length || missingUdp.length || unexpectedUdp.length) {
    throw new Error(
      `${address} failed the external scan. Unexpected TCP ${unexpected.join(",") || "none"}, missing TCP ${missing.join(",") || "none"}, unexpected UDP ${unexpectedUdp.map(({ port }) => port).join(",") || "none"}, missing UDP ${missingUdp.join(",") || "none"}. UDP probe: ${udpResults.map(({ port, state }) => `${port} ${state}`).join(", ")}.`,
    );
  }
  const udpSummary = udpResults
    .filter(({ port }) => udp.includes(port))
    .map(({ port, state }) => `${port} ${state}`);
  console.log(
    `${address} TCP open: ${[...openTcp].toSorted((a, b) => a - b).join(", ")}. UDP: ${udpSummary.join(", ")}.`,
  );
}

export async function readExternalInventory(file: string) {
  const { config } = JSON.parse(await readFile(file, "utf8")) as { config: HostPortConfig };
  publicHostPorts(config);
  return config;
}

async function main(args: string[]) {
  if (args[0] === "--external" && args.length >= 3) {
    const config = await readExternalInventory(args[1]!);
    await Promise.all(args.slice(2).map((address) => auditExternal(config, address)));
    return;
  }
  if (args.length > 1 || (args.length === 1 && args[0] !== "--inventory")) {
    throw new Error("Usage: host:audit [--inventory | --external INVENTORY.json IP [IP...]]");
  }
  const config = await appliedHostConfig(join(import.meta.dir, ".."));
  if (args[0] === "--inventory") {
    console.log(JSON.stringify({ config, providerRules: providerFirewallRules(config) }, null, 2));
    return;
  }
  await auditLocal(config);
  console.log("Host listeners, Docker publications and ark_host match the public inventory.");
}

if (import.meta.main) await main(process.argv.slice(2));
