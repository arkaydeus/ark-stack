import { readFile } from "node:fs/promises";
import { isIP } from "node:net";

import { publicHostPorts, type HostPortConfig } from "@ark-stack/shared";

import { hostCommand } from "./install-host-hardening.ts";

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

export async function auditExternal(
  config: HostPortConfig,
  address: string,
  observeUdp?: (address: string, ports: number[]) => Promise<ReadonlySet<number>>,
) {
  if (!isIP(address) || address.includes("%")) throw new Error("Provide an IPv4 or IPv6 address literal.");
  const { tcp, udp } = publicHostPorts(config);
  const restricted = new Map(config.routes?.map(({ port, policy }) => [port, policy]));
  const privatePorts = [22, 2019, 3000, 15432];
  // Probe the inventory at normal timing before the full-range scan. In particular,
  // a flood of unanswered SYNs can delay unrelated replies on an IPv6 scan.
  const tcpCheck = await nmapPorts(address, ["-sS", "-p", [...tcp, ...privatePorts].join(",")]);
  const udpResults = await nmapPorts(address, ["-sU", "-p", [...udp, ...privatePorts].join(",")]);
  // UDP services that ignore unsolicited datagrams cannot be discovered by a port sweep.
  const [tcpSweep, udpSweep] = await Promise.all([
    nmapPorts(address, ["-sS", "-p-", "--open", "--min-rate", "2000"]),
    nmapPorts(address, ["-sU", "-p-", "--open", "--min-rate", "2000"]),
  ]);
  const openTcp = new Set(
    [...tcpCheck, ...tcpSweep].filter(({ state }) => state === "open").map(({ port }) => port),
  );
  const unexpected = [...openTcp].filter(
    (port) => !tcp.includes(port) || restricted.get(port) === "deny-all",
  );
  const missing = tcp.filter(
    (port) => (restricted.get(port) ?? "internet") === "internet" && !openTcp.has(port),
  );
  const openUdp = new Set(
    [...udpResults, ...udpSweep].filter(({ state }) => state === "open").map(({ port }) => port),
  );
  const unexpectedUdp = [...openUdp].filter((port) => !udp.includes(port));
  const unresolvedUdp = udp.filter((port) => !openUdp.has(port));
  const observed = unresolvedUdp.length && observeUdp ? await observeUdp(address, unresolvedUdp) : new Set();
  const missingUdp = unresolvedUdp.filter((port) => !observed.has(port));
  if (unexpected.length || missing.length || missingUdp.length || unexpectedUdp.length) {
    throw new Error(
      `${address} failed the external scan. Unexpected TCP ${unexpected.join(",") || "none"}, missing TCP ${missing.join(",") || "none"}, unexpected UDP ${unexpectedUdp.join(",") || "none"}, UDP reachability unverified for ${missingUdp.join(",") || "none"}. UDP probe: ${udpResults.map(({ port, state }) => `${port} ${state}`).join(", ")}.`,
    );
  }
  const udpSummary = udp.map((port) => `${port} ${openUdp.has(port) ? "open" : "observed at VPS"}`);
  console.log(
    `${address} TCP open: ${[...openTcp].toSorted((a, b) => a - b).join(", ")}. UDP: ${udpSummary.join(", ")}.`,
  );
}

export async function readExternalInventory(file: string) {
  const { config } = JSON.parse(await readFile(file, "utf8")) as { config: HostPortConfig };
  publicHostPorts(config);
  return config;
}
