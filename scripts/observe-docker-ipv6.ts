import { rename, writeFile, stat } from "node:fs/promises";
import { join } from "node:path";

import {
  IPV6_PREFLIGHT_HTTP_PATH,
  publicIpv6,
  type Ipv6DockerState,
  type Ipv6EdgeLog,
} from "@ark-stack/shared";

import {
  daemonConfigPath,
  dockerStartedAt,
  publishedNetworkState,
  readDockerDaemonConfig,
} from "./install-docker-ipv6.ts";
import { hostCommand } from "./install-host-hardening.ts";

export function parseIpv6EdgeLogs(lines: string, service: "edge" | "edge-l4") {
  const events: Ipv6EdgeLog[] = [];
  for (const entry of lines.split("\n")) {
    const separator = entry.indexOf(" ");
    if (separator < 0) continue;
    const at = Date.parse(entry.slice(0, separator));
    if (!Number.isFinite(at)) continue;
    const line = entry.slice(separator + 1);
    if (service === "edge-l4") {
      // HAProxy's default tcplog: client:port, accept date, frontend, backend/server,
      // queue/connect/total timings. Tc is -1 when HAProxy never reached a backend.
      const match = /^(\S+):(\d+)\s+\[[^\]]+\]\s+(\S+)\s+(\S+)\/(\S+)\s+-?\d+\/(-?\d+)\/-?\d+\s/.exec(line);
      const source = publicIpv6(match?.[1]?.replace(/^\[|\]$/g, ""));
      if (match && source) {
        events.push({
          protocol: "haproxy",
          at,
          source,
          sourcePort: Number(match[2]),
          frontend: match[3]!.replace(/~$/, ""),
          backend: match[4]!,
          server: match[5]!,
          connected: Number(match[6]) >= 0 && match[5] !== "<NOSRV>",
        });
      }
    } else if (line.includes(IPV6_PREFLIGHT_HTTP_PATH)) {
      try {
        const record = JSON.parse(line);
        const request = record.request;
        const source = publicIpv6(request?.remote_ip);
        if (
          source &&
          typeof request?.uri === "string" &&
          request.uri.startsWith(IPV6_PREFLIGHT_HTTP_PATH) &&
          typeof request.host === "string" &&
          [404, 301, 302, 307, 308].includes(record.status)
        ) {
          events.push({
            protocol: "http",
            at,
            source,
            sourcePort: Number(request.remote_port),
            path: request.uri,
            hostname: request.host,
          });
        }
      } catch {
        // Only structured Caddy access logs count as evidence.
      }
    }
  }
  return events;
}

async function edgeLogs(service: "edge" | "edge-l4") {
  const id = (
    await hostCommand("docker", [
      "ps",
      "-q",
      "--filter",
      "label=com.docker.compose.project=ark-platform",
      "--filter",
      `label=com.docker.compose.service=${service}`,
    ])
  ).trim();
  if (!/^[a-f0-9]{12,64}$/.test(id)) throw new Error(`Expected one running ${service} container.`);
  // Docker writes container stderr to the CLI's stderr. Caddy logs requests there.
  const process = Bun.spawn(["docker", "logs", "--timestamps", "--since", "16m", "--tail", "4096", id], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, stdout, stderr] = await Promise.all([
    process.exited,
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
  ]);
  if (status !== 0) throw new Error(`Could not read ${service} access logs.`);
  return parseIpv6EdgeLogs(stdout + "\n" + stderr, service);
}

async function observeDocker(): Promise<Ipv6DockerState> {
  const { config, raw } = await readDockerDaemonConfig();
  const started = await dockerStartedAt();
  const configLoaded = raw !== null && (await stat(daemonConfigPath)).mtimeMs < Date.parse(started) + 1_000;
  const [bridge] = JSON.parse(await hostCommand("docker", ["network", "inspect", "bridge"]));
  const liveRestore =
    (await hostCommand("docker", ["info", "--format", "{{.LiveRestoreEnabled}}"])).trim() === "true";
  const filter =
    config["firewall-backend"] === "nftables"
      ? await hostCommand("nft", ["list", "table", "ip6", "docker-bridges"]).catch(() => "")
      : await hostCommand("ip6tables", ["-t", "nat", "-S", "DOCKER"]).catch(() => "");
  return {
    ...(await publishedNetworkState("ark-platform", "admin", "edge-ts")),
    at: Date.now(),
    daemon: started,
    ipv6: configLoaded && config.ipv6 === true && bridge?.EnableIPv6 === true,
    ip6tables: configLoaded && config.ip6tables === true && Boolean(filter.trim()),
    userlandProxy: !configLoaded || config["userland-proxy"] !== false,
    liveRestore,
  };
}

export async function observeDockerIpv6(directory: string) {
  const [docker, http, tcp] = await Promise.all([observeDocker(), edgeLogs("edge"), edgeLogs("edge-l4")]);
  const path = join(directory, "snapshot.json");
  const temporary = path + "." + crypto.randomUUID();
  await writeFile(temporary, JSON.stringify({ docker, logs: [...http, ...tcp] }), {
    mode: 0o644,
    flag: "wx",
  });
  await rename(temporary, path);
}

if (import.meta.main) {
  const directory = process.argv[2];
  if (!directory) throw new Error("Supply the Docker IPv6 observation directory.");
  await observeDockerIpv6(directory);
}
