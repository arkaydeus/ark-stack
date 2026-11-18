import { mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { isIPv6 } from "node:net";

import { hostCommand } from "./install-host-hardening.ts";

export const daemonConfigPath = "/etc/docker/daemon.json";
export const dockerIpv6EvidenceDir = "/var/lib/ark/ipv6";

export function dockerStartedAt() {
  return hostCommand("env", [
    "TZ=UTC",
    "systemctl",
    "show",
    "-p",
    "ExecMainStartTimestamp",
    "--value",
    "docker.service",
  ]).then((value) => value.trim());
}

export async function readDockerDaemonConfig(path = daemonConfigPath) {
  const raw = await readFile(path, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
  const config = raw === null ? {} : JSON.parse(raw);
  if (!config || Array.isArray(config) || typeof config !== "object") {
    throw new Error("Docker's daemon.json must contain an object.");
  }
  return { raw, config: config as Record<string, unknown> };
}

export function dockerIpv6DaemonConfig(config: Record<string, unknown>, disableProxy: boolean) {
  return {
    ...config,
    ipv6: true,
    ip6tables: true,
    "live-restore": true,
    ...(disableProxy ? { "userland-proxy": false } : {}),
  };
}

export async function configureDockerIpv6(disableProxy: boolean) {
  const { raw, config } = await readDockerDaemonConfig();
  const desired = dockerIpv6DaemonConfig(config, disableProxy);
  const changed = JSON.stringify(desired) !== JSON.stringify(config);
  const [current] = JSON.parse(await hostCommand("docker", ["network", "inspect", "bridge"]));
  const liveRestore = (await hostCommand("docker", ["info", "--format", "{{.LiveRestoreEnabled}}"])).trim();
  const loaded =
    raw !== null && (await stat(daemonConfigPath)).mtimeMs < Date.parse(await dockerStartedAt()) + 1_000;
  if (!changed && loaded && current?.EnableIPv6 && liveRestore === "true") return false;

  await mkdir(dirname(daemonConfigPath), { recursive: true });
  const next = `${daemonConfigPath}.${crypto.randomUUID()}.tmp`;
  const mode = raw === null ? 0o644 : (await stat(daemonConfigPath)).mode & 0o777;
  try {
    await writeFile(next, JSON.stringify(desired, null, 2) + "\n", { flag: "wx", mode });
    await hostCommand("dockerd", ["--validate", "--config-file", next]);
    await rename(next, daemonConfigPath);
    try {
      await hostCommand("systemctl", ["restart", "docker.service"]);
      await hostCommand("docker", ["info"]);
      const [bridge] = JSON.parse(await hostCommand("docker", ["network", "inspect", "bridge"]));
      if (
        !bridge?.EnableIPv6 ||
        (await hostCommand("docker", ["info", "--format", "{{.LiveRestoreEnabled}}"])).trim() !== "true"
      ) {
        throw new Error("Docker did not start with IPv6 and live-restore enabled.");
      }
    } catch (error) {
      if (raw === null) await rm(daemonConfigPath);
      else {
        await writeFile(next, raw, { flag: "wx", mode });
        await rename(next, daemonConfigPath);
      }
      await hostCommand("systemctl", ["restart", "docker.service"]);
      throw error;
    }
    return true;
  } finally {
    await rm(next, { force: true });
  }
}

type DockerNetwork = {
  Id: string;
  EnableIPv6: boolean;
  Labels: Record<string, string>;
  Containers: Record<string, { Name: string }> | null;
};

type PublishedNetwork = {
  project: string;
  network: string;
  service: string;
  compose: string[];
  dependents?: string[];
};

export async function migratePublishedNetwork({
  project,
  network,
  compose,
  dependents = [],
}: PublishedNetwork) {
  const name = `${project}_${network}`;
  const ids = await hostCommand("docker", ["network", "ls", "-q", "--filter", `name=^${name}$`]);
  if (!ids.trim()) return;
  const [existing] = JSON.parse(await hostCommand("docker", ["network", "inspect", name])) as DockerNetwork[];
  if (!existing) throw new Error(`Could not inspect ${name}.`);
  if (
    existing.Labels?.["com.docker.compose.project"] !== project ||
    existing.Labels?.["com.docker.compose.network"] !== network
  ) {
    throw new Error(`Docker network ${name} is not owned by this Compose project.`);
  }
  if (existing.EnableIPv6) return;
  const containers = Object.keys(existing.Containers ?? {});
  const services = new Set(dependents);
  for (const id of containers) {
    const labels = JSON.parse(
      await hostCommand("docker", ["inspect", "--format", "{{json .Config.Labels}}", id]),
    );
    const service = labels?.["com.docker.compose.service"];
    if (labels?.["com.docker.compose.project"] !== project || !/^[a-z0-9][a-z0-9_-]*$/.test(service ?? "")) {
      throw new Error(`Docker network ${name} has an attachment outside the Compose project.`);
    }
    services.add(service);
  }
  if (services.size) await hostCommand("docker", [...compose, "rm", "--stop", "--force", ...services]);
  await hostCommand("docker", ["network", "rm", existing.Id]);
}

export async function publishedNetworkState(project: string, network: string, service: string) {
  const name = `${project}_${network}`;
  const [existing] = JSON.parse(await hostCommand("docker", ["network", "inspect", name])) as DockerNetwork[];
  const id = (
    await hostCommand("docker", [
      "ps",
      "-q",
      "--no-trunc",
      "--filter",
      `label=com.docker.compose.project=${project}`,
      "--filter",
      `label=com.docker.compose.service=${service}`,
    ])
  ).trim();
  if (!/^[a-f0-9]{64}$/.test(id)) throw new Error(`Expected one running ${project}/${service} container.`);
  const networks = JSON.parse(
    await hostCommand("docker", ["inspect", "--format", "{{json .NetworkSettings.Networks}}", id]),
  );
  const endpoint = networks?.[name];
  const edgeAddress = endpoint?.GlobalIPv6Address as string | undefined;
  return {
    edge: id,
    networkIpv6: existing?.EnableIPv6 === true && endpoint?.NetworkID === existing.Id,
    edgeAddress: edgeAddress && isIPv6(edgeAddress) && !/^fe[89ab]/i.test(edgeAddress) ? edgeAddress : null,
  };
}

export async function verifyPublishedNetwork({ project, network, service }: PublishedNetwork) {
  const state = await publishedNetworkState(project, network, service);
  if (!state.networkIpv6 || !state.edgeAddress) {
    throw new Error(
      `Verify an IPv6 address on ${service} in ${project}_${network} before disabling Docker's proxy.`,
    );
  }
  return state.edge;
}

export async function publicationPredatesDaemonConfig(id: string) {
  const created = await hostCommand("docker", ["inspect", "--format", "{{.Created}}", id]);
  return Date.parse(created.trim()) <= (await stat(daemonConfigPath)).mtimeMs;
}

// Disabling the daemon-wide proxy would remove the IPv6 translation used by any
// wildcard publication backed exclusively by an IPv4 endpoint.
export async function verifyOtherIpv6Publications() {
  const ids = (await hostCommand("docker", ["ps", "-q"])).trim().split("\n").filter(Boolean);
  if (!ids.length) return;
  const containers = JSON.parse(await hostCommand("docker", ["inspect", ...ids])) as {
    Name: string;
    HostConfig: { PortBindings?: Record<string, { HostIp: string }[] | null> };
    NetworkSettings: { Networks: Record<string, { GlobalIPv6Address: string }> };
  }[];
  for (const container of containers) {
    const wildcard = Object.values(container.HostConfig.PortBindings ?? {})
      .flat()
      .some((port) => port && (port.HostIp === "" || port.HostIp === "::"));
    if (!wildcard) continue;
    const hasIpv6 = Object.values(container.NetworkSettings.Networks ?? {}).some(({ GlobalIPv6Address }) =>
      isIPv6(GlobalIPv6Address),
    );
    if (!hasIpv6) {
      throw new Error(
        `Give ${container.Name} an IPv6 Docker network or explicitly bind its ports to IPv4 before disabling the userland proxy.`,
      );
    }
  }
}

export async function installIpv6Observer(root: string) {
  await mkdir(dockerIpv6EvidenceDir, { recursive: true, mode: 0o755 });
  const executable = "/usr/local/lib/ark/observe-docker-ipv6";
  await mkdir(dirname(executable), { recursive: true, mode: 0o755 });
  const candidate = executable + "." + crypto.randomUUID();
  try {
    // The persistent root service runs an installed executable, independently of checkout and Bun updates.
    await hostCommand(process.execPath, [
      "build",
      "--compile",
      join(root, "scripts", "observe-docker-ipv6.ts"),
      "--outfile",
      candidate,
    ]);
    await rename(candidate, executable);
  } finally {
    await rm(candidate, { force: true });
  }
  const unit = "/etc/systemd/system/ark-docker-ipv6";
  await writeFile(
    `${unit}.service`,
    `[Unit]
Description=Observe Docker native IPv6 and edge connections
After=docker.service
[Service]
Type=oneshot
ExecStart=${executable} ${dockerIpv6EvidenceDir}
TimeoutStartSec=20s
`,
    { mode: 0o644 },
  );
  await writeFile(
    `${unit}.timer`,
    `[Unit]
Description=Refresh Ark Docker IPv6 evidence
[Timer]
OnBootSec=10s
OnUnitInactiveSec=5s
AccuracySec=1s
[Install]
WantedBy=timers.target
`,
    { mode: 0o644 },
  );
  await hostCommand("systemctl", ["daemon-reload"]);
  await hostCommand("systemctl", ["enable", "--now", "ark-docker-ipv6.timer"]);
  await hostCommand("systemctl", ["start", "ark-docker-ipv6.service"]);
}
