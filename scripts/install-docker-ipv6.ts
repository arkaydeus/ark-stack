import { mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { isIPv6 } from "node:net";

import { hostCommand } from "./install-host-hardening.ts";

export const daemonConfigPath = "/etc/docker/daemon.json";
export const dockerIpv6EvidenceDir = "/var/lib/ark/ipv6";

export function dockerStartedAt(command = hostCommand) {
  return command("env", [
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

export async function configureDockerIpv6(
  disableProxy: boolean,
  { path = daemonConfigPath, command = hostCommand } = {},
) {
  const { raw, config } = await readDockerDaemonConfig(path);
  const desired = dockerIpv6DaemonConfig(config, disableProxy);
  const changed = JSON.stringify(desired) !== JSON.stringify(config);
  const [current] = JSON.parse(await command("docker", ["network", "inspect", "bridge"]));
  const liveRestore = (await command("docker", ["info", "--format", "{{.LiveRestoreEnabled}}"])).trim();
  const loaded =
    raw !== null && (await stat(path)).mtimeMs < Date.parse(await dockerStartedAt(command)) + 1_000;
  if (!changed && loaded && current?.EnableIPv6 && liveRestore === "true") return false;

  await mkdir(dirname(path), { recursive: true });
  const next = `${path}.${crypto.randomUUID()}.tmp`;
  const mode = raw === null ? 0o644 : (await stat(path)).mode & 0o777;
  try {
    await writeFile(next, JSON.stringify(desired, null, 2) + "\n", { flag: "wx", mode });
    await command("dockerd", ["--validate", "--config-file", next]);
    await rename(next, path);
    try {
      await command("systemctl", ["restart", "docker.service"]);
      await command("docker", ["info"]);
      const [bridge] = JSON.parse(await command("docker", ["network", "inspect", "bridge"]));
      if (
        !bridge?.EnableIPv6 ||
        (await command("docker", ["info", "--format", "{{.LiveRestoreEnabled}}"])).trim() !== "true"
      ) {
        throw new Error("Docker did not start with IPv6 and live-restore enabled.");
      }
    } catch (error) {
      if (raw === null) await rm(path);
      else {
        await writeFile(next, raw, { flag: "wx", mode });
        await rename(next, path);
      }
      await command("systemctl", ["restart", "docker.service"]);
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

export async function migratePublishedNetwork(
  { project, network, compose, dependents = [] }: PublishedNetwork,
  command = hostCommand,
) {
  const name = `${project}_${network}`;
  const ids = await command("docker", ["network", "ls", "-q", "--filter", `name=^${name}$`]);
  if (!ids.trim()) return;
  const [existing] = JSON.parse(await command("docker", ["network", "inspect", name])) as DockerNetwork[];
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
      await command("docker", ["inspect", "--format", "{{json .Config.Labels}}", id]),
    );
    const service = labels?.["com.docker.compose.service"];
    if (labels?.["com.docker.compose.project"] !== project || !/^[a-z0-9][a-z0-9_-]*$/.test(service ?? "")) {
      throw new Error(`Docker network ${name} has an attachment outside the Compose project.`);
    }
    services.add(service);
  }
  if (services.size) await command("docker", [...compose, "rm", "--stop", "--force", ...services]);
  await command("docker", ["network", "rm", existing.Id]);
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
export async function verifyOtherIpv6Publications(command = hostCommand) {
  const ids = (await command("docker", ["ps", "-q"])).trim().split("\n").filter(Boolean);
  if (!ids.length) return;
  const containers = JSON.parse(await command("docker", ["inspect", ...ids])) as {
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

export async function installIpv6Observer(
  root: string,
  {
    directory = dockerIpv6EvidenceDir,
    executable = "/usr/local/lib/ark/observe-docker-ipv6",
    unit = "/etc/systemd/system/ark-docker-ipv6",
    command = hostCommand,
  } = {},
) {
  await mkdir(directory, { recursive: true, mode: 0o755 });
  await mkdir(dirname(executable), { recursive: true, mode: 0o755 });
  const candidate = executable + "." + crypto.randomUUID();
  try {
    // The persistent root service runs an installed executable, independently of checkout and Bun updates.
    await command(process.execPath, [
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
  await writeFile(
    `${unit}.service`,
    `[Unit]
Description=Observe Docker native IPv6 and edge connections
After=docker.service
[Service]
Type=oneshot
ExecStart=${executable} ${directory}
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
  await command("systemctl", ["daemon-reload"]);
  await command("systemctl", ["enable", "--now", "ark-docker-ipv6.timer"]);
  await command("systemctl", ["start", "ark-docker-ipv6.service"]);
}

/** Stage the daemon and networks while the Docker proxy can still serve IPv4-only endpoints. */
export async function preparePublishedIpv6({
  edge,
  mail,
  hardened,
  tailnetRestorePath,
}: {
  edge: PublishedNetwork;
  mail?: PublishedNetwork;
  hardened: boolean;
  tailnetRestorePath: string;
}) {
  // The optional admin profile shares the old network. Remember its live services across retries
  // so replacing the bridge or restarting Docker cannot strand a tailnet admin installation.
  const tailnetLabels = await hostCommand("docker", [
    "ps",
    "--filter",
    `label=com.docker.compose.project=${edge.project}`,
    "--format",
    '{{.Label "com.docker.compose.service"}}',
  ]);
  const previousTailnet = (await Bun.file(tailnetRestorePath).exists())
    ? await Bun.file(tailnetRestorePath).text()
    : "";
  const tailnetServices = [
    ...new Set(
      (tailnetLabels + "\n" + previousTailnet)
        .split("\n")
        .filter((service) => service === "tailscale" || service === "tailnet-gateway"),
    ),
  ];
  const tailnetCompose = [...edge.compose, "--profile", "tailnet"];
  if (tailnetServices.length) await Bun.write(tailnetRestorePath, tailnetServices.join("\n"));
  // Preserve IPv6-to-IPv4 proxying until the published containers have dual-stack endpoints.
  if (hardened) await configureDockerIpv6(false);
  await migratePublishedNetwork(
    tailnetServices.length
      ? {
          ...edge,
          compose: tailnetCompose,
          dependents: [...(edge.dependents ?? []), "tailnet-gateway", "tailscale"],
        }
      : edge,
  );
  if (mail) await migratePublishedNetwork(mail);
  if (!tailnetServices.length) return;
  return async () => {
    await hostCommand("docker", [
      ...tailnetCompose,
      "up",
      "-d",
      "--wait",
      "--wait-timeout",
      "120",
      ...tailnetServices,
    ]);
    await rm(tailnetRestorePath, { force: true });
  };
}

/** Verify endpoints before turning off the Docker proxy and recreating pre-transition publications. */
export async function finishPublishedIpv6(edge: PublishedNetwork, mail?: PublishedNetwork) {
  const edgeId = await verifyPublishedNetwork(edge);
  const mailId = mail ? await verifyPublishedNetwork(mail) : null;
  if ((await readDockerDaemonConfig()).config["userland-proxy"] !== false) {
    await verifyOtherIpv6Publications();
  }
  await configureDockerIpv6(true);
  // Live-restore can retain publications created under the old daemon settings.
  if (await publicationPredatesDaemonConfig(edgeId)) {
    const services = [...(edge.dependents ?? []), edge.service];
    await hostCommand("docker", [...edge.compose, "rm", "--stop", "--force", ...services]);
    await hostCommand("docker", [
      ...edge.compose,
      "up",
      "-d",
      "--wait",
      "--wait-timeout",
      "120",
      ...services.toReversed(),
    ]);
  }
  if (mail && mailId && (await publicationPredatesDaemonConfig(mailId))) {
    await hostCommand("docker", [
      ...mail.compose,
      "up",
      "-d",
      "--wait",
      "--wait-timeout",
      "120",
      "--force-recreate",
      mail.service,
    ]);
  }
  await verifyPublishedNetwork(edge);
  if (mail) await verifyPublishedNetwork(mail);
}
