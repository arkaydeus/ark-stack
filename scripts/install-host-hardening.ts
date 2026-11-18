import { chmod, mkdir, rename, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import {
  ARK_VPS_TAG,
  HOST_FIREWALL_TABLE,
  assertHostFirewall,
  renderHostFirewall,
  type HostPortConfig,
} from "@ark-stack/shared";

export const hostFirewallPath = "/etc/nftables.d/ark-host.nft";
export const hostMetricsPath = "/var/lib/ark/host-metrics";
const systemd = "/etc/systemd/system";
const rebootService = "ark-host-reboot-metric.service";
const firewallService = "ark-host-firewall.service";

export async function hostCommand(command: string, args: string[], stdin?: string) {
  const child = Bun.spawn([command, ...args], {
    env: process.env,
    stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, output, error] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (status !== 0) throw new Error(`${command} exited ${status}. ${(error || output).trim().slice(-4000)}`);
  return output;
}

function requireLinuxRoot() {
  if (process.platform !== "linux" || process.getuid?.() !== 0) {
    throw new Error("VPS host setup requires root on the Ubuntu VPS.");
  }
}

async function aptInstall(packages: string[]) {
  await hostCommand("apt-get", ["update"]);
  await hostCommand("apt-get", ["install", "-y", "--no-install-recommends", ...packages]);
}

async function tailscaleState() {
  return JSON.parse(await hostCommand("tailscale", ["status", "--json"])) as {
    BackendState: string;
    TUN: boolean;
    Self?: { Online: boolean; Tags?: string[] };
  };
}

function vpsNodeReady(state: Awaited<ReturnType<typeof tailscaleState>>) {
  return (
    state.BackendState === "Running" &&
    state.TUN &&
    state.Self?.Online &&
    state.Self.Tags?.length === 1 &&
    state.Self.Tags[0] === ARK_VPS_TAG
  );
}

export async function enrollVps() {
  requireLinuxRoot();
  if (!Bun.which("tailscale")) await aptInstall(["tailscale"]);
  await hostCommand("systemctl", ["enable", "--now", "tailscaled.service"]);
  const state = await tailscaleState();
  if (!vpsNodeReady(state)) {
    if (state.BackendState === "Running") {
      throw new Error(`The running Tailscale node must use the host TUN interface and only ${ARK_VPS_TAG}.`);
    }
    const keyFile = process.env.TS_VPS_AUTHKEY_FILE;
    if (!keyFile?.startsWith("/") || ((await stat(keyFile)).mode & 0o077) !== 0) {
      throw new Error(`Set TS_VPS_AUTHKEY_FILE to a private absolute key file for ${ARK_VPS_TAG}.`);
    }
    await hostCommand("tailscale", [
      "up",
      `--auth-key=file:${keyFile}`,
      `--advertise-tags=${ARK_VPS_TAG}`,
      "--accept-dns=false",
    ]);
  }
  if (!vpsNodeReady(await tailscaleState()))
    throw new Error(`The host Tailscale node must be running with ${ARK_VPS_TAG}.`);
  await hostCommand("tailscale", ["set", "--ssh"]);
  console.log("Verify Tailscale SSH as the owner before running host:install --harden-vps.");
}

async function installFile(path: string, content: string) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${crypto.randomUUID()}.tmp`;
  await writeFile(temporary, content, { mode: 0o644, flag: "wx" });
  await rename(temporary, path);
}

export function automaticUpdatesConfig(rebootTime: string) {
  if (!/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(rebootTime)) {
    throw new Error("ARK_HOST_REBOOT_TIME must be a 24-hour HH:MM value in the host time zone.");
  }
  return `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "${rebootTime}";
`;
}

export function rebootMetricCommands(directory: string) {
  return [
    [
      "/usr/bin/find",
      "/run",
      "-maxdepth",
      "1",
      "-name",
      "reboot-required",
      "-fprint",
      `${directory}/.reboot-required`,
    ],
    ["/usr/bin/mv", "-fT", `${directory}/.reboot-required`, `${directory}/reboot-required`],
  ];
}

export async function installHostHardening(config: HostPortConfig) {
  requireLinuxRoot();
  if (
    !vpsNodeReady(await tailscaleState()) ||
    !JSON.parse(await hostCommand("tailscale", ["debug", "prefs"])).RunSSH
  ) {
    throw new Error("Run host:install --enroll-vps and verify owner Tailscale SSH first.");
  }
  const updates = automaticUpdatesConfig(process.env.ARK_HOST_REBOOT_TIME ?? "04:00");
  await aptInstall(["nftables", "iproute2", "unattended-upgrades"]);
  await installFile("/etc/apt/apt.conf.d/52ark-unattended-upgrades", updates);
  await hostCommand("unattended-upgrades", ["--dry-run"]);
  await hostCommand("systemctl", ["enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer"]);

  await mkdir(hostMetricsPath, { recursive: true, mode: 0o755 });
  await chmod(hostMetricsPath, 0o755);
  await installFile(
    `${systemd}/${rebootService}`,
    `[Unit]
Description=Record whether the Ark VPS needs a reboot
[Service]
Type=oneshot
UMask=0022
${rebootMetricCommands(hostMetricsPath)
  .map((command) => `ExecStart=${command.join(" ")}`)
  .join("\n")}
`,
  );
  await installFile(
    `${systemd}/ark-host-reboot-metric.timer`,
    `[Unit]
Description=Refresh the Ark VPS reboot metric
[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
[Install]
WantedBy=timers.target
`,
  );
  await installFile(
    `${systemd}/${firewallService}`,
    `[Unit]
Description=Ark VPS firewall baseline
DefaultDependencies=no
Wants=network-pre.target
After=local-fs.target nftables.service
Before=network-pre.target docker.service shutdown.target
Conflicts=shutdown.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ${hostFirewallPath}
[Install]
WantedBy=multi-user.target
`,
  );
  await installFile(
    `${systemd}/docker.service.d/ark-host-firewall.conf`,
    `[Unit]
Requires=${firewallService}
After=${firewallService}
`,
  );
  // Boot starts with dedicated routes closed. The reconciler restores them with verified ark_front.
  const baseline = renderHostFirewall({ ...config, routes: [] });
  await hostCommand("nft", ["-c", "-f", "-"], baseline);
  await installFile(hostFirewallPath, baseline);
  await hostCommand("systemctl", ["daemon-reload"]);
  await hostCommand("systemctl", ["start", rebootService]);
  await hostCommand("systemctl", ["enable", "--now", "ark-host-reboot-metric.timer"]);
  await hostCommand("systemctl", ["enable", "--now", firewallService]);
  // Preserve acknowledged routes on an update. The new reconciler will replay the full policy.
  const active = renderHostFirewall(config);
  await hostCommand("nft", ["-f", "-"], active);
  assertHostFirewall(
    await hostCommand("nft", ["-s", "-y", "list", "table", "inet", HOST_FIREWALL_TABLE]),
    config,
  );
}
