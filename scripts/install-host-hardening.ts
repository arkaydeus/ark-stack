import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import {
  ARK_VPS_TAG,
  HOST_FIREWALL_TABLE,
  assertHostFirewall,
  readHostSshAccess,
  renderHostFirewall,
  type HostPortConfig,
  type HostSshAccess,
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
  await hostCommand("apt-get", ["install", "-y", "--no-remove", "--no-install-recommends", ...packages]);
}

export type TailscaleState = {
  BackendState: string;
  TUN: boolean;
  Self?: {
    ID?: string;
    PublicKey?: string;
    Online: boolean;
    Tags?: string[];
    /** The requested machine name (`--hostname`, else the OS hostname). */
    HostName?: string;
    /** The MagicDNS name Tailscale assigned; its first label may carry a `-1` suffix. */
    DNSName?: string;
    TailscaleIPs?: string[];
  };
};

export const TAILSCALE_HOSTNAME_RULES =
  "use 1-63 lowercase letters, digits and hyphens, not starting or ending with a hyphen (no spaces, dots or underscores)";

/** A Tailscale machine name: one DNS label. Uppercase is lowercased; anything else invalid is refused. */
export function validateTailscaleHostname(value: string, label = "Tailscale machine name") {
  const name = value.trim().toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(name)) {
    throw new Error(`${label} "${value.trim()}" is not valid: ${TAILSCALE_HOSTNAME_RULES}.`);
  }
  return name;
}

/** The name Tailscale assigned: the first label of the node's MagicDNS name. */
export function assignedTailscaleName(state: TailscaleState | undefined) {
  return state?.Self?.DNSName?.replace(/\.$/, "").split(".")[0] || undefined;
}

/** The assigned name is the requested one, or Tailscale's `-<n>` suffix for a taken name. */
export function assignedNameSettled(state: TailscaleState | undefined, requested: string) {
  const assigned = assignedTailscaleName(state);
  if (state?.Self?.HostName !== requested || !assigned) return false;
  return (
    assigned === requested ||
    (assigned.startsWith(requested) && /^-\d+$/.test(assigned.slice(requested.length)))
  );
}

/** Says when Tailscale assigned a different name than the one requested, else nothing. */
export function nameDifference(requested: string, assigned: string | undefined) {
  if (!assigned || assigned === requested) return undefined;
  return `Tailscale assigned the name ${assigned}, not the requested ${requested} (the name is taken on the tailnet, or the machine was renamed in the admin console).`;
}

async function tailscaleState() {
  return JSON.parse(await hostCommand("tailscale", ["status", "--json"])) as TailscaleState;
}

export const VPS_NODE_OFFLINE = "the node is not online with the Tailscale control server yet";

/** Why the host node is not up on the host TUN interface, online and tagged exactly `tag:ark-vps`. */
export function vpsNodeProblem(state: TailscaleState): string | undefined {
  if (state.BackendState !== "Running") return `Tailscale is ${state.BackendState || "not running"}`;
  if (!state.TUN) return "tailscaled uses userspace networking, not the host TUN interface";
  const tags = state.Self?.Tags ?? [];
  if (tags.length !== 1 || tags[0] !== ARK_VPS_TAG) {
    const current = tags.length ? `tagged ${tags.join(", ")}` : "untagged (owned by a user)";
    return `the node is ${current}; it must be tagged exactly ${ARK_VPS_TAG}`;
  }
  if (!state.Self?.Online) return VPS_NODE_OFFLINE;
  return undefined;
}

/** The host node is up on the host TUN interface, online and tagged exactly `tag:ark-vps`. */
export function vpsNodeReady(state: TailscaleState) {
  return vpsNodeProblem(state) === undefined;
}

const ONLINE_POLL_MS = 2000;
const ONLINE_POLL_ATTEMPTS = 15;

/**
 * Reads the status again for up to ~30 s while the node is otherwise correct but not yet online:
 * `Self.Online` briefly reads false right after tailscaled starts or reconnects.
 */
export async function settledVpsNode<T extends TailscaleState | undefined>(
  read: () => Promise<T>,
  sleep: (ms: number) => Promise<void> = Bun.sleep,
): Promise<T> {
  let state = await read();
  for (
    let attempt = 1;
    attempt < ONLINE_POLL_ATTEMPTS && state && vpsNodeProblem(state) === VPS_NODE_OFFLINE;
    attempt++
  ) {
    await sleep(ONLINE_POLL_MS);
    state = await read();
  }
  return state;
}

const NAME_POLL_MS = 1000;
const NAME_POLL_ATTEMPTS = 10;

/**
 * Reads the status again for up to ~10 s until the control server reports the requested name (or
 * its `-<n>` form). A machine renamed in the admin console keeps that name, so this never fails.
 */
export async function settledTailscaleName<T extends TailscaleState | undefined>(
  read: () => Promise<T>,
  requested: string,
  sleep: (ms: number) => Promise<void> = Bun.sleep,
): Promise<T> {
  let state = await read();
  for (let attempt = 1; attempt < NAME_POLL_ATTEMPTS && !assignedNameSettled(state, requested); attempt++) {
    await sleep(NAME_POLL_MS);
    state = await read();
  }
  return state;
}

/** The host commands enrolVps uses; tests replace them with stubs. */
export type EnrollIo = {
  run: (command: string, args: string[], stdin?: string) => Promise<string>;
  which: (command: string) => string | null;
  requireRoot: () => void;
  sleep: (ms: number) => Promise<void>;
  log: (line: string) => void;
};

/**
 * Enrols the host node as `tag:ark-vps`. With `hostname` (TS_VPS_HOSTNAME), a fresh node joins
 * under that machine name and an enrolled, correctly tagged node is renamed in place with
 * `tailscale set --hostname`; it is never logged out or re-enrolled and its tags are untouched.
 * Without it, enrolment is unchanged.
 */
export async function enrollVps(
  readKey?: () => Promise<string>,
  requestedHostname: string | undefined = process.env.TS_VPS_HOSTNAME,
  stubs: Partial<EnrollIo> = {},
) {
  const io: EnrollIo = {
    run: hostCommand,
    which: (command) => Bun.which(command),
    requireRoot: requireLinuxRoot,
    sleep: Bun.sleep,
    log: (line) => console.log(line),
    ...stubs,
  };
  const readState = async () => JSON.parse(await io.run("tailscale", ["status", "--json"])) as TailscaleState;
  io.requireRoot();
  const hostname = requestedHostname?.trim()
    ? validateTailscaleHostname(requestedHostname, "TS_VPS_HOSTNAME")
    : undefined;
  if (!io.which("tailscale")) {
    await io.run("apt-get", ["update"]);
    await io.run("apt-get", ["install", "-y", "--no-remove", "--no-install-recommends", "tailscale"]);
  }
  await io.run("systemctl", ["enable", "--now", "tailscaled.service"]);
  const state = await settledVpsNode(readState, io.sleep);
  const problem = vpsNodeProblem(state);
  if (problem) {
    if (state.BackendState === "Running") {
      throw new Error(
        `The running Tailscale node must use the host TUN interface and only ${ARK_VPS_TAG}: ${problem}.`,
      );
    }
    const keyFile = readKey ? "/dev/stdin" : await vpsAuthKeyFile(process.env.TS_VPS_AUTHKEY_FILE);
    const args = [
      "up",
      `--auth-key=file:${keyFile}`,
      `--advertise-tags=${ARK_VPS_TAG}`,
      "--accept-dns=false",
      ...(hostname ? [`--hostname=${hostname}`] : []),
    ];
    if (readKey) {
      // Give Tailscale an anonymous pipe it can reopen. Bun's stdin may be backed by a socket.
      const key = (await readKey()).trim();
      if (!/^tskey-[A-Za-z0-9-]+$/.test(key)) throw new Error("Expected a Tailscale auth key on stdin.");
      await io.run("sh", ["-c", 'cat | tailscale "$@"', "sh", ...args], key);
    } else {
      await io.run("tailscale", args);
    }
  }
  const joined = await settledVpsNode(readState, io.sleep);
  const enrolled = vpsNodeProblem(joined);
  if (enrolled) throw new Error(`The host Tailscale node must be running with ${ARK_VPS_TAG}: ${enrolled}.`);
  if (hostname) {
    // Rename in place: `tailscale set` changes only the name, never the login or the tags.
    const renaming = joined.Self?.HostName !== hostname;
    if (renaming) await io.run("tailscale", ["set", `--hostname=${hostname}`]);
    const named = renaming ? await settledTailscaleName(readState, hostname, io.sleep) : joined;
    const assigned = assignedTailscaleName(named);
    io.log(`Tailscale machine name: ${assigned ?? hostname}`);
    const difference = nameDifference(hostname, assigned);
    if (difference) io.log(difference);
  }
  await io.run("tailscale", ["set", "--ssh"]);
  io.log("Verify Tailscale SSH as the owner before running host:install --harden-vps.");
}

export async function vpsAuthKeyFile(path: string | undefined) {
  if (path?.startsWith("/")) {
    const info = await stat(path).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT" && error.code !== "ENOTDIR") throw error;
      return null;
    });
    if (info?.isFile() && (info.mode & 0o077) === 0) return path;
  }
  throw new Error(`Set TS_VPS_AUTHKEY_FILE to a private absolute key file for ${ARK_VPS_TAG}.`);
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
  return `APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "${rebootTime}";
`;
}

function aptEnabled(value: string | undefined) {
  return /^(?:1|true|yes|on|enable)$/i.test(value ?? "");
}

export function assertAutomaticUpdates(config: string, rebootTime: string, codename: string) {
  const entries = [...config.matchAll(/^([\w:-]+) "([^"]*)";$/gm)];
  const settings = new Map(entries.map(([, key, value]) => [key!, value!]));
  const problems = [];
  if (settings.has("APT::Periodic::Enable") && !aptEnabled(settings.get("APT::Periodic::Enable"))) {
    problems.push("APT::Periodic::Enable must enable periodic updates");
  }
  for (const key of ["APT::Periodic::Update-Package-Lists", "APT::Periodic::Unattended-Upgrade"]) {
    if (settings.get(key) !== "1") problems.push(`${key} must be 1 (daily)`);
  }
  if (!aptEnabled(settings.get("Unattended-Upgrade::Automatic-Reboot"))) {
    problems.push("Unattended-Upgrade::Automatic-Reboot must be enabled");
  }
  if (settings.get("Unattended-Upgrade::Automatic-Reboot-Time") !== rebootTime) {
    problems.push(`Unattended-Upgrade::Automatic-Reboot-Time must be ${rebootTime}`);
  }
  const security = `${codename}-security`;
  const origins = entries
    .filter(([, key]) => key?.startsWith("Unattended-Upgrade::Allowed-Origins::"))
    .map(([, , value]) =>
      value?.replaceAll("${distro_id}", "Ubuntu").replaceAll("${distro_codename}", codename),
    );
  if (!origins.includes(`Ubuntu:${security}`)) {
    problems.push(`Unattended-Upgrade::Allowed-Origins must include Ubuntu:${security}`);
  }
  if (problems.length) throw new Error(`Effective apt configuration: ${problems.join(", ")}.`);
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

export async function installHostHardening(getConfig: (ssh: HostSshAccess) => Promise<HostPortConfig>) {
  requireLinuxRoot();
  if (
    !vpsNodeReady(await settledVpsNode(tailscaleState)) ||
    !JSON.parse(await hostCommand("tailscale", ["debug", "prefs"])).RunSSH
  ) {
    throw new Error("Run host:install --enroll-vps and verify owner Tailscale SSH first.");
  }
  const rebootTime = process.env.ARK_HOST_REBOOT_TIME ?? "04:00";
  const updates = automaticUpdatesConfig(rebootTime);
  // nftables resolves ipv6-icmp through /etc/protocols, absent on some minimal Ubuntu images.
  await aptInstall(["nftables", "iproute2", "netbase", "unattended-upgrades"]);
  await installFile("/etc/apt/apt.conf.d/52ark-unattended-upgrades", updates);
  const codename = /^VERSION_CODENAME="?([a-z]+)"?$/m.exec(await Bun.file("/etc/os-release").text())?.[1];
  if (!codename) throw new Error("Could not determine the Ubuntu release codename from /etc/os-release.");
  assertAutomaticUpdates(await hostCommand("apt-config", ["dump"]), rebootTime, codename);
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
  const saved = await readFile(hostFirewallPath, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
    return "";
  });
  const ssh =
    process.env.ARK_SETUP_HOST_SSH_ACCESS === undefined
      ? readHostSshAccess(saved)
      : (JSON.parse(process.env.ARK_SETUP_HOST_SSH_ACCESS) as HostSshAccess);
  const config = await getConfig(ssh);
  const baseline = renderHostFirewall({ ...config, routes: [] }, ssh);
  await hostCommand("nft", ["-c", "-f", "-"], baseline);
  await installFile(hostFirewallPath, baseline);
  await hostCommand("systemctl", ["daemon-reload"]);
  await hostCommand("systemctl", ["start", rebootService]);
  await hostCommand("systemctl", ["enable", "--now", "ark-host-reboot-metric.timer"]);
  await hostCommand("systemctl", ["enable", "--now", firewallService]);
  // Preserve acknowledged routes on an update. The new reconciler will replay the full policy.
  const active = renderHostFirewall(config, ssh);
  await hostCommand("nft", ["-f", "-"], active);
  assertHostFirewall(
    await hostCommand("nft", ["-s", "-y", "list", "table", "inet", HOST_FIREWALL_TABLE]),
    config,
    ssh,
  );
}
