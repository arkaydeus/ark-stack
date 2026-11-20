// The guided setup's steps (docs/getting-started/production-install.md, end to end). Each step
// verifies whether it is already complete and skips itself, so a re-run resumes where it stopped.
// The existing installer phases do the work: `install.ts --enroll-vps`, `install.ts --harden-vps`,
// `edge-namespace.ts` (edge:rejoin) and `host-audit.ts`.
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ARK_EDGE_TAG, ARK_VPS_TAG, applyEdgeAuthKey, parseEnvFile } from "@ark-stack/shared";

import { vpsNodeReady, type TailscaleState } from "../install-host-hardening.ts";
import type { Answers, Options } from "./answers.ts";
import { desiredConfiguration, readEnv, setEnvValues, writeEnv } from "./env-file.ts";
import {
  selectProviderFirewall,
  type FirewallContext,
  type ProviderFirewall,
  type ProviderRule,
} from "./provider-firewall.ts";
import type { SetupState, StepId } from "./state.ts";
import type { Redactor, RunOptions, Runner, SetupLog, Ui } from "./system.ts";
import type { TailscaleKeySource } from "./tailscale-keys.ts";

export const SUPPORTED_UBUNTU = ["22.04", "24.04", "26.04"];

export type HostPaths = {
  osRelease: string;
  hostFirewall: string;
};

export type SessionOrigin = { via: "tailscale" | "openssh" | "local" | "unknown"; detail?: string };

export type Context = {
  root: string;
  envPath: string;
  /** The Bun executable that runs the existing installer scripts. */
  bun: string;
  run: Runner;
  ui: Ui;
  log: SetupLog;
  redactor: Redactor;
  state: SetupState;
  save: () => void;
  answers: Answers;
  options: Options;
  interactive: boolean;
  env: Record<string, string | undefined>;
  keys: TailscaleKeySource;
  firewalls: ProviderFirewall[];
  paths: HostPaths;
  isRoot: boolean;
  platform: string;
  resumeCommand: string;
  sleep: (ms: number) => Promise<void>;
  sessionOrigin: () => Promise<SessionOrigin>;
};

export type StepResult = {
  status: "done" | "skipped" | "pending";
  /** Short outcome shown on the step's progress line. */
  message?: string;
  fingerprint?: string;
  note?: string;
  finish?: string;
};

/** The owner has not confirmed Tailscale SSH: stop before anything that could lock them out. */
export class SetupPaused extends Error {}

export type Step = { id: StepId; title: string; run: (context: Context) => Promise<StepResult> };

// ---- Command helpers ------------------------------------------------------------------------

export async function exec(context: Context, argv: string[], options: RunOptions = {}) {
  context.log.write(`$ ${argv.join(" ")}`);
  const result = await context.run(argv, {
    cwd: context.root,
    ...options,
    onLine: (line) => context.log.write(`  | ${line}`),
  });
  if (result.status !== 0) context.log.write(`  (exit ${result.status})`);
  return result;
}

export async function must(context: Context, argv: string[], options: RunOptions = {}) {
  const result = await exec(context, argv, options);
  if (result.status !== 0) {
    const tail = context.redactor.redact(`${result.stderr || result.stdout}`.trim().slice(-1500));
    throw new Error(
      `${argv.slice(0, 3).join(" ")} failed (exit ${result.status}).${tail ? `\n${tail}` : ""}`,
    );
  }
  return result.stdout;
}

/**
 * The environment for children: this process's environment without any `.env` key, so Compose and
 * the installer read the file (an exported stale value would otherwise win over `--env-file`).
 */
export function childEnv(context: Context, extra: Record<string, string> = {}) {
  const env: Record<string, string | undefined> = { ...context.env };
  for (const key of Object.keys(parseEnvFile(readEnv(context.envPath)))) delete env[key];
  for (const key of ["TS_EDGE_AUTHKEY", "TS_VPS_AUTHKEY", "TS_VPS_AUTHKEY_FILE", "DNS_API_TOKEN"])
    delete env[key];
  return { ...env, ...extra };
}

function compose(context: Context, ...args: string[]) {
  return [
    "docker",
    "compose",
    "--env-file",
    context.envPath,
    "-f",
    "infra/platform/docker-compose.yml",
    ...args,
  ];
}

export async function tailscaleStatus(context: Context): Promise<TailscaleState | undefined> {
  const result = await exec(context, ["tailscale", "status", "--json"]);
  try {
    return JSON.parse(result.stdout) as TailscaleState;
  } catch {
    return undefined;
  }
}

async function tailscaleSshEnabled(context: Context) {
  const result = await exec(context, ["tailscale", "debug", "prefs"]);
  try {
    return result.status === 0 && Boolean((JSON.parse(result.stdout) as { RunSSH?: boolean }).RunSSH);
  } catch {
    return false;
  }
}

/** Host node enrolled as tag:ark-vps, tailscaled active and Tailscale SSH on. */
async function tailscaleSshReady(context: Context) {
  const status = await tailscaleStatus(context);
  if (!status || !vpsNodeReady(status)) return "the host node is not running with exactly tag:ark-vps";
  if (!(await tailscaleSshEnabled(context))) return "Tailscale SSH is not enabled (tailscale set --ssh)";
  const active = await exec(context, ["systemctl", "is-active", "tailscaled.service"]);
  if (active.stdout.trim() !== "active") return "tailscaled.service is not active";
  return undefined;
}

function magicDnsName(status: TailscaleState | undefined) {
  return status?.Self?.DNSName?.replace(/\.$/, "") || "<vps-magicdns-name>";
}

function sshTarget(context: Context, status: TailscaleState | undefined) {
  return `${context.answers.sshUser || "<user>"}@${magicDnsName(status)}`;
}

async function apiHealthy(context: Context) {
  for (let attempt = 0; attempt < 12; attempt++) {
    const result = await exec(context, [
      "curl",
      "-fsS",
      "--max-time",
      "5",
      "http://127.0.0.1:3000/api/health",
    ]);
    if (result.status === 0) return true;
    if (attempt < 11) await context.sleep(5000);
  }
  return false;
}

async function gitCommit(context: Context) {
  const result = await exec(context, ["git", "-C", context.root, "rev-parse", "HEAD"]);
  return result.status === 0 ? result.stdout.trim() : "unknown";
}

export async function publicAddresses(context: Context) {
  const result = await exec(context, ["ip", "-j", "address", "show", "scope", "global"]);
  const ipv4: string[] = [];
  const ipv6: string[] = [];
  try {
    const links = JSON.parse(result.stdout) as {
      ifname: string;
      addr_info?: { family: string; local: string; temporary?: boolean; deprecated?: boolean }[];
    }[];
    for (const link of links) {
      if (/^(?:lo|docker|br-|veth|tailscale|virbr)/.test(link.ifname)) continue;
      for (const address of link.addr_info ?? []) {
        if (address.temporary || address.deprecated) continue;
        if (
          address.family === "inet" &&
          !/^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(
            address.local,
          )
        ) {
          ipv4.push(address.local);
        }
        if (address.family === "inet6" && /^[23]/.test(address.local)) ipv6.push(address.local);
      }
    }
  } catch {
    // Unknown addresses are shown as placeholders.
  }
  return { ipv4, ipv6 };
}

/** `ss` listeners for OpenSSH: TCP 22 or any sshd socket, on an address other than loopback or tailnet. */
export function publicSshListeners(ss: string, tailnet: Set<string>) {
  const found: string[] = [];
  for (const line of ss.split("\n")) {
    const match = /^(?:tcp\s+)?\S+\s+\d+\s+\d+\s+(\S+):(\d+)\s/.exec(line.trim());
    if (!match) continue;
    const address = match[1]!.replace(/^\[|\]$/g, "").split("%")[0]!;
    const port = Number(match[2]);
    if (port !== 22 && !/"sshd"/.test(line)) continue;
    if (address === "::1" || address.startsWith("127.") || tailnet.has(address)) continue;
    found.push(`${address.includes(":") ? `[${address}]` : address}:${port}`);
  }
  return found;
}

async function sshListeners(context: Context) {
  const ss = await must(context, ["ss", "-H", "-ltnp"]);
  const status = await tailscaleStatus(context);
  return publicSshListeners(ss, new Set(status?.Self?.TailscaleIPs ?? []));
}

// ---- Steps ----------------------------------------------------------------------------------------

async function prerequisites(context: Context): Promise<StepResult> {
  if (context.platform !== "linux" || !context.isRoot) {
    throw new Error(`host:setup must run as root on the Ubuntu VPS. Run: ${context.resumeCommand}`);
  }
  const release = existsSync(context.paths.osRelease) ? readFileSync(context.paths.osRelease, "utf8") : "";
  const field = (name: string) => new RegExp(`^${name}="?([^"\\n]*)"?$`, "m").exec(release)?.[1] ?? "";
  if (
    field("ID") !== "ubuntu" ||
    !SUPPORTED_UBUNTU.includes(field("VERSION_ID")) ||
    !field("VERSION_CODENAME")
  ) {
    throw new Error(
      `Unsupported operating system ${field("PRETTY_NAME") || "(unknown)"}; use Ubuntu ${SUPPORTED_UBUNTU.join(", ")}.`,
    );
  }
  const missing = [];
  for (const command of [
    "git",
    "curl",
    "jq",
    "openssl",
    "docker",
    "tailscale",
    "systemctl",
    "ss",
    "ip",
    "flock",
  ]) {
    const found = await exec(context, ["sh", "-c", 'command -v "$1"', "sh", command]);
    if (found.status !== 0) missing.push(command);
  }
  if (missing.length) {
    throw new Error(`Missing ${missing.join(", ")}. Run install.sh as root to install the prerequisites.`);
  }
  if ((await exec(context, ["docker", "compose", "version"])).status !== 0) {
    throw new Error("docker compose (Compose v2) is not available. Run install.sh to install it.");
  }
  if ((await exec(context, ["docker", "info", "--format", "{{.ServerVersion}}"])).status !== 0) {
    throw new Error("The Docker daemon is not running: systemctl enable --now docker.service");
  }
  return {
    status: "done",
    message: `Ubuntu ${field("VERSION_ID")}, Docker, Compose v2, Tailscale and tools present`,
  };
}

async function tailscaleEnrolment(context: Context): Promise<StepResult> {
  if (!(await tailscaleSshReady(context))) {
    return { status: "done", message: `already enrolled as ${ARK_VPS_TAG} with Tailscale SSH` };
  }
  for (const line of context.keys.policyInstructions()) context.ui.print(`      ${line}`);
  if (context.interactive) await context.ui.ask("Press Enter once the policy is saved", "");
  const key = await context.keys.acquire({ tag: ARK_VPS_TAG, variable: "TS_VPS_AUTHKEY", optional: false });
  if (!key) throw new Error(`A ${ARK_VPS_TAG} key is required.`);
  let directory: string | undefined;
  let file = key.file;
  try {
    if (!file) {
      context.redactor.add(key.key);
      directory = mkdtempSync(join(tmpdir(), "ark-vps-key-"));
      chmodSync(directory, 0o700);
      file = join(directory, "authkey");
      writeFileSync(file, `${key.key}\n`, { mode: 0o600, flag: "wx" });
    }
    await must(context, [context.bun, "scripts/install.ts", "--enroll-vps"], {
      env: childEnv(context, { TS_VPS_AUTHKEY_FILE: file }),
    });
  } finally {
    if (directory) rmSync(directory, { recursive: true, force: true });
  }
  const problem = await tailscaleSshReady(context);
  if (problem) throw new Error(`Enrolment finished but ${problem}.`);
  await key.release?.();
  return {
    status: "done",
    message: `enrolled as ${ARK_VPS_TAG}${key.file ? `; delete ${key.file} and revoke the key` : "; the key file was deleted"}`,
  };
}

async function sshGate(context: Context): Promise<StepResult> {
  if (context.state.sshConfirmedAt) {
    return { status: "done", message: `Tailscale SSH confirmed ${context.state.sshConfirmedAt}` };
  }
  const status = await tailscaleStatus(context);
  const command = `tailscale ssh ${sshTarget(context, status)}`;
  context.ui.print(
    "      From your own device (not this session), open a new Tailscale SSH session and keep it open:",
  );
  context.ui.print("");
  context.ui.print(`        ${command}`);
  context.ui.print("");
  const origin = await context.sessionOrigin();
  if (origin.via === "tailscale") {
    context.ui.print("      This session already arrives over Tailscale (tailscale0).");
  } else if (origin.via === "openssh") {
    context.ui.print(
      "      This session arrives over public OpenSSH. Hardening keeps established connections, but",
    );
    context.ui.print("      new public SSH connections will be refused, so check Tailscale SSH works first.");
  }
  let confirmed = context.options.tailscaleSshConfirmed;
  if (!confirmed && context.interactive) {
    const answer = await context.ui.ask("Type yes once that session works (anything else stops here)", "");
    confirmed = /^yes$/i.test(answer.trim());
  }
  if (!confirmed) {
    throw new SetupPaused(
      `Stopped before hardening: Tailscale SSH has not been confirmed. Nothing on the firewall or OpenSSH changed.
Check that \`${command}\` works from your own device, then resume with:

  ${context.resumeCommand}${context.interactive ? "" : " --tailscale-ssh-confirmed"}`,
    );
  }
  context.state.sshConfirmedAt = new Date().toISOString();
  context.save();
  return { status: "done", message: "Tailscale SSH confirmed by the owner" };
}

async function install(context: Context): Promise<StepResult> {
  if (!context.state.sshConfirmedAt) throw new SetupPaused("Tailscale SSH has not been confirmed.");
  const { mailEnabled, sniPorts, rebootTime } = context.answers;
  const fingerprint = JSON.stringify({ mailEnabled, sniPorts, rebootTime, commit: await gitCommit(context) });
  const record = context.state.steps.install;
  if (
    record?.status === "done" &&
    record.fingerprint === fingerprint &&
    existsSync(context.paths.hostFirewall) &&
    (await apiHealthy(context))
  ) {
    return { status: "done", fingerprint, message: "already hardened and installed with these settings" };
  }
  context.ui.print(`      Hardening and installing; this takes several minutes. Detail: ${context.log.path}`);
  const env = childEnv(context, {
    ARK_MAIL_ENABLED: mailEnabled ? "1" : "0",
    ARK_EDGE_SNI_PORTS: sniPorts.join(","),
    ARK_HOST_REBOOT_TIME: rebootTime,
    // The edge key is handled by the edge step, never prompted for by the installer.
    ARK_INSTALL_NONINTERACTIVE: "1",
  });
  await must(context, [context.bun, "scripts/install.ts", "--harden-vps"], { env });
  context.redactor.addEnv(readEnv(context.envPath));
  if (!(await apiHealthy(context)))
    throw new Error("The install finished but http://127.0.0.1:3000/api/health does not answer.");
  return { status: "done", fingerprint, message: "host hardened, platform installed and healthy" };
}

async function edgeTags(context: Context) {
  const result = await exec(
    context,
    compose(
      context,
      "exec",
      "-T",
      "edge-ts",
      "tailscale",
      "--socket=/var/run/tailscale/tailscaled.sock",
      "status",
      "--json",
    ),
    { env: childEnv(context) },
  );
  if (result.status !== 0) return undefined;
  try {
    const status = JSON.parse(result.stdout) as TailscaleState;
    return { running: status.BackendState === "Running", tags: status.Self?.Tags ?? [] };
  } catch {
    return undefined;
  }
}

function emptyEdgeKey(context: Context) {
  const current = readEnv(context.envPath);
  if (parseEnvFile(current).TS_EDGE_AUTHKEY?.trim()) {
    writeEnv(context.envPath, setEnvValues(current, { TS_EDGE_AUTHKEY: "" }));
  }
}

const EDGE_FINISH =
  "Re-run host:setup and paste a one-off tag:ark-edge key when asked (or set TS_EDGE_AUTHKEY), or follow docs/getting-started/production-install.md#enrol-the-edge-node.";

async function edgeEnrolment(context: Context): Promise<StepResult> {
  const exact = (tags: string[]) => tags.length === 1 && tags[0] === ARK_EDGE_TAG;
  const before = await edgeTags(context);
  if (before?.running && exact(before.tags)) {
    emptyEdgeKey(context);
    return { status: "done", message: `edge-ts already joined as ${ARK_EDGE_TAG}` };
  }
  if (before?.running && before.tags.length) {
    throw new Error(
      `edge-ts is running with tags ${JSON.stringify(before.tags)}, not exactly ["${ARK_EDGE_TAG}"]. Remove that device in the admin console and re-enrol it (docs/operating.md#edge-tailscale-node).`,
    );
  }
  if (context.options.skipEdge) {
    return {
      status: "skipped",
      note: "The edge node (edge-ts) has not joined the tailnet.",
      finish: EDGE_FINISH,
    };
  }
  const current = readEnv(context.envPath);
  const kept = parseEnvFile(current).TS_EDGE_AUTHKEY?.trim();
  let release: (() => Promise<void>) | undefined;
  if (!kept) {
    context.ui.print(
      `      The edge node needs its own one-off key tagged ${ARK_EDGE_TAG} (never the VPS key).`,
    );
    const key = await context.keys.acquire({
      tag: ARK_EDGE_TAG,
      variable: "TS_EDGE_AUTHKEY",
      optional: true,
    });
    if (!key?.key) {
      return {
        status: "skipped",
        note: "The edge node (edge-ts) has not joined the tailnet.",
        finish: EDGE_FINISH,
      };
    }
    context.redactor.add(key.key);
    release = key.release;
    writeEnv(context.envPath, applyEdgeAuthKey(current, key.key).env);
  } else context.redactor.add(kept);
  await must(context, compose(context, "up", "-d", "edge-ts", "edge", "edge-l4"), { env: childEnv(context) });
  await must(context, [context.bun, `--env-file=${context.envPath}`, "scripts/edge-namespace.ts"], {
    env: childEnv(context),
  });
  let after = await edgeTags(context);
  for (let attempt = 0; attempt < 24 && !after?.running; attempt++) {
    await context.sleep(5000);
    after = await edgeTags(context);
  }
  if (!after?.running)
    throw new Error("edge-ts did not join the tailnet within two minutes. Check the key and the policy.");
  if (!exact(after.tags)) {
    throw new Error(
      `edge-ts joined with tags ${JSON.stringify(after.tags)}, not exactly ["${ARK_EDGE_TAG}"]. Remove that device in the admin console and re-enrol it (docs/operating.md#edge-tailscale-node).`,
    );
  }
  emptyEdgeKey(context);
  await release?.();
  return { status: "done", message: `edge-ts joined as ${ARK_EDGE_TAG}; TS_EDGE_AUTHKEY emptied in .env` };
}

async function configuration(context: Context): Promise<StepResult> {
  const current = readEnv(context.envPath);
  if (!current) throw new Error(".env is missing; the install step must run first.");
  const { desired, changed, adminOrigin } = desiredConfiguration(
    context.answers,
    current,
    context.state.adminOrigin,
  );
  const { DNS_API_TOKEN: _token, ...visible } = desired;
  const fingerprint = JSON.stringify({
    ...visible,
    dns: Boolean(desired.DNS_API_TOKEN ?? parseEnvFile(current).DNS_API_TOKEN),
  });
  const record = context.state.steps.configuration;
  if (!changed && record?.status === "done" && record.fingerprint === fingerprint) {
    return { status: "done", fingerprint, message: "admin origin and ACME settings already in .env" };
  }
  if (changed) {
    writeEnv(context.envPath, setEnvValues(current, desired));
    context.redactor.addEnv(readEnv(context.envPath));
  }
  await must(context, compose(context, "up", "-d", "api", "domain-worker"), { env: childEnv(context) });
  context.state.adminOrigin = adminOrigin;
  context.save();
  return {
    status: "done",
    fingerprint,
    message: `BETTER_AUTH_URL=${adminOrigin}, ARK_ACME_STAGING=${desired.ARK_ACME_STAGING}; api and domain-worker recreated`,
  };
}

const SSH_UNITS = ["ssh.socket", "ssh.service"];

async function closePublicSsh(context: Context): Promise<StepResult> {
  if (context.options.keepPublicSsh) {
    return {
      status: "skipped",
      note: "Public OpenSSH was left running (--keep-public-ssh).",
      finish: "Re-run host:setup without --keep-public-ssh to close it.",
    };
  }
  if (!context.state.sshConfirmedAt) throw new SetupPaused("Tailscale SSH has not been confirmed.");
  const units: { unit: string; enabled: boolean; active: boolean }[] = [];
  for (const unit of SSH_UNITS) {
    const listed = await exec(context, ["systemctl", "list-unit-files", "--no-legend", unit]);
    if (!listed.stdout.trim()) continue;
    const enabled = (await exec(context, ["systemctl", "is-enabled", unit])).stdout.trim() === "enabled";
    const active = (await exec(context, ["systemctl", "is-active", unit])).stdout.trim() === "active";
    units.push({ unit, enabled, active });
  }
  const listening = await sshListeners(context);
  const notes: string[] = [];
  if (listening.length || units.some((item) => item.active || item.enabled)) {
    const before = await tailscaleSshReady(context);
    if (before) throw new Error(`Not closing public SSH: ${before}. OpenSSH was left running.`);
    const restore = async () => {
      for (const item of units) {
        if (item.enabled) await exec(context, ["systemctl", "enable", item.unit]);
        if (item.active) await exec(context, ["systemctl", "start", item.unit]);
      }
    };
    const present = units.map((item) => item.unit);
    if (present.length) {
      const stopped = await exec(context, ["systemctl", "disable", "--now", ...present]);
      if (stopped.status !== 0) {
        await restore();
        throw new Error("Stopping OpenSSH failed; it was left running. See the log.");
      }
    }
    const after = await tailscaleSshReady(context);
    if (after) {
      await restore();
      throw new Error(
        `After stopping OpenSSH, ${after}. OpenSSH was started again; public SSH is still open.`,
      );
    }
    if (context.interactive) {
      const status = await tailscaleStatus(context);
      context.ui.print(
        `      Open one more new session from your device: tailscale ssh ${sshTarget(context, status)}`,
      );
      const answer = await context.ui.ask("Type yes if it works (anything else restores OpenSSH)", "");
      if (!/^yes$/i.test(answer.trim())) {
        await restore();
        throw new Error("Tailscale SSH was not confirmed after closing OpenSSH. OpenSSH was started again.");
      }
    }
    const remaining = await sshListeners(context);
    if (remaining.length) {
      throw new Error(
        `OpenSSH is still listening on ${remaining.join(", ")} (started outside ssh.service or ssh.socket). It was left as it is; stop it or bind it to a private address.`,
      );
    }
  }
  // UFW: remove only the rules that keep public SSH open; anything else is reported, never changed.
  const ufw = await exec(context, ["ufw", "status", "numbered"]);
  if (ufw.status === 0 && /Status: active/.test(ufw.stdout)) {
    const numbers = [
      ...ufw.stdout.matchAll(/^\[\s*(\d+)\]\s+(?:22(?:\/tcp)?|OpenSSH)(?:\s+\(v6\))?\s+ALLOW/gm),
    ]
      .map((match) => Number(match[1]))
      .toSorted((a, b) => b - a);
    for (const number of numbers) await must(context, ["ufw", "--force", "delete", String(number)]);
    if (numbers.length) notes.push(`removed ${numbers.length} UFW SSH rule(s)`);
    return {
      status: "done",
      message: ["public OpenSSH closed", ...notes].join("; "),
      note: "UFW is active. Ark's host firewall is nftables (ark_host); UFW's default policy can block Ark's public ports.",
      finish: "Review `sudo ufw status verbose`; if nothing else depends on it, run `sudo ufw disable`.",
    };
  }
  return { status: "done", message: "public OpenSSH is not listening; Tailscale SSH answers" };
}

async function providerFirewall(context: Context): Promise<StepResult> {
  const inventory = await must(context, [context.bun, "scripts/host-audit.ts", "--inventory"], {
    env: childEnv(context),
  });
  const parsed = JSON.parse(inventory) as { config: unknown; providerRules: ProviderRule[] };
  const inventoryPath = join(context.root, "tmp", "ark-host-inventory.json");
  writeFileSync(inventoryPath, inventory.endsWith("\n") ? inventory : `${inventory}\n`, { mode: 0o644 });
  const fingerprint = JSON.stringify(parsed.providerRules);
  const addresses = await publicAddresses(context);
  const record = context.state.steps["provider-firewall"];
  const alreadyApplied = record?.status === "done" && record.fingerprint === fingerprint;
  const firewallContext: FirewallContext = {
    ui: context.ui,
    interactive: context.interactive,
    env: context.env,
    publicAddresses: addresses,
    confirmed: context.options.providerFirewallApplied || alreadyApplied,
  };
  const adapter = await selectProviderFirewall(
    context.firewalls,
    firewallContext,
    context.options.providerFirewall,
  );
  const plan = await adapter.plan(parsed.providerRules, firewallContext);
  let result: StepResult = { status: "done", fingerprint, message: `rules applied (${adapter.label})` };
  if (alreadyApplied) {
    result = { status: "done", fingerprint, message: "rules unchanged since they were applied" };
  } else if (plan.inSync) {
    result = { status: "done", fingerprint, message: `provider already matches (${adapter.label})` };
  } else {
    for (const line of plan.changes) context.ui.print(`      ${line}`);
    const applied = await adapter.apply(plan, firewallContext);
    if (applied.status === "pending")
      result = { status: "pending", note: applied.note, finish: applied.finish };
  }
  await must(context, [context.bun, "scripts/host-audit.ts"], { env: childEnv(context) });
  const ips = [...addresses.ipv4, ...addresses.ipv6];
  context.ui.print("      Local audit passed. Scan from another machine with Nmap (in a checkout, as root):");
  context.ui.print(`        scp ${sshTarget(context, await tailscaleStatus(context))}:${inventoryPath} .`);
  context.ui.print(
    `        sudo mise run host:audit --external ark-host-inventory.json ${ips.length ? ips.join(" ") : "<public-ipv4> <public-ipv6>"}`,
  );
  if (result.status === "done") result.message = `${result.message}; local audit passed`;
  return result;
}

export const STEPS: Step[] = [
  { id: "prerequisites", title: "Prerequisite checks", run: prerequisites },
  { id: "tailscale", title: "Tailscale enrolment (tag:ark-vps)", run: tailscaleEnrolment },
  { id: "ssh-gate", title: "Tailscale SSH safety check", run: sshGate },
  { id: "install", title: "Harden the host and install", run: install },
  { id: "edge", title: "Edge node enrolment (tag:ark-edge)", run: edgeEnrolment },
  { id: "configuration", title: "Admin origin and ACME settings", run: configuration },
  { id: "public-ssh", title: "Close public SSH", run: closePublicSsh },
  { id: "provider-firewall", title: "Provider firewall and local audit", run: providerFirewall },
];

const RECOVERY_KEYS = [
  "ARK_ROOT_KEY",
  "ARK_ROOT_KEY_ID",
  "ARK_MFA_RECOVERY_TOKEN",
  "ARK_PLATFORM_PG_REPO_CIPHER_PASS",
  "ARK_APP_PG_REPO_CIPHER_PASS",
];

/** The final summary. The setup token is the only secret it shows, on the terminal only. */
export async function summary(context: Context) {
  const status = await tailscaleStatus(context);
  const target = sshTarget(context, status);
  const values = parseEnvFile(readEnv(context.envPath));
  const { ipv4, ipv6 } = await publicAddresses(context);
  const { answers } = context;
  const lines = [
    "",
    "Ark Stack is installed.",
    "",
    "Sign in:",
    `  1. From your own device, open the tunnel:  ssh -L 3000:127.0.0.1:3000 ${target}`,
    "  2. Browse to http://localhost:3000 and create the owner with this setup token:",
    `       ${values.ARK_SETUP_TOKEN ?? "(missing: re-run host:setup)"}`,
    `  3. Enrol MFA, then run the domain wizard for ${answers.domain}: choose Public HTTPS at ${answers.adminHost}.`,
    "",
    "DNS:",
  ];
  if (values.DNS_API_TOKEN?.trim()) {
    lines.push(
      "  Cloudflare is configured: in the domain wizard, review the DNS diff and publish it after MFA.",
    );
  } else {
    lines.push(`  Create at your DNS provider:  A  ${answers.adminHost}  ${ipv4[0] ?? "<public-ipv4>"}`);
    if (ipv6[0]) lines.push(`  (AAAA ${answers.adminHost} ${ipv6[0]} only after the IPv6 preflight passes)`);
    lines.push(
      `  The domain wizard lists every record to create${answers.mailEnabled ? ", including MX, SPF, DKIM and DMARC for mail" : ""}.`,
    );
  }
  const open: string[] = [];
  for (const step of STEPS) {
    const record = context.state.steps[step.id];
    if (record && (record.status === "skipped" || record.status === "pending" || record.note)) {
      open.push(`  - ${step.title}: ${record.note ?? record.status}`);
      if (record.finish) open.push(`      ${record.finish}`);
    }
  }
  if (!answers.acmeEmail) {
    open.push("  - Certificates: no ACME email, so no certificate can be issued.");
    open.push("      Re-run host:setup with --acme-email you@example.com.");
  } else if (!answers.trustedCertificates) {
    open.push("  - Certificates: Let's Encrypt staging (untrusted, never served).");
    open.push("      Re-run host:setup with --trusted-certificates, then reissue the certificates.");
  }
  lines.push("", open.length ? "Still to do:" : "Nothing was skipped.", ...open);
  lines.push(
    "",
    "Recovery material: copy these .env values off the host now (they are not printed here):",
    `  ${RECOVERY_KEYS.join(", ")}`,
    `  sudo grep -E '^(${RECOVERY_KEYS.join("|")})=' ${context.envPath}`,
    "  and every backup target's restic password once you configure backups (docs/operations/recovery.md).",
    "",
    "Also: with Tailnet Lock, sign the new nodes; revoke any auth key that was not one-off.",
    `Log: ${context.log.path}`,
  );
  return lines;
}

/** Where the session that started setup came from, by walking the process ancestry in /proc. */
export async function detectSessionOrigin(env: Record<string, string | undefined>): Promise<SessionOrigin> {
  const fromConnection = (value: string | undefined): SessionOrigin | undefined => {
    const server = value?.trim().split(/\s+/)[2];
    if (!server) return undefined;
    const tailnet =
      /^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(server) || /^fd7a:115c:a1e0:/i.test(server);
    return { via: tailnet ? "tailscale" : "openssh", detail: server };
  };
  const direct = fromConnection(env.SSH_CONNECTION);
  if (direct) return direct;
  let pid = process.ppid;
  for (let depth = 0; depth < 32 && pid > 1; depth++) {
    try {
      const comm = readFileSync(`/proc/${pid}/comm`, "utf8").trim();
      if (comm === "tailscaled") return { via: "tailscale" };
      const environ = readFileSync(`/proc/${pid}/environ`, "utf8").split("\0");
      const found = fromConnection(environ.find((item) => item.startsWith("SSH_CONNECTION="))?.slice(15));
      if (found) return found;
      if (comm === "sshd") return { via: "openssh" };
      pid = Number(
        readFileSync(`/proc/${pid}/stat`, "utf8")
          .replace(/^.*\)\s+\S+\s+/, "")
          .split(" ")[0],
      );
    } catch {
      break;
    }
  }
  return { via: env.SSH_TTY ? "unknown" : "local" };
}
