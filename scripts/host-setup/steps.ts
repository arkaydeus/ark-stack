// The guided setup's steps (docs/getting-started/production-install.md, end to end). Each step
// verifies whether it is already complete and skips itself, so a re-run resumes where it stopped.
// The existing installer phases do the work: `install.ts --enroll-vps`, `install.ts --harden-vps`,
// `edge-namespace.ts` (edge:rejoin) and `host-audit.ts`. Keys come from the context's
// TailscaleKeySource and the provider firewall from the first ProviderFirewall that detects the VPS.
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { isIP } from "node:net";
import { join } from "node:path";

import {
  ARK_BACKUP_TAG,
  ARK_EDGE_TAG,
  ARK_VPS_TAG,
  applyEdgeAuthKey,
  assertHostFirewall,
  parseEnvFile,
  readHostSshAccess,
  replaceHostSshAccess,
  updateHostSshAccess,
  type HostPortConfig,
  type HostSshAccess,
} from "@ark-stack/shared";

import {
  assignedTailscaleName,
  nameDifference,
  settledTailscaleName,
  settledVpsNode,
  validateTailscaleHostname,
  vpsNodeProblem,
  vpsNodeReady,
  type TailscaleState,
} from "../install-host-hardening.ts";
import { backupHostname, edgeHostname, type Answers, type Options } from "./answers.ts";
import { desiredConfiguration, readEnv, setEnvValues, writeEnv, writeHostFile } from "./env-file.ts";
import {
  selectProviderFirewall,
  type FirewallContext,
  type ProviderFirewall,
  type ProviderRule,
} from "./provider-firewall.ts";
import type { SetupState, StepId, TailscaleNode } from "./state.ts";
import {
  withoutSetupSecrets,
  withoutApiCredentials,
  type Redactor,
  type RunOptions,
  type Runner,
  type SetupLog,
  type Ui,
} from "./system.ts";
import type { AcquiredKey, TailscaleKeySource } from "./tailscale-keys.ts";

export const SUPPORTED_UBUNTU = ["22.04", "24.04", "26.04"];

export type HostPaths = {
  osRelease: string;
  hostFirewall: string;
  ufwDirectory?: string;
  sshHomeBase?: string;
  sshdConfigDir?: string;
};

export type SessionOrigin = {
  via: "tailscale" | "openssh" | "local" | "unknown";
  detail?: string;
  source?: string;
};

export type Context = {
  root: string;
  stateDir: string;
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
    onLine: (line) => context.log.write(`  | ${line}`),
    ...options,
    env: options.env ? withoutApiCredentials(options.env) : withoutSetupSecrets(context.env),
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
  const env = withoutSetupSecrets(context.env);
  for (const key of Object.keys(parseEnvFile(readEnv(context.envPath)))) delete env[key];
  if (context.env.ARK_HOST_DEPLOYMENT_LOCK_HELD === "1") env.ARK_HOST_DEPLOYMENT_LOCK_HELD = "1";
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
    // NeedsLogin can still produce usable status JSON with a non-zero exit.
    return JSON.parse(result.stdout) as TailscaleState;
  } catch {
    return undefined;
  }
}

/** The status, after a short wait if the node is correctly enrolled but not online yet. */
function vpsTailscaleStatus(context: Context) {
  return settledVpsNode(() => tailscaleStatus(context), context.sleep);
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
async function tailscaleSshReady(context: Context, status: TailscaleState | undefined) {
  const problem = status ? vpsNodeProblem(status) : "tailscale status is unavailable";
  if (problem) return `the host node is not ready as ${ARK_VPS_TAG} (${problem})`;
  if (!(await tailscaleSshEnabled(context))) return "Tailscale SSH is not enabled (tailscale set --ssh)";
  const active = await exec(context, ["systemctl", "is-active", "tailscaled.service"]);
  if (active.stdout.trim() !== "active") return "tailscaled.service is not active";
  return undefined;
}

function magicDnsName(status: TailscaleState | undefined) {
  return status?.Self?.DNSName?.replace(/\.$/, "") || "<vps-magicdns-name>";
}

function sshTarget(context: Context, status: TailscaleState | undefined) {
  return `${context.answers.sshUser}@${magicDnsName(status)}`;
}

/** Says when the host node's assigned name differs from the requested one. */
function vpsNameNotice(context: Context, status: TailscaleState | undefined) {
  return nameDifference(context.answers.tailscaleHostname, assignedTailscaleName(status));
}

/**
 * Reads back the name Tailscale assigned to a node (it may add a suffix if the name is taken),
 * records it in the state and says so when it differs. Polls briefly only after a change.
 */
async function recordTailscaleName(
  context: Context,
  node: TailscaleNode,
  requested: string,
  read: () => Promise<TailscaleState | undefined>,
  changed: boolean,
) {
  const status = changed ? await settledTailscaleName(read, requested, context.sleep) : await read();
  const assigned = assignedTailscaleName(status);
  context.state.tailscaleNames = { ...context.state.tailscaleNames, [node]: { requested, assigned } };
  context.save();
  const difference = nameDifference(requested, assigned);
  if (difference) context.ui.print(`      ${difference}`);
  return assigned ?? requested;
}

function confirmationTarget(context: Context, status?: TailscaleState) {
  const node = status?.Self?.ID ?? status?.Self?.PublicKey;
  if (!status || !vpsNodeReady(status) || !node || !status.Self?.DNSName) {
    throw new Error("Cannot identify the enrolled Tailscale node and its SSH target.");
  }
  return JSON.stringify([node, sshTarget(context, status)]);
}

async function requireSshConfirmation(context: Context) {
  const status = await vpsTailscaleStatus(context);
  const target = confirmationTarget(context, status);
  if (
    context.state.sshUserProvisioning ||
    context.state.sshUserNeedsConfirmation ||
    context.state.sshConfirmation?.target !== target
  ) {
    throw new SetupPaused("The current Tailscale node and local user need a fresh SSH confirmation.");
  }
  const problem = await tailscaleSshReady(context, status);
  if (problem) throw new Error(`Tailscale SSH is unavailable: ${problem}.`);
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
          isIP(address.local) === 4 &&
          Number(address.local.split(".")[0]) < 224 &&
          sshIngressSource(address.local) === "public"
        ) {
          ipv4.push(address.local);
        }
        if (address.family === "inet6" && isIP(address.local) === 6 && /^[23]/.test(address.local))
          ipv6.push(address.local);
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
    if (port !== 22 && !/"sshd(?:-session)?"/.test(line)) continue;
    if (localBind(address, tailnet)) continue;
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
    "getent",
    "systemd-run",
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
  const enrolled = { enrolled: true, offerCredential: !context.state.sshConfirmation };
  const requested = context.answers.tailscaleHostname;
  // install.ts --enroll-vps joins with this name, or renames an enrolled node in place.
  const named = { TS_VPS_HOSTNAME: requested };
  const readName = () => tailscaleStatus(context);
  const status = await vpsTailscaleStatus(context);
  if (!(await tailscaleSshReady(context, status))) {
    await context.keys.preparePolicy?.(enrolled);
    // Rename in place: never log out, re-enrol or touch the node's tags.
    const rename = status?.Self?.HostName !== requested;
    if (rename) await must(context, ["tailscale", "set", `--hostname=${requested}`]);
    const name = await recordTailscaleName(context, "vps", requested, readName, rename);
    return {
      status: "done",
      message: rename
        ? `already enrolled as ${ARK_VPS_TAG} with Tailscale SSH; renamed to ${name}`
        : `already enrolled as ${ARK_VPS_TAG} with Tailscale SSH (${name})`,
    };
  }
  if (status && vpsNodeReady(status)) {
    await context.keys.preparePolicy?.(enrolled);
    await must(context, [context.bun, "scripts/install.ts", "--enroll-vps"], {
      env: childEnv(context, named),
    });
    const problem = await tailscaleSshReady(context, await vpsTailscaleStatus(context));
    if (problem) throw new Error(`Enrolment finished but ${problem}.`);
    const name = await recordTailscaleName(
      context,
      "vps",
      requested,
      readName,
      status.Self?.HostName !== requested,
    );
    return { status: "done", message: `resumed enrolment with the existing ${ARK_VPS_TAG} node (${name})` };
  }
  if (status?.BackendState === "Running") {
    throw new Error(
      `The running Tailscale node must use the host TUN interface and only ${ARK_VPS_TAG}: ${vpsNodeProblem(status)}.`,
    );
  }
  delete context.state.sshConfirmation;
  context.save();
  if (context.keys.preparePolicy) await context.keys.preparePolicy();
  else {
    for (const line of context.keys.policyInstructions()) context.ui.print(`      ${line}`);
    if (context.interactive) await context.ui.ask("Press Enter once the policy is saved", "");
  }
  const key = await context.keys.acquire({ tag: ARK_VPS_TAG, variable: "TS_VPS_AUTHKEY", optional: false });
  if (!key?.file && !key?.key) throw new Error(`A ${ARK_VPS_TAG} key is required.`);
  context.redactor.add(key.key);
  let revoked: boolean | undefined;
  try {
    const command = [context.bun, "scripts/install.ts", "--enroll-vps"];
    if (key.file) {
      await must(context, command, {
        env: childEnv(context, { ...named, TS_VPS_AUTHKEY_FILE: key.file }),
      });
    } else {
      await must(context, [...command, "--key-stdin"], { env: childEnv(context, named), stdin: key.key });
    }
    const problem = await tailscaleSshReady(context, await vpsTailscaleStatus(context));
    if (problem) throw new Error(`Enrolment finished but ${problem}.`);
  } finally {
    // The node joined, or the attempt failed: a minted key is revoked either way.
    revoked = await key.release?.();
  }
  const name = await recordTailscaleName(context, "vps", requested, readName, true);
  return {
    status: "done",
    message: `enrolled as ${ARK_VPS_TAG} named ${name}${key.file ? `; delete ${key.file} and revoke the key` : ""}`,
    ...keyCleanupNote(revoked, ARK_VPS_TAG),
  };
}

const MIN_PASSWORD_LENGTH = 8;

async function lookupSshUser(context: Context, user: string) {
  const result = await exec(context, ["getent", "passwd", user]);
  if (result.status === 2) return undefined;
  if (result.status !== 0) {
    const detail = context.redactor.redact((result.stderr || result.stdout).trim().slice(-1500));
    throw new Error(
      `Could not look up the local user ${user} (getent exit ${result.status}).${detail ? `\n${detail}` : ""}`,
    );
  }
  const [name, , uid, , , home, shell, ...extra] = result.stdout.trimEnd().split(":");
  if (
    name !== user ||
    !/^\d+$/.test(uid ?? "") ||
    home === undefined ||
    shell === undefined ||
    extra.length
  ) {
    throw new Error(`getent returned an invalid passwd entry for ${user}.`);
  }
  return { uid: Number(uid), home, shell };
}

function requireFreshHome(home: string) {
  if (lstatSync(home, { throwIfNoEntry: false })) {
    throw new Error(
      `The home path ${home} already exists. Inspect it and move it aside or choose a different --ssh-user.`,
    );
  }
}

/** Effective password policy for the default OpenSSH configuration on disk. */
async function openSshPasswordCheck(context: Context, user: string) {
  const result = await exec(context, ["/usr/sbin/sshd", "-ddd", "-T", "-C", `user=${user}`]);
  // sshd evaluates Match User before the account exists. Group and connection-specific criteria
  // can produce a different result after useradd or for a remote client. Refuse those configs.
  const matches = [...result.stderr.matchAll(/^debug3: checking syntax for 'Match (.*)'\r?$/gim)];
  const userOnly = matches.every(([, rule]) =>
    /^(?:all|user[ \t]+[\w*,!?-]+)(?:[ \t]+#.*)?\s*$/i.test(rule!),
  );
  const policy = result.stdout.split(/\r?\n/);
  const deniesUser = policy.some(
    (line) => line.startsWith("denyusers ") && line.split(/\s+/).slice(1).includes(user),
  );
  const disablesPasswords =
    policy.includes("passwordauthentication no") && policy.includes("kbdinteractiveauthentication no");
  if (result.status !== 0 || !userOnly) return "unverified";
  return deniesUser || disablesPasswords ? "safe" : "passwords-allowed";
}

function openSshPasswordError(user: string, prefix = "", cause?: unknown) {
  return new Error(
    `${prefix}Cannot verify that OpenSSH blocks password login for ${user}. Keep your current recovery session open. ` +
      `Apply and reload a policy that denies ${user} or disables PasswordAuthentication and KbdInteractiveAuthentication for ${user}, then retry. ` +
      `For a custom OpenSSH configuration, provision a protected local account manually and pass it with --ssh-user.`,
    { cause },
  );
}

async function sshUnitProperties(context: Context, unit: string, ...properties: string[]) {
  const result = await exec(
    context,
    ["systemctl", "show", ...properties.map((p) => `--property=${p}`), unit],
    {
      onLine: undefined,
    },
  );
  const values = new Map<string, string>();
  if (result.status !== 0) return values;
  for (const [, key, value] of result.stdout.matchAll(/^(\w+)=(.*)$/gm)) {
    values.set(key!, [values.get(key!), value].filter(Boolean).join(" "));
  }
  return values;
}

const sshdProcess = /^sshd(?:-session|-auth)?$/;
const socketOwner = /\("([^"]+)",pid=(\d+),fd=\d+\)/g;

/** Which OpenSSH listener can use the default configuration, and which daemon image is running. */
async function openSshService(context: Context, user: string) {
  const refuse = () =>
    openSshPasswordError(
      user,
      "Could not establish that every SSH listener uses the default Ubuntu service and configuration. ",
    );
  const service = await sshUnitProperties(
    context,
    "ssh.service",
    "LoadState",
    "ActiveState",
    "MainPID",
    "FragmentPath",
    "DropInPaths",
    "NeedDaemonReload",
    "ExecStart",
    "Environment",
    "PassEnvironment",
    "EnvironmentFiles",
  );
  const state = service.get("ActiveState");
  const pid = service.get("MainPID");
  let generation: string | undefined;
  const installed = service.get("LoadState") !== "not-found";
  if (installed) {
    if (
      !["loaded", "masked"].includes(service.get("LoadState") ?? "") ||
      (state !== "active" && state !== "inactive" && state !== "failed")
    )
      throw refuse();
    if (service.get("LoadState") === "loaded") {
      // Ubuntu starts sshd with the default config and optional flags from /etc/default/ssh.
      // Limit provisioning to that service, including when it is waiting for socket activation.
      if (
        !/^\/(?:usr\/)?lib\/systemd\/system\/ssh\.service$/.test(service.get("FragmentPath") ?? "") ||
        service.get("NeedDaemonReload") !== "no" ||
        (service.get("DropInPaths") ?? "") !== "" ||
        !/^\{ path=\/usr\/sbin\/sshd ; argv\[\]=\/usr\/sbin\/sshd -D(?: \$SSHD_OPTS)? ; [^{}]*\}$/.test(
          service.get("ExecStart") ?? "",
        ) ||
        service.get("Environment") ||
        service.get("PassEnvironment") ||
        !/^(?:\/etc\/default\/ssh \(ignore_errors=yes\))?$/.test(service.get("EnvironmentFiles") ?? "")
      )
        throw refuse();
      if (service.get("EnvironmentFiles")) {
        const defaults = await exec(
          context,
          ["sh", "-ec", "if [ -e /etc/default/ssh ]; then cat /etc/default/ssh; fi"],
          { onLine: undefined },
        );
        if (
          defaults.status !== 0 ||
          !defaults.stdout
            .split("\n")
            .every((line) => /^\s*(?:#.*|SSHD_OPTS\s*=\s*(?:""|'')?\s*)?$/.test(line))
        )
          throw refuse();
      }
    }
    if (state === "active") {
      if (!/^[1-9]\d+$/.test(pid ?? "") || service.get("LoadState") !== "loaded") throw refuse();
      // sshd rewrites its title with its original arguments. The image's auxv changes on
      // re-exec even though SIGHUP keeps the PID. Keep both proc values out of the setup log.
      const process = await exec(
        context,
        [
          "sh",
          "-ec",
          'readlink "/proc/$1/exe"; tr "\\000" "\\n" < "/proc/$1/cmdline"; ' +
            'mount=$(readlink /proc/self/ns/mnt); daemon_mount=$(readlink "/proc/$1/ns/mnt"); ' +
            'root=$(stat -Lc %d:%i /); daemon_root=$(stat -Lc %d:%i "/proc/$1/root"); ' +
            'test "$mount" = "$daemon_mount"; test "$root" = "$daemon_root"; sha256sum "/proc/$1/auxv"',
          "sh",
          pid!,
        ],
        { onLine: undefined },
      );
      const [executable, title] = process.stdout.split("\n");
      generation = /^([0-9a-f]{64})  \/proc\/\d+\/auxv$/m.exec(process.stdout)?.[1];
      if (
        process.status !== 0 ||
        executable !== "/usr/sbin/sshd" ||
        !generation ||
        !/^sshd: \/usr\/sbin\/sshd -D \[listener\](?: |$)/.test(title ?? "")
      )
        throw refuse();
    } else if (pid !== "0") throw refuse();
  }

  const socket = await sshUnitProperties(
    context,
    "ssh.socket",
    "ActiveState",
    "Triggers",
    "Accept",
    "Listen",
  );
  const socketEndpoints = new Set<string>();
  if (socket.get("ActiveState") === "active") {
    if (!installed || socket.get("Triggers") !== "ssh.service" || socket.get("Accept") !== "no")
      throw refuse();
    for (const [, endpoint] of (socket.get("Listen") ?? "").matchAll(/(\S+) \(Stream\)/g)) {
      socketEndpoints.add(endpoint);
    }
    if (!socketEndpoints.size) throw refuse();
  } else if (!["inactive", "failed"].includes(socket.get("ActiveState") ?? "")) throw refuse();

  const result = await exec(context, ["ss", "-H", "-ltnp"]);
  if (result.status !== 0) throw refuse();
  let listening = false;
  for (const line of result.stdout.trim().split("\n").filter(Boolean)) {
    const endpoint = /^(?:tcp\s+)?LISTEN\s+\d+\s+\d+\s+(\S+:\d+)\s/.exec(line.trim())?.[1];
    if (!endpoint) throw refuse();
    const owners = [...line.matchAll(socketOwner)];
    const manager = (name: string, owner: string) => name === "systemd" && owner === "1";
    const knownSocket = socketEndpoints.has(endpoint.replace(/^\*:/, "[::]:"));
    if (
      !endpoint.endsWith(":22") &&
      !owners.some(([, name, owner]) => sshdProcess.test(name!) || manager(name!, owner!))
    ) {
      continue;
    }
    if (
      !owners.length ||
      !owners.every(
        ([, name, owner]) =>
          (sshdProcess.test(name!) && owner === pid && generation) || (manager(name!, owner!) && knownSocket),
      )
    )
      throw refuse();
    if (owners.some(([, name]) => sshdProcess.test(name!))) listening = true;
  }
  if (generation && !listening) throw refuse();
  return { installed, generation };
}

async function requireSshHandshakesFinished(context: Context, user: string) {
  // Children that were already negotiating can retain the pre-reload policy.
  // A logged-in session has an owner titled `sshd: user@...` and can stay open.
  const sockets = await exec(context, ["ss", "-H", "-tnp", "state", "connected"]);
  if (sockets.status !== 0) throw openSshPasswordError(user);
  const connections = sockets.stdout
    .split("\n")
    .map((line) =>
      [...line.matchAll(socketOwner)].filter(([, name]) => sshdProcess.test(name!)).map(([, , pid]) => pid!),
    )
    .filter((owners) => owners.length);
  if (!connections.length) return;
  const pids = [...new Set(connections.flat())].join(",");
  const processes = await exec(context, ["ps", "-ww", "-p", pids, "-o", "pid=,args="], { onLine: undefined });
  const loggedIn = new Set(
    [...processes.stdout.matchAll(/^[ \t]*(\d+)\s+sshd(?:-session)?: [^\s@]+@\S+[ \t]*$/gm)].map(
      ([, pid]) => pid,
    ),
  );
  if (connections.some((owners) => !owners.some((pid) => loggedIn.has(pid)))) {
    throw openSshPasswordError(user, "Wait for pending OpenSSH logins to finish, then retry. ");
  }
}

async function reloadOpenSsh(context: Context, user: string, generation: string) {
  await must(context, ["systemctl", "reload", "ssh.service"]);
  // Ubuntu's reload command sends SIGHUP. Wait for the replacement image to listen.
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      const service = await openSshService(context, user);
      if (service.generation && service.generation !== generation) return service;
    } catch {
      // The process and sockets may briefly be between re-exec and listen.
    }
    await context.sleep(250);
  }
  throw new Error("ssh.service did not return with a verified listening daemon after reload.");
}

/** Scoped to `user` only: a Match block in an Included file ends at the end of that file. */
export function sshUserPolicy(user: string) {
  return [
    "# Written by Ark Stack host:setup. The account's password is for sudo, not for OpenSSH.",
    `Match User ${user}`,
    "    PasswordAuthentication no",
    "    KbdInteractiveAuthentication no",
    "",
  ].join("\n");
}

/**
 * Before a password account is created, OpenSSH must refuse password login for it. A stock Ubuntu
 * VPS image often allows passwords (cloud-init's `PasswordAuthentication yes`), so setup adds a
 * `Match User` drop-in for this account only, verifies the effective policy and reloads OpenSSH.
 * Any other login, root included, keeps its current settings.
 */
async function blockOpenSshPasswords(context: Context, user: string) {
  const service = await openSshService(context, user);
  if (!service.installed) {
    // An installed binary without the stock service is a custom setup.
    if ((await exec(context, ["test", "-x", "/usr/sbin/sshd"])).status !== 1)
      throw openSshPasswordError(user);
    return { ...service, policyPath: undefined };
  }
  const check = await openSshPasswordCheck(context, user);
  const directory = context.paths.sshdConfigDir ?? "/etc/ssh/sshd_config.d";
  const path = join(directory, `10-ark-ssh-user-${user}.conf`);
  const policy = sshUserPolicy(user);
  const existing = lstatSync(path, { throwIfNoEntry: false });
  if (
    existing &&
    (!existing.isFile() ||
      existing.uid !== process.getuid?.() ||
      existing.gid !== process.getgid?.() ||
      (existing.mode & 0o7777) !== 0o644 ||
      readFileSync(path, "utf8") !== policy)
  )
    throw openSshPasswordError(user, `Setup will preserve the existing file at ${path}. `);
  if (check === "unverified" || (check === "passwords-allowed" && (existing || !existsSync(directory)))) {
    throw openSshPasswordError(user);
  }

  let created: ReturnType<typeof lstatSync> | undefined;
  try {
    if (check === "passwords-allowed") {
      // Publish the complete file atomically without replacing an entry created by an administrator.
      const temp = mkdtempSync(join(directory, ".ark-ssh-user-"));
      try {
        const draft = join(temp, "policy");
        writeFileSync(draft, policy);
        chmodSync(draft, 0o644);
        const info = lstatSync(draft);
        linkSync(draft, path);
        created = info;
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
      if ((await exec(context, ["/usr/sbin/sshd", "-t"])).status !== 0) {
        throw new Error("OpenSSH rejected the configuration.");
      }
      if ((await openSshPasswordCheck(context, user)) !== "safe") {
        throw new Error("OpenSSH still allows password login or the effective policy could not be verified.");
      }
    }
    // Refresh even a safe on-disk policy. A previous attempt or administrator may have left
    // it on disk without loading it in the daemon.
    const current = await openSshService(context, user);
    const verified = current.generation ? await reloadOpenSsh(context, user, current.generation) : current;
    if (created) context.ui.print(`      Turned off OpenSSH password login for ${user} only (${path}).`);
    return { ...verified, policyPath: created || existing ? path : undefined };
  } catch (error) {
    const current = created && lstatSync(path, { throwIfNoEntry: false });
    const ours =
      current &&
      current.dev === created?.dev &&
      current.ino === created?.ino &&
      readFileSync(path, "utf8") === policy;
    if (ours) rmSync(path);
    const message = error instanceof Error ? error.message : String(error);
    throw openSshPasswordError(
      user,
      `${message} ${ours ? `Setup removed its new file at ${path}. ` : ""}`,
      error,
    );
  }
}

async function reconcileSshUserProvisioning(context: Context) {
  const pending = context.state.sshUserProvisioning;
  if (!pending) return;
  if ((await lookupSshUser(context, pending.user)) !== undefined) {
    throw new Error(
      `Setup did not finish provisioning ${pending.user}, and the account still exists. ` +
        `From your recovery session, inspect the account, then run \`sudo userdel -- ${pending.user}\` to remove it and retry. ` +
        `Inspect and move aside any leftover home directory before retrying.`,
    );
  }
  delete context.state.sshUserProvisioning;
  context.save();
}

async function rollbackSshUser(context: Context, user: string, passwordStatus: number) {
  const removal = await exec(context, ["userdel", "--", user]);
  const failure = `Setting the password for ${user} failed (exit ${passwordStatus})`;
  let removed: boolean;
  try {
    removed = (await lookupSshUser(context, user)) === undefined;
  } catch (error) {
    throw new Error(
      `${failure}. Could not verify cleanup of ${user} (userdel exit ${removal.status}). ${String(error)}`,
      { cause: error },
    );
  }
  if (!removed) {
    throw new Error(
      `${failure}. Cleanup failed (userdel exit ${removal.status}) and ${user} still exists. ` +
        `From your recovery session, inspect the account and run \`sudo userdel -- ${user}\` before retrying.`,
    );
  }
  delete context.state.sshUserProvisioning;
  context.save();
  const result =
    removal.status === 0
      ? "the account was removed"
      : `userdel exited ${removal.status}, and the account is absent`;
  throw new Error(
    `${failure}. ${result}. Inspect and move aside the leftover home directory before retrying.`,
  );
}

/**
 * The Tailscale SSH user must be a local account with a login shell. A fresh VPS often has only
 * root, so an interactive run offers to create the account (home, bash, sudo group, a password for
 * sudo). An existing account is never changed, and non-interactive runs only say what to do.
 */
async function ensureSshUser(context: Context) {
  await reconcileSshUserProvisioning(context);
  const user = context.answers.sshUser;
  const account = await lookupSshUser(context, user);
  if (account !== undefined) {
    if (/(?:^|\/)(?:nologin|false)$/.test(account.shell)) {
      throw new Error(
        `Set --ssh-user to a non-root account with a login shell. ${user} exists but cannot log in.`,
      );
    }
    return;
  }
  const manual = `Create it with \`adduser ${user} && usermod -aG sudo ${user}\`, or set --ssh-user to an existing non-root account.`;
  if (!context.interactive) throw new Error(`The local user ${user} does not exist. ${manual}`);
  context.ui.print(`      The local user ${user} does not exist on this VPS.`);
  const answer = await context.ui.ask(
    `Create ${user} with a home directory, bash and sudo access? (yes/no)`,
    "",
  );
  if (!/^yes$/i.test(answer.trim())) throw new Error(`The local user ${user} does not exist. ${manual}`);
  const home = join(context.paths.sshHomeBase ?? "/home", user);
  requireFreshHome(home);
  const protectedSsh = await blockOpenSshPasswords(context, user);
  await requireSshHandshakesFinished(context, user);
  let password: string;
  for (;;) {
    password = await context.ui.askPassword(`Password for ${user} (used for sudo)`);
    if (password.length < MIN_PASSWORD_LENGTH) {
      context.ui.print(`  Use at least ${MIN_PASSWORD_LENGTH} characters.`);
      continue;
    }
    if (/[\0\r\n]/.test(password)) {
      context.ui.print("  The password cannot contain a NUL or line break.");
      continue;
    }
    if ((await context.ui.askPassword(`Repeat the password for ${user}`)) === password) break;
    context.ui.print("  The passwords did not match.");
  }
  requireFreshHome(home);
  delete context.state.sshConfirmation;
  context.state.sshUserNeedsConfirmation = true;
  context.state.sshUserProvisioning = { user };
  context.save();
  await must(context, [
    "useradd",
    "--create-home",
    "--home-dir",
    home,
    "--shell",
    "/bin/bash",
    "--groups",
    "sudo",
    "--",
    user,
  ]);
  const created = await lookupSshUser(context, user);
  const directory = lstatSync(home, { throwIfNoEntry: false });
  if (
    created?.home !== home ||
    created.shell !== "/bin/bash" ||
    !directory?.isDirectory() ||
    directory.uid !== created.uid
  ) {
    throw new Error(`Could not verify the new login account ${user} and its home directory ${home}.`);
  }
  if (protectedSsh.installed && (await openSshPasswordCheck(context, user)) !== "safe") {
    throw openSshPasswordError(user);
  }
  const current = await openSshService(context, user);
  if (
    current.installed !== protectedSsh.installed ||
    (protectedSsh.generation && current.generation && current.generation !== protectedSsh.generation)
  )
    throw openSshPasswordError(user, "The OpenSSH service changed during account provisioning. ");
  const set = await exec(context, ["chpasswd"], { stdin: `${user}:${password}\n`, onLine: undefined });
  if (set.status !== 0) await rollbackSshUser(context, user, set.status);
  delete context.state.sshUserProvisioning;
  context.save();
  context.ui.print(`      Created ${user} (member of sudo).`);
  return protectedSsh.policyPath;
}

async function sshGate(context: Context): Promise<StepResult> {
  const rollback = await exec(context, [
    "systemctl",
    "is-active",
    SSH_ROLLBACK_TIMER + ".timer",
    SSH_ROLLBACK_TIMER + ".service",
  ]);
  if (/^(?:active|activating)$/m.test(rollback.stdout)) {
    throw new SetupPaused(
      "An earlier OpenSSH cutover is awaiting automatic recovery. Wait for its rollback timer to finish and retry.",
    );
  }
  const status = await vpsTailscaleStatus(context);
  const target = confirmationTarget(context, status);
  const policyPath = await ensureSshUser(context);
  if (
    !context.state.sshUserNeedsConfirmation &&
    !context.state.sshCutoverPending &&
    context.state.sshConfirmation?.target === target
  ) {
    return { status: "done", message: `Tailscale SSH confirmed ${context.state.sshConfirmation.at}` };
  }
  const changed = Boolean(
    context.state.sshUserNeedsConfirmation ||
    context.state.sshConfirmation ||
    context.state.sshCutoverPending ||
    context.state.steps["ssh-gate"]?.status === "done",
  );
  const command = freshSshCommand(context, status);
  context.ui.print(
    "      From your own device (not this session), open a new Tailscale SSH session and keep it open:",
  );
  context.ui.print("");
  context.ui.print(`        ${command}`);
  context.ui.print("");
  const notice = vpsNameNotice(context, status);
  if (notice) context.ui.print(`      ${notice}`);
  const origin = await context.sessionOrigin();
  if (origin.via === "tailscale") {
    context.ui.print("      This session already arrives over Tailscale (tailscale0).");
  } else if (origin.via === "openssh") {
    context.ui.print(
      "      This session arrives over public OpenSSH. Hardening keeps established connections, but",
    );
    context.ui.print(
      "      a scoped recovery rule preserves new connections from your client during cutover.",
    );
  }
  let confirmed = !changed && context.options.tailscaleSshConfirmed;
  if (!confirmed && context.interactive) {
    const answer = await context.ui.ask("Type yes once that session works (anything else stops here)", "");
    confirmed = /^yes$/i.test(answer.trim());
  }
  if (!confirmed) {
    delete context.state.sshUserNeedsConfirmation;
    delete context.state.sshConfirmation;
    delete context.state.sshCutoverPending;
    delete context.state.steps["ssh-gate"];
    context.save();
    throw new SetupPaused(
      `Stopped before firewall hardening and the public SSH cutover. Tailscale SSH has not been confirmed.
${policyPath ? `OpenSSH password login remains disabled for ${context.answers.sshUser} in ${policyPath}.\n` : ""}
Check that \`${command}\` works from your own device, then resume with:

  ${context.resumeCommand}${context.interactive ? "" : " --tailscale-ssh-confirmed"}`,
    );
  }
  delete context.state.sshUserNeedsConfirmation;
  delete context.state.sshCutoverPending;
  context.state.sshConfirmation = { target, at: new Date().toISOString() };
  context.save();
  return { status: "done", message: "Tailscale SSH confirmed by the owner" };
}

async function install(context: Context): Promise<StepResult> {
  await requireSshConfirmation(context);
  const { ports } = await inspectSsh(context);
  const existing = readHostSshAccess(readEnv(context.paths.hostFirewall));
  const origin = await context.sessionOrigin();
  const source =
    context.options.sshRecoverySource ??
    (origin.via === "openssh" ? origin.source : undefined) ??
    existing.source;
  if (ports.length && !source && !context.options.keepPublicSsh) {
    throw new SetupPaused(
      `Public OpenSSH needs a recovery source before hardening. Resume with --ssh-recovery-source IP using the IP of your OpenSSH client, or use --keep-public-ssh to explicitly retain public access.\n  ${context.resumeCommand}`,
    );
  }
  const ssh: HostSshAccess = {
    ports,
    source: ports.length && !context.options.keepPublicSsh ? source : undefined,
  };
  const { mailEnabled, sniPorts, rebootTime } = context.answers;
  const fingerprint = JSON.stringify({ mailEnabled, sniPorts, rebootTime, commit: await gitCommit(context) });
  const record = context.state.steps.install;
  if (
    record?.status === "done" &&
    record.fingerprint === fingerprint &&
    (await hardeningMatches(context, ssh)) &&
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
    ARK_SETUP_HOST_SSH_ACCESS: JSON.stringify(ssh),
  });
  await must(context, [context.bun, "scripts/install.ts", "--harden-vps"], { env });
  context.redactor.addEnv(readEnv(context.envPath));
  if (!(await apiHealthy(context)))
    throw new Error("The install finished but http://127.0.0.1:3000/api/health does not answer.");
  return { status: "done", fingerprint, message: "host hardened, platform installed and healthy" };
}

async function hardeningMatches(context: Context, ssh: HostSshAccess) {
  try {
    const boot = readEnv(context.paths.hostFirewall);
    if (!boot || replaceHostSshAccess(boot, ssh) !== boot) return false;
    const active = await exec(context, ["systemctl", "is-active", "ark-host-firewall.service"]);
    if (active.status !== 0 || active.stdout.trim() !== "active") return false;
    const enabled = await exec(context, ["systemctl", "is-enabled", "ark-host-firewall.service"]);
    if (enabled.stdout.trim() !== "enabled") return false;
    const inventory = await must(context, [context.bun, "scripts/host-audit.ts", "--inventory"], {
      env: childEnv(context),
    });
    const { config } = JSON.parse(inventory) as { config: HostPortConfig };
    const tableStart = boot.indexOf("table inet ark_host {");
    if (tableStart < 0) return false;
    assertHostFirewall(boot.slice(tableStart), { ...config, routes: [] }, ssh);
    const rules = await must(context, ["nft", "-s", "-y", "list", "table", "inet", "ark_host"]);
    assertHostFirewall(rules, config, ssh);
    return true;
  } catch (error) {
    context.log.write(`Hardening needs reconciliation: ${String(error)}`);
    return false;
  }
}

type ContainerStatus = TailscaleState & { Health?: string[] };

const CONTAINER_SOCKET = "/var/run/tailscale/tailscaled.sock";

async function containerStatus(context: Context, service: string) {
  const result = await exec(
    context,
    compose(context, "exec", "-T", service, "tailscale", `--socket=${CONTAINER_SOCKET}`, "status", "--json"),
    { env: childEnv(context) },
  );
  try {
    return JSON.parse(result.stdout) as ContainerStatus;
  } catch {
    return undefined;
  }
}

async function edgeTags(context: Context, service = "edge-ts") {
  const status = await containerStatus(context, service);
  if (!status) return undefined;
  const rejected = status.Health?.some((notice) =>
    /(?:invalid|expired|revoked) (?:auth(?:orization)? )?key|auth key.*(?:expired|revoked|not found)/i.test(
      notice,
    ),
  );
  return { running: status.BackendState === "Running", tags: status.Self?.Tags ?? [], rejected, status };
}

/** A container node's name: what compose passes to containerboot as TS_HOSTNAME on every start. */
type ContainerName = {
  node: Exclude<TailscaleNode, "vps">;
  service: string;
  /** The `.env` key behind TS_HOSTNAME in infra/platform/docker-compose.yml. */
  variable: "TS_EDGE_HOSTNAME" | "TS_BACKUP_HOSTNAME";
  /** Compose's default when the key is empty: the name every earlier install used. */
  composeDefault: string;
  desired: string;
  /** Given by flag or variable (now or on an earlier run): only then is an enrolled node renamed. */
  explicit: boolean;
};

function edgeName(context: Context): ContainerName {
  return {
    node: "edge",
    service: "edge-ts",
    variable: "TS_EDGE_HOSTNAME",
    composeDefault: "ark-edge",
    desired: edgeHostname(context.answers),
    explicit: context.answers.tailscaleEdgeHostname !== undefined,
  };
}

function backupName(context: Context): ContainerName {
  return {
    node: "backup",
    service: "backup-ts",
    variable: "TS_BACKUP_HOSTNAME",
    composeDefault: "ark-backup",
    desired: backupHostname(context.answers),
    explicit: context.answers.tailscaleBackupHostname !== undefined,
  };
}

function configuredName(context: Context, spec: ContainerName) {
  return parseEnvFile(readEnv(context.envPath))[spec.variable]?.trim() || spec.composeDefault;
}

/** Keeps containerboot's TS_HOSTNAME equal to the node's name, so a restart never renames it. */
function configureName(context: Context, spec: ContainerName, name: string) {
  if (configuredName(context, spec) === name) return;
  writeEnv(context.envPath, setEnvValues(readEnv(context.envPath), { [spec.variable]: name }));
}

function validName(name: string | undefined) {
  try {
    return name ? validateTailscaleHostname(name) === name : false;
  } catch {
    return false;
  }
}

/**
 * An enrolled container node keeps its name unless the operator gave a different one explicitly;
 * then it is renamed in place with `tailscale set --hostname`, never re-enrolled.
 */
async function reconcileContainerName(context: Context, spec: ContainerName, status?: TailscaleState) {
  const current = status?.Self?.HostName;
  const rename = spec.explicit && current !== spec.desired;
  let requested: string;
  if (rename) {
    configureName(context, spec, spec.desired);
    await must(
      context,
      compose(
        context,
        "exec",
        "-T",
        spec.service,
        "tailscale",
        `--socket=${CONTAINER_SOCKET}`,
        "set",
        `--hostname=${spec.desired}`,
      ),
      { env: childEnv(context) },
    );
    requested = spec.desired;
  } else if (current && validName(current)) {
    configureName(context, spec, current);
    requested = current;
  } else requested = configuredName(context, spec);
  const name = await recordTailscaleName(
    context,
    spec.node,
    requested,
    () => containerStatus(context, spec.service),
    rename,
  );
  return { name, renamed: rename };
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
  const spec = edgeName(context);
  const before = await edgeTags(context);
  if (before?.running && exact(before.tags)) {
    const { name, renamed } = await reconcileContainerName(context, spec, before.status);
    await rejoinEdge(context);
    emptyEdgeKey(context);
    return {
      status: "done",
      message: renamed
        ? `edge-ts already joined as ${ARK_EDGE_TAG}; renamed to ${name}`
        : `edge-ts already joined as ${ARK_EDGE_TAG} (${name})`,
    };
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
  let acquired: AcquiredKey | undefined;
  const retiring = context.state.edgeKeyRetry;
  if (!kept || context.env.TS_EDGE_AUTHKEY?.trim() || (retiring && context.interactive)) {
    context.ui.print(
      `      The edge node needs its own one-off key tagged ${ARK_EDGE_TAG} (never the VPS key).`,
    );
    const key = await context.keys.acquire({
      tag: ARK_EDGE_TAG,
      variable: "TS_EDGE_AUTHKEY",
      optional: true,
    });
    if (!key?.key && !kept) {
      return {
        status: "skipped",
        note: "The edge node (edge-ts) has not joined the tailnet.",
        finish: EDGE_FINISH,
      };
    }
    if (key?.key) {
      context.redactor.add(key.key);
      acquired = key;
      // API-minted keys are sent to the running daemon on stdin.
      if (!key.inMemoryOnly) writeEnv(context.envPath, applyEdgeAuthKey(current, key.key).env);
    }
  } else context.redactor.add(kept);
  const transient = acquired?.inMemoryOnly ? acquired.key : undefined;
  let revoked: boolean | undefined;
  let name = spec.desired;
  try {
    if (!transient) {
      // A timeout may be transient. Keep the key but allow a replacement on the next run.
      context.state.edgeKeyRetry = true;
      context.save();
    }
    // A new node joins with the chosen name; containerboot repeats it on every start.
    configureName(context, spec, spec.desired);
    await must(context, compose(context, "up", "-d", "edge-ts", "edge", "edge-l4"), {
      env: childEnv(context, transient ? { TS_EDGE_AUTHKEY: "" } : {}),
    });
    if (transient) await enrolContainer(context, "edge-ts", spec.desired, transient);
    await waitForNode(context, "edge-ts", ARK_EDGE_TAG);
    name = await recordTailscaleName(
      context,
      "edge",
      spec.desired,
      () => containerStatus(context, "edge-ts"),
      true,
    );
    await rejoinEdge(context);
    emptyEdgeKey(context);
    delete context.state.edgeKeyRetry;
  } finally {
    revoked = await acquired?.release?.();
  }
  return {
    status: "done",
    message: transient
      ? `edge-ts joined as ${ARK_EDGE_TAG} named ${name}`
      : `edge-ts joined as ${ARK_EDGE_TAG} named ${name}; TS_EDGE_AUTHKEY emptied in .env`,
    ...keyCleanupNote(revoked, ARK_EDGE_TAG),
  };
}

/** Waits up to two minutes for a Tailscale container to join with exactly `tag`. */
async function waitForNode(context: Context, service: string, tag: string) {
  let after = await edgeTags(context, service);
  for (let attempt = 0; attempt < 24 && !after?.running && !after?.rejected; attempt++) {
    await context.sleep(5000);
    after = await edgeTags(context, service);
  }
  if (after?.rejected) {
    if (service === "edge-ts") emptyEdgeKey(context);
    throw new Error(
      `Tailscale rejected the ${service === "edge-ts" ? "edge" : "backup node"} auth key. Retry with a fresh one-off ${tag} key.`,
    );
  }
  if (!after?.running)
    throw new Error(`${service} did not join the tailnet within two minutes. Check the key and the policy.`);
  if (after.tags.length !== 1 || after.tags[0] !== tag) {
    if (service === "edge-ts") emptyEdgeKey(context);
    throw new Error(
      `${service} joined with tags ${JSON.stringify(after.tags)}, not exactly ["${tag}"]. Remove that device in the admin console and re-enrol it (docs/operating.md#edge-tailscale-node).`,
    );
  }
  return after;
}

function keyCleanupNote(revoked: boolean | undefined, tag: string) {
  if (revoked !== false) return {};
  return {
    note: `Tailscale did not confirm revocation of the one-off ${tag} key.`,
    finish: "Revoke the key under Settings > Keys in the Tailscale admin console.",
  };
}

/** The pinned Tailscale CLI reads file:/dev/stdin without placing the key in argv or Docker config. */
async function enrolContainer(context: Context, service: string, hostname: string, key: string) {
  const socket = CONTAINER_SOCKET;
  await must(
    context,
    compose(
      context,
      "exec",
      "-T",
      service,
      "sh",
      "-c",
      'until [ -S "$1" ]; do sleep 1; done; exec tailscale --socket="$1" up --timeout=90s --auth-key=file:/dev/stdin --accept-dns=false --shields-up --hostname="$2"',
      "sh",
      socket,
      hostname,
    ),
    { env: childEnv(context), stdin: key, timeoutMs: 120_000 },
  );
}

const BACKUP_FINISH =
  "Re-run host:setup with --backup-node (with a Tailscale API credential, or a one-off tag:ark-backup key in TS_BACKUP_AUTHKEY), or follow docs/guides/backups.md#setting-up-the-home-machine.";

/** Optional: the backup node (backup-ts) for a home backup target, never sharing a key or a tag. */
async function backupNode(context: Context): Promise<StepResult> {
  if (!context.options.backupNode) {
    return { status: "skipped", message: "not requested (--backup-node enrols it for a home backup target)" };
  }
  const spec = backupName(context);
  const before = await edgeTags(context, "backup-ts");
  if (before?.running && before.tags.length === 1 && before.tags[0] === ARK_BACKUP_TAG) {
    const { name, renamed } = await reconcileContainerName(context, spec, before.status);
    return {
      status: "done",
      message: renamed
        ? `backup-ts already joined as ${ARK_BACKUP_TAG}; renamed to ${name}`
        : `backup-ts already joined as ${ARK_BACKUP_TAG} (${name})`,
    };
  }
  if (before?.running && before.tags.length) {
    throw new Error(
      `backup-ts is running with tags ${JSON.stringify(before.tags)}, not exactly ["${ARK_BACKUP_TAG}"]. Remove that device in the admin console and re-enrol it (docs/operating.md#revocation).`,
    );
  }
  context.ui.print(`      The backup node needs its own one-off key tagged ${ARK_BACKUP_TAG}.`);
  const key = await context.keys.acquire({
    tag: ARK_BACKUP_TAG,
    variable: "TS_BACKUP_AUTHKEY",
    optional: true,
  });
  if (!key?.key) {
    return {
      status: "skipped",
      note: "The backup node (backup-ts) has not joined the tailnet.",
      finish: BACKUP_FINISH,
    };
  }
  context.redactor.add(key.key);
  let revoked: boolean | undefined;
  let name = spec.desired;
  try {
    configureName(context, spec, spec.desired);
    await must(context, compose(context, "up", "-d", "backup-ts"), {
      env: childEnv(context, { TS_BACKUP_AUTHKEY: key.inMemoryOnly ? "" : key.key }),
    });
    if (key.inMemoryOnly) await enrolContainer(context, "backup-ts", spec.desired, key.key);
    await waitForNode(context, "backup-ts", ARK_BACKUP_TAG);
    if (!key.inMemoryOnly) {
      await must(context, compose(context, "up", "-d", "backup-ts"), {
        env: childEnv(context, { TS_BACKUP_AUTHKEY: "" }),
      });
      await waitForNode(context, "backup-ts", ARK_BACKUP_TAG);
    }
    name = await recordTailscaleName(
      context,
      "backup",
      spec.desired,
      () => containerStatus(context, "backup-ts"),
      true,
    );
  } finally {
    revoked = await key.release?.();
  }
  return {
    status: "done",
    message: `backup-ts joined as ${ARK_BACKUP_TAG} named ${name}`,
    ...keyCleanupNote(revoked, ARK_BACKUP_TAG),
  };
}

async function rejoinEdge(context: Context) {
  await must(context, [context.bun, `--env-file=${context.envPath}`, "scripts/edge-namespace.ts"], {
    env: childEnv(context),
  });
  delete context.state.edgeKeyRetry;
}

const configuredServices = ["api", "domain-worker"];

async function configurationReady(context: Context, env: ReturnType<typeof childEnv>) {
  const expected = new Map(
    (await must(context, compose(context, "config", "--hash=*"), { env }))
      .trim()
      .split("\n")
      .map((line) => line.trim().split(/\s+/) as [string, string]),
  );
  for (const service of configuredServices) {
    const id = (await must(context, compose(context, "ps", "-a", "-q", service), { env })).trim();
    if (!id || !expected.get(service)) return false;
    const observed = await exec(
      context,
      [
        "docker",
        "inspect",
        "--format",
        '{{.State.Status}} {{index .Config.Labels "com.docker.compose.config-hash"}}',
        id,
      ],
      { env },
    );
    if (observed.status !== 0 || observed.stdout.trim() !== `running ${expected.get(service)}`) return false;
  }
  const worker = await exec(
    context,
    compose(
      context,
      "exec",
      "-T",
      "domain-worker",
      "bun",
      "-e",
      'const response = await fetch("http://127.0.0.1:3102/", {signal: AbortSignal.timeout(3000)}); if (response.status !== 404) process.exit(1);',
    ),
    { env, timeoutMs: 5000 },
  );
  return worker.status === 0 && (await apiHealthy(context));
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
  const env = childEnv(context);
  if (
    !changed &&
    record?.status === "done" &&
    record.fingerprint === fingerprint &&
    (await configurationReady(context, env))
  ) {
    return { status: "done", fingerprint, message: "admin origin and ACME settings already in .env" };
  }
  if (changed) {
    writeEnv(context.envPath, setEnvValues(current, desired));
    context.redactor.addEnv(readEnv(context.envPath));
  }
  const appliedEnv = childEnv(context);
  await must(context, compose(context, "up", "--wait", "--wait-timeout", "120", ...configuredServices), {
    env: appliedEnv,
  });
  let ready = false;
  for (let attempt = 0; attempt < 12 && !ready; attempt++) {
    if (attempt) await context.sleep(2000);
    ready = await configurationReady(context, appliedEnv);
  }
  if (!ready)
    throw new Error("The API and domain worker did not become ready with the desired Compose configuration.");
  context.state.adminOrigin = adminOrigin;
  context.save();
  return {
    status: "done",
    fingerprint,
    message: `BETTER_AUTH_URL=${adminOrigin}, ARK_ACME_STAGING=${desired.ARK_ACME_STAGING}; api and domain-worker recreated`,
  };
}

type SshUnit = { name: string; enabled: string; active: boolean };
const SSH_UNITS = ["ssh.socket", "ssh.service"];
const SSH_ROLLBACK_TIMER = "ark-ssh-rollback";

function localBind(address: string, tailnet: Set<string>) {
  const ip = address
    .replace(/^\[|\]$/g, "")
    .split("%")[0]!
    .replace(/^::ffff:(?=\d+\.)/, "");
  return ip === "::1" || ip.startsWith("127.") || tailnet.has(ip);
}

async function inspectSsh(context: Context) {
  const ss = await must(context, ["ss", "-H", "-ltnp"]);
  const tailnet = new Set((await tailscaleStatus(context))?.Self?.TailscaleIPs ?? []);
  const listeners = publicSshListeners(ss, tailnet);
  const ports = new Set<number>();
  const units: SshUnit[] = [];
  for (const name of SSH_UNITS) {
    const listed = await must(context, ["systemctl", "list-unit-files", "--no-legend", name]);
    if (!listed.trim()) continue;
    const enabled = (await exec(context, ["systemctl", "is-enabled", name])).stdout.trim();
    const active = (await exec(context, ["systemctl", "is-active", name])).stdout.trim() === "active";
    if (!active && enabled !== "enabled" && enabled !== "enabled-runtime") continue;
    const socket = name === "ssh.socket";
    const owner = socket ? /"systemd",pid=1,/ : /"sshd(?:-session)?",pid=\d+,/;
    const running = ss
      .split("\n")
      .filter((line) => owner.test(line))
      .join("\n");
    const binds = publicSshListeners(running, tailnet);
    if (socket || !active) {
      const settings = socket
        ? await must(context, ["systemctl", "show", "--property=Listen", "--value", name])
        : await must(context, ["/usr/sbin/sshd", "-T"]);
      const addresses = socket
        ? [...settings.matchAll(/(\S+) \(Stream\)/g)].map((match) => match[1]!)
        : [...settings.matchAll(/^listenaddress (\S+)$/gm)].map((match) => match[1]!);
      if (!addresses.length) throw new Error("Cannot determine the effective listeners for " + name + ".");
      if (socket) binds.length = 0; // PID 1 may also own unrelated sockets.
      for (const address of addresses) {
        const endpoint = /^(.*):(\d+)$/.exec(address);
        if (endpoint && !localBind(endpoint[1]!, tailnet)) binds.push(address);
      }
    }
    if (!binds.length) continue;
    units.push({ name, enabled, active });
    for (const bind of binds) ports.add(Number(bind.split(":").at(-1)));
  }
  return { listeners, units, ports: [...ports].toSorted((a, b) => a - b) };
}

function sshIngressSource(source: string) {
  if (/^Anywhere(?: \(v6\))?$/.test(source)) return "public";
  const [address, prefix] = source.split("/");
  if (!address || !isIP(address) || (prefix && !/^\d+$/.test(prefix))) return "ambiguous";
  if (prefix === "0") return "public";
  if (isIP(address) === 4) {
    return /^(?:0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(
      address,
    )
      ? "private"
      : "public";
  }
  if (/^[23]/.test(address)) return "public";
  return /^(?:fc|fd|fe[89ab]|::1$)/i.test(address) ? "private" : "ambiguous";
}

export function publicUfwSshRules(status: string) {
  const remove: number[] = [];
  let ambiguous = 0;
  for (const match of status.matchAll(/^\[\s*(\d+)\]\s+(.+?)\s{2,}ALLOW( IN| OUT| FWD)?\s{2,}(.+?)\s*$/gm)) {
    const [, number, to, direction, from] = match;
    if (!/^(?:22(?:\/tcp)?|OpenSSH)(?:\s|$)/.test(to!) || direction === " OUT" || direction === " FWD")
      continue;
    if (/^(?:22(?:\/tcp)?|OpenSSH)(?: \(v6\))?$/.test(to!)) {
      const source = sshIngressSource(from!.split(/\s+#/)[0]!.trim());
      if (source === "public") remove.push(Number(number));
      if (source === "ambiguous") ambiguous++;
    } else {
      ambiguous++;
    }
  }
  return { remove: remove.toSorted((a, b) => b - a), ambiguous };
}

async function setSshAccess(context: Context, access: HostSshAccess) {
  const path = context.paths.hostFirewall;
  const boot = readFileSync(path, "utf8");
  const next = replaceHostSshAccess(boot, access);
  if (next !== boot) writeHostFile(path, next, 0o644);
  await must(context, ["nft", "-f", "-"], { stdin: updateHostSshAccess(access) });
  const live = await must(context, ["nft", "-s", "-y", "list", "table", "inet", "ark_host"]);
  const actual = readHostSshAccess(live);
  const address = (source?: string) =>
    source && isIP(source) === 6 ? new URL("http://[" + source + "]/").hostname : source;
  if (String(actual.ports) !== String(access.ports) || address(actual.source) !== address(access.source)) {
    throw new Error("The live firewall's SSH access differs from the requested policy.");
  }
}

async function closePublicSsh(context: Context): Promise<StepResult> {
  const { keepPublicSsh, verifySshCutover } = context.options;
  if (keepPublicSsh) {
    return {
      status: "skipped",
      note: "Public OpenSSH was left running (--keep-public-ssh).",
      finish: "Re-run host:setup without --keep-public-ssh to close it.",
    };
  }
  const { units, listeners, ports } = await inspectSsh(context);
  if (listeners.length && !units.length) {
    throw new Error("Public TCP listeners remain outside the managed OpenSSH units: " + listeners.join(", "));
  }
  if (units.length && !context.interactive && !verifySshCutover) {
    return {
      status: "pending",
      note: "OpenSSH is retained while a fresh off-host Tailscale SSH login is pending.",
      finish: "Re-run interactively or with --verify-ssh-cutover to close public SSH.",
    };
  }
  const status = await exec(context, ["ufw", "status", "numbered"]);
  const ufwActive = status.status === 0 && /^Status: active$/m.test(status.stdout);
  // Leave a private service's UFW profile alone.
  const { remove, ambiguous } = publicUfwSshRules(ufwActive && units.length ? status.stdout : "");
  if (!units.length) return sshClosed(ufwActive, ambiguous, 0);

  await requireSshConfirmation(context);
  const access = readHostSshAccess(readFileSync(context.paths.hostFirewall, "utf8"));
  if (ports.length && (!access.source || ports.some((port) => !access.ports.includes(port)))) {
    throw new Error(
      "The scoped OpenSSH recovery path is missing. Re-run host setup from the recovery client.",
    );
  }
  const directory = mkdtempSync(join(context.stateDir, "ssh-cutover-"));
  const ufwDirectory = context.paths.ufwDirectory ?? "/etc/ufw";
  const lock = join(directory, "lock");
  const helper = join(context.root, "scripts", "host-setup", "restore-ssh.sh");
  const restore = (mode: "timed" | "force") => [
    "flock",
    lock,
    "/bin/sh",
    helper,
    directory,
    mode,
    ufwDirectory,
    ...units.map(({ name, enabled, active }) => [name, enabled, active].join(":")),
  ];
  let armed = false;
  let accessChanged = false;
  let finished = false;
  try {
    if (remove.length) {
      for (const file of ["user.rules", "user6.rules"]) {
        if (existsSync(join(ufwDirectory, file))) {
          await must(context, ["cp", "-p", "--", join(ufwDirectory, file), join(directory, file)]);
        }
      }
    }
    // Reassert the recovery rule before touching systemd, in case live rules drifted.
    if (access.ports.length) await setSshAccess(context, access);
    context.state.sshCutoverPending = true;
    context.save();
    await must(context, [
      "systemd-run",
      "--collect",
      "--unit=" + SSH_ROLLBACK_TIMER,
      "--on-active=5min",
      "--timer-property=AccuracySec=1s",
      ...restore("timed"),
    ]);
    armed = true;
    if (units.length) {
      await must(context, ["systemctl", "stop", ...units.map((unit) => unit.name)]);
      await requireSshConfirmation(context);
      const remaining = await sshListeners(context);
      if (remaining.length) throw new Error("OpenSSH is still listening on " + remaining.join(", ") + ".");

      const command = freshSshCommand(context, await tailscaleStatus(context));
      if (context.interactive) {
        context.ui.print("      Open a fresh session from your own device within four minutes: " + command);
        const notice = vpsNameNotice(context, await tailscaleStatus(context));
        if (notice) context.ui.print(`      ${notice}`);
        const answer = await context.ui.ask(
          "Type yes if it works (anything else restores OpenSSH)",
          "",
          AbortSignal.timeout(240_000),
        );
        if (!/^yes$/i.test(answer.trim()))
          throw new Error("The fresh Tailscale SSH login was not confirmed.");
      } else {
        const proof = join(directory, "proof");
        const remote = "sudo touch -- " + quoteShell(proof);
        context.ui.print(
          "      Verify from an off-host client within four minutes: " + command + " " + quoteShell(remote),
        );
        for (let attempt = 0; attempt < 120 && !existsSync(proof); attempt++) await context.sleep(2000);
        if (!existsSync(proof))
          throw new Error("Timed out waiting for a fresh off-host Tailscale SSH login.");
      }
    }

    // Claim the transaction only if the independent rollback has not fired.
    await must(context, [
      "flock",
      lock,
      "/bin/sh",
      "-ec",
      'test ! -e "$1/rollback-started"; touch "$1/verified"',
      "sh",
      directory,
    ]);
    for (const { name, enabled } of units) {
      if (enabled === "enabled" || enabled === "enabled-runtime") {
        await must(context, [
          "systemctl",
          "disable",
          ...(enabled === "enabled-runtime" ? ["--runtime"] : []),
          name,
        ]);
      }
    }
    if (remove.length) writeFileSync(join(directory, "ufw-changed"), "");
    for (const number of remove) await must(context, ["ufw", "--force", "delete", String(number)]);
    if (access.ports.length) {
      accessChanged = true;
      await setSshAccess(context, { ports: [] });
    }
    delete context.state.sshCutoverPending;
    context.save();
    finished = true;
  } catch (error) {
    delete context.state.sshConfirmation;
    if (!armed) throw error;
    const rollbackErrors: unknown[] = [];
    if (accessChanged) {
      try {
        await setSshAccess(context, access);
      } catch (failure) {
        rollbackErrors.push(failure);
      }
    }
    try {
      await must(context, restore("force"));
      const restored = await sshListeners(context);
      if (listeners.some((listener) => !restored.includes(listener)))
        throw new Error("The original public SSH listeners did not return.", { cause: error });
    } catch (rollbackError) {
      rollbackErrors.push(rollbackError);
    }
    if (rollbackErrors.length) {
      throw new Error(
        String(error) +
          " SSH restoration failed: " +
          rollbackErrors.map(String).join(", ") +
          ". Recovery files: " +
          directory,
        { cause: error },
      );
    }
    finished = true;
    throw new Error(String(error) + " The prior OpenSSH listener and firewall configuration were restored.", {
      cause: error,
    });
  } finally {
    if (!armed || finished) {
      const stopped =
        !armed || (await exec(context, ["systemctl", "stop", SSH_ROLLBACK_TIMER + ".timer"])).status === 0;
      if (stopped) rmSync(directory, { recursive: true, force: true });
    }
  }
  return sshClosed(ufwActive, ambiguous, remove.length);
}

function quoteShell(value: string) {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

function freshSshCommand(context: Context, status: TailscaleState | undefined) {
  return `tailscale ssh ${sshTarget(context, status)} -o ControlPath=none`;
}

function sshClosed(ufwActive: boolean, ambiguous: number, removed: number): StepResult {
  return {
    status: "done",
    message: removed
      ? "public OpenSSH closed; removed " + removed + " public UFW SSH rule(s)"
      : "public OpenSSH is not listening",
    note: ufwActive
      ? "UFW is active; its policy can block Ark's public ports." +
        (ambiguous ? " Retained " + ambiguous + " scoped or ambiguous SSH rule(s)." : "")
      : undefined,
    finish: ufwActive ? "Review the remaining rules with sudo ufw status verbose." : undefined,
  };
}

async function providerFirewall(context: Context): Promise<StepResult> {
  // Never touch the provider's firewall (which may still carry the only SSH path) before the gate.
  if (context.state.steps["ssh-gate"]?.status !== "done" || !context.state.sshConfirmation) {
    throw new SetupPaused(
      "The Tailscale SSH safety check has not passed; the provider firewall was not changed.",
    );
  }
  const inventory = await must(context, [context.bun, "scripts/host-audit.ts", "--inventory"], {
    env: childEnv(context),
  });
  const parsed = JSON.parse(inventory) as { config: unknown; providerRules: ProviderRule[] };
  const inventoryPath = join(context.root, "tmp", "ark-host-inventory.json");
  writeFileSync(inventoryPath, inventory.endsWith("\n") ? inventory : `${inventory}\n`, { mode: 0o644 });
  const addresses = await publicAddresses(context);
  const status = await tailscaleStatus(context);
  const retainSsh = context.state.steps["public-ssh"]?.status !== "done";
  const access = readHostSshAccess(readEnv(context.paths.hostFirewall));
  const rules = [...parsed.providerRules];
  if (retainSsh && access.ports.length) {
    rules.push({
      protocol: "tcp",
      ports: access.ports,
      sourceCidrs: access.source
        ? [`${access.source}/${isIP(access.source) === 4 ? 32 : 128}`]
        : ["0.0.0.0/0", "::/0"],
    });
  }
  const firewallContext: FirewallContext = {
    ui: context.ui,
    interactive: context.interactive,
    env: context.env,
    publicAddresses: addresses,
    confirmed: context.options.providerFirewallApplied,
    retainSsh,
    approved: context.options.nonInteractive && context.options.approveProviderFirewall,
    secret: (value) => context.redactor.add(value),
    log: (line) => context.log.write(line),
  };
  const node = status?.Self?.ID ?? status?.Self?.PublicKey;
  const fingerprintFor = (adapter: string) => JSON.stringify({ adapter, node, addresses, rules, retainSsh });
  const record = context.state.steps["provider-firewall"];
  const requested = context.options.providerFirewall;
  const useRecordedHetzner =
    node &&
    !context.env.HCLOUD_TOKEN?.trim() &&
    (!requested || requested === "hetzner") &&
    record?.status === "done" &&
    record.fingerprint === fingerprintFor("hetzner");
  let result: StepResult;
  if (useRecordedHetzner) {
    result = {
      status: "done",
      fingerprint: record.fingerprint,
      message:
        "rules unchanged since the recorded Hetzner apply (HCLOUD_TOKEN needed to re-verify at the provider)",
    };
  } else {
    const adapter = await selectProviderFirewall(context.firewalls, firewallContext, requested);
    const fingerprint = fingerprintFor(adapter.id);
    const plan = await adapter.plan(rules, firewallContext);
    for (const line of plan.notices ?? []) context.ui.print(`      ${line}`);
    if (adapter.id === "manual" && record?.status === "done" && record.fingerprint === fingerprint) {
      result = { status: "done", fingerprint, message: "rules unchanged since they were applied" };
    } else if (plan.inSync) {
      result = { status: "done", fingerprint, message: `provider already matches (${adapter.label})` };
    } else {
      for (const line of plan.changes) context.ui.print(`      ${line}`);
      const applied = await adapter.apply(plan, firewallContext);
      if (applied.status === "pending")
        return { status: "pending", note: applied.note, finish: applied.finish };
      result = { status: "done", fingerprint, message: `rules applied (${adapter.label})` };
    }
  }
  // The local audit follows confirmation or verified provider application.
  await must(context, [context.bun, "scripts/host-audit.ts", ...(retainSsh ? ["--retain-ssh"] : [])], {
    env: childEnv(context),
  });
  const ips = [...addresses.ipv4, ...addresses.ipv6];
  if (retainSsh && access.ports.length) {
    context.ui.print(
      "      Local audit passed with OpenSSH retained. Run the standard external scan after closing public SSH.",
    );
  } else {
    context.ui.print(
      "      Local audit passed. Scan from another machine with Nmap (in a checkout, as root):",
    );
    context.ui.print(`        scp ${sshTarget(context, status)}:${inventoryPath} .`);
    context.ui.print(
      `        sudo mise run host:audit --external ark-host-inventory.json ${ips.length ? ips.join(" ") : "<public-ipv4> <public-ipv6>"}`,
    );
  }
  result.message = `${result.message}; local audit passed`;
  return result;
}

export const STEPS: Step[] = [
  { id: "prerequisites", title: "Prerequisite checks", run: prerequisites },
  { id: "tailscale", title: "Tailscale enrolment (tag:ark-vps)", run: tailscaleEnrolment },
  { id: "ssh-gate", title: "Tailscale SSH safety check", run: sshGate },
  { id: "install", title: "Harden the host and install", run: install },
  { id: "edge", title: "Edge node enrolment (tag:ark-edge)", run: edgeEnrolment },
  { id: "backup-node", title: "Backup node enrolment (tag:ark-backup)", run: backupNode },
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

/** The machine names Tailscale assigned, as read back from each node's status. */
function tailscaleNameLines(context: Context, status: TailscaleState | undefined) {
  const requested = context.answers.tailscaleHostname;
  const assigned = assignedTailscaleName(status) ?? requested;
  const lines = [
    "Tailscale machine names:",
    `  This VPS:      ${assigned}${assigned === requested ? "" : ` (requested ${requested}; Tailscale assigned a different name)`}`,
  ];
  const labels = { edge: "Edge node:     ", backup: "Backup node:   " } as const;
  for (const node of ["edge", "backup"] as const) {
    const record = context.state.tailscaleNames?.[node];
    if (!record) continue;
    const name = record.assigned ?? record.requested;
    lines.push(
      `  ${labels[node]}${name}${name === record.requested ? "" : ` (requested ${record.requested}; Tailscale assigned a different name)`}`,
    );
  }
  lines.push(`  Connect with:  tailscale ssh ${sshTarget(context, status)}`);
  return lines;
}

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
    ...tailscaleNameLines(context, status),
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
    // A step skipped without a note (the backup node nobody asked for) has nothing left to do.
    if (record && (record.status === "pending" || record.note)) {
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
export async function detectSessionOrigin(
  env: Record<string, string | undefined>,
  proc = "/proc",
  parent = process.ppid,
): Promise<SessionOrigin> {
  const fromConnection = (value: string | undefined): SessionOrigin | undefined => {
    const [client, clientPort, target, serverPort, extra] = value?.trim().split(/\s+/) ?? [];
    const source = client?.replace(/^::ffff:(?=\d+\.)/, "").split("%")[0];
    const server = target?.replace(/^::ffff:(?=\d+\.)/, "").split("%")[0];
    if (
      !source ||
      !server ||
      !isIP(source) ||
      !isIP(server) ||
      !/^\d+$/.test(clientPort ?? "") ||
      !/^\d+$/.test(serverPort ?? "") ||
      extra
    )
      return undefined;
    const tailnet =
      /^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(server) || /^fd7a:115c:a1e0:/i.test(server);
    return { via: tailnet ? "tailscale" : "openssh", detail: server, source };
  };
  const direct = fromConnection(env.SSH_CONNECTION);
  if (direct) return direct;
  let pid = parent;
  for (let depth = 0; depth < 32 && pid > 1; depth++) {
    try {
      const comm = readFileSync(join(proc, String(pid), "comm"), "utf8").trim();
      if (comm === "tailscaled") return { via: "tailscale" };
      const environ = readFileSync(join(proc, String(pid), "environ"), "utf8").split("\0");
      const found = fromConnection(environ.find((item) => item.startsWith("SSH_CONNECTION="))?.slice(15));
      if (found) return found;
      if (comm === "sshd") return { via: "openssh" };
      pid = Number(
        readFileSync(join(proc, String(pid), "stat"), "utf8")
          .replace(/^.*\)\s+\S+\s+/, "")
          .split(" ")[0],
      );
    } catch {
      break;
    }
  }
  return { via: env.SSH_TTY ? "unknown" : "local" };
}
