// The guided setup against a simulated Ubuntu host. The opt-in Docker tests verify live OpenSSH
// and enrolment in disposable, network-isolated containers.
import assert from "node:assert/strict";
import { afterEach, describe, expect, test } from "bun:test";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  chmodSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  type Dirent,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  generateInstallSecrets,
  generateTailnetAcl,
  mergeInstallEnv,
  parseEnvFile,
  parseHujson,
  parseSniPorts,
  providerFirewallRules,
  renderFrontIngress,
  type HostPortConfig,
  readHostSshAccess,
  sha256Hex,
  renderHostFirewall,
  replaceHostSshAccess,
  type HostSshAccess,
} from "@ark-stack/shared";

import { appliedHostConfig, frontPolicyPending } from "./host-inventory.ts";
import { runSetup, type SetupDependencies } from "./host-setup.ts";
import {
  USAGE,
  derivedNodeName,
  parseFlags,
  resolveOptions,
  sanitizeHostname,
} from "./host-setup/answers.ts";
import { desiredConfiguration, setEnvValues } from "./host-setup/env-file.ts";
import { StateStore } from "./host-setup/state.ts";
import {
  describeProviderRules,
  manualProviderFirewall,
  selectProviderFirewall,
  type FirewallContext,
  type ProviderFirewall,
} from "./host-setup/provider-firewall.ts";
import { portRanges } from "./host-setup/provider-firewalls/common.ts";
import {
  hetznerProviderFirewall,
  hetznerRules,
  type HetznerFirewall,
  type HetznerRule,
} from "./host-setup/provider-firewalls/hetzner.ts";
import {
  ENROL_CONTAINER,
  READ_IDENTITY,
  detectSessionOrigin,
  parseStoredIdentity,
  publicSshListeners,
  publicUfwSshRules,
  sshUserPolicy,
} from "./host-setup/steps.ts";
import {
  Redactor,
  runCommand,
  withoutSetupSecrets,
  type RunOptions,
  type RunResult,
  type Ui,
} from "./host-setup/system.ts";
import { catchAllRules, mergeArkPolicy, rulesDigest } from "./host-setup/tailnet-policy.ts";
import { policyGate } from "./host-setup/policy-gate.ts";
import { enrollVps, validateTailscaleHostname } from "./install-host-hardening.ts";
import {
  KEY_EXPIRY_SECONDS,
  TailscaleApi,
  apiKeySource,
  automaticKeySource,
  credentialFromEnv,
} from "./host-setup/tailscale-api.ts";
import { manualKeySource } from "./host-setup/tailscale-keys.ts";
import {
  credentialsOnStdin,
  verifyMintedKeyRevocations,
  withStreamedCredentials,
} from "./test-install-live.ts";

const repoRoot = join(import.meta.dir, "..");
const BUN = "/test/bun";
const INVENTORY = `${BUN} scripts/host-audit.ts --inventory`;
const AUDIT = `${INVENTORY} --audit`;
const VPS_KEY = "tskey-auth-kVPS1234CNTRL-vpsSecretValue0123456789";
const EDGE_KEY = "tskey-auth-kEDGE5678CNTRL-edgeSecretValue0123456789";
const RECOVERY_IP = "198.51.100.23";
const DNS_TOKEN = "cfDnsToken_0123456789abcdefghijABCDEFGHIJ";
const PROVIDER_RULES = [
  { protocol: "tcp", ports: [25, 80, 443, 465, 587, 993, 5432], sourceCidrs: ["0.0.0.0/0", "::/0"] },
  { protocol: "udp", ports: [41641, 41642], sourceCidrs: ["0.0.0.0/0", "::/0"] },
] satisfies import("./host-setup/provider-firewall.ts").ProviderRule[];

const ok = (stdout = ""): RunResult => ({ status: 0, stdout, stderr: "" });
const fail = (stderr = "", status = 1): RunResult => ({ status, stdout: "", stderr });

type RestartLoop = {
  logs: string;
  /** The hostname preference in the state volume; undefined without an identity, null if unreadable. */
  storedName?: string | null;
  fixedBy: (created: { name: string; key: string }) => boolean;
};

const fixturePrivateKey = `privkey:${"1".repeat(64)}`;
const encodeState = (value: string) => Buffer.from(value).toString("base64");
const storedPrefs = (hostName: string, nodeId: string) =>
  JSON.stringify({ Hostname: hostName, Config: { PrivateNodeKey: fixturePrivateKey, NodeID: nodeId } });
function storedState(hostName: string, nodeId: string, prefs = storedPrefs(hostName, nodeId)) {
  return JSON.stringify({
    "_current-profile": encodeState("profile-1234"),
    _profiles: encodeState(JSON.stringify({ "1234": { Key: "profile-1234", NodeID: nodeId } })),
    "profile-1234": encodeState(prefs),
  });
}

const flagsLog = (name: string) => `boot: 2026/11/24 Running 'tailscale up'
Error: changing settings via 'tailscale up' requires mentioning all
non-default flags. To proceed, either re-run your command with --reset or

\ttailscale up --accept-dns=false --shields-up --hostname=${name}

boot: 2026/11/24 failed to auth tailscale: tailscale up failed: exit status 1
`;

/** A simulated Ubuntu VPS. Each stub mutates this state the way the real command would. */
class FakeHost {
  calls: string[] = [];
  enrolled = false;
  /** Status reads that report the enrolled node as not online yet. */
  offlineReads = 0;
  vpsTags?: string[];
  runSsh = false;
  healthy = false;
  reconcilerRunning = false;
  platformServices: string[] = [];
  onPlatformRestart?: () => void;
  routes: HostPortConfig["routes"];
  ssh = { service: { enabled: true, active: true }, socket: { enabled: false, active: false } };
  edge = { running: false, tags: [] as string[], hostName: "" };
  edgeJoinTags = ["tag:ark-edge"];
  backup = { running: false, tags: [] as string[], hostName: "" };
  stoppedContainers = new Set<string>();
  /** Containers Docker keeps restarting, until one is recreated and `fixedBy` holds for it. */
  restartLoops = new Map<string, RestartLoop>();
  orphanedState = new Map<string, string>();
  failSidecarUp = false;
  /** A diverged or stopped dependency would be reconciled by up without --no-deps. */
  edgeDependencyStarts = 0;
  /** containerboot exits when Tailscale refuses the key, instead of staying up to report it. */
  crashOnRejectedKey = false;
  startupNames = new Map<string, string>();
  containerCreations: [string, string][] = [];
  firstContainerJoins: [string, string][] = [];
  containerNodeIds = new Map<string, string>();
  missingDns = new Set<string>();
  consoleNames = new Map<string, string>();
  /** The host node's requested machine name (Self.HostName). */
  vpsHostName = "ark-vps";
  /** Names already used by another machine: Tailscale assigns `<name>-1` instead. */
  takenNames = new Set<string>();
  /** Every `tailscale set --hostname` on the VPS: [where, name]. */
  renames: [string, string][] = [];
  /** `tailscale up` on the host was run with this machine name. */
  enrolledHostName?: string;
  /** Every key a container was started with, and where it came from. */
  containerKeys: { service: string; key: string; from: "env" | ".env" }[] = [];
  stdinEnrolments: string[] = [];
  /** Keys still present in a container's configuration. */
  configuredKeys = new Map<string, string>();
  ufw: string | undefined;
  failInstall = 0;
  /** Fails only the full platform install, after hardening and the SSH cutover succeeded. */
  failPlatformInstall = 0;
  /** "harden" or "platform" for each scripts/install.ts --harden-vps run, in order. */
  installModes: string[] = [];
  failAudit = 0;
  breakTailscaleOnSshStop = false;
  privateSsh = false;
  nodeId = "nTest1";
  denyProof = false;
  failListenersAfterStop = false;
  failRollback = false;
  failUfwDelete = false;
  failRejoin = 0;
  rejectEdgeKey?: string;
  staleWorker = false;
  workerExitsAfterUp = false;
  liveFirewall = "";
  vpsKeyFiles: string[] = [];
  vpsKeyFromStdin = false;
  /** Local accounts that `getent passwd` does not find; `useradd` creates them. */
  missingUsers = new Set<string>();
  createdHomes = new Map<string, string>();
  userShell = "/bin/bash";
  passwdLookupError?: RunResult;
  opensshConfig = ok("passwordauthentication no\nkbdinteractiveauthentication no\n");
  sshdConfigDir = "";
  /** The fixture's UFW rules directory, standing in for /etc/ufw. */
  ufwDirectory = "";
  /** UFW rules files the SSH cutover backed up, as [source, destination]. */
  ufwBackups: [string, string][] = [];
  /** Whether the effective policy honours setup's per-user drop-in (false: something else wins). */
  sshdHonoursDropIn = true;
  sshdSyntax = ok();
  sshReloads = 0;
  failSshReloads = 0;
  delayedSshReload = false;
  liveSshBlocked = new Set<string>();
  alternateSshConfig = false;
  unmanagedSshListener = false;
  sshHandshakePending = false;
  sleeps: number[] = [];
  failUseradd?: "before-create" | "after-create";
  passwords = new Map<string, string>();
  failChpasswd = false;
  failUserdel = false;

  constructor(
    readonly root: string,
    readonly firewallPath: string,
  ) {}

  get envPath() {
    return join(this.root, ".env");
  }

  /** Tailscale's assigned name: the requested one, or `<name>-1` if another machine has it. */
  assigned(name: string) {
    return this.takenNames.has(name) ? `${name}-1` : name;
  }

  /** TS_HOSTNAME as Compose resolves it from .env (infra/platform/docker-compose.yml). */
  composeName(service: string) {
    const values = existsSync(this.envPath) ? parseEnvFile(readFileSync(this.envPath, "utf8")) : {};
    return service === "edge-ts"
      ? values.TS_EDGE_HOSTNAME || "ark-edge"
      : values.TS_BACKUP_HOSTNAME || "ark-backup";
  }

  container(service: string) {
    return service === "edge-ts" ? this.edge : this.backup;
  }

  restartContainer(service: string) {
    const node = this.container(service);
    const startupName = this.startupNames.get(service);
    const defaultName = service === "edge-ts" ? "ark-edge" : "ark-backup";
    if (node.running && !startupName && node.hostName !== defaultName) {
      throw new Error("containerboot omitted the non-default Tailscale hostname");
    }
    if (node.running && startupName) node.hostName = startupName;
    this.stoppedContainers.delete(service);
  }

  composeUp(service: string, env: RunOptions["env"], force = false) {
    this.orphanedState.delete(service);
    const fromFile = parseEnvFile(readFileSync(this.envPath, "utf8"));
    const variable = service === "edge-ts" ? "TS_EDGE_AUTHKEY" : "TS_BACKUP_AUTHKEY";
    const key = env?.[variable] ?? fromFile[variable] ?? "";
    const startupName = this.composeName(service);
    const sameConfig =
      this.startupNames.get(service) === startupName && (this.configuredKeys.get(service) ?? "") === key;
    if (!force && sameConfig && !this.stoppedContainers.has(service)) return;
    if (force || !sameConfig) this.containerCreations.push([service, startupName]);
    this.startupNames.set(service, startupName);
    if (key) {
      this.containerKeys.push({ service, key, from: env?.[variable] ? "env" : ".env" });
      this.configuredKeys.set(service, key);
    } else this.configuredKeys.delete(service);
    const node = this.container(service);
    this.restartContainer(service);
    const loop = this.restartLoops.get(service);
    if (loop && !loop.fixedBy({ name: startupName, key })) return;
    this.restartLoops.delete(service);
    if (!node.running && key && key === this.rejectEdgeKey && this.crashOnRejectedKey) {
      this.restartLoops.set(service, {
        logs: `backend error: invalid key: API key does not exist (${key})\nboot: failed to auth tailscale\n`,
        fixedBy: (created) => created.key !== key,
      });
    }
    if (!node.running && key && key !== this.rejectEdgeKey) {
      this.joinContainer(service, startupName);
    }
  }

  joinContainer(service: string, hostname: string) {
    this.firstContainerJoins.push([service, hostname]);
    this.containerNodeIds.set(service, `n-${service}-${this.firstContainerJoins.length}`);
    Object.assign(this.container(service), {
      running: true,
      tags: service === "edge-ts" ? this.edgeJoinTags : ["tag:ark-backup"],
      hostName: hostname,
    });
  }

  containerSelf(service: string) {
    const node = this.container(service);
    return {
      ID: this.containerNodeIds.get(service) ?? `n-${service}-legacy`,
      Tags: node.tags,
      HostName: node.hostName,
      DNSName: this.dnsName(service, node.hostName),
    };
  }

  dnsName(node: string, hostName: string) {
    if (this.missingDns.has(node)) return undefined;
    return `${this.consoleNames.get(node) ?? this.assigned(hostName)}.tail1234.ts.net.`;
  }

  finishSshReload() {
    this.sshReloads++;
    this.liveSshBlocked.clear();
    if (!this.sshdHonoursDropIn || !existsSync(this.sshdConfigDir)) return;
    for (const file of readdirSync(this.sshdConfigDir)) {
      const user = /^10-ark-ssh-user-(.+)\.conf$/.exec(file)?.[1];
      if (user && readFileSync(join(this.sshdConfigDir, file), "utf8") === sshUserPolicy(user)) {
        this.liveSshBlocked.add(user);
      }
    }
  }

  run = async (argv: string[], options: RunOptions = {}): Promise<RunResult> => {
    for (const variable of ["TS_API_KEY", "TS_OAUTH_CLIENT_SECRET", "TS_OAUTH_CLIENT_ID", "HCLOUD_TOKEN"])
      expect(options.env?.[variable]).toBeUndefined();
    const line = argv.join(" ");
    this.calls.push(line);
    const result = await this.respond(argv, line, options);
    for (const output of `${result.stdout}${result.stderr}`.split("\n")) if (output) options.onLine?.(output);
    return result;
  };

  private async respond(argv: string[], line: string, options: RunOptions): Promise<RunResult> {
    if (argv[0] === "sh" && argv[2] === 'command -v "$1"') return ok(`/usr/bin/${argv[4]}\n`);
    if (line === "docker compose version" || line.startsWith("docker info")) return ok("v2\n");
    if (line.startsWith("getent passwd ")) {
      if (this.passwdLookupError) return this.passwdLookupError;
      const user = argv[2]!;
      if (this.missingUsers.has(user)) return fail("", 2);
      const home = this.createdHomes.get(user);
      const uid = home ? statSync(home).uid : 1000;
      return ok(`${user}:x:${uid}:1000::${home ?? `/home/${user}`}:${this.userShell}\n`);
    }
    if (argv[0] === "/usr/sbin/sshd") {
      if (line === "/usr/sbin/sshd -t") return this.sshdSyntax;
      const user = /^user=(.+)$/.exec(argv.at(-1) ?? "")?.[1];
      const dropIn = user && join(this.sshdConfigDir, `10-ark-ssh-user-${user}.conf`);
      if (
        dropIn &&
        this.sshdHonoursDropIn &&
        existsSync(dropIn) &&
        readFileSync(dropIn, "utf8") === sshUserPolicy(user!)
      ) {
        return {
          ...this.opensshConfig,
          stdout: "passwordauthentication no\nkbdinteractiveauthentication no\n",
        };
      }
      return this.opensshConfig;
    }
    if (line.startsWith("systemctl show --property=LoadState") && argv.at(-1) === "ssh.service") {
      return ok(
        [
          "LoadState=loaded",
          `ActiveState=${this.ssh.service.active ? "active" : "inactive"}`,
          `MainPID=${this.ssh.service.active ? 900 : 0}`,
          "FragmentPath=/usr/lib/systemd/system/ssh.service",
          "NeedDaemonReload=no",
          "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ignore_errors=no ; }",
          "EnvironmentFiles=/etc/default/ssh (ignore_errors=yes)",
        ].join("\n"),
      );
    }
    if (line.startsWith("systemctl show --property=ActiveState") && argv.at(-1) === "ssh.socket") {
      return ok(
        this.ssh.socket.active
          ? "ActiveState=active\nTriggers=ssh.service\nAccept=no\nListen=0.0.0.0:22 (Stream) [::]:22 (Stream)\n"
          : "ActiveState=inactive\n",
      );
    }
    if (line.startsWith("sh -ec if [ -e /etc/default/ssh ]")) return ok("SSHD_OPTS=\n");
    if (line.startsWith('sh -ec readlink "/proc/$1/exe";')) {
      const flags = this.alternateSshConfig ? " -f /opt/ssh/sshd_config" : "";
      return ok(
        `/usr/sbin/sshd\nsshd: /usr/sbin/sshd -D${flags} [listener] 0 of 10-100 startups\n` +
          `${this.sshReloads.toString(16).padStart(64, "0")}  /proc/900/auxv\n`,
      );
    }
    if (line === "systemctl reload ssh.service") {
      if (this.failSshReloads > 0) {
        this.failSshReloads--;
        return fail("reload failed");
      }
      if (!this.delayedSshReload) this.finishSshReload();
      return ok();
    }
    if (line === "ss -H -tnp state connected") {
      return ok(
        this.sshHandshakePending
          ? 'ESTAB 0 0 203.0.113.10:22 198.51.100.23:49152 users:(("sshd",pid=899,fd=4))\n'
          : "",
      );
    }
    if (line === "ps -ww -p 899 -o pid=,args=") return ok("899 sshd: example@notty [priv]\n");
    if (argv[0] === "useradd") {
      if (this.failUseradd === "before-create") return fail("useradd: group 'sudo' does not exist", 6);
      const user = argv.at(-1)!;
      const home = argv[argv.indexOf("--home-dir") + 1]!;
      this.missingUsers.delete(user);
      mkdirSync(home, { recursive: true });
      this.createdHomes.set(user, home);
      if (this.failUseradd === "after-create") return fail("useradd: post-create hook failed", 14);
      return ok();
    }
    if (argv[0] === "chpasswd") {
      const user = options.stdin?.split(":", 1)[0];
      if (this.ssh.service.active && this.opensshConfig.stdout.includes("authentication yes")) {
        expect(this.liveSshBlocked.has(user!)).toBe(true);
      }
      if (this.failChpasswd) return fail(`Rejected input: ${options.stdin}`);
      const record = options.stdin ?? "";
      const separator = record.indexOf(":");
      this.passwords.set(record.slice(0, separator), record.slice(separator + 1, -1));
      return ok();
    }
    if (argv[0] === "userdel") {
      if (this.failUserdel) return fail("userdel: user is logged in", 8);
      this.missingUsers.add(argv.at(-1)!);
      this.createdHomes.delete(argv.at(-1)!);
      return ok();
    }
    if (line === "tailscale status --json") {
      let online = this.enrolled;
      if (online && this.offlineReads > 0) {
        this.offlineReads--;
        online = false;
      }
      return ok(
        JSON.stringify({
          BackendState: this.enrolled ? "Running" : "NeedsLogin",
          TUN: true,
          Self: {
            ID: this.nodeId,
            Online: online,
            Tags: this.vpsTags ?? (this.enrolled ? ["tag:ark-vps"] : []),
            HostName: this.vpsHostName,
            DNSName: this.dnsName("vps", this.vpsHostName),
            TailscaleIPs: ["100.100.1.2", "fd7a:115c:a1e0::1"],
          },
        }),
      );
    }
    if (line === "tailscale debug prefs") return ok(JSON.stringify({ RunSSH: this.runSsh }));
    if (argv[0] === "tailscale" && argv[1] === "set" && argv[2]?.startsWith("--hostname=")) {
      expect(this.enrolled).toBe(true);
      this.vpsHostName = argv[2].slice("--hostname=".length);
      this.renames.push(["vps", this.vpsHostName]);
      return ok();
    }
    if (line === "systemctl is-active tailscaled.service") return ok("active\n");
    if (line.startsWith(`${BUN} scripts/install.ts --enroll-vps`)) {
      // enrollVps: `tailscale up --hostname` for a new node, `tailscale set --hostname` otherwise.
      const name = options.env?.TS_VPS_HOSTNAME;
      if (name && this.enrolled && name !== this.vpsHostName) this.renames.push(["vps", name]);
      if (name && !this.enrolled) this.enrolledHostName = name;
      if (name) this.vpsHostName = name;
      const file = options.env?.TS_VPS_AUTHKEY_FILE ?? "";
      if (file) {
        this.vpsKeyFiles.push(file);
        expect((statSync(file).mode & 0o077) === 0).toBe(true);
        expect(readFileSync(file, "utf8").trim()).toBe(VPS_KEY);
      } else if (!this.enrolled) {
        expect(options.stdin).toBe(VPS_KEY);
        this.vpsKeyFromStdin = true;
      }
      this.enrolled = true;
      this.runSsh = true;
      return ok("Verify Tailscale SSH as the owner before running host:install --harden-vps.\n");
    }
    if (line === `${BUN} scripts/install.ts --harden-vps`) {
      expect(options.env?.ARK_INSTALL_NONINTERACTIVE).toBe("1");
      expect(options.env?.TS_EDGE_AUTHKEY).toBeUndefined();
      const mode = options.env?.ARK_INSTALL_HARDEN_ONLY === "1" ? "harden" : "platform";
      this.installModes.push(mode);
      if (this.failInstall > 0) {
        this.failInstall--;
        return fail("docker build failed\n");
      }
      if (mode === "platform" && this.failPlatformInstall > 0) {
        this.failPlatformInstall--;
        return fail("docker build failed\n");
      }
      const existing = existsSync(this.envPath) ? readFileSync(this.envPath, "utf8") : "";
      const template = existing ? "" : readFileSync(join(this.root, ".env.example"), "utf8");
      const merged = mergeInstallEnv(existing || template, generateInstallSecrets(), { template: !existing });
      const values: Record<string, string> = {
        ...parseEnvFile(merged),
        ARK_MAIL_ENABLED: options.env?.ARK_MAIL_ENABLED ?? "1",
        ARK_EDGE_SNI_PORTS: options.env?.ARK_EDGE_SNI_PORTS ?? "",
        ARK_HOST_HARDENING: "1",
      };
      writeFileSync(
        this.envPath,
        Object.entries(values)
          .map(([key, value]) => `${key}=${value}\n`)
          .join(""),
        { mode: 0o600 },
      );
      const firewall = renderHostFirewall(
        {
          mailEnabled: values.ARK_MAIL_ENABLED === "1",
          sniPorts: parseSniPorts(values.ARK_EDGE_SNI_PORTS),
        },
        JSON.parse(options.env!.ARK_SETUP_HOST_SSH_ACCESS!),
      );
      writeFileSync(this.firewallPath, firewall);
      const active = renderHostFirewall(
        {
          mailEnabled: values.ARK_MAIL_ENABLED === "1",
          sniPorts: parseSniPorts(values.ARK_EDGE_SNI_PORTS),
          routes: this.routes,
        },
        JSON.parse(options.env!.ARK_SETUP_HOST_SSH_ACCESS!),
      );
      this.liveFirewall = active.split("\n").slice(2).join("\n");
      if (mode === "harden") return ok("Ark Stack host hardened.\n");
      if (values.ARK_MAIL_ENABLED === "0") {
        this.platformServices.push("stop database-ingress", "stop api");
        this.reconcilerRunning = false;
        this.healthy = false;
      }
      this.reconcilerRunning = true;
      this.platformServices.push("up database-ingress");
      this.onPlatformRestart?.();
      this.composeUp(
        "edge-ts",
        options.env?.ARK_SETUP_DEFER_EDGE_ENROLMENT === "1" ? { TS_EDGE_AUTHKEY: "" } : undefined,
      );
      this.healthy = true;
      this.platformServices.push("up api");
      return ok(`Ark Stack host install ready.\nSetup token: ${values.ARK_SETUP_TOKEN}\n`);
    }
    if (line.startsWith("curl -fsS")) return this.healthy ? ok("{}") : fail("", 7);
    if (line.startsWith("git -C")) return ok("0123abc\n");
    if (line.includes("--auth-key=file:/dev/stdin")) {
      const service = argv[argv.indexOf("-T") + 1]!;
      expect(this.configuredKeys.has(service)).toBe(false);
      this.stdinEnrolments.push(service);
      const hostName = argv.at(-1)!;
      if (service === "edge-ts") {
        expect(options.stdin).toBe(EDGE_KEY);
        if (options.stdin === this.rejectEdgeKey) return fail("Tailscale rejected the edge auth key");
      } else {
        expect(service).toBe("backup-ts");
        expect(options.stdin).toBe(BACKUP_KEY);
      }
      this.joinContainer(service, hostName);
      return ok();
    }
    const serviceExec = /exec -T (edge-ts|backup-ts) (tailscale|printenv) /.exec(line);
    if (serviceExec) {
      const service = serviceExec[1]!;
      const command = serviceExec[2];
      if (this.orphanedState.has(service)) return fail(`service ${service} does not exist`);
      if (this.restartLoops.has(service))
        return fail(`Error response from daemon: Container ${service} is restarting, wait until`);
      if (this.stoppedContainers.has(service)) return fail(`service ${service} is not running`);
      if (command === "printenv") {
        const name = this.startupNames.get(service);
        return name ? ok(name + "\n") : fail();
      }
      if (this.container(service).running)
        return ok(JSON.stringify({ BackendState: "Running", Self: this.containerSelf(service) }));
      if (!this.startupNames.has(service)) return fail(`service ${service} does not exist`);
      const key = this.configuredKeys.get(service);
      const Health = key && key === this.rejectEdgeKey ? ["invalid auth key"] : [];
      return ok(JSON.stringify({ BackendState: "NeedsLogin", Health }));
    }
    const serviceUp =
      /up -d (?:--no-deps )?(?:--force-recreate )?(edge-ts|backup-ts)(?: edge edge-l4)?$/.exec(line);
    if (serviceUp) {
      const service = serviceUp[1]!;
      if (argv.includes("edge") && !argv.includes("--no-deps")) this.edgeDependencyStarts++;
      this.composeUp(service, options.env, argv.includes("--force-recreate"));
      if (this.failSidecarUp && this.restartLoops.has(service))
        return fail("cannot join the network namespace of a restarting container");
      return ok();
    }
    if (line.startsWith("docker ps -aq")) {
      const service = argv
        .find((arg) => arg.startsWith("label=com.docker.compose.service="))!
        .split("=")
        .at(-1)!;
      return ok(
        !this.orphanedState.has(service) &&
          (this.startupNames.has(service) || this.container(service).running)
          ? service + "\n"
          : "",
      );
    }
    if (line.startsWith("docker volume ls ")) {
      const service = argv.at(-1)!.includes("_edge_") ? "edge-ts" : "backup-ts";
      return ok(this.orphanedState.has(service) ? `ark-platform_ark_${service.slice(0, -3)}_ts_state\n` : "");
    }
    if (line.startsWith("docker inspect --format {{.State.Status}} {{.State.ExitCode}}")) {
      const service = argv.at(-1)!;
      const image = `sha256:image ark-${service.replace("-ts", "")}`;
      if (this.restartLoops.has(service)) return ok(`restarting 1 4143 ${image}\n`);
      return ok(`${this.stoppedContainers.has(service) ? "exited" : "running"} 0 0 ${image}\n`);
    }
    if (line.startsWith("docker inspect --format {{range .Config.Env}}")) {
      const service = argv.at(-1)!;
      return ok(
        `TS_USERSPACE=false\nTS_AUTHKEY=${this.configuredKeys.get(service) ?? ""}\nTS_HOSTNAME=${this.startupNames.get(service) ?? ""}\n`,
      );
    }
    if (line.startsWith("docker logs --tail ")) {
      return { status: 0, stdout: "", stderr: this.restartLoops.get(argv.at(-1)!)?.logs ?? "" };
    }
    if (line.startsWith("docker run --rm ")) {
      expect(argv).toContain("--network=none");
      expect(argv).toContain("--cap-drop=ALL");
      expect(options.onLine).toBeUndefined();
      const mount = argv.find((arg) => arg.startsWith("--mount=type=volume,source=ark-platform_ark_"));
      if (mount) {
        expect(mount).toContain("readonly,volume-nocopy");
        return ok(this.orphanedState.get(mount.includes("_edge_") ? "edge-ts" : "backup-ts")!);
      }
      const from = argv.find((arg) => arg.startsWith("--volumes-from="))!;
      expect(from).toEndWith(":ro");
      const service = from.slice("--volumes-from=".length, -":ro".length);
      const loop = this.restartLoops.get(service);
      const stored = loop ? loop.storedName : this.container(service).hostName;
      if (stored === null) return fail("cat: permission denied");
      return ok(stored ? storedState(stored, this.containerSelf(service).ID) : "{}");
    }
    if (line.startsWith("docker start ") && this.restartLoops.has(argv.at(-1)!)) return ok();
    if (line.startsWith("docker start ")) {
      const service = argv.at(-1)!;
      this.restartContainer(service);
      const key = this.configuredKeys.get(service);
      const node = this.container(service);
      if (!node.running && !node.hostName && key && key !== this.rejectEdgeKey)
        this.joinContainer(service, this.startupNames.get(service)!);
      return ok();
    }
    if (line.endsWith("scripts/edge-namespace.ts"))
      return this.failRejoin-- > 0
        ? fail("namespace rejoin failed")
        : ok("ark-platform: every managed dependent is live.\n");
    if (line.endsWith("up --wait --wait-timeout 120 api domain-worker")) {
      this.staleWorker = false;
      return ok();
    }
    if (line.endsWith("config --hash=*")) return ok("api config-api\ndomain-worker config-worker\n");
    if (line.includes("ps -a -q ")) return ok(argv.at(-1)! + "\n");
    if (line.startsWith("docker inspect --format")) {
      if (argv.at(-1) === "api") return ok("running config-api");
      if (this.workerExitsAfterUp) return ok("exited config-worker");
      return ok(this.staleWorker ? "running old-config" : "running config-worker");
    }
    if (line.includes("exec -T domain-worker")) return ok();
    if (line === "systemctl is-active ark-host-firewall.service") return ok("active\n");
    if (line === "systemctl is-enabled ark-host-firewall.service") return ok("enabled\n");
    if (line.includes("systemctl is-active ark-ssh-rollback.timer")) return fail();
    if (line.startsWith("systemd-run ")) return ok();
    if (argv[0] === "cp" && argv[1] === "-p" && argv[2] === "--" && argv.length === 5) {
      const [source, destination] = [argv[3]!, argv[4]!];
      expect(source.startsWith(this.ufwDirectory + "/")).toBe(true);
      copyFileSync(source, destination);
      this.ufwBackups.push([source, destination]);
      return ok();
    }
    if (argv[0] === "flock") {
      if (argv.includes("force")) {
        if (this.failRollback) return fail("OpenSSH refused to start");
        this.ssh.service = { active: true, enabled: true };
        return ok();
      }
      expect(existsSync(join(argv.at(-1)!, "proof"))).toBe(!this.denyProof);
      return ok();
    }
    if (line === "nft -f -") {
      const access: HostSshAccess = { ports: [] };
      for (const [, source, port] of (options.stdin ?? "").matchAll(
        /(?:saddr (\S+) )?tcp dport (\d+) accept/g,
      )) {
        access.source = source;
        access.ports.push(Number(port));
      }
      this.liveFirewall = replaceHostSshAccess(this.liveFirewall, access);
      return ok();
    }
    if (line === "nft -s -y list table inet ark_host") {
      return this.liveFirewall ? ok(this.liveFirewall) : fail("missing table");
    }
    const unit = (name: string) => (name === "ssh.socket" ? this.ssh.socket : this.ssh.service);
    if (line.startsWith("systemctl list-unit-files")) return ok(`${argv[3]} enabled enabled\n`);
    if (argv[0] === "systemctl" && argv[1] === "is-enabled") {
      return unit(argv[2]!).enabled ? ok("enabled\n") : { status: 1, stdout: "disabled\n", stderr: "" };
    }
    if (argv[0] === "systemctl" && argv[1] === "is-active") {
      return unit(argv[2]!).active ? ok("active\n") : { status: 3, stdout: "inactive\n", stderr: "" };
    }
    if (argv[0] === "systemctl" && argv[1] === "stop") {
      if (argv[2] === "ark-ssh-rollback.timer") return ok();
      for (const name of argv.slice(2)) unit(name).active = false;
      if (this.breakTailscaleOnSshStop) this.runSsh = false;
      return ok();
    }
    if (argv[0] === "systemctl" && argv[1] === "disable") {
      unit(argv.at(-1)!).enabled = false;
      return ok();
    }
    if (argv[0] === "/usr/sbin/sshd") return ok("listenaddress 0.0.0.0:22\n");
    if (argv[0] === "systemctl" && argv[1] === "enable") {
      unit(argv[2]!).enabled = true;
      return ok();
    }
    if (argv[0] === "systemctl" && argv[1] === "start") {
      unit(argv[2]!).active = true;
      return ok();
    }
    if (line === "ss -H -ltnp") {
      if (!this.ssh.service.active && this.failListenersAfterStop) return fail("ss failed");
      if (this.unmanagedSshListener)
        return ok('LISTEN 0 128 127.0.0.1:2222 0.0.0.0:* users:(("sshd",pid=901,fd=3))\n');
      if (this.ssh.service.active && this.privateSsh)
        return ok('LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n');
      return ok(
        this.ssh.service.active
          ? 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))\nLISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=900,fd=4))\n'
          : this.ssh.socket.active
            ? 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("systemd",pid=1,fd=3))\n'
            : 'LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:* users:(("docker-proxy",pid=1,fd=4))\n',
      );
    }
    if (line === "ufw status numbered")
      return this.ufw === undefined ? fail("ufw: not found", 127) : ok(this.ufw);
    if (argv[0] === "ufw") return this.failUfwDelete ? fail("ufw delete failed") : ok();
    if (line === INVENTORY || line.startsWith(AUDIT)) {
      try {
        const values = parseEnvFile(readFileSync(this.envPath, "utf8"));
        const config = await appliedHostConfig(this.root, values);
        if (argv.includes("--audit")) {
          if (this.failAudit > 0) {
            this.failAudit--;
            return fail("Unexpected TCP 0.0.0.0:22 listening on the host.");
          }
          if (
            this.ssh.service.active &&
            !this.privateSsh &&
            (!argv.includes("--retain-ssh") || !readHostSshAccess(this.liveFirewall).ports.includes(22))
          ) {
            return fail("Unexpected TCP 0.0.0.0:22 listening on the host.");
          }
        }
        return ok(JSON.stringify({ config, providerRules: providerFirewallRules(config) }));
      } catch (error) {
        return fail(String(error));
      }
    }
    if (line.startsWith("ip -j address show")) {
      return ok(
        JSON.stringify([
          {
            ifname: "eth0",
            addr_info: [
              { family: "inet", local: "203.0.113.10" },
              { family: "inet6", local: "2001:db8::10" },
              { family: "inet", local: "10.0.0.12" },
              { family: "inet", local: "100.64.1.2" },
              { family: "inet", local: "169.254.3.4" },
              { family: "inet6", local: "fd7a:115c:a1e0::10" },
              { family: "inet6", local: "2001:db8::11", temporary: true },
              { family: "inet6", local: "2001:db8::12", deprecated: true },
            ],
          },
          { ifname: "docker0", addr_info: [{ family: "inet", local: "198.51.100.1" }] },
        ]),
      );
    }
    throw new Error(`Unexpected command in the fake host: ${line}`);
  }
}

/** A UI that answers prompts from a script (question substring -> answer) and records the output. */
class ScriptedUi implements Ui {
  output: string[] = [];
  prompts: string[] = [];
  onPrompt?: (question: string) => void;
  constructor(
    readonly interactive: boolean,
    private answers: [string, string][] = [],
    private secrets: [string, string][] = [],
  ) {}
  print(line = "") {
    this.output.push(line);
  }
  private take(list: [string, string][], question: string) {
    this.prompts.push(question);
    this.onPrompt?.(question);
    const index = list.findIndex(([match]) => question.includes(match));
    if (index < 0) throw new Error(`Unscripted prompt: ${question}`);
    const [, answer] = list.splice(index, 1)[0]!;
    return answer;
  }
  async ask(question: string, fallback = "") {
    const answer = this.take(this.answers, question);
    return answer === "<default>" ? fallback : answer;
  }
  async askSecret(question: string) {
    return this.take(this.secrets, question);
  }
  async askPassword(question: string) {
    return this.take(this.secrets, question);
  }
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ark-setup-root-"));
  copyFileSync(join(repoRoot, ".env.example"), join(root, ".env.example"));
  const hostDir = mkdtempSync(join(tmpdir(), "ark-setup-host-"));
  const osRelease = join(hostDir, "os-release");
  writeFileSync(
    osRelease,
    'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04 LTS"\n',
  );
  const host = new FakeHost(root, join(hostDir, "ark-host.nft"));
  const homeBase = join(hostDir, "home");
  const sshdConfigDir = join(hostDir, "sshd_config.d");
  mkdirSync(sshdConfigDir);
  host.sshdConfigDir = sshdConfigDir;
  // Never let the cutover read the real /etc/ufw: Ubuntu CI runners ship UFW rules files.
  const ufwDirectory = join(hostDir, "ufw");
  mkdirSync(ufwDirectory);
  for (const file of ["user.rules", "user6.rules"]) writeFileSync(join(ufwDirectory, file), `# ${file}\n`);
  host.ufwDirectory = ufwDirectory;
  const stateDir = join(root, "tmp", "host-setup");
  return { root, host, stateDir, osRelease, homeBase, sshdConfigDir, ufwDirectory };
}

type Fixture = ReturnType<typeof fixture>;

async function setup(
  f: Fixture,
  argv: string[],
  env: Record<string, string> = {},
  overrides: Partial<SetupDependencies> & { scripted?: ScriptedUi } = {},
) {
  let out = "";
  const ui = overrides.scripted;
  const code = await runSetup({
    root: f.root,
    argv,
    env: { PATH: "/usr/bin", SUDO_USER: "alice", ...env },
    run: f.host.run,
    stateDir: f.stateDir,
    paths: {
      osRelease: f.osRelease,
      hostFirewall: f.host.firewallPath,
      sshHomeBase: f.homeBase,
      sshdConfigDir: f.sshdConfigDir,
      ufwDirectory: f.ufwDirectory,
    },
    isRoot: true,
    platform: "linux",
    bun: BUN,
    stdinIsTty: Boolean(ui?.interactive),
    hostname: "ark-vps",
    sleep: async (ms) => {
      f.host.sleeps.push(ms);
      if (ms === 250 && f.host.delayedSshReload) f.host.finishSshReload();
      if (!f.host.denyProof && existsSync(f.stateDir)) {
        const transaction = readdirSync(f.stateDir).find((name) => name.startsWith("ssh-cutover-"));
        if (transaction) writeFileSync(join(f.stateDir, transaction, "proof"), "");
      }
    },
    sessionOrigin: async () => ({ via: "openssh", detail: "203.0.113.10", source: RECOVERY_IP }),
    out: (text) => (out += text),
    // Never probe the real Hetzner metadata service from a test machine.
    firewalls: [manualProviderFirewall],
    ...(ui ? { ui: () => ui } : {}),
    ...overrides,
  });
  const text = ui ? ui.output.join("\n") : out;
  const log = existsSync(join(f.stateDir, "setup.log"))
    ? readFileSync(join(f.stateDir, "setup.log"), "utf8")
    : "";
  const state = existsSync(join(f.stateDir, "state.json"))
    ? JSON.parse(readFileSync(join(f.stateDir, "state.json"), "utf8"))
    : undefined;
  return { code, text, log, state };
}

const BASE = [
  "--non-interactive",
  "--domain",
  "example.com",
  "--acme-email",
  "ops@example.com",
  "--tailnet-policy-reviewed",
];
const KEYS = { TS_VPS_AUTHKEY: VPS_KEY, TS_EDGE_AUTHKEY: EDGE_KEY };
const FULL = [...BASE, "--tailscale-ssh-confirmed", "--provider-firewall-applied", "--verify-ssh-cutover"];

describe("host:setup refusals", () => {
  test("without root it changes nothing and prints the sudo command", async () => {
    const f = fixture();
    const result = await setup(f, BASE, KEYS, { isRoot: false });
    expect(result.code).toBe(1);
    expect(result.text).toContain("Nothing was changed");
    expect(result.text).toContain(`cd ${f.root} && sudo mise run host:setup --non-interactive`);
    expect(f.host.calls).toEqual([]);
    expect(existsSync(f.stateDir)).toBe(false);
  });

  test("non-interactive without a domain fails naming it, before any host command", async () => {
    const f = fixture();
    const result = await setup(f, ["--non-interactive"], KEYS);
    expect(result.code).toBe(1);
    expect(result.text).toContain("Missing required answer: the domain (--domain or ARK_SETUP_DOMAIN)");
    expect(f.host.calls).toEqual([]);
  });

  test("non-interactive without a VPS key fails naming TS_VPS_AUTHKEY", async () => {
    const f = fixture();
    const result = await setup(f, BASE, {});
    expect(result.code).toBe(1);
    expect(result.text).toContain("TS_VPS_AUTHKEY or TS_VPS_AUTHKEY_FILE");
    expect(result.state.steps.tailscale.status).toBe("failed");
  });

  test("rejects unknown flags and an unsupported OS", async () => {
    const f = fixture();
    expect((await setup(f, ["--frobnicate"])).code).toBe(1);
    writeFileSync(
      f.osRelease,
      'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\nPRETTY_NAME="Debian 12"\n',
    );
    const result = await setup(f, FULL, KEYS);
    expect(result.code).toBe(1);
    expect(result.text).toContain("Unsupported operating system Debian 12");
  });
});

describe("host:setup Tailscale SSH gate", () => {
  test("an enrolled node with SSH off resumes without requesting another key", async () => {
    const f = fixture();
    f.host.enrolled = true;
    const result = await setup(f, BASE);
    expect(result.code).toBe(2);
    expect(f.host.calls).toContain(`${BUN} scripts/install.ts --enroll-vps`);
    expect(f.host.vpsKeyFromStdin).toBe(false);
    expect(f.host.runSsh).toBe(true);
  });

  test("waits for an enrolled node that is briefly offline instead of refusing it", async () => {
    const f = fixture();
    f.host.enrolled = true;
    f.host.runSsh = true;
    f.host.offlineReads = 3;
    const result = await setup(f, BASE);
    expect(result.code).toBe(2);
    expect(result.text).not.toContain("host TUN interface");
    expect(f.host.offlineReads).toBe(0);
  });

  test.each([
    ["stays offline", { offlineReads: 1000 }, "not online with the Tailscale control server"],
    ["has another tag", { vpsTags: ["tag:ark-vps", "tag:other"] }, "tagged tag:ark-vps, tag:other"],
    ["is owned by a user", { vpsTags: [] }, "untagged (owned by a user)"],
  ])("a running node that %s is refused with the reason", async (scenario, change, reason) => {
    const f = fixture();
    f.host.enrolled = true;
    Object.assign(f.host, change);
    const result = await setup(f, BASE, KEYS);
    expect(result.code).toBe(1);
    expect(result.text).toContain("host TUN interface");
    expect(result.text).toContain(reason);
    expect(f.host.calls.some((call) => call.includes("--enroll-vps"))).toBe(false);
    expect(f.host.sleeps).toEqual(scenario === "stays offline" ? Array(14).fill(2000) : []);
  });

  test("requires a local SSH user before mutating the host", async () => {
    const f = fixture();
    const result = await setup(f, BASE, { SUDO_USER: "" });
    expect(result.code).toBe(1);
    expect(result.text).toContain("the local SSH user (--ssh-user or ARK_SETUP_SSH_USER)");
    expect(f.host.calls).toEqual([]);
  });

  test.each(["node", "user"])("requires new confirmation when the %s changes", async (change) => {
    const f = fixture();
    f.host.failInstall = 1;
    expect((await setup(f, FULL, KEYS)).code).toBe(1);
    if (change === "node") f.host.nodeId = "nTest2";
    const args = change === "user" ? [...FULL, "--ssh-user", "bob"] : FULL;
    f.host.calls = [];
    const blocked = await setup(f, args);
    expect(blocked.code).toBe(2);
    expect(blocked.state.sshConfirmation).toBeUndefined();
    expect(f.host.calls.some((call) => call.endsWith("--harden-vps"))).toBe(false);
    expect((await setup(f, args)).code).toBe(0);
  });
  test("without confirmation it enrols, then stops before hardening or OpenSSH changes", async () => {
    const f = fixture();
    const result = await setup(f, BASE, KEYS);
    expect(result.code).toBe(2);
    expect(f.host.calls).toContain(`${BUN} scripts/install.ts --enroll-vps --key-stdin`);
    expect(f.host.calls.some((call) => call.includes("--harden-vps"))).toBe(false);
    expect(f.host.calls.some((call) => /systemctl (disable|stop)|ufw/.test(call))).toBe(false);
    expect(existsSync(f.host.firewallPath)).toBe(false);
    expect(result.text).toContain("tailscale ssh alice@ark-vps.tail1234.ts.net");
    expect(result.text).toContain("arrives over public OpenSSH");
    expect(result.text).toContain(`sudo mise run host:setup ${BASE.join(" ")} --tailscale-ssh-confirmed`);
    // The generated key travelled by stdin, without a temporary file or a log entry.
    expect(f.host.vpsKeyFromStdin).toBe(true);
    expect(f.host.vpsKeyFiles).toHaveLength(0);
    expect(result.log).not.toContain(VPS_KEY);
    expect(result.text).not.toContain(VPS_KEY);
  });

  test("an interactive 'no' at the gate also stops before hardening", async () => {
    const f = fixture();
    const ui = new ScriptedUi(
      true,
      [
        ["Your domain", "example.com"],
        ["Admin hostname", "<default>"],
        ["Let's Encrypt", "ops@example.com"],
        ["trusted Let's Encrypt", "<default>"],
        ["incoming mail", "no"],
        ["Shared SNI", "8883"],
        ["reboot time", "03:30"],
        ["local (non-root) user", "alice"],
        ["Tailscale machine name", "<default>"],
        ["Continue", "<default>"],
        ["policy is saved", "yes"],
        ["session works", "not yet"],
      ],
      [
        ["Cloudflare", ""],
        ["Tailscale API access token", ""],
        ["tag:ark-vps key", VPS_KEY],
      ],
    );
    const result = await setup(f, [], {}, { scripted: ui });
    expect(result.code).toBe(2);
    expect(result.text).toContain("tailscale ssh alice@ark-vps.tail1234.ts.net");
    expect(result.text).toContain('"tag:ark-vps": ["autogroup:admin"]');
    expect(result.text).toContain('"action": "check"');
    expect(f.host.calls.some((call) => call.includes("--harden-vps"))).toBe(false);
    expect(result.state.answers).toMatchObject({
      domain: "example.com",
      adminHost: "admin.example.com",
      mailEnabled: false,
      sniPorts: [8883],
      rebootTime: "03:30",
      sshUser: "alice",
    });
  });
});

describe("host:setup missing SSH user", () => {
  const PASSWORD = "correct-horse-battery";
  const passwordPrompts = (password = PASSWORD): [string, string][] => [
    ["Password for alice", password],
    ["Repeat the password", password],
  ];
  const interactiveUi = (create: string, passwords = passwordPrompts()) =>
    new ScriptedUi(
      true,
      [
        ["Your domain", "example.com"],
        ["Admin hostname", "<default>"],
        ["Let's Encrypt", "ops@example.com"],
        ["trusted Let's Encrypt", "<default>"],
        ["incoming mail", "no"],
        ["Shared SNI", "8883"],
        ["reboot time", "03:30"],
        ["local (non-root) user", "alice"],
        ["Tailscale machine name", "<default>"],
        ["Continue", "<default>"],
        ["policy is saved", "yes"],
        ["Create alice", create],
        ["session works", "not yet"],
      ],
      [["Cloudflare", ""], ["Tailscale API access token", ""], ["tag:ark-vps key", VPS_KEY], ...passwords],
    );

  test("non-interactive: fails naming the commands and creates nothing", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    const result = await setup(f, FULL, KEYS);
    expect(result.code).toBe(1);
    expect(result.text).toContain("The local user alice does not exist");
    expect(result.text).toContain("adduser alice && usermod -aG sudo alice");
    expect(f.host.calls.some((call) => call.startsWith("useradd"))).toBe(false);
    expect(f.host.calls.some((call) => call.includes("--harden-vps"))).toBe(false);
  });

  test("interactive: offers to create the user with sudo and a password, then continues", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    const ui = interactiveUi("yes", [
      ["Password for alice", "short"],
      ["Password for alice", PASSWORD],
      ["Repeat the password", "something-else"],
      ["Password for alice", PASSWORD],
      ["Repeat the password", PASSWORD],
    ]);
    const result = await setup(f, [], {}, { scripted: ui });
    expect(result.code).toBe(2);
    expect(f.host.calls).toContain(
      `useradd --create-home --home-dir ${join(f.homeBase, "alice")} --shell /bin/bash --groups sudo -- alice`,
    );
    expect(f.host.passwords.get("alice")).toBe(PASSWORD);
    expect(result.text).toContain("Use at least 8 characters.");
    expect(result.text).toContain("The passwords did not match.");
    expect(result.text).toContain("Created alice (member of sudo).");
    expect(result.text).toContain("tailscale ssh alice@ark-vps.tail1234.ts.net");
    expect(result.text.indexOf("After enrolment, interactive")).toBeLessThan(
      result.text.indexOf("Created alice"),
    );
    expect(result.text).toContain("For scripted runs, create the user");
    expect(result.log).not.toContain(PASSWORD);
    expect(result.text).not.toContain(PASSWORD);
    expect(result.state.sshUserProvisioning).toBeUndefined();
  });

  test("interactive: declining stops without creating the account", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    const result = await setup(f, [], {}, { scripted: interactiveUi("no") });
    expect(result.code).toBe(1);
    expect(result.text).toContain("adduser alice && usermod -aG sudo alice");
    expect(f.host.calls.some((call) => call.startsWith("useradd"))).toBe(false);
  });

  test("preserves the literal password and requires an exact confirmation", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    const literal = ` ${PASSWORD}: with spaces  `;
    const ui = interactiveUi("yes", [
      ["Password for alice", literal],
      ["Repeat the password", literal.trim()],
      ...passwordPrompts(literal),
    ]);
    const result = await setup(f, [], {}, { scripted: ui });
    expect(result.code).toBe(2);
    expect(result.text).toContain("The passwords did not match.");
    expect(f.host.passwords.get("alice")).toBe(literal);
    expect(result.log).not.toContain(PASSWORD);
    expect(JSON.stringify(result.state)).not.toContain(PASSWORD);
  });

  test("refuses a pre-existing home and preserves its files", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    const home = join(f.homeBase, "alice");
    mkdirSync(home, { recursive: true });
    const sentinel = join(home, "saved-file");
    writeFileSync(sentinel, "keep");
    const result = await setup(f, [], {}, { scripted: interactiveUi("yes", []) });
    expect(result.code).toBe(1);
    expect(result.text).toContain(`The home path ${home} already exists`);
    expect(f.host.calls.some((call) => /^(useradd|userdel|chpasswd)/.test(call))).toBe(false);
    expect(readFileSync(sentinel, "utf8")).toBe("keep");
  });

  test("a failed password change removes only the new account", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    f.host.failChpasswd = true;
    const result = await setup(f, [], {}, { scripted: interactiveUi("yes") });
    expect(result.code).toBe(1);
    expect(result.text).toContain("the account was removed");
    expect(f.host.calls.filter((call) => call.startsWith("userdel"))).toEqual(["userdel -- alice"]);
    expect(existsSync(join(f.homeBase, "alice"))).toBe(true);
    expect(f.host.missingUsers.has("alice")).toBe(true);
    expect(result.state.sshUserProvisioning).toBeUndefined();
    expect(result.log).not.toContain(PASSWORD);
    expect(result.text).not.toContain(PASSWORD);
  });

  test.each(["after-create", "interrupted", "cleanup-failed"])(
    "blocks later runs after provisioning is %s",
    async (failure) => {
      const f = fixture();
      f.host.missingUsers.add("alice");
      if (failure === "after-create") f.host.failUseradd = "after-create";
      if (failure === "cleanup-failed") {
        f.host.failChpasswd = true;
        f.host.failUserdel = true;
      }
      const result = await setup(
        f,
        [],
        {},
        {
          scripted: interactiveUi("yes"),
          run: async (argv, options) => {
            if (failure === "interrupted" && argv[0] === "chpasswd") throw new Error("Interrupted");
            return f.host.run(argv, options);
          },
        },
      );
      expect(result.code).toBe(1);
      expect(f.host.missingUsers.has("alice")).toBe(false);
      const diagnostic = {
        "after-create": "post-create hook failed",
        interrupted: "Interrupted",
        "cleanup-failed": "Cleanup failed (userdel exit 8) and alice still exists",
      }[failure]!;
      expect(result.text).toContain(diagnostic);
      expect(result.state.sshUserProvisioning).toEqual({ user: "alice" });

      f.host.calls.length = 0;
      const retry = await setup(f, FULL);
      expect(retry.code).toBe(1);
      expect(retry.text).toContain("Setup did not finish provisioning alice");
      expect(retry.text).toContain("sudo userdel -- alice");
      expect(f.host.calls.some((call) => /chpasswd|--harden-vps/.test(call))).toBe(false);
    },
  );

  test("reports a useradd failure before creation and retries once the cause is fixed", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    f.host.failUseradd = "before-create";
    const failed = await setup(f, [], {}, { scripted: interactiveUi("yes") });
    expect(failed.code).toBe(1);
    expect(failed.text).toContain("group 'sudo' does not exist");
    expect(f.host.calls).not.toContain("chpasswd");
    f.host.failUseradd = undefined;
    expect((await setup(f, [], {}, { scripted: interactiveUi("yes") })).code).toBe(2);
    expect(f.host.passwords.get("alice")).toBe(PASSWORD);
  });

  test("a recreated account needs fresh confirmation even with the flag and the same node and name", async () => {
    const f = fixture();
    f.host.failInstall = 1;
    const first = await setup(f, FULL, KEYS);
    expect(first.state.sshConfirmation).toBeDefined();
    f.host.missingUsers.add("alice");
    f.host.calls.length = 0;
    const blocked = await setup(f, ["--tailscale-ssh-confirmed"], {}, { scripted: interactiveUi("yes") });
    expect(blocked.code).toBe(2);
    expect(blocked.state.sshConfirmation).toBeUndefined();
    expect(f.host.calls).not.toContain(`${BUN} scripts/install.ts --harden-vps`);
    expect((await setup(f, FULL)).code).toBe(0);
    expect(f.host.calls).toContain(`${BUN} scripts/install.ts --harden-vps`);
  });

  test.each(["/usr/sbin/nologin", "/bin/false"])("blocks a login shell of %s", async (shell) => {
    const f = fixture();
    f.host.userShell = shell;
    const result = await setup(f, FULL, KEYS);
    expect(result.code).toBe(1);
    expect(result.text).toContain("alice exists but cannot log in");
    expect(f.host.calls).not.toContain(`${BUN} scripts/install.ts --harden-vps`);
  });

  test("stops on a getent execution failure without offering creation", async () => {
    const f = fixture();
    f.host.passwdLookupError = fail(`getent failed while reading ${VPS_KEY}`, 127);
    const result = await setup(f, [], KEYS, { scripted: interactiveUi("yes", []) });
    expect(result.code).toBe(1);
    expect(result.text).toContain("Could not look up the local user alice (getent exit 127)");
    expect(result.text).toContain("getent failed while reading <redacted>");
    expect(result.text).not.toContain("does not exist");
    expect(f.host.calls.some((call) => call.startsWith("useradd"))).toBe(false);
  });

  test.each([
    { password: "yes", keyboard: "no" },
    { password: "no", keyboard: "yes" },
  ])(
    "turns off OpenSSH password login for the new user only (password $password, keyboard $keyboard)",
    async (policy) => {
      const f = fixture();
      f.host.missingUsers.add("alice");
      f.host.opensshConfig = ok(
        `passwordauthentication ${policy.password}\nkbdinteractiveauthentication ${policy.keyboard}\n`,
      );
      const result = await setup(f, [], {}, { scripted: interactiveUi("yes") });
      expect(result.code).toBe(2);
      const dropIn = join(f.sshdConfigDir, "10-ark-ssh-user-alice.conf");
      expect(readFileSync(dropIn, "utf8")).toBe(sshUserPolicy("alice"));
      expect((statSync(dropIn).mode & 0o777).toString(8)).toBe("644");
      expect(result.text).toContain(`Turned off OpenSSH password login for alice only (${dropIn}).`);
      expect(result.text).toContain("Stopped before firewall hardening and the public SSH cutover.");
      expect(result.text).toContain(`OpenSSH password login remains disabled for alice in ${dropIn}.`);
      const index = (call: string) => f.host.calls.indexOf(call);
      expect(index("/usr/sbin/sshd -t")).toBeGreaterThan(-1);
      expect(index("/usr/sbin/sshd -t")).toBeLessThan(index("systemctl reload ssh.service"));
      expect(index("systemctl reload ssh.service")).toBeLessThan(
        f.host.calls.findIndex((call) => call.startsWith("useradd")),
      );
      expect(f.host.sshReloads).toBe(1);
      expect(f.host.passwords.get("alice")).toBe(PASSWORD);
    },
  );

  test("writes the drop-in without a reload while ssh.service is socket-activated and idle", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    f.host.ssh.service.active = false;
    f.host.ssh.socket.active = true;
    f.host.opensshConfig = ok("passwordauthentication yes\nkbdinteractiveauthentication no\n");
    const result = await setup(f, [], {}, { scripted: interactiveUi("yes") });
    expect(result.code).toBe(2);
    expect(existsSync(join(f.sshdConfigDir, "10-ark-ssh-user-alice.conf"))).toBe(true);
    expect(f.host.sshReloads).toBe(0);
  });

  test.each([false, true])("retries a failed SSH reload with an existing drop-in: %s", async (existing) => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    f.host.opensshConfig = ok("passwordauthentication yes\nkbdinteractiveauthentication no\n");
    const path = join(f.sshdConfigDir, "10-ark-ssh-user-alice.conf");
    if (existing) {
      writeFileSync(path, sshUserPolicy("alice"));
      chmodSync(path, 0o644);
    }
    f.host.failSshReloads = 1;
    const failed = await setup(f, [], {}, { scripted: interactiveUi("yes", []) });
    expect(failed.code).toBe(1);
    expect(failed.text).toContain("systemctl reload ssh.service failed");
    expect(existsSync(path)).toBe(existing);
    expect(f.host.liveSshBlocked.has("alice")).toBe(false);
    expect(f.host.calls.some((call) => /^(useradd|chpasswd)/.test(call))).toBe(false);

    f.host.calls.length = 0;
    f.host.delayedSshReload = true;
    const retry = await setup(f, [], {}, { scripted: interactiveUi("yes") });
    expect(retry.code).toBe(2);
    expect(f.host.sleeps).toEqual([250]);
    expect(f.host.liveSshBlocked.has("alice")).toBe(true);
    expect(f.host.calls.indexOf("systemctl reload ssh.service")).toBeLessThan(
      f.host.calls.findIndex((call) => call.startsWith("useradd")),
    );
    expect(f.host.passwords.get("alice")).toBe(PASSWORD);
  });

  test("preserves the administrator's SSH file and metadata when refusing provisioning", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    f.host.opensshConfig = ok("passwordauthentication yes\nkbdinteractiveauthentication no\n");
    f.host.sshdSyntax = fail("sshd: bad configuration", 255);
    const path = join(f.sshdConfigDir, "10-ark-ssh-user-alice.conf");
    const content = "Match User existing\n    PasswordAuthentication no\n";
    writeFileSync(path, content, { mode: 0o640 });
    const before = statSync(path);
    const result = await setup(f, [], {}, { scripted: interactiveUi("yes", []) });
    const after = statSync(path);
    expect(result.code).toBe(1);
    expect(result.text).toContain(`Setup will preserve the existing file at ${path}.`);
    expect(readFileSync(path, "utf8")).toBe(content);
    for (const key of ["ino", "mode", "uid", "gid", "mtimeMs"] as const) expect(after[key]).toBe(before[key]);
    expect(f.host.calls.some((call) => /^(useradd|chpasswd)/.test(call))).toBe(false);
  });

  test("waits for stale OpenSSH handshakes before creating a password account", async () => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    f.host.opensshConfig = ok("passwordauthentication yes\nkbdinteractiveauthentication no\n");
    f.host.sshHandshakePending = true;
    const first = await setup(f, [], {}, { scripted: interactiveUi("yes", []) });
    expect(first.code).toBe(1);
    expect(first.text).toContain("Wait for pending OpenSSH logins to finish, then retry.");
    expect(f.host.calls.some((call) => /^(useradd|chpasswd)/.test(call))).toBe(false);
    f.host.sshHandshakePending = false;
    expect((await setup(f, [], {}, { scripted: interactiveUi("yes") })).code).toBe(2);
    expect(f.host.passwords.get("alice")).toBe(PASSWORD);
  });

  test.each(["alternate config", "unmanaged listener"])("refuses an %s before provisioning", async (kind) => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    if (kind === "alternate config") f.host.alternateSshConfig = true;
    else {
      f.host.ssh.service.active = false;
      f.host.unmanagedSshListener = true;
    }
    const result = await setup(f, [], {}, { scripted: interactiveUi("yes", []) });
    expect(result.code).toBe(1);
    expect(result.text).toContain("provision a protected local account manually");
    expect(f.host.calls.some((call) => /^(useradd|chpasswd)/.test(call))).toBe(false);
    expect(readdirSync(f.sshdConfigDir)).toEqual([]);
  });

  test("leaves an existing user's OpenSSH policy alone", async () => {
    const f = fixture();
    f.host.opensshConfig = ok("passwordauthentication yes\nkbdinteractiveauthentication no\n");
    await setup(f, FULL, KEYS);
    expect(readdirSync(f.sshdConfigDir)).toEqual([]);
    expect(f.host.sshReloads).toBe(0);
  });

  test.each([
    {
      name: "a connection-specific Match",
      match: "debug3: checking syntax for 'Match Address 203.0.113.2'\n",
    },
    { name: "a drop-in that does not take effect", honoured: false },
    { name: "a configuration sshd -t rejects", syntax: fail("sshd: bad configuration", 255) },
    { name: "no sshd_config.d directory", noDirectory: true },
  ])("refuses $name, removes its drop-in and keeps public SSH", async (policy) => {
    const f = fixture();
    f.host.missingUsers.add("alice");
    f.host.opensshConfig = {
      ...ok("passwordauthentication yes\nkbdinteractiveauthentication no\n"),
      stderr: policy.match ?? "",
    };
    if (policy.honoured === false) f.host.sshdHonoursDropIn = false;
    if (policy.syntax) f.host.sshdSyntax = policy.syntax;
    if (policy.noDirectory) rmSync(f.sshdConfigDir, { recursive: true });
    const result = await setup(f, ["--keep-public-ssh"], {}, { scripted: interactiveUi("yes", []) });
    expect(result.code).toBe(1);
    expect(result.text).toContain("Cannot verify that OpenSSH blocks password login for alice");
    expect(f.host.calls).toContain("/usr/sbin/sshd -ddd -T -C user=alice");
    if (policy.honoured === false) expect(result.text).toContain("still allows password login");
    if (policy.syntax) expect(result.text).toContain("rejected the configuration");
    if (!policy.noDirectory) expect(readdirSync(f.sshdConfigDir)).toEqual([]);
    expect(f.host.sshReloads).toBe(0);
    expect(f.host.calls.some((call) => /^(useradd|chpasswd)|--harden-vps/.test(call))).toBe(false);
    expect(f.host.ssh.service.active).toBe(true);
  });
});

describe("host:setup full run", () => {
  test.each([false, true])(
    "the default source collects remaining manual answers before install (skip=%s)",
    async (skip) => {
      const f = fixture();
      const backupKey = "tskey-auth-manual-backup";
      const ui = new ScriptedUi(
        true,
        [
          ["Your domain", "example.com"],
          ["Admin hostname", "<default>"],
          ["Let's Encrypt", "ops@example.com"],
          ["trusted Let's Encrypt", "<default>"],
          ["incoming mail", "<default>"],
          ["Shared SNI", "<default>"],
          ["reboot time", "<default>"],
          ["local (non-root) user", "alice"],
          ["Tailscale machine name", "<default>"],
          ["Continue", "<default>"],
          ["policy is saved", "yes"],
          ["session works", "yes"],
          ["Type yes once they are applied", "yes"],
        ],
        [
          ["Cloudflare", ""],
          ["Tailscale API access token", ""],
          ["tag:ark-edge key", skip ? "" : EDGE_KEY],
          ["tag:ark-backup key", skip ? "" : backupKey],
        ],
      );
      ui.onPrompt = () => expect(f.host.installModes).not.toContain("platform");
      const result = await setup(
        f,
        ["--backup-node", "--keep-public-ssh"],
        { TS_VPS_AUTHKEY: VPS_KEY },
        { scripted: ui },
      );
      expect(result.code, result.text).toBe(0);
      expect(
        ui.prompts.filter((question) => /Paste the tag:ark-(edge|backup) key/.test(question)),
      ).toHaveLength(2);
      expect(f.host.installModes).toEqual(["harden", "platform"]);
      expect(result.state.steps.edge.status).toBe(skip ? "skipped" : "done");
      expect(result.state.steps["backup-node"].status).toBe(skip ? "skipped" : "done");
      expect(f.host.containerKeys).toEqual(
        skip
          ? []
          : [
              { service: "edge-ts", key: EDGE_KEY, from: ".env" },
              { service: "backup-ts", key: backupKey, from: "env" },
            ],
      );
      for (const secret of [EDGE_KEY, backupKey]) {
        expect(result.log + JSON.stringify(result.state)).not.toContain(secret);
      }
    },
  );

  test("installs end to end without editing files; summary has the token, the log does not", async () => {
    const f = fixture();
    f.host.ufw = `Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n[ 2] 80/tcp                     ALLOW IN    Anywhere\n[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n`;
    const result = await setup(f, [...FULL, "--ssh-user", "alice"], { ...KEYS, DNS_API_TOKEN: DNS_TOKEN });
    expect(result.code).toBe(0);
    // Hardening, then the public SSH cutover while the operator is present, then the unattended install.
    const installs = f.host.calls.flatMap((call, index) =>
      call === `${BUN} scripts/install.ts --harden-vps` ? [index] : [],
    );
    expect(f.host.installModes).toEqual(["harden", "platform"]);
    const order = [
      f.host.calls.indexOf(`${BUN} scripts/install.ts --enroll-vps --key-stdin`),
      installs[0]!,
      f.host.calls.indexOf("systemctl stop ssh.service"),
      installs[1]!,
      ...[
        "up -d --no-deps edge-ts edge edge-l4",
        "scripts/edge-namespace.ts",
        "up --wait --wait-timeout 120 api domain-worker",
      ].map((needle) => f.host.calls.findIndex((call) => call === needle || call.endsWith(needle))),
      f.host.calls.lastIndexOf(AUDIT),
    ];
    expect(order.every((index) => index >= 0)).toBe(true);
    expect(order).toEqual(order.toSorted((a, b) => a - b));
    // UFW: only the SSH rules are removed, highest number first.
    expect(f.host.calls.filter((call) => call.startsWith("ufw --force delete"))).toEqual([
      "ufw --force delete 3",
      "ufw --force delete 1",
    ]);
    // Both UFW rules files are backed up for rollback before any rule is removed.
    expect(f.host.ufwBackups.map(([source]) => source)).toEqual(
      ["user.rules", "user6.rules"].map((file) => join(f.ufwDirectory, file)),
    );
    expect(f.host.calls.findLastIndex((call) => call.startsWith("cp -p -- "))).toBeLessThan(
      f.host.calls.findIndex((call) => call.startsWith("ufw --force delete")),
    );

    const env = parseEnvFile(readFileSync(f.host.envPath, "utf8"));
    expect(statSync(f.host.envPath).mode & 0o777).toBe(0o600);
    expect(env.BETTER_AUTH_URL).toBe("https://admin.example.com");
    expect(env.BETTER_AUTH_TRUSTED_ORIGINS!.split(",")).toEqual(
      expect.arrayContaining(["https://admin.example.com", "http://localhost:3000"]),
    );
    expect(env.ARK_ACME_EMAIL).toBe("ops@example.com");
    expect(env.ARK_ACME_STAGING).toBe("0");
    expect(env.DNS_API_TOKEN).toBe(DNS_TOKEN);
    expect(env.ARK_HOST_REBOOT_TIME).toBe("04:00");
    expect(env.TS_EDGE_AUTHKEY).toBe("");
    expect(f.host.ssh.service).toEqual({ enabled: false, active: false });

    expect(result.text).toContain("ssh -L 3000:127.0.0.1:3000 alice@ark-vps.tail1234.ts.net");
    expect(result.text).toContain("http://localhost:3000");
    expect(result.text).toContain(env.ARK_SETUP_TOKEN!);
    expect(result.text).toContain("Cloudflare is configured");
    expect(
      result.text
        .split("\n")
        .find((line) => line.includes("host:audit --external"))
        ?.trim(),
    ).toBe("sudo mise run host:audit --external ark-host-inventory.json 203.0.113.10 2001:db8::10");
    expect(result.text).toContain("allow TCP 25, 80, 443, 465, 587, 993, 5432 from 0.0.0.0/0 and ::/0");
    expect(result.text).toContain("ARK_ROOT_KEY, ARK_ROOT_KEY_ID, ARK_MFA_RECOVERY_TOKEN");
    expect(result.text).toContain("sudo ufw status verbose");
    for (const line of result.text.split("\n").filter((item) => /^\[\d+\/10\]/.test(item)))
      expect(line.length).toBeLessThan(60);

    // No secret in the log: not the setup token, keys, DNS token or any generated secret.
    for (const secret of [
      env.ARK_SETUP_TOKEN!,
      env.ARK_ROOT_KEY!,
      env.BETTER_AUTH_SECRET!,
      VPS_KEY,
      EDGE_KEY,
      DNS_TOKEN,
    ]) {
      expect(result.log).not.toContain(secret);
    }
    // The only secret on the terminal is the setup token.
    for (const secret of [env.ARK_ROOT_KEY!, VPS_KEY, EDGE_KEY, DNS_TOKEN])
      expect(result.text).not.toContain(secret);
    expect(statSync(join(f.stateDir, "state.json")).mode & 0o777).toBe(0o600);
    expect(JSON.stringify(result.state)).not.toContain(DNS_TOKEN);
    expect(result.state.steps.summary.status).toBe("done");
  });

  test("a re-run verifies and skips every step and rotates no secret", async () => {
    const f = fixture();
    expect((await setup(f, FULL, KEYS)).code).toBe(0);
    const before = readFileSync(f.host.envPath, "utf8");
    f.host.calls = [];
    const again = await setup(f, FULL, {});
    expect(again.code).toBe(0);
    expect(f.host.calls.some((call) => /install\.ts|up -d|systemctl disable|ufw --force/.test(call))).toBe(
      false,
    );
    expect(readFileSync(f.host.envPath, "utf8")).toBe(before);
    expect(again.text).toContain("already hardened and installed with these settings");
    expect(again.text).toContain("edge-ts already joined as tag:ark-edge");
  });

  test("resumes at the failed step and keeps every secret", async () => {
    const f = fixture();
    f.host.failAudit = 1;
    const first = await setup(f, FULL, KEYS);
    expect(first.code).toBe(1);
    // The provider confirmation came before the install; only the final local audit failed.
    expect(first.state.steps["provider-firewall"].status).toBe("done");
    expect(first.state.steps.audit.status).toBe("failed");
    expect(first.text).toContain(`cd ${f.root} && sudo mise run host:setup`);
    const secrets = parseEnvFile(readFileSync(f.host.envPath, "utf8"));
    f.host.calls = [];
    const second = await setup(f, FULL, {});
    expect(second.code).toBe(0);
    expect(f.host.calls).not.toContain(`${BUN} scripts/install.ts --enroll-vps --key-stdin`);
    expect(f.host.calls).not.toContain(`${BUN} scripts/install.ts --harden-vps`);
    expect(f.host.calls).toContain(AUDIT);
    const after = parseEnvFile(readFileSync(f.host.envPath, "utf8"));
    for (const key of ["ARK_ROOT_KEY", "BETTER_AUTH_SECRET", "ARK_SETUP_TOKEN", "ARK_CONTROL_DB_PASSWORD"]) {
      expect(after[key]).toBe(secrets[key]!);
    }
  });

  test("a failed install resumes at the install step without enrolling again", async () => {
    const f = fixture();
    f.host.failPlatformInstall = 1;
    const first = await setup(f, FULL, KEYS);
    expect(first.code).toBe(1);
    expect(first.state.steps.install.status).toBe("failed");
    expect(first.state.steps.harden.status).toBe("done");
    expect(first.state.steps["public-ssh"].status).toBe("done");
    expect(first.state.steps.tailscale.status).toBe("done");
    f.host.calls = [];
    f.host.installModes = [];
    expect((await setup(f, FULL, { TS_EDGE_AUTHKEY: EDGE_KEY })).code).toBe(0);
    expect(f.host.calls).not.toContain(`${BUN} scripts/install.ts --enroll-vps --key-stdin`);
    // Hardening and the cutover are verified and skipped; only the platform install runs again.
    expect(f.host.installModes).toEqual(["platform"]);
    expect(f.host.calls).not.toContain("systemctl stop ssh.service");
  });

  test("a failed hardening stops before the public SSH cutover and the platform install", async () => {
    const f = fixture();
    f.host.failInstall = 1;
    const first = await setup(f, FULL, KEYS);
    expect(first.code).toBe(1);
    expect(first.state.steps.harden.status).toBe("failed");
    expect(first.state.steps["public-ssh"]).toBeUndefined();
    expect(f.host.installModes).toEqual(["harden"]);
    expect(f.host.calls).not.toContain("systemctl stop ssh.service");
  });

  test("declining the SSH cutover on an installed host leaves the platform running", async () => {
    const f = fixture();
    expect((await setup(f, [...FULL, "--no-mail", "--keep-public-ssh"], KEYS)).code).toBe(0);
    const store = new StateStore(f.stateDir);
    const legacyState = store.load();
    delete legacyState.steps.harden;
    store.save(legacyState);
    f.host.installModes = [];
    f.host.platformServices = [];
    const ui = new ScriptedUi(
      true,
      [
        ["Your domain", "<default>"],
        ["Admin hostname", "<default>"],
        ["Let's Encrypt", "<default>"],
        ["trusted Let's Encrypt", "<default>"],
        ["Shared SNI", "<default>"],
        ["reboot time", "<default>"],
        ["local (non-root) user", "<default>"],
        ["Tailscale machine name", "<default>"],
        ["Continue", "<default>"],
        ["new session works", "no"],
      ],
      [["Cloudflare", ""]],
    );

    const result = await setup(f, ["--no-mail"], {}, { scripted: ui });
    expect(result.code, result.text).toBe(1);
    expect(result.state.steps["public-ssh"].error).toContain("restored");
    expect(f.host.ssh.service.active).toBe(true);
    expect(f.host.installModes).toEqual(["harden"]);
    expect(f.host.platformServices).toEqual([]);
    expect(f.host.healthy).toBe(true);
    expect(f.host.reconcilerRunning).toBe(true);
  });

  test("changed answers re-run the install with the new settings", async () => {
    const f = fixture();
    expect((await setup(f, FULL, KEYS)).code).toBe(0);
    f.host.calls = [];
    expect((await setup(f, [...FULL, "--no-mail"], {})).code).toBe(0);
    expect(f.host.calls).toContain(`${BUN} scripts/install.ts --harden-vps`);
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).ARK_MAIL_ENABLED).toBe("0");
  });

  test("repairs live firewall drift even when the boot baseline survives", async () => {
    const f = fixture();
    expect((await setup(f, FULL, KEYS)).code).toBe(0);
    expect(existsSync(f.host.firewallPath)).toBe(true);
    f.host.liveFirewall = "";
    f.host.calls = [];
    expect((await setup(f, FULL)).code).toBe(0);
    expect(f.host.calls).toContain(`${BUN} scripts/install.ts --harden-vps`);
    expect(f.host.liveFirewall).toContain("chain input");
  });

  test("reconciles outdated or unhealthy service containers on resume", async () => {
    const f = fixture();
    expect((await setup(f, FULL, KEYS)).code).toBe(0);
    f.host.staleWorker = true;
    f.host.workerExitsAfterUp = true;
    const failed = await setup(f, FULL);
    expect(failed.code).toBe(1);
    expect(failed.state.steps.configuration.status).toBe("failed");
    f.host.workerExitsAfterUp = false;
    f.host.calls = [];
    expect((await setup(f, FULL)).code).toBe(0);
    expect(f.host.calls.some((call) => call.includes("--wait-timeout 120 api domain-worker"))).toBe(true);
  });

  test("preserves installed settings and honours installed staging on rerun", async () => {
    const f = fixture();
    expect((await setup(f, FULL, KEYS)).code).toBe(0);
    writeFileSync(
      f.host.envPath,
      setEnvValues(readFileSync(f.host.envPath, "utf8"), {
        ARK_ACME_EMAIL: "new@example.com",
        ARK_ACME_STAGING: "1",
        ARK_MAIL_ENABLED: "0",
        ARK_EDGE_SNI_PORTS: "8883",
        ARK_HOST_REBOOT_TIME: "05:30",
      }),
    );
    const args = FULL.filter((arg) => !["--acme-email", "ops@example.com"].includes(arg));
    const result = await setup(f, args);
    expect(result.code).toBe(0);
    expect(result.state.answers).toMatchObject({
      acmeEmail: "new@example.com",
      trustedCertificates: false,
      mailEnabled: false,
      sniPorts: [8883],
      rebootTime: "05:30",
    });
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).ARK_ACME_STAGING).toBe("1");
  });

  test.each([false, true])(
    "Adding the first ACME email honours explicit staging intent %s",
    async (staging) => {
      const f = fixture();
      const args = FULL.filter((arg) => !["--acme-email", "ops@example.com"].includes(arg));
      expect((await setup(f, [...args, ...(staging ? ["--staging-certificates"] : [])], KEYS)).code).toBe(0);
      expect((await setup(f, FULL)).code).toBe(0);
      expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).ARK_ACME_STAGING).toBe(staging ? "1" : "0");
    },
  );
});

describe("host:setup public SSH", () => {
  test("--keep-public-ssh leaves OpenSSH alone and the summary says how to finish", async () => {
    const f = fixture();
    const result = await setup(f, [...FULL, "--keep-public-ssh"], KEYS);
    expect(result.code).toBe(0);
    expect(f.host.calls.some((call) => call.startsWith("systemctl disable"))).toBe(false);
    expect(f.host.ssh.service).toEqual({ enabled: true, active: true });
    expect(result.text).toContain("Public OpenSSH was left running (--keep-public-ssh).");
    expect(result.text).toContain("Re-run host:setup without --keep-public-ssh to close it.");
    expect(result.text).toContain("keep the listed OpenSSH allowance");
    expect(f.host.calls).toContain(`${AUDIT} --retain-ssh`);
  });

  test("scripted setup without off-host verification leaves cutover pending", async () => {
    const f = fixture();
    const result = await setup(
      f,
      FULL.filter((arg) => arg !== "--verify-ssh-cutover"),
      KEYS,
    );
    expect(result.code).toBe(0);
    expect(result.state.steps["public-ssh"].status).toBe("pending");
    expect(readHostSshAccess(f.host.liveFirewall)).toEqual({ ports: [22], source: RECOVERY_IP });
    expect(f.host.ssh.service.active).toBe(true);
  });

  test("a healthy daemon without an off-host login rolls back and invalidates confirmation", async () => {
    const f = fixture();
    f.host.denyProof = true;
    const result = await setup(f, FULL, KEYS);
    expect(result.code).toBe(1);
    expect(result.text).toContain("Timed out waiting for a fresh off-host Tailscale SSH login");
    expect(readHostSshAccess(f.host.liveFirewall)).toEqual({ ports: [22], source: RECOVERY_IP });
    expect(f.host.ssh.service).toEqual({ active: true, enabled: true });
    expect((await setup(f, FULL)).code).toBe(2);
  });

  test.each(["listener", "ufw", "rollback"])(
    "reports or restores earlier access on %s failure",
    async (failure) => {
      const f = fixture();
      f.host.ufw = "Status: active\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n";
      f.host.failUfwDelete = failure === "ufw";
      f.host.failListenersAfterStop = failure !== "ufw";
      f.host.failRollback = failure === "rollback";
      const result = await setup(f, FULL, KEYS);
      expect(result.code).toBe(1);
      expect(readHostSshAccess(f.host.liveFirewall).source).toBe(RECOVERY_IP);
      if (failure === "rollback") {
        expect(result.text).toContain("SSH restoration failed:");
      } else {
        expect(result.text).toContain("The prior OpenSSH listener and firewall configuration were restored");
        expect(f.host.ssh.service).toEqual({ active: true, enabled: true });
      }
    },
  );

  test("leaves a private OpenSSH service and its UFW rules enabled", async () => {
    const f = fixture();
    f.host.privateSsh = true;
    f.host.ufw = "Status: active\n[ 1] OpenSSH                     ALLOW IN    10.2.0.0/24\n";
    const result = await setup(f, FULL, KEYS);
    expect(result.code).toBe(0);
    expect(f.host.ssh.service).toEqual({ active: true, enabled: true });
    expect(f.host.calls).not.toContain("systemctl stop ssh.service");
    expect(f.host.calls.some((call) => call.startsWith("ufw --force delete"))).toBe(false);
  });

  test("if Tailscale SSH stops answering, OpenSSH is started again and the failure reported", async () => {
    const f = fixture();
    f.host.breakTailscaleOnSshStop = true;
    const result = await setup(f, FULL, KEYS);
    expect(result.code).toBe(1);
    expect(result.text).toContain("The prior OpenSSH listener and firewall configuration were restored");
    expect(f.host.ssh.service).toEqual({ enabled: true, active: true });
    expect(result.state.steps["public-ssh"].status).toBe("failed");
  });
});

describe("host:setup edge node", () => {
  test("resumes namespace reconciliation after the edge node has already joined", async () => {
    const f = fixture();
    f.host.failRejoin = 1;
    expect((await setup(f, FULL, KEYS)).code).toBe(1);
    expect(f.host.edge.running).toBe(true);
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_EDGE_AUTHKEY).toBe(EDGE_KEY);
    f.host.calls = [];
    expect((await setup(f, FULL)).code).toBe(0);
    expect(f.host.calls.some((call) => call.endsWith("scripts/edge-namespace.ts"))).toBe(true);
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_EDGE_AUTHKEY).toBe("");
  });

  test("accepts a fresh edge key after the previous one is rejected", async () => {
    const f = fixture();
    f.host.rejectEdgeKey = EDGE_KEY;
    const failed = await setup(f, FULL, KEYS);
    expect(failed.code).toBe(1);
    expect(failed.text).toContain("Tailscale rejected the edge auth key");
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_EDGE_AUTHKEY).toBe("");
    expect((await setup(f, FULL, { TS_EDGE_AUTHKEY: EDGE_KEY + "-replacement" })).code).toBe(0);
  });

  /** An edge node that joined before Compose passed TS_HOSTNAME: containerboot now exits on every start. */
  function loopingEdge(f: Fixture, storedName: string, fixed = true) {
    writeFileSync(f.host.envPath, "", { mode: 0o600 });
    f.host.edge = { running: true, tags: ["tag:ark-edge"], hostName: storedName };
    f.host.restartLoops.set("edge-ts", {
      logs: flagsLog(storedName),
      storedName,
      fixedBy: ({ name }) => fixed && name === storedName,
    });
  }

  test.each(["ark-edge", "custom-edge"])(
    "a re-run recovers an enrolled edge-ts stuck in a restart loop and keeps its name %s",
    async (name) => {
      const f = fixture();
      loopingEdge(f, name);
      writeFileSync(f.host.envPath, "TS_EDGE_HOSTNAME=stale-edge\n", { mode: 0o600 });
      const identity = f.host.containerSelf("edge-ts").ID;
      // Where the failure left setup: the host node is enrolled, nothing is hardened.
      f.host.enrolled = true;
      f.host.runSsh = true;
      const result = await setup(f, [...FULL, "--tailscale-hostname", "prod"], KEYS);
      expect(result.code).toBe(0);
      expect(f.host.installModes).toEqual(["harden", "platform"]);
      expect(result.text).toContain(
        "edge-ts cannot stay up (restarting, exit code 1, restarted 4143 times); the install recreates it",
      );
      expect(f.host.containerSelf("edge-ts")).toMatchObject({ ID: identity, HostName: name });
      expect(f.host.containerCreations).toEqual([["edge-ts", name]]);
      expect(f.host.firstContainerJoins).toEqual([]);
      expect(f.host.containerKeys).toEqual([]);
      // Docker ignores a start while it restarts the container itself.
      expect(f.host.calls).not.toContain("docker start edge-ts");
      expect(
        f.host.calls.some(
          (call) => /volume|prune|compose .* down/.test(call) && !/volume ls|--volumes-from/.test(call),
        ),
      ).toBe(false);
    },
  );

  test.each([false, true])(
    "repairs edge-ts after a skipped install (explicit rename: %s)",
    async (rename) => {
      const f = fixture();
      expect((await setup(f, [...FULL, "--tailscale-hostname", "prod"], KEYS)).code).toBe(0);
      writeFileSync(
        f.host.envPath,
        setEnvValues(readFileSync(f.host.envPath, "utf8"), { TS_EDGE_HOSTNAME: "stale-edge" }),
      );
      const store = new StateStore(f.stateDir);
      const saved = store.load();
      delete saved.answers.tailscaleEdgeHostname;
      store.save(saved);
      const identity = f.host.containerSelf("edge-ts").ID;
      let recreated = 0;
      f.host.restartLoops.set("edge-ts", {
        logs: flagsLog("prod-edge"),
        storedName: "prod-edge",
        fixedBy: ({ name, key }) => {
          recreated++;
          return name === "prod-edge" && key === "";
        },
      });
      f.host.containerCreations.length = 0;
      f.host.calls = [];
      const result = await setup(f, rename ? [...FULL, "--tailscale-edge-hostname", "new-edge"] : FULL, {});
      expect(result.code).toBe(0);
      expect(recreated).toBe(1);
      expect(result.text).toContain("recreating it and keeping its state volume");
      expect(f.host.installModes).toEqual(["harden", "platform"]);
      expect(f.host.containerSelf("edge-ts")).toMatchObject({
        ID: identity,
        HostName: rename ? "new-edge" : "prod-edge",
      });
      expect(f.host.containerCreations).toEqual(
        rename
          ? [
              ["edge-ts", "prod-edge"],
              ["edge-ts", "new-edge"],
            ]
          : [["edge-ts", "prod-edge"]],
      );
      expect(f.host.edgeDependencyStarts).toBe(0);
      expect(f.host.calls.some((call) => call.endsWith("scripts/edge-namespace.ts"))).toBe(true);
    },
  );

  test("gives up with the container's state and redacted log when recreating it does not help", async () => {
    const f = fixture();
    loopingEdge(f, "ark-edge", false);
    f.host.failSidecarUp = true;
    const key = "tskey-auth-kOLD00000CNTRL-oldSecretValue0123456789";
    f.host.restartLoops.get("edge-ts")!.logs =
      `boot: up --authkey=${key} at https://login.tailscale.com/a/abc123def\nboot: failed to create TUN\n`;
    const result = await setup(f, FULL, KEYS);
    expect(result.code).toBe(1);
    expect(f.host.installModes).toEqual(["harden", "platform"]);
    expect(result.state.steps.edge.status).toBe("failed");
    expect(result.text).toContain("edge-ts container: restarting, exit code 1, restarted 4143 times.");
    expect(result.text).toContain("boot: failed to create TUN");
    expect(result.text).toContain("cannot join the network namespace");
    expect(result.text).toContain("docs/operations/troubleshooting.md#");
    for (const text of [result.text, result.log]) {
      expect(text).not.toContain(key);
      expect(text).not.toContain("abc123def");
    }
  });

  test("does not recreate a looping edge-ts whose identity cannot be read, but still hardens", async () => {
    const f = fixture();
    loopingEdge(f, "ark-edge");
    writeFileSync(f.host.envPath, "TS_EDGE_HOSTNAME=prod-edge\n", { mode: 0o600 });
    f.host.restartLoops.get("edge-ts")!.storedName = null;
    const result = await setup(f, FULL, KEYS);
    expect(result.code).toBe(1);
    expect(f.host.installModes).toEqual(["harden"]);
    expect(f.host.containerCreations).toEqual([]);
    expect(result.text).toContain("stored identity could not be read");
    expect(result.text).toContain("exit code 1, restarted 4143 times");
  });

  test.each([false, true])(
    "checks the retained edge state when the container is absent (readable: %s)",
    async (readable) => {
      const f = fixture();
      writeFileSync(f.host.envPath, "TS_EDGE_HOSTNAME=\n", { mode: 0o600 });
      f.host.edge = { running: true, tags: ["tag:ark-edge"], hostName: "retained-edge" };
      const identity = f.host.containerSelf("edge-ts").ID;
      f.host.orphanedState.set("edge-ts", readable ? storedState("retained-edge", identity) : "{");
      const result = await setup(f, FULL, KEYS);
      expect(result.code).toBe(readable ? 0 : 1);
      expect(f.host.installModes).toEqual(readable ? ["harden", "platform"] : ["harden"]);
      expect(f.host.containerCreations).toEqual(readable ? [["edge-ts", "retained-edge"]] : []);
      if (readable)
        expect(f.host.containerSelf("edge-ts")).toMatchObject({ ID: identity, HostName: "retained-edge" });
      else {
        expect(f.host.orphanedState.get("edge-ts")).toBe("{");
        expect(result.text).toContain("stored identity could not be read");
      }
    },
  );

  test.each([false, true])(
    "a rejected edge key is replaced after a failed join (Compose up fails: %s)",
    async (upFails) => {
      const f = fixture();
      f.host.rejectEdgeKey = EDGE_KEY;
      f.host.crashOnRejectedKey = true;
      f.host.failSidecarUp = upFails;
      const failed = await setup(f, FULL, KEYS);
      expect(failed.code).toBe(1);
      if (upFails) {
        expect(failed.text).toContain("cannot join the network namespace");
        expect(failed.text).toContain("exit code 1, restarted 4143 times");
        expect(failed.text).toContain("failed to auth tailscale");
        expect(failed.text).toContain("docs/operations/troubleshooting.md#");
      } else expect(failed.text).toContain("Tailscale rejected the edge auth key");
      expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_EDGE_AUTHKEY).toBe("");
      const replacement = `${EDGE_KEY}-replacement`;
      const result = await setup(f, FULL, { TS_EDGE_AUTHKEY: replacement });
      expect(result.code).toBe(0);
      expect(f.host.edge.running).toBe(true);
      for (const text of [failed.text, failed.log, result.text, result.log])
        expect(text).not.toContain(EDGE_KEY);
    },
  );

  test.each([
    { name: "drops the rejected key from .env", inEnv: EDGE_KEY, kept: "" },
    { name: "keeps a fresh key placed in .env since", inEnv: `${EDGE_KEY}-fresh`, kept: `${EDGE_KEY}-fresh` },
  ])("a crash on a rejected key $name", async ({ inEnv, kept }) => {
    const f = fixture();
    writeFileSync(f.host.envPath, `TS_EDGE_AUTHKEY=${EDGE_KEY}\n`, { mode: 0o600 });
    f.host.rejectEdgeKey = EDGE_KEY;
    f.host.crashOnRejectedKey = true;
    f.host.composeUp("edge-ts", {});
    expect(f.host.restartLoops.has("edge-ts")).toBe(true);
    writeFileSync(f.host.envPath, `TS_EDGE_AUTHKEY=${inEnv}\n`, { mode: 0o600 });
    const ui = new ScriptedUi(true, [], []);
    const asked: string[] = [];
    const source = manualKeySource({ env: {}, ui, interactive: false });
    await setup(
      f,
      FULL,
      { TS_VPS_AUTHKEY: VPS_KEY },
      {
        keys: () => ({
          ...source,
          acquire: async (request, options) => {
            asked.push(request.tag);
            return request.tag === "tag:ark-vps" ? { key: VPS_KEY } : source.acquire(request, options);
          },
        }),
      },
    );
    // Nothing joined with the rejected key; a fresh one in .env is used without asking.
    expect(f.host.edge.running).toBe(Boolean(kept));
    expect(asked.includes("tag:ark-edge")).toBe(!kept);
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_EDGE_AUTHKEY).toBe("");
  });

  test("a looping backup-ts is recreated with its stored name and identity, without a key", async () => {
    const f = fixture();
    const args = [...FULL, "--backup-node"];
    expect((await setup(f, args, { ...KEYS, TS_BACKUP_AUTHKEY: BACKUP_KEY })).code).toBe(0);
    const identity = f.host.containerSelf("backup-ts").ID;
    const name = f.host.backup.hostName;
    writeFileSync(
      f.host.envPath,
      setEnvValues(readFileSync(f.host.envPath, "utf8"), { TS_BACKUP_HOSTNAME: "stale-backup" }),
    );
    f.host.restartLoops.set("backup-ts", {
      logs: flagsLog(name),
      storedName: name,
      fixedBy: (created) => created.name === name && created.key === "",
    });
    f.host.containerKeys.length = 0;
    const result = await setup(f, args, {});
    expect(result.code).toBe(0);
    expect(result.text).toContain("backup-ts cannot stay up");
    expect(f.host.containerSelf("backup-ts")).toMatchObject({ ID: identity, HostName: name });
    expect(f.host.containerKeys).toEqual([]);
  });

  test.each([false, true])(
    "drops the spent backup key and accepts a replacement from .env (%s)",
    async (replace) => {
      const f = fixture();
      const args = [...FULL, "--backup-node"];
      expect((await setup(f, FULL, KEYS)).code).toBe(0);
      writeFileSync(
        f.host.envPath,
        setEnvValues(readFileSync(f.host.envPath, "utf8"), { TS_BACKUP_AUTHKEY: BACKUP_KEY }),
      );
      f.host.rejectEdgeKey = BACKUP_KEY;
      f.host.crashOnRejectedKey = true;
      f.host.composeUp("backup-ts", {});
      const fresh = `${BACKUP_KEY}-replacement`;
      if (replace)
        writeFileSync(
          f.host.envPath,
          setEnvValues(readFileSync(f.host.envPath, "utf8"), { TS_BACKUP_AUTHKEY: fresh }),
        );
      f.host.containerKeys.length = 0;
      const result = await setup(f, args, {});
      expect(result.code).toBe(0);
      expect(f.host.backup.running).toBe(replace);
      expect(f.host.containerKeys.map(({ key }) => key)).toEqual(replace ? [fresh] : []);
      expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_BACKUP_AUTHKEY).toBe("");
      f.host.containerKeys.length = 0;
      f.host.composeUp("backup-ts", {});
      expect(f.host.containerKeys).toEqual([]);
      expect(result.log).not.toContain(BACKUP_KEY);
      expect(result.log).not.toContain(fixturePrivateKey);
    },
  );

  test("refuses an edge node that joined with the wrong tags", async () => {
    const f = fixture();
    f.host.edgeJoinTags = ["tag:ark-edge", "tag:server"];
    const result = await setup(f, FULL, KEYS);
    expect(result.code).toBe(1);
    expect(result.text).toContain('not exactly ["tag:ark-edge"]');
    expect(result.log).not.toContain(EDGE_KEY);
  });

  test("--skip-edge continues and the summary says how to finish", async () => {
    const f = fixture();
    const result = await setup(f, [...FULL, "--skip-edge"], { TS_VPS_AUTHKEY: VPS_KEY });
    expect(result.code).toBe(0);
    expect(result.state.steps.edge.status).toBe("skipped");
    expect(result.text).toContain(
      "Edge node enrolment (tag:ark-edge): The edge node (edge-ts) has not joined",
    );
    expect(result.text).toContain("docs/getting-started/production-install.md#enrol-the-edge-node");
  });
});

describe("Tailscale state volume reader", () => {
  const hostname = "kept-name";
  const nodeId = "n-fixture";
  const profile = storedState(hostname, nodeId);
  test.each([
    { label: "missing file", state: undefined, identity: "none" },
    { label: "empty store", state: "{}", identity: "none" },
    {
      label: "machine key only",
      state: JSON.stringify({ _machinekey: encodeState(fixturePrivateKey) }),
      identity: "none",
    },
    { label: "empty file", state: "", identity: "unknown" },
    { label: "truncated store", state: "{", identity: "unknown" },
    { label: "invalid store entry", state: profile.replace("{", '{"other":999,'), identity: "unknown" },
    {
      label: "truncated preferences",
      state: storedState(hostname, nodeId, '{"Hostname":"kept-name"'),
      identity: "unknown",
    },
    {
      label: "missing profile entry",
      state: JSON.stringify({ "_current-profile": encodeState("profile-1234") }),
      identity: "unknown",
    },
    {
      label: "profile without a node ID",
      state: storedState(hostname, nodeId, storedPrefs(hostname, "")),
      identity: "unknown",
    },
    {
      label: "inactive profile",
      state: JSON.stringify({ "profile-1234": encodeState(storedPrefs(hostname, nodeId)) }),
      identity: "unknown",
    },
    {
      label: "legacy preferences without a node ID",
      state: JSON.stringify({ _daemon: encodeState("{}") }),
      identity: "unknown",
    },
    {
      label: "legacy enrolled preferences",
      state: JSON.stringify({ _daemon: encodeState(storedPrefs(hostname, nodeId)) }),
      identity: { hostName: hostname, nodeId },
    },
    { label: "enrolled profile", state: profile, identity: { hostName: hostname, nodeId } },
    {
      label: "enrolled profile with no saved hostname or container",
      state: storedState("", nodeId),
      identity: "unknown",
    },
    {
      label: "enrolled profile using its container hostname",
      state: storedState("", nodeId),
      fallback: hostname,
      identity: { hostName: hostname, nodeId },
    },
  ])("reads $label", async ({ state, identity, fallback }) => {
    const directory = mkdtempSync(join(tmpdir(), "ark-ts-identity-"));
    try {
      if (state !== undefined) writeFileSync(join(directory, "tailscaled.state"), state);
      const result = await runCommand([
        "/bin/sh",
        "-c",
        READ_IDENTITY.replace("/var/lib/tailscale", '"$1"'),
        "sh",
        directory,
      ]);
      expect(parseStoredIdentity(result, fallback)).toEqual(identity);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

describe("host:setup provider firewall", () => {
  test("an existing mail-disabled platform stays up if early provider verification fails", async () => {
    const f = fixture();
    const args = [...FULL, "--no-mail"];
    expect((await setup(f, args, KEYS)).code).toBe(0);
    const store = new StateStore(f.stateDir);
    const legacyState = store.load();
    delete legacyState.steps.harden;
    store.save(legacyState);
    f.host.installModes = [];
    f.host.platformServices = [];
    const adapter = {
      ...manualProviderFirewall,
      async plan() {
        throw new Error("provider is temporarily unavailable");
      },
    };
    const result = await setup(f, args, {}, { firewalls: [adapter] });
    expect(result.code).toBe(1);
    expect(result.state.steps["provider-firewall"].error).toContain("provider is temporarily unavailable");
    expect(f.host.installModes).toEqual(["harden"]);
    expect(f.host.platformServices).toEqual([]);
    expect(f.host.healthy).toBe(true);
    expect(f.host.reconcilerRunning).toBe(true);
  });

  test("without confirmation (non-interactive) the rules are printed and the audit waits", async () => {
    const f = fixture();
    const result = await setup(f, [...BASE, "--tailscale-ssh-confirmed"], KEYS);
    expect(result.code).toBe(0);
    expect(result.state.steps["provider-firewall"].status).toBe("pending");
    expect(result.text).toContain("allow UDP 41641, 41642 from 0.0.0.0/0 and ::/0");
    expect(result.text).toContain("--provider-firewall-applied");
    expect(f.host.calls).not.toContain(`${AUDIT} --retain-ssh`);
  });

  test("an inspectable adapter overrides an earlier manual confirmation and repairs later drift", async () => {
    const f = fixture();
    const applied: unknown[] = [];
    let inSync = false;
    const adapter: ProviderFirewall = {
      id: "example-cloud",
      label: "Example Cloud API",
      detect: async (context) => context.env.EXAMPLE_CLOUD_TOKEN === "x",
      plan: async (rules) => ({
        adapter: "example-cloud",
        inSync,
        changes: [`set ${rules.length} rules`],
      }),
      apply: async (plan) => {
        applied.push(plan);
        return { status: "applied" };
      },
    };
    expect((await setup(f, FULL, KEYS)).state.steps["provider-firewall"].status).toBe("done");
    const result = await setup(
      f,
      [...BASE, "--tailscale-ssh-confirmed"],
      { EXAMPLE_CLOUD_TOKEN: "x" },
      {
        firewalls: [adapter, manualProviderFirewall],
      },
    );
    expect(result.code).toBe(0);
    expect(applied).toHaveLength(1);
    expect(result.text).toContain("set 2 rules");
    expect(result.state.steps["provider-firewall"].status).toBe("done");
    const withApi = () =>
      setup(f, BASE, { EXAMPLE_CLOUD_TOKEN: "x" }, { firewalls: [adapter, manualProviderFirewall] });
    inSync = true;
    expect((await withApi()).code).toBe(0);
    expect(applied).toHaveLength(1);
    inSync = false;
    expect((await withApi()).code).toBe(0);
    expect(applied).toHaveLength(2);
  });
});

describe("host:setup Tailscale machine names", () => {
  const interactive = (names: string[]) =>
    new ScriptedUi(
      true,
      [
        ["Your domain", "example.com"],
        ["Admin hostname", "<default>"],
        ["Let's Encrypt", "ops@example.com"],
        ["trusted Let's Encrypt", "<default>"],
        ["incoming mail", "<default>"],
        ["Shared SNI", "<default>"],
        ["reboot time", "<default>"],
        ["local (non-root) user", "alice"],
        ...names.map((name): [string, string] => ["Tailscale machine name", name]),
        ["Continue", "<default>"],
        ["policy is saved", "yes"],
        ["session works", "not yet"],
      ],
      [
        ["Cloudflare", ""],
        ["Tailscale API access token", ""],
        ["tag:ark-vps key", VPS_KEY],
      ],
    );

  test("interactive: asks with the sanitised OS hostname, re-prompts on an invalid name and joins with it", async () => {
    const f = fixture();
    f.host.vpsHostName = "Ubuntu-4GB_hel1-2";
    const ui = interactive(["my box", "-edge", "   ", ""]);
    const result = await setup(f, [], {}, { scripted: ui, hostname: "Ubuntu-4GB_hel1-2.example.net" });
    expect(result.code).toBe(2);
    expect(result.text).toContain(
      'Tailscale machine name "my box" is not valid: use 1-63 lowercase letters, digits and hyphens, not starting or ending with a hyphen',
    );
    expect(result.text).toContain('Tailscale machine name "-edge" is not valid');
    expect(result.text).toContain('Tailscale machine name "   " is not valid');
    expect(result.text).toContain("Tailscale names:     ubuntu-4gb-hel1-2 (this VPS)");
    expect(result.text).toContain("edge ubuntu-4gb-hel1-2-edge (a new edge node)");
    expect(result.text).toContain("tailscale ssh alice@ubuntu-4gb-hel1-2.tail1234.ts.net");
    expect(f.host.enrolledHostName).toBe("ubuntu-4gb-hel1-2");
    expect(result.state.answers.tailscaleHostname).toBe("ubuntu-4gb-hel1-2");
    expect(result.state.tailscaleNames.vps).toEqual({
      requested: "ubuntu-4gb-hel1-2",
      assigned: "ubuntu-4gb-hel1-2",
    });

    // A re-run offers the previous answer, not the OS hostname.
    const again = interactive(["<default>"]);
    await setup(f, [], {}, { scripted: again, hostname: "something-else" });
    expect(again.output.join("\n")).toContain("Tailscale names:     ubuntu-4gb-hel1-2 (this VPS)");
  });

  test("interactive: an invalid explicit VPS name falls through to the prompt", async () => {
    const f = fixture();
    const ui = interactive(["Replacement"]);
    const result = await setup(f, [], { ARK_SETUP_TAILSCALE_HOSTNAME: " bad " }, { scripted: ui });
    expect(result.code).toBe(2);
    expect(result.text).toContain('Tailscale machine name " bad " is not valid');
    expect(f.host.enrolledHostName).toBe("replacement");
  });

  test("non-interactive: a flag or variable is used without prompting; uppercase is lowercased", async () => {
    const f = fixture();
    const result = await setup(f, [...FULL, "--tailscale-hostname", "Prod-VPS"], KEYS);
    expect(result.code).toBe(0);
    expect(f.host.enrolledHostName).toBe("prod-vps");
    expect(f.host.edge.hostName).toBe("prod-vps-edge");
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_EDGE_HOSTNAME).toBe("prod-vps-edge");
    expect(result.state.answers.tailscaleHostname).toBe("prod-vps");
    expect(result.state.tailscaleNames).toEqual({
      vps: { requested: "prod-vps", assigned: "prod-vps" },
      edge: { requested: "prod-vps-edge", assigned: "prod-vps-edge" },
    });
    expect(result.text).toContain("Tailscale names:     prod-vps (this VPS)");
    expect(result.text).toContain("  This VPS:      prod-vps");
    expect(result.text).toContain("  Edge node:     prod-vps-edge");
    expect(result.text).toContain("  Connect with:  tailscale ssh alice@prod-vps.tail1234.ts.net");
    expect(f.host.renames).toEqual([]);

    const g = fixture();
    const scripted = await setup(g, FULL, { ...KEYS, ARK_SETUP_TAILSCALE_HOSTNAME: "from-env" });
    expect(scripted.code).toBe(0);
    expect(g.host.enrolledHostName).toBe("from-env");
  });

  test("non-interactive without a name uses the sanitised OS hostname and does not fail", async () => {
    const f = fixture();
    const result = await setup(f, FULL, KEYS, { hostname: "UBUNTU--4gb_hel1-2.local" });
    expect(result.code).toBe(0);
    expect(f.host.enrolledHostName).toBe("ubuntu-4gb-hel1-2");
    expect(f.host.edge.hostName).toBe("ubuntu-4gb-hel1-2-edge");
  });

  test.each([
    ["has space", "has space"],
    ["a.b", "a.b"],
    ["a_b", "a_b"],
    ["-leading", "-leading"],
    ["trailing-", "trailing-"],
    ["padded", " prod "],
    ["x".repeat(64), "x".repeat(64)],
  ])("non-interactive: refuses %s before any host command", async (_label, name) => {
    const f = fixture();
    const result = await setup(f, [...FULL, "--tailscale-hostname", name], KEYS);
    expect(result.code).toBe(1);
    expect(result.text).toContain(
      "is not valid: use 1-63 lowercase letters, digits and hyphens, not starting or ending with a hyphen (no spaces, dots or underscores).",
    );
    expect(f.host.calls).toEqual([]);
  });

  test.each([
    "ARK_SETUP_TAILSCALE_HOSTNAME",
    "ARK_SETUP_TAILSCALE_EDGE_HOSTNAME",
    "ARK_SETUP_TAILSCALE_BACKUP_HOSTNAME",
  ])("non-interactive: refuses whitespace-only %s", async (variable) => {
    const f = fixture();
    const result = await setup(f, FULL, { ...KEYS, [variable]: " \t " });
    expect(result.code).toBe(1);
    expect(result.text).toContain("is not valid");
    expect(f.host.calls).toEqual([]);
  });

  test("refuses an invalid edge or backup override", async () => {
    const f = fixture();
    const result = await setup(f, FULL, { ...KEYS, ARK_SETUP_TAILSCALE_EDGE_HOSTNAME: "edge_1" });
    expect(result.code).toBe(1);
    expect(result.text).toContain(
      'Edge node name (--tailscale-edge-hostname or ARK_SETUP_TAILSCALE_EDGE_HOSTNAME) "edge_1" is not valid',
    );
    const backup = await setup(f, [...FULL, "--tailscale-backup-hostname=b.k"], KEYS);
    expect(backup.text).toContain(
      'Backup node name (--tailscale-backup-hostname or ARK_SETUP_TAILSCALE_BACKUP_HOSTNAME) "b.k"',
    );
    expect(f.host.calls).toEqual([]);
  });

  test("renames an enrolled host in place, without re-enrolling or touching tags; a second run changes nothing", async () => {
    const f = fixture();
    expect((await setup(f, FULL, KEYS)).code).toBe(0);
    const enrolments = f.host.calls.filter((call) => call.includes("--enroll-vps")).length;
    f.host.calls = [];

    const renamed = await setup(f, [...FULL, "--tailscale-hostname", "new-name"], {});
    expect(f.host.renames).toEqual([["vps", "new-name"]]);
    expect(f.host.calls.filter((call) => call.includes("--enroll-vps"))).toEqual([]);
    expect(f.host.calls.some((call) => /tailscale (?:up|logout|down)|advertise-tags/.test(call))).toBe(false);
    expect(f.host.vpsTags).toBeUndefined();
    expect(renamed.text).toContain("Tailscale machine name: new-name");
    // The SSH command changed, so the gate asks for a fresh confirmation (it is never skipped).
    expect(renamed.code).toBe(2);
    expect(renamed.text).toContain("tailscale ssh alice@new-name.tail1234.ts.net");
    // The edge node was enrolled earlier under the old name and keeps it.
    expect(f.host.edge.hostName).toBe("ark-vps-edge");

    const resumed = await setup(f, [...FULL, "--tailscale-hostname", "new-name"], {});
    expect(resumed.code).toBe(0);
    const again = await setup(f, [...FULL, "--tailscale-hostname", "new-name"], {});
    expect(again.code).toBe(0);
    expect(f.host.renames).toEqual([["vps", "new-name"]]);
    expect(enrolments).toBe(1);
    expect(again.text).toContain("  Edge node:     ark-vps-edge");
  });

  test("reports the name Tailscale actually assigned when the requested one is taken", async () => {
    const f = fixture();
    f.host.takenNames.add("prod");
    f.host.takenNames.add("prod-edge");
    const result = await setup(f, [...FULL, "--tailscale-hostname", "prod"], KEYS);
    expect(result.code).toBe(0);
    expect(result.text).toContain(
      "Tailscale assigned the name prod-1, not the requested prod (the name is taken on the tailnet",
    );
    expect(result.text).toContain("Tailscale assigned the name prod-edge-1, not the requested prod-edge");
    expect(result.text).toContain("tailscale ssh alice@prod-1.tail1234.ts.net");
    expect(result.text).toContain(
      "  This VPS:      prod-1 (requested prod; Tailscale assigned a different name)",
    );
    expect(result.text).toContain(
      "  Edge node:     prod-edge-1 (requested prod-edge; Tailscale assigned a different name)",
    );
    expect(result.state.tailscaleNames.vps).toEqual({ requested: "prod", assigned: "prod-1" });
  });

  test("the scripted gate also names the assigned host name when it differs", async () => {
    const f = fixture();
    f.host.takenNames.add("prod");
    const result = await setup(f, [...BASE, "--tailscale-hostname", "prod"], KEYS);
    expect(result.code).toBe(2);
    expect(result.text).toContain("tailscale ssh alice@prod-1.tail1234.ts.net -o ControlPath=none");
    expect(result.text).toContain("Tailscale assigned the name prod-1, not the requested prod");
  });

  test.each([
    { override: [], name: "prod-edge" },
    { override: ["--tailscale-edge-hostname", "first-edge"], name: "first-edge" },
  ])("the retained edge key first enrols the node as $name", async ({ override, name }) => {
    const f = fixture();
    writeFileSync(f.host.envPath, `TS_EDGE_AUTHKEY=${EDGE_KEY}\n`, { mode: 0o600 });
    const result = await setup(f, [...FULL, "--tailscale-hostname", "prod", ...override], {
      TS_VPS_AUTHKEY: VPS_KEY,
    });
    expect(result.code).toBe(0);
    expect(f.host.firstContainerJoins).toEqual([["edge-ts", name]]);
    expect(f.host.containerKeys).toEqual([{ service: "edge-ts", key: EDGE_KEY, from: ".env" }]);
  });

  test("an existing edge node keeps its name unless one is given explicitly", async () => {
    const f = fixture();
    // An install from before machine names: the edge node is ark-edge and .env names nothing.
    f.host.edge = { running: true, tags: ["tag:ark-edge"], hostName: "ark-edge" };
    const first = await setup(f, [...FULL, "--tailscale-hostname", "prod"], KEYS);
    expect(first.code).toBe(0);
    expect(f.host.edge.hostName).toBe("ark-edge");
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_EDGE_HOSTNAME ?? "").toBe("");
    expect(first.text).toContain("edge-ts already joined as tag:ark-edge (ark-edge)");
    expect(first.text).toContain("  Edge node:     ark-edge");
    expect(f.host.renames).toEqual([]);

    // A pre-TS_HOSTNAME container still has its original creation environment.
    f.host.startupNames.delete("edge-ts");
    f.host.containerCreations.length = 0;
    const identity = f.host.containerSelf("edge-ts").ID;
    const renamed = await setup(f, [...FULL, "--tailscale-edge-hostname", "Prod-Edge"], {});
    expect(renamed.code).toBe(0);
    expect(f.host.containerCreations).toEqual([["edge-ts", "prod-edge"]]);
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_EDGE_HOSTNAME).toBe("prod-edge");
    expect(renamed.text).toContain(
      "edge-ts already joined as tag:ark-edge; Tailscale machine name: prod-edge",
    );
    expect(renamed.state.answers.tailscaleEdgeHostname).toBe("prod-edge");
    expect(f.host.calls.findLastIndex((call) => call.endsWith("scripts/edge-namespace.ts"))).toBeGreaterThan(
      f.host.calls.findLastIndex((call) => call.endsWith("up -d edge-ts edge edge-l4")),
    );
    f.host.restartContainer("edge-ts");
    expect(f.host.containerSelf("edge-ts")).toMatchObject({ ID: identity, HostName: "prod-edge" });

    // The recorded explicit name is re-applied idempotently: nothing changes again.
    const again = await setup(f, FULL, {});
    expect(again.code).toBe(0);
    expect(f.host.containerCreations).toEqual([["edge-ts", "prod-edge"]]);
    expect(f.host.edge.tags).toEqual(["tag:ark-edge"]);
  });

  test("the backup node joins as <name>-backup, or with its explicit name", async () => {
    const f = fixture();
    const result = await setup(f, [...FULL, "--backup-node", "--tailscale-hostname", "prod"], {
      ...KEYS,
      TS_BACKUP_AUTHKEY: BACKUP_KEY,
    });
    expect(result.code).toBe(0);
    expect(f.host.backup.hostName).toBe("prod-backup");
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_BACKUP_HOSTNAME).toBe("prod-backup");
    expect(result.text).toContain("backup-ts joined as tag:ark-backup (prod-backup)");
    expect(result.text).toContain("  Backup node:   prod-backup");

    const identity = f.host.containerSelf("backup-ts").ID;
    const renamed = await setup(
      f,
      [...FULL, "--backup-node", "--tailscale-backup-hostname", "home-backup"],
      {},
    );
    expect(renamed.code).toBe(0);
    f.host.restartContainer("backup-ts");
    expect(f.host.containerSelf("backup-ts")).toMatchObject({ ID: identity, HostName: "home-backup" });
    expect(f.host.backup.tags).toEqual(["tag:ark-backup"]);
  });

  test.each([
    { service: "edge-ts", flag: "--tailscale-edge-hostname", variable: "TS_EDGE_HOSTNAME", options: [] },
    {
      service: "backup-ts",
      flag: "--tailscale-backup-hostname",
      variable: "TS_BACKUP_HOSTNAME",
      options: ["--backup-node"],
    },
  ])(
    "a stopped enrolled $service keeps its name or accepts an explicit rename without a key",
    async ({ service, flag, variable, options }) => {
      const f = fixture();
      const args = [...FULL, ...options, "--tailscale-hostname", "prod"];
      expect(
        (await setup(f, [...args, flag, "custom"], { ...KEYS, TS_BACKUP_AUTHKEY: BACKUP_KEY })).code,
      ).toBe(0);
      const identity = f.host.containerSelf(service).ID;
      // Simulate an enrolled service with a custom startup name and no name saved in .env or answers.
      writeFileSync(f.host.envPath, setEnvValues(readFileSync(f.host.envPath, "utf8"), { [variable]: "" }));
      const state = new StateStore(f.stateDir);
      const saved = state.load();
      delete saved.answers[service === "edge-ts" ? "tailscaleEdgeHostname" : "tailscaleBackupHostname"];
      state.save(saved);
      f.host.stoppedContainers.add(service);
      f.host.containerKeys.length = 0;
      expect((await setup(f, args, {})).code).toBe(0);
      expect(f.host.containerSelf(service)).toMatchObject({ ID: identity, HostName: "custom" });
      if (service === "edge-ts") {
        // The existing identity is recovered without the old configured auth key.
        expect(f.host.calls).not.toContain("docker start edge-ts");
        expect(f.host.configuredKeys.has(service)).toBe(false);
      }

      f.host.stoppedContainers.add(service);
      expect((await setup(f, [...args, flag, "renamed"], {})).code).toBe(0);
      expect(f.host.calls).toContain(`docker start ${service}`);
      expect(f.host.containerSelf(service)).toMatchObject({ ID: identity, HostName: "renamed" });
      expect(f.host.containerKeys).toEqual([]);
    },
  );

  test("installed names take precedence over stale saved overrides", async () => {
    const f = fixture();
    const args = [...FULL, "--backup-node"];
    const result = await setup(
      f,
      [...args, "--tailscale-edge-hostname", "old-edge", "--tailscale-backup-hostname", "old-backup"],
      { ...KEYS, TS_BACKUP_AUTHKEY: BACKUP_KEY },
    );
    expect(result.code).toBe(0);
    writeFileSync(
      f.host.envPath,
      setEnvValues(readFileSync(f.host.envPath, "utf8"), {
        TS_EDGE_HOSTNAME: "manual-edge",
        TS_BACKUP_HOSTNAME: "manual-backup",
      }),
    );
    f.host.composeUp("edge-ts", {});
    f.host.composeUp("backup-ts", {});
    f.host.containerCreations.length = 0;
    const rerun = await setup(f, args, {});
    expect(rerun.code).toBe(0);
    expect(f.host.containerCreations).toEqual([]);
    expect(rerun.state.answers).toMatchObject({
      tailscaleEdgeHostname: "manual-edge",
      tailscaleBackupHostname: "manual-backup",
    });
    expect(rerun.text).toContain("  Edge node:     manual-edge");
    expect(rerun.text).toContain("  Backup node:   manual-backup");
  });

  test("a skipped backup is reported from live DNS or labelled last observed", async () => {
    const f = fixture();
    expect(
      (await setup(f, [...FULL, "--backup-node"], { ...KEYS, TS_BACKUP_AUTHKEY: BACKUP_KEY })).code,
    ).toBe(0);
    f.host.consoleNames.set("backup-ts", "console-backup");
    const live = await setup(f, FULL, {});
    expect(live.code).toBe(0);
    expect(live.text).toContain("  Backup node:   console-backup");
    f.host.stoppedContainers.add("backup-ts");
    const stopped = await setup(f, FULL, {});
    expect(stopped.code).toBe(0);
    expect(stopped.text).toContain(
      "  Backup node:   last observed as console-backup; current name could not be verified",
    );
    expect(f.host.stoppedContainers.has("backup-ts")).toBe(true);
  });

  test("a requested name is not reported as assigned when the container has no DNS name", async () => {
    const f = fixture();
    expect((await setup(f, FULL, KEYS)).code).toBe(0);
    f.host.missingDns.add("edge-ts");
    const result = await setup(f, [...FULL, "--tailscale-edge-hostname", "unverified-edge"], {});
    expect(result.code).toBe(0);
    expect(result.text).toContain(
      "Tailscale machine name: assigned name could not be verified (requested unverified-edge)",
    );
    expect(result.text).toContain(
      "  Edge node:     assigned name could not be verified (requested unverified-edge)",
    );
    expect(result.state.tailscaleNames.edge).toEqual({ requested: "unverified-edge" });
  });

  test("name helpers: sanitising, derived names within 63 characters, usage", () => {
    expect(sanitizeHostname("Ubuntu-4GB_hel1-2.example.net")).toBe("ubuntu-4gb-hel1-2");
    expect(sanitizeHostname("--a__b--")).toBe("a-b");
    expect(sanitizeHostname("___")).toBe("ark-vps");
    expect(sanitizeHostname(undefined)).toBe("ark-vps");
    expect(sanitizeHostname(`${"a".repeat(62)}-b`)).toBe("a".repeat(62));
    expect(validateTailscaleHostname("Prod-1")).toBe("prod-1");
    expect(() => validateTailscaleHostname(" Prod-1 ")).toThrow("is not valid");
    expect(validateTailscaleHostname("x".repeat(63))).toBe("x".repeat(63));
    const long = derivedNodeName("x".repeat(63), "backup");
    expect(long).toBe(`${"x".repeat(56)}-backup`);
    expect(long.length).toBe(63);
    expect(derivedNodeName(`${"x".repeat(57)}-yz`, "edge")).toBe(`${"x".repeat(57)}-edge`);
    expect(USAGE).toContain("--tailscale-hostname NAME");
    expect(USAGE).toContain("ARK_SETUP_TAILSCALE_EDGE_HOSTNAME");
    expect(
      parseFlags(["--tailscale-hostname=a", "--tailscale-edge-hostname", "b"]).get(
        "--tailscale-edge-hostname",
      ),
    ).toBe("b");
  });
});

describe("enrollVps (host:install --enroll-vps)", () => {
  /** A stubbed host tailscale: records every command and answers status like the real CLI. */
  function stubHost(initial: { state: string; tags?: string[]; hostName?: string; tun?: boolean }) {
    const calls: string[][] = [];
    const logs: string[] = [];
    const node = { ...initial, taken: new Set<string>(), dnsName: undefined as string | undefined };
    const sleeps: number[] = [];
    const run = async (wrapper: string, argv: string[]) => {
      calls.push([wrapper, ...argv]);
      // The key-on-stdin form runs `sh -c 'cat | tailscale "$@"' sh <args>`.
      const [command, args] = wrapper === "sh" ? ["tailscale", argv.slice(3)] : [wrapper, argv];
      if (command === "tailscale" && args[0] === "status") {
        const running = node.state === "Running";
        const name = node.hostName ?? "ubuntu-4gb-hel1-2";
        return JSON.stringify({
          BackendState: node.state,
          TUN: node.tun ?? true,
          Self: {
            Online: running,
            Tags: running ? (node.tags ?? ["tag:ark-vps"]) : [],
            HostName: name,
            DNSName: node.dnsName ?? `${node.taken.has(name) ? `${name}-1` : name}.tail1234.ts.net.`,
          },
        });
      }
      if (command === "tailscale" && args[0] === "up") {
        node.state = "Running";
        const hostname = args.find((arg) => arg.startsWith("--hostname="));
        if (hostname) node.hostName = hostname.slice("--hostname=".length);
      }
      if (command === "tailscale" && args[0] === "set" && args[1]?.startsWith("--hostname=")) {
        node.hostName = args[1].slice("--hostname=".length);
      }
      return "";
    };
    const io = {
      run,
      which: () => "/usr/bin/tailscale",
      requireRoot: () => {},
      sleep: async (ms: number) => {
        sleeps.push(ms);
      },
      log: (line: string) => logs.push(line),
    };
    return { calls, logs, node, io, sleeps };
  }

  test("without a name, a fresh node joins with exactly the earlier flags", async () => {
    const host = stubHost({ state: "NeedsLogin" });
    await enrollVps(async () => VPS_KEY, "", host.io);
    const up = host.calls.find((call) => call.includes("up"))!;
    expect(up).toEqual([
      "sh",
      "-c",
      'cat | tailscale "$@"',
      "sh",
      "up",
      "--auth-key=file:/dev/stdin",
      "--advertise-tags=tag:ark-vps",
      "--accept-dns=false",
    ]);
    expect(host.calls.filter((call) => call[1] === "set")).toEqual([["tailscale", "set", "--ssh"]]);
    expect(host.logs).toEqual([
      "Verify Tailscale SSH as the owner before running host:install --harden-vps.",
    ]);
  });

  test("with TS_VPS_HOSTNAME, a fresh node joins with that name and the same tag, TUN and DNS settings", async () => {
    const host = stubHost({ state: "NeedsLogin" });
    const previous = process.env.TS_VPS_HOSTNAME;
    try {
      process.env.TS_VPS_HOSTNAME = "Prod-VPS";
      await enrollVps(async () => VPS_KEY, undefined, host.io);
    } finally {
      if (previous === undefined) delete process.env.TS_VPS_HOSTNAME;
      else process.env.TS_VPS_HOSTNAME = previous;
    }
    const up = host.calls.find((call) => call.includes("up"))!;
    expect(up.slice(4)).toEqual([
      "up",
      "--auth-key=file:/dev/stdin",
      "--advertise-tags=tag:ark-vps",
      "--accept-dns=false",
      "--hostname=prod-vps",
    ]);
    expect(host.calls.filter((call) => call[1] === "set")).toEqual([["tailscale", "set", "--ssh"]]);
    expect(host.logs).toContain("Tailscale machine name: prod-vps");
  });

  test("reports the admin console name when DNS never settles on the requested name", async () => {
    const host = stubHost({ state: "Running" });
    host.node.dnsName = "console-name.tail1234.ts.net.";
    await enrollVps(undefined, "new-name", host.io);
    expect(host.sleeps).toEqual(Array(9).fill(1000));
    expect(host.logs).toContain("Tailscale machine name: console-name");
    expect(host.logs.join("\n")).toContain(
      "Tailscale assigned the name console-name, not the requested new-name",
    );
  });

  test("reports the assigned name as unverified when DNS readback is missing", async () => {
    const host = stubHost({ state: "Running" });
    host.node.dnsName = "";
    await enrollVps(undefined, "new-name", host.io);
    expect(host.sleeps).toEqual(Array(9).fill(1000));
    expect(host.logs).toContain(
      "Tailscale machine name: assigned name could not be verified (requested new-name)",
    );
  });

  test("an enrolled, tagged node is renamed in place; a second run changes nothing", async () => {
    const host = stubHost({ state: "Running" });
    host.node.taken.add("prod");
    await enrollVps(undefined, "prod", host.io);
    expect(host.calls.some((call) => call.includes("up") || call.includes("logout"))).toBe(false);
    expect(host.calls.filter((call) => call[1] === "set")).toEqual([
      ["tailscale", "set", "--hostname=prod"],
      ["tailscale", "set", "--ssh"],
    ]);
    expect(host.logs).toContain("Tailscale machine name: prod-1");
    expect(host.logs.join("\n")).toContain("Tailscale assigned the name prod-1, not the requested prod");
    host.calls.length = 0;
    await enrollVps(undefined, "prod", host.io);
    expect(host.calls.filter((call) => call[1] === "set")).toEqual([["tailscale", "set", "--ssh"]]);
  });

  test("keeps refusing a wrongly tagged or userspace node, and an invalid name before any command", async () => {
    const tagged = stubHost({ state: "Running", tags: ["tag:server"] });
    await expect(enrollVps(undefined, "prod", tagged.io)).rejects.toThrow("must use the host TUN interface");
    expect(tagged.calls.some((call) => call.join(" ").includes("--hostname"))).toBe(false);
    const userspace = stubHost({ state: "Running", tun: false });
    await expect(enrollVps(undefined, "prod", userspace.io)).rejects.toThrow("userspace networking");
    const invalid = stubHost({ state: "NeedsLogin" });
    await expect(enrollVps(undefined, "bad_name", invalid.io)).rejects.toThrow(
      'TS_VPS_HOSTNAME "bad_name" is not valid',
    );
    expect(invalid.calls).toEqual([]);
    await expect(enrollVps(undefined, "  ", invalid.io)).rejects.toThrow("is not valid");
    expect(invalid.calls).toEqual([]);
  });
});

describe("host:setup helpers", () => {
  test("identifies the client through sudo's proc ancestry when SSH_CONNECTION is missing", async () => {
    const proc = mkdtempSync(join(tmpdir(), "ark-setup-proc-"));
    for (const pid of [40, 50]) mkdirSync(join(proc, String(pid)));
    writeFileSync(join(proc, "50/comm"), "sudo\n");
    writeFileSync(join(proc, "50/environ"), "USER=root\0");
    writeFileSync(join(proc, "50/stat"), "50 (sudo (session)) S 40 0 0\n");
    writeFileSync(join(proc, "40/comm"), "sshd\n");
    writeFileSync(join(proc, "40/environ"), "SSH_CONNECTION=198.51.100.9 51123 203.0.113.10 22\0");
    expect(await detectSessionOrigin({}, proc, 50)).toEqual({
      via: "openssh",
      detail: "203.0.113.10",
      source: "198.51.100.9",
    });
    expect(
      await detectSessionOrigin(
        {
          SSH_CONNECTION: "fd7a:115c:a1e0::f 51234 fd7a:115c:a1e0::a 22",
        },
        proc,
        50,
      ),
    ).toEqual({
      via: "tailscale",
      detail: "fd7a:115c:a1e0::a",
      source: "fd7a:115c:a1e0::f",
    });
    expect(await detectSessionOrigin({ SSH_CONNECTION: "wrong", SSH_TTY: "/dev/pts/1" }, proc, 99)).toEqual({
      via: "unknown",
    });
  });

  test("only removes unambiguous public inbound UFW SSH rules", () => {
    const rules = [
      "[ 1] 22/tcp                     ALLOW IN    198.51.100.9",
      "[ 2] OpenSSH                    ALLOW IN    10.0.0.0/8",
      "[ 3] 22/tcp on private0         ALLOW IN    Anywhere",
      "[ 4] 22/tcp                     ALLOW OUT   Anywhere",
      "[ 5] OpenSSH (v6)               ALLOW IN    Anywhere (v6)",
      "[ 6] 22/tcp (v6)                ALLOW IN    fd7a:115c:a1e0::/48",
    ].join("\n");
    expect(publicUfwSshRules(rules)).toEqual({ remove: [5, 1], ambiguous: 1 });
  });
  test("setEnvValues replaces in place, drops duplicates and appends", () => {
    const text = "A=1\n# comment\nB=2\nB=3\nSECRET=keep\n";
    expect(setEnvValues(text, { B: "x", C: "y" })).toBe("A=1\n# comment\nB=x\nSECRET=keep\nC=y\n");
    expect(() => setEnvValues(text, { B: "a\nEVIL=1" })).toThrow();
  });

  test("desiredConfiguration keeps the tunnel origin and replaces the previous admin origin", () => {
    const answers = {
      domain: "example.com",
      adminHost: "ark.example.com",
      acmeEmail: "",
      trustedCertificates: true,
      mailEnabled: true,
      sniPorts: [],
      rebootTime: "04:00",
      sshUser: "",
      tailscaleHostname: "ark-vps",
    };
    const current = "BETTER_AUTH_TRUSTED_ORIGINS=https://admin.example.com,http://localhost:5173\n";
    const { desired } = desiredConfiguration(answers, current, "https://admin.example.com");
    expect(desired.BETTER_AUTH_TRUSTED_ORIGINS).toBe(
      "https://ark.example.com,http://localhost:3000,http://localhost:5173",
    );
    // No email: staging stays on whatever the trust answer says.
    expect(desired.ARK_ACME_STAGING).toBe("1");
    expect(desired.DNS_API_TOKEN).toBeUndefined();
  });

  test("publicSshListeners ignores loopback and tailnet addresses", () => {
    const ss = [
      'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))',
      'LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))',
      'LISTEN 0 128 100.100.1.2:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))',
      'LISTEN 0 128 *:2222 *:* users:(("sshd",pid=1,fd=5))',
      'LISTEN 0 4096 [::]:22 [::]:* users:(("systemd",pid=1,fd=50))',
      'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("docker-proxy",pid=9,fd=4))',
    ].join("\n");
    expect(publicSshListeners(ss, new Set(["100.100.1.2"]))).toEqual(["0.0.0.0:22", "*:2222", "[::]:22"]);
  });

  test("the redactor removes known secrets, auth keys and the setup token line", () => {
    const redactor = new Redactor();
    redactor.addEnv(
      "ARK_ROOT_KEY=rootkeyvalue123456\nARK_ROOT_KEY_ID=k1\nDATABASE_URL=postgres://u:pw123456789@h/db\n",
    );
    const text = redactor.redact("rootkeyvalue123456 tskey-auth-abc-def Setup token: abcdefgh k1");
    expect(text).not.toContain("rootkeyvalue123456");
    expect(text).not.toContain("tskey-auth");
    expect(text).not.toContain("abcdefgh");
    expect(text).toContain("k1");
  });

  test("flags and variables resolve the options", () => {
    const options = resolveOptions(parseFlags(["--keep-public-ssh", "--provider-firewall=manual"]), {
      ARK_SETUP_SKIP_EDGE: "1",
    });
    expect(options).toMatchObject({ keepPublicSsh: true, skipEdge: true, providerFirewall: "manual" });
    expect(() => parseFlags(["--domain"])).toThrow("--domain needs a value.");
    expect(() => parseFlags(["--mail", "--no-mail"])).toThrow();
  });

  test("the manual key source names the variable in non-interactive mode", async () => {
    const ui = new ScriptedUi(false);
    const source = manualKeySource({ env: {}, ui, interactive: false });
    await expect(
      source.acquire({ tag: "tag:ark-vps", variable: "TS_VPS_AUTHKEY", optional: false }),
    ).rejects.toThrow("TS_VPS_AUTHKEY or TS_VPS_AUTHKEY_FILE");
    expect(
      await source.acquire({ tag: "tag:ark-edge", variable: "TS_EDGE_AUTHKEY", optional: true }),
    ).toBeUndefined();
    const bad = manualKeySource({ env: { TS_EDGE_AUTHKEY: "nope" }, ui, interactive: false });
    await expect(
      bad.acquire({ tag: "tag:ark-edge", variable: "TS_EDGE_AUTHKEY", optional: true }),
    ).rejects.toThrow();
  });

  test("selectProviderFirewall falls back to the manual adapter and rejects unknown ids", async () => {
    const context = {
      ui: new ScriptedUi(false),
      interactive: false,
      env: {},
      publicAddresses: { ipv4: [], ipv6: [] },
      confirmed: false,
    } satisfies FirewallContext;
    expect((await selectProviderFirewall([manualProviderFirewall], context)).id).toBe("manual");
    await expect(selectProviderFirewall([manualProviderFirewall], context, "hetzner")).rejects.toThrow(
      "Unknown provider firewall",
    );
    expect(describeProviderRules([])).toContain(
      "  remove inbound public OpenSSH allowances: administration is over Tailscale SSH",
    );
  });
});

// ---- Part 2: the Tailscale API key source and the Hetzner Cloud firewall, against mock servers ----

const API_TOKEN = "tskey-api-kAPI1234CNTRL-apiSecretValue0123456789";
const OAUTH_SECRET = "tskey-client-kOAU5678CNTRL-oauthSecretValue0123456789";
const OAUTH_ACCESS = "oauthAccessToken0123456789abcdefABCDEF";
const BACKUP_KEY = "tskey-auth-kBAK9012CNTRL-backupSecretValue0123456789";
const HCLOUD_TOKEN = "hcloudToken0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const SECRETS = [API_TOKEN, OAUTH_SECRET, OAUTH_ACCESS, VPS_KEY, EDGE_KEY, BACKUP_KEY, HCLOUD_TOKEN];

/** Tailscale's default policy for a new tailnet: tabs, comments, trailing commas, a catch-all grant. */
const DEFAULT_POLICY = `// Example/default ACLs for unrestricted connections.
{
\t// Declare static groups of users.
\t// "groups": {},

\t// Define grants that govern access for users, groups, autogroups, tags,
\t// Tailscale IP addresses, and subnet ranges.
\t"grants": [
\t\t// Allow all connections.
\t\t{"src": ["*"], "dst": ["*"], "ip": ["*"]},
\t],

\t// Define users and devices that can use Tailscale SSH.
\t"ssh": [
\t\t// Allow all users to SSH into their own devices in check mode.
\t\t{
\t\t\t"action": "check",
\t\t\t"src":    ["autogroup:member"],
\t\t\t"dst":    ["autogroup:self"],
\t\t\t"users":  ["autogroup:nonroot", "root"],
\t\t},
\t],
}
`;

/** The same policy with the replacement setup suggests. */
const NARROWED_POLICY = DEFAULT_POLICY.replace('"src": ["*"]', '"src": ["autogroup:member"]');

const servers: { stop: (force?: boolean) => unknown }[] = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});

/** A mock of the Tailscale API v2 endpoints the setup uses. */
class MockTailscale {
  tailnets = ["-"];
  policy = NARROWED_POLICY;
  etag = '"etag-1"';
  requests: { method: string; path: string; auth: string; body: string; ifMatch?: string }[] = [];
  keys = new Map<string, { key: string; body: Record<string, any>; revoked: boolean }>();
  validateProblem?: string;
  validateData?: unknown;
  policyError?: { method: "GET" | "POST"; message: string };
  revokeStatuses = new Map<string, number[]>();
  oauthScopes = ["policy_file", "auth_keys", "devices:posture_attributes", "devices:core:read"];
  oauthTag = "tag:ark-setup";
  /** Change the policy behind the setup's back on the next read (a concurrent edit). */
  raceOnRead = false;
  timeline?: string[];
  readonly server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: (request) => this.handle(request) });

  constructor() {
    servers.push(this.server);
  }

  get url() {
    return `http://127.0.0.1:${this.server.port}`;
  }

  writes() {
    return this.requests.filter((request) => request.method !== "GET" && !request.path.endsWith("/validate"));
  }

  private async handle(request: Request) {
    const url = new URL(request.url);
    const body = await request.text();
    const auth = request.headers.get("authorization") ?? "";
    this.requests.push({
      method: request.method,
      path: url.pathname,
      auth,
      body,
      ifMatch: request.headers.get("if-match") ?? undefined,
    });
    this.timeline?.push(`api ${request.method} ${url.pathname}`);
    if (url.pathname === "/api/v2/oauth/token") {
      const form = new URLSearchParams(body);
      if (form.get("client_id") !== "kOAU5678CNTRL" || form.get("client_secret") !== OAUTH_SECRET)
        return Response.json({ message: "invalid client" }, { status: 401 });
      const scopes = form.get("scope")?.split(" ") ?? [];
      if (scopes.some((scope) => !this.oauthScopes.includes(scope)))
        return Response.json({ message: "invalid_scope" }, { status: 400 });
      if (!(parseHujson(this.policy) as { tagOwners?: Record<string, string[]> }).tagOwners?.[this.oauthTag])
        return Response.json({ message: "OAuth tag is not declared" }, { status: 400 });
      return Response.json({ access_token: OAUTH_ACCESS, token_type: "Bearer", expires_in: 3600 });
    }
    if (auth !== `Bearer ${API_TOKEN}` && auth !== `Bearer ${OAUTH_ACCESS}`)
      return Response.json({ message: "unauthorized" }, { status: 401 });
    const base = this.tailnets
      .map((tailnet) => `/api/v2/tailnet/${tailnet}`)
      .find((path) => url.pathname.startsWith(`${path}/`));
    if (!base) return Response.json({ message: "unknown tailnet" }, { status: 404 });
    if (
      auth === `Bearer ${OAUTH_ACCESS}` &&
      url.pathname.startsWith(`${base}/acl`) &&
      !["policy_file", "devices:posture_attributes", "devices:core:read"].every((scope) =>
        this.oauthScopes.includes(scope),
      )
    )
      return Response.json({ message: "insufficient scope" }, { status: 403 });
    if (url.pathname === `${base}/acl` && request.method === this.policyError?.method)
      return Response.json({ message: this.policyError.message }, { status: 400 });
    if (request.method === "GET" && url.pathname === `${base}/acl`) {
      const response = new Response(this.policy, {
        headers: { "content-type": "application/hujson", etag: this.etag },
      });
      if (this.raceOnRead) {
        this.policy = `${this.policy}// edited elsewhere\n`;
        this.etag = '"etag-race"';
      }
      return response;
    }
    if (request.method === "POST" && url.pathname === `${base}/acl/validate`) {
      parseHujson(body);
      return this.validateProblem || this.validateData
        ? Response.json({ message: this.validateProblem, data: this.validateData })
        : new Response("");
    }
    if (request.method === "POST" && url.pathname === `${base}/acl`) {
      if (request.headers.get("if-match") !== this.etag)
        return Response.json({ message: "precondition failed" }, { status: 412 });
      this.policy = body;
      this.etag = `"etag-${this.requests.length}"`;
      return new Response(body, { headers: { etag: this.etag } });
    }
    if (request.method === "POST" && url.pathname === `${base}/keys`) {
      const parsed = JSON.parse(body);
      const tag = parsed.capabilities.devices.create.tags[0];
      if (auth === `Bearer ${OAUTH_ACCESS}`) {
        const { tagOwners } = parseHujson(this.policy) as { tagOwners?: Record<string, string[]> };
        if (!this.oauthScopes.includes("auth_keys") || !tagOwners?.[tag]?.includes(this.oauthTag))
          return Response.json({ message: "cannot mint for this tag" }, { status: 403 });
      }
      const key = tag === "tag:ark-vps" ? VPS_KEY : tag === "tag:ark-edge" ? EDGE_KEY : BACKUP_KEY;
      const id = `k${this.keys.size + 1}`;
      this.keys.set(id, { key, body: parsed, revoked: false });
      return Response.json({ id, key, keyType: "auth", capabilities: parsed.capabilities });
    }
    const revoke = new RegExp(`^${base}/keys/(k\\d+)$`).exec(url.pathname);
    if (request.method === "DELETE" && revoke) {
      const status = this.revokeStatuses.get(revoke[1]!)?.shift();
      if (status) return Response.json({ message: "DELETE failed" }, { status });
      const entry = this.keys.get(revoke[1]!);
      if (!entry) return Response.json({ message: "not found" }, { status: 404 });
      entry.revoked = true;
      return new Response(null, { status: 200 });
    }
    return Response.json({ message: `unexpected ${request.method} ${url.pathname}` }, { status: 500 });
  }
}

/** A mock of the Hetzner Cloud metadata service and API v1. */
class MockHetzner {
  serverId = 4242;
  serverIpv4 = "203.0.113.10";
  firewalls: HetznerFirewall[] = [];
  requests: { method: string; path: string; auth: string }[] = [];
  actions = new Map<number, number>();
  associationStatus = "applied";
  actionStatus = "success";
  timeline?: string[];
  readonly server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: (request) => this.handle(request) });

  constructor() {
    servers.push(this.server);
  }

  get url() {
    return `http://127.0.0.1:${this.server.port}`;
  }

  adapter() {
    return hetznerProviderFirewall({
      apiBase: `${this.url}/v1`,
      metadataBase: this.url,
      sleep: async () => {},
    });
  }

  writes() {
    return this.requests.filter((request) => request.method !== "GET");
  }

  private action() {
    const id = this.actions.size + 1;
    this.actions.set(id, 0);
    return { id, status: "running" };
  }

  private async handle(request: Request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const auth = request.headers.get("authorization") ?? "";
    this.requests.push({ method: request.method, path, auth });
    this.timeline?.push(`hetzner ${request.method} ${path}`);
    if (path === "/hetzner/v1/metadata/instance-id") return new Response(`${this.serverId}`);
    if (auth !== `Bearer ${HCLOUD_TOKEN}`)
      return Response.json(
        { error: { code: "unauthorized", message: "unable to authenticate" } },
        { status: 401 },
      );
    const body = request.method === "POST" ? await request.json() : undefined;
    if (path === `/v1/servers/${this.serverId}`) {
      return Response.json({
        server: {
          id: this.serverId,
          name: "ark-vps-1",
          public_net: {
            ipv4: { ip: this.serverIpv4 },
            ipv6: { ip: "2001:db8::/64" },
            firewalls: this.firewalls
              .filter((firewall) => firewall.applied_to?.some((item) => item.server?.id === this.serverId))
              .map((firewall) => ({ id: firewall.id, status: this.associationStatus })),
          },
        },
      });
    }
    if (path === "/v1/firewalls" && request.method === "GET") {
      const name = url.searchParams.get("name");
      return Response.json({
        firewalls: this.firewalls.filter((firewall) => !name || firewall.name === name),
      });
    }
    if (path === "/v1/firewalls" && request.method === "POST") {
      const firewall: HetznerFirewall = {
        id: 100 + this.firewalls.length,
        name: body.name,
        labels: body.labels,
        rules: body.rules,
        applied_to: body.apply_to,
      };
      this.firewalls.push(firewall);
      return Response.json({ firewall, actions: [this.action()] }, { status: 201 });
    }
    const match = /^\/v1\/firewalls\/(\d+)(?:\/actions\/(set_rules|apply_to_resources))?$/.exec(path);
    if (match) {
      const firewall = this.firewalls.find((item) => item.id === Number(match[1]));
      if (!firewall) return Response.json({ error: { message: "not found" } }, { status: 404 });
      if (!match[2]) return Response.json({ firewall });
      if (match[2] === "set_rules") firewall.rules = body.rules;
      else firewall.applied_to = [...(firewall.applied_to ?? []), ...body.apply_to];
      return Response.json({ action: this.action() }, { status: 201 });
    }
    const action = /^\/v1\/actions\/(\d+)$/.exec(path);
    if (action)
      return Response.json({
        action: {
          id: Number(action[1]),
          status: this.actionStatus,
          error: { message: "provider refused the action" },
        },
      });
    return Response.json({ error: { message: `unexpected ${request.method} ${path}` } }, { status: 500 });
  }
}

/** Every file under `directory` whose content contains one of `secrets`. */
function filesWithSecrets(directory: string, secrets: string[]): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true }) as Dirent[]) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...filesWithSecrets(path, secrets));
    else if (entry.isFile()) {
      const content = readFileSync(path, "utf8");
      for (const secret of secrets)
        if (content.includes(secret)) found.push(`${path}: ${secret.slice(0, 12)}…`);
    }
  }
  return found;
}

const tsApi = (mock: MockTailscale) => ({ tailscaleApi: mock.url });

describe("live installer harness", () => {
  test("streams secrets into the wrapper and leaves no files even if the command fails", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ark-setup-stream-"));
    try {
      const result = Bun.spawnSync(["bash", "-c", withStreamedCredentials("bash -s")], {
        cwd: directory,
        stdin: new TextEncoder().encode(
          credentialsOnStdin(
            [API_TOKEN, HCLOUD_TOKEN, VPS_KEY, EDGE_KEY],
            '[[ -n "$TS_API_KEY" && -n "$HCLOUD_TOKEN" && -n "$TS_VPS_AUTHKEY" && -n "$TS_EDGE_AUTHKEY" ]] || exit 1\nexit 42\n',
          ),
        ),
      });
      expect(result.exitCode).toBe(42);
      expect(readdirSync(directory)).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("requires this run's mint IDs and fails on any live key", async () => {
    const mintOutput = [
      "Minted a one-off tag:ark-vps key through the Tailscale API (ID kVps, expires in one hour).",
      "Minted a one-off tag:ark-edge key through the Tailscale API (ID kEdge, expires in one hour).",
    ];
    const expected = ["tag:ark-vps", "tag:ark-edge"];
    const lookedUp: string[] = [];
    const lookup = async (id: string) => {
      lookedUp.push(id);
      return id === "kVps" ? new Response(null, { status: 404 }) : Response.json({ invalid: false });
    };
    await expect(verifyMintedKeyRevocations([mintOutput[0]!], expected, lookup)).rejects.toThrow(
      "did not report a minted key ID for tag:ark-edge",
    );
    expect(lookedUp).toEqual([]);
    await expect(verifyMintedKeyRevocations(mintOutput, expected, lookup)).rejects.toThrow(
      "kEdge is still valid",
    );
    expect(lookedUp).toEqual(["kVps", "kEdge"]);
    await verifyMintedKeyRevocations(mintOutput, expected, async () => Response.json({ revoked: "now" }));
  });
});

describe("host:setup with a Tailscale API credential", () => {
  test("the real command runner strips API credentials from its default environment", async () => {
    const variables = ["TS_API_KEY", "TS_OAUTH_CLIENT_SECRET", "TS_OAUTH_CLIENT_ID", "HCLOUD_TOKEN"];
    const previous = variables.map((key) => process.env[key]);
    try {
      for (const key of variables) process.env[key] = "credential-probe";
      const script = `console.log(JSON.stringify(${JSON.stringify(variables)}.filter((key) => key in process.env)))`;
      const result = await runCommand([process.execPath, "--no-env-file", "-e", script]);
      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual([]);
    } finally {
      for (const [index, key] of variables.entries()) {
        const value = previous[index];
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  });
  test("merges the policy after approval, mints one-off keys, revokes each after its join; no secret is stored or shown", async () => {
    const f = fixture();
    const mock = new MockTailscale();
    mock.timeline = f.host.calls;
    const result = await setup(
      f,
      [...FULL, "--approve-tailnet-policy"],
      { TS_API_KEY: API_TOKEN },
      tsApi(mock),
    );
    expect(result.code).toBe(0);

    // The policy: read with its ETag, validated, applied with If-Match, the owner's content intact.
    const write = mock.requests.find(
      (request) => request.method === "POST" && request.path.endsWith("/acl"),
    )!;
    expect(write.ifMatch).toBe('"etag-1"');
    expect(mock.requests.some((request) => request.path.endsWith("/acl/validate"))).toBe(true);
    for (const line of NARROWED_POLICY.split("\n")) expect(mock.policy).toContain(line);
    const policy = parseHujson(mock.policy) as Record<string, any>;
    expect(policy.tagOwners).toEqual({
      "tag:ark-vps": ["autogroup:admin"],
      "tag:ark-edge": ["autogroup:admin"],
    });
    expect(policy.grants).toContainEqual({ src: ["autogroup:owner"], dst: ["tag:ark-vps"], ip: ["tcp:22"] });
    expect(policy.ssh).toHaveLength(2);
    expect(result.text).toContain('+ \t"tagOwners"');
    expect(result.text).not.toContain("catch-all");
    expect(result.text).toContain("Tailnet policy updated.");

    // Keys: single-use, not ephemeral, pre-approved, one tag, an hour at most; every one revoked.
    expect([...mock.keys.values()].map((entry) => entry.body.capabilities.devices.create.tags)).toEqual([
      ["tag:ark-vps"],
      ["tag:ark-edge"],
    ]);
    for (const { body, revoked } of mock.keys.values()) {
      expect(body.capabilities.devices.create).toMatchObject({
        reusable: false,
        ephemeral: false,
        preauthorized: true,
      });
      expect(body.expirySeconds).toBeLessThanOrEqual(3600);
      expect(revoked).toBe(true);
    }
    const at = (needle: string) => f.host.calls.findIndex((call) => call === needle || call.endsWith(needle));
    expect(at("api POST /api/v2/tailnet/-/acl")).toBeLessThan(at("api POST /api/v2/tailnet/-/keys"));
    expect(at(`${BUN} scripts/install.ts --enroll-vps --key-stdin`)).toBeLessThan(
      at("api DELETE /api/v2/tailnet/-/keys/k1"),
    );
    expect(at("api DELETE /api/v2/tailnet/-/keys/k1")).toBeLessThan(
      at(`${BUN} scripts/install.ts --harden-vps`),
    );
    expect(f.host.containerKeys).toEqual([]);
    expect(f.host.stdinEnrolments).toEqual(["edge-ts"]);
    expect(f.host.configuredKeys.has("edge-ts")).toBe(false);
    expect(at("up -d edge-ts edge edge-l4")).toBeLessThan(at("api DELETE /api/v2/tailnet/-/keys/k2"));
    expect(result.state.steps.edge.status).toBe("done");

    // No credential or key anywhere: output, log, state, .env or any other file setup wrote.
    for (const secret of SECRETS) {
      expect(result.text).not.toContain(secret);
      expect(result.log).not.toContain(secret);
    }
    expect(filesWithSecrets(f.root, SECRETS)).toEqual([]);
    expect(parseEnvFile(readFileSync(f.host.envPath, "utf8")).TS_EDGE_AUTHKEY).toBe("");
  });

  test("scripted runs without --approve-tailnet-policy show the change and apply nothing", async () => {
    const f = fixture();
    const mock = new MockTailscale();
    const result = await setup(f, FULL, { TS_API_KEY: API_TOKEN }, tsApi(mock));
    expect(result.code).toBe(1);
    expect(result.text).toContain('+ \t"tagOwners"');
    expect(result.text).toContain("--approve-tailnet-policy");
    expect(mock.writes()).toEqual([]);
    expect(f.host.calls.some((call) => call.includes("--enroll-vps"))).toBe(false);
  });

  test("a key whose node fails to join is revoked as well", async () => {
    const f = fixture();
    const mock = new MockTailscale();
    f.host.rejectEdgeKey = EDGE_KEY;
    const result = await setup(
      f,
      [...FULL, "--approve-tailnet-policy"],
      { TS_API_KEY: API_TOKEN },
      tsApi(mock),
    );
    expect(result.code).toBe(1);
    expect(result.text).toContain("Tailscale rejected the edge auth key");
    expect(f.host.containerKeys).toEqual([]);
    expect(f.host.configuredKeys.has("edge-ts")).toBe(false);
    expect([...mock.keys.values()].every((entry) => entry.revoked)).toBe(true);
    expect(filesWithSecrets(f.root, SECRETS)).toEqual([]);
  });

  test("--backup-node mints, uses and revokes a tag:ark-backup key and declares the tag", async () => {
    const f = fixture();
    const mock = new MockTailscale();
    const result = await setup(
      f,
      [...FULL, "--approve-tailnet-policy", "--backup-node"],
      { TS_API_KEY: API_TOKEN },
      tsApi(mock),
    );
    expect(result.code).toBe(0);
    expect((parseHujson(mock.policy) as any).tagOwners["tag:ark-backup"]).toEqual(["autogroup:admin"]);
    expect(
      [...mock.keys.values()].map((entry) => [entry.body.capabilities.devices.create.tags, entry.revoked]),
    ).toEqual([
      [["tag:ark-vps"], true],
      [["tag:ark-edge"], true],
      [["tag:ark-backup"], true],
    ]);
    expect(f.host.containerKeys).toEqual([]);
    expect(f.host.stdinEnrolments).toEqual(["edge-ts", "backup-ts"]);
    expect(f.host.configuredKeys.has("backup-ts")).toBe(false);
    expect(result.state.steps["backup-node"].status).toBe("done");
    expect(filesWithSecrets(f.root, SECRETS)).toEqual([]);
  });

  test("without a credential the manual flow is unchanged and the API is never called", async () => {
    const f = fixture();
    const mock = new MockTailscale();
    const result = await setup(f, FULL, KEYS, tsApi(mock));
    expect(result.code).toBe(0);
    expect(mock.requests).toEqual([]);
    expect(result.text).toContain("make sure the tailnet policy file has:");
    expect(result.state.steps["backup-node"].status).toBe("skipped");
    expect(result.text).not.toContain("Backup node enrolment (tag:ark-backup): skipped");
  });

  test("an explicitly supplied key wins over the API for that node", async () => {
    const f = fixture();
    const mock = new MockTailscale();
    const result = await setup(
      f,
      [...FULL, "--approve-tailnet-policy"],
      { TS_API_KEY: API_TOKEN, TS_VPS_AUTHKEY: VPS_KEY },
      tsApi(mock),
    );
    expect(result.code).toBe(0);
    expect([...mock.keys.values()].map((entry) => entry.body.capabilities.devices.create.tags)).toEqual([
      ["tag:ark-edge"],
    ]);
  });

  test("prepares policy for an enrolled VPS before the SSH gate without minting", async () => {
    const f = fixture();
    f.host.enrolled = f.host.runSsh = true;
    const mock = new MockTailscale();
    mock.timeline = f.host.calls;
    const result = await setup(
      f,
      [...BASE, "--skip-edge", "--approve-tailnet-policy"],
      { TS_API_KEY: API_TOKEN },
      tsApi(mock),
    );
    expect(result.code).toBe(2);
    expect(f.host.calls.indexOf("api POST /api/v2/tailnet/-/acl")).toBeGreaterThan(-1);
    expect(f.host.calls.indexOf("api POST /api/v2/tailnet/-/acl")).toBeLessThan(
      f.host.calls.findIndex((call) => call.includes("systemctl is-active ark-ssh-rollback.timer")),
    );
    expect(mock.keys.size).toBe(0);
  });

  test("redirected input and an approval flag do not opt into non-interactive writes", async () => {
    const f = fixture();
    const mock = new MockTailscale();
    const result = await setup(
      f,
      [...FULL.slice(1), "--approve-tailnet-policy"],
      { TS_API_KEY: API_TOKEN },
      tsApi(mock),
    );
    expect(result.code).toBe(1);
    expect(result.text).toContain("Re-run with --non-interactive and --approve-tailnet-policy");
    expect(mock.writes()).toEqual([]);
  });

  test.each([true, false])(
    "retries transient revocation failures and reports the result (eventual success: %s)",
    async (success) => {
      const f = fixture();
      const mock = new MockTailscale();
      mock.revokeStatuses.set("k2", success ? [503] : [503, 429, 504]);
      const result = await setup(
        f,
        [...FULL, "--approve-tailnet-policy"],
        { TS_API_KEY: API_TOKEN },
        tsApi(mock),
      );
      expect(result.code).toBe(0);
      expect(
        mock.requests.filter(({ method, path }) => method === "DELETE" && path.endsWith("/k2")),
      ).toHaveLength(success ? 2 : 3);
      expect(mock.keys.get("k2")?.revoked).toBe(success);
      expect(result.text.includes("Revoked the tag:ark-edge key.")).toBe(success);
      if (success) expect(result.state.steps.edge.note).toBeUndefined();
      else {
        expect(result.text).toContain("Could not revoke the tag:ark-edge key (ID k2)");
        expect(result.state.steps.edge.note).toContain("did not confirm revocation");
      }
    },
  );
});

test.skipIf(process.env.ARK_TEST_SETUP_DOCKER !== "1")(
  "Ubuntu applies the new user's live OpenSSH policy and waits for enrolled nodes",
  async () => {
    const name = `ark-setup-ssh-${crypto.randomUUID().slice(0, 12)}`;
    const directory = mkdtempSync(join(tmpdir(), `${name}-`));
    const image = `${name}:fixture`;
    const docker = async (...args: string[]) => {
      const result = await runCommand(["docker", ...args]);
      assert.equal(result.status, 0, `${args[0]}: ${result.stdout}\n${result.stderr}`);
    };
    try {
      const bundle = await Bun.build({
        entrypoints: [join(import.meta.dir, "host-hardening-test/ssh.ts")],
        target: "bun",
        outdir: directory,
        sourcemap: "inline",
      });
      assert.ok(bundle.success, bundle.logs.join("\n"));
      await docker(
        "build",
        "--quiet",
        "--target",
        "ssh",
        "-t",
        image,
        join(import.meta.dir, "host-hardening-test"),
      );
      await docker(
        "run",
        "-d",
        "--name",
        name,
        "--network",
        "none",
        "--privileged",
        "--cgroupns",
        "private",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/run/lock",
        image,
        "/sbin/init",
      );
      for (let attempt = 0; ; attempt++) {
        const ready = await runCommand([
          "docker",
          "exec",
          name,
          "systemctl",
          "show",
          "--property=SystemState",
          "--value",
        ]);
        if (ready.status === 0 && /^(?:running|degraded)\s*$/.test(ready.stdout)) break;
        assert.ok(attempt < 100, `Ubuntu systemd did not start: ${ready.stderr}`);
        await Bun.sleep(100);
      }
      await docker("exec", name, "mkdir", "/work");
      await docker("cp", join(directory, "ssh.js"), `${name}:/work/ssh.js`);
      await docker("exec", name, "bun", "/work/ssh.js", "ssh");
      await docker(
        "exec",
        "-e",
        "PATH=/work/bin:/usr/local/bin:/usr/bin:/bin",
        name,
        "bun",
        "/work/ssh.js",
        "tailscale",
      );
    } finally {
      await runCommand(["docker", "rm", "-f", name]);
      await runCommand(["docker", "image", "rm", image]);
      rmSync(directory, { recursive: true, force: true });
    }
  },
  240_000,
);

// Uses the real Tailscale image and Docker metadata, in a unique Compose project with no network,
// host mounts or published ports. The simulated API hands off dummy keys only.
for (const service of ["edge-ts", "backup-ts"]) {
  test.skipIf(process.env.ARK_TEST_SETUP_DOCKER !== "1")(
    `Docker does not persist the ${service} key during or after interrupted enrolment`,
    async () => {
      const f = fixture();
      const key = service === "edge-ts" ? EDGE_KEY : BACKUP_KEY;
      const platform = Bun.YAML.parse(
        readFileSync(join(repoRoot, "infra/platform/docker-compose.yml"), "utf8"),
      ) as {
        services: Record<
          string,
          { image: string; hostname: string; entrypoint: string[]; environment: Record<string, string> }
        >;
      };
      const { image, hostname, entrypoint, environment } = platform.services[service]!;
      const file = join(f.root, "offline-compose.json");
      writeFileSync(
        file,
        JSON.stringify({
          services: {
            [service]: {
              image,
              hostname,
              entrypoint,
              environment: { ...environment, TS_USERSPACE: "true" },
              network_mode: "none",
            },
          },
        }),
      );
      const prefix = [
        "docker",
        "compose",
        "-p",
        `ark-setup-${crypto.randomUUID()}`,
        "--env-file",
        f.host.envPath,
        "-f",
        file,
      ];
      const runDocker = (argv: string[], options?: RunOptions) =>
        runCommand(argv, {
          cwd: f.root,
          env: { ...withoutSetupSecrets(process.env), ...options?.env, PATH: process.env.PATH },
          timeoutMs: 10_000,
        });
      let inspected = false;
      const run: SetupDependencies["run"] = async (argv, options) => {
        // Nothing created the real container yet, whatever the simulated install did.
        if (argv[1] === "ps" && argv.some((arg) => arg.endsWith(`.service=${service}`))) return ok();
        if (argv[0] !== "docker" || !argv.includes(service)) return f.host.run(argv, options);
        const args = argv.slice(argv.indexOf("infra/platform/docker-compose.yml") + 1);
        if (args[0] === "up") return runDocker([...prefix, "up", "-d", service], options);
        if (args[0] !== "exec") return f.host.run(argv, options);
        if (!options?.stdin) return runDocker([...prefix, ...args], options);

        const idResult = await runDocker([...prefix, "ps", "-q", service]);
        const id = idResult.stdout.trim();
        assert.equal(idResult.status, 0, idResult.stderr);
        expect(id).not.toBe("");
        const assertNoKey = async () => {
          const config = await runDocker(["docker", "inspect", "--format", "{{json .Config.Env}}", id]);
          assert.equal(config.status, 0, config.stderr);
          expect(JSON.parse(config.stdout)).toContain("TS_AUTHKEY=");
          expect(config.stdout).not.toContain(key);
        };
        const cli = Bun.spawn([...prefix, ...args], {
          env: { ...withoutSetupSecrets(process.env), ...options.env, PATH: process.env.PATH },
          stdin: "pipe",
          stdout: "ignore",
          stderr: "ignore",
        });
        try {
          // Leave stdin open while the in-container CLI is reading the key.
          cli.stdin.write(options.stdin);
          await cli.stdin.flush();
          let execRunning = false;
          for (let attempt = 0; attempt < 20; attempt++) {
            const top = await runDocker(["docker", "top", id, "-eo", "pid,args"]);
            assert.equal(top.status, 0, top.stderr);
            expect(top.stdout).not.toContain(key);
            if (
              top.stdout
                .split("\n")
                .some((line) => /^\s*\d+\s+(?:\S*\/)?tailscale .*--auth-key=file:\/dev\/stdin/.test(line))
            ) {
              execRunning = true;
              break;
            }
            await Bun.sleep(100);
          }
          expect(execRunning).toBe(true);
          await assertNoKey();
        } finally {
          cli.kill("SIGKILL");
          await cli.exited;
        }
        await assertNoKey();
        inspected = true;
        return fail("test interrupted the enrolment subprocess");
      };
      try {
        const mock = new MockTailscale();
        const result = await setup(
          f,
          [...FULL, "--approve-tailnet-policy", "--backup-node"],
          { TS_API_KEY: API_TOKEN },
          { ...tsApi(mock), run },
        );
        expect(result.code).toBe(1);
        expect(result.text).toContain("test interrupted the enrolment subprocess");
        expect(inspected).toBe(true);
        expect([...mock.keys.values()].every(({ revoked }) => revoked)).toBe(true);
        expect(filesWithSecrets(f.root, [key])).toEqual([]);
      } finally {
        const removed = await runDocker([...prefix, "down", "--volumes"]);
        expect(removed.status).toBe(0);
        rmSync(f.root, { recursive: true, force: true });
      }
    },
    30_000,
  );
}

// Enrols, restarts and recreates the shipped services against a local coordination server on an
// internal network (no internet, so no real tailnet), with every container and volume removed after.
const HEADSCALE =
  "headscale/headscale:0.26.1@sha256:ea9b5ee06274d757a4d52103de56cd11a9c393acb19d9a35f4b9fe52ada410de";
for (const service of ["edge-ts", "backup-ts"]) {
  test.skipIf(process.env.ARK_TEST_SETUP_DOCKER !== "1")(
    `${service} waits for login, then keeps its identity and name through restarts and recreations`,
    async () => {
      const directory = mkdtempSync(join(tmpdir(), "ark-setup-ts-"));
      const tag = service === "edge-ts" ? "tag:ark-edge" : "tag:ark-backup";
      const variable = service === "edge-ts" ? "TS_EDGE" : "TS_BACKUP";
      const platform = Bun.YAML.parse(
        readFileSync(join(repoRoot, "infra/platform/docker-compose.yml"), "utf8"),
      ) as {
        services: Record<string, { image: string; volumes: string[]; environment: Record<string, string> }>;
      };
      const shipped = platform.services[service]!;
      const login = "--login-server=https://hs";
      const gate = join(directory, "gate");
      mkdirSync(gate);
      mkdirSync(join(directory, "hs"));
      const certificate = await runCommand([
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=hs",
        "-addext",
        "subjectAltName=DNS:hs",
        "-keyout",
        join(directory, "hs", "server.key"),
        "-out",
        join(gate, "ca.pem"),
      ]);
      assert.equal(certificate.status, 0, certificate.stderr);
      copyFileSync(join(gate, "ca.pem"), join(directory, "hs", "server.pem"));
      writeFileSync(
        join(gate, "tailscale"),
        `#!/bin/sh
if [ "$2" = up ] && [ -e /tmp/hold-up ]; then
  touch /tmp/up-waiting
  while [ -e /tmp/hold-up ]; do sleep 0.1; done
fi
exec /usr/local/bin/tailscale "$@"
`,
        { mode: 0o755 },
      );
      writeFileSync(join(gate, "reply"), "#!/bin/sh\nprintf 'fixture-reachable\\n'\n", { mode: 0o755 });
      const definition = {
        ...shipped,
        ports: [],
        networks: ["test"],
        volumes: [...shipped.volumes, `${gate}:/gate:ro`],
        environment: {
          ...shipped.environment,
          PATH: "/gate:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          SSL_CERT_FILE: "/gate/ca.pem",
          TS_EXTRA_ARGS: `${shipped.environment.TS_EXTRA_ARGS} ${login}`,
        },
      };
      // What Compose created before #72: no TS_HOSTNAME, no --reset and the image's own entrypoint.
      const { TS_HOSTNAME: _name, ...earlier } = shipped.environment;
      const before72 = {
        ...definition,
        entrypoint: ["/usr/local/bin/containerboot"],
        environment: { ...earlier, SSL_CERT_FILE: "/gate/ca.pem", TS_EXTRA_ARGS: `--shields-up ${login}` },
      };
      writeFileSync(
        join(directory, "hs", "config.yaml"),
        JSON.stringify({
          server_url: "https://hs",
          listen_addr: "0.0.0.0:443",
          tls_cert_path: "/etc/headscale/server.pem",
          tls_key_path: "/etc/headscale/server.key",
          metrics_listen_addr: "127.0.0.1:9090",
          grpc_listen_addr: "127.0.0.1:50443",
          noise: { private_key_path: "/var/lib/headscale/noise.key" },
          prefixes: { v4: "100.64.0.0/10", v6: "fd7a:115c:a1e0::/48", allocation: "sequential" },
          derp: {
            server: {
              enabled: true,
              region_id: 999,
              region_code: "test",
              region_name: "test",
              stun_listen_addr: "0.0.0.0:3478",
              private_key_path: "/var/lib/headscale/derp.key",
              automatically_add_embedded_derp_region: true,
            },
            urls: [],
            paths: [],
            auto_update_enabled: false,
          },
          disable_check_updates: true,
          database: { type: "sqlite", sqlite: { path: "/var/lib/headscale/db.sqlite" } },
          dns: { magic_dns: false, base_domain: "example.test", override_local_dns: false },
          unix_socket: "/var/run/headscale/headscale.sock",
        }),
      );
      const sleeper = { image: shipped.image, entrypoint: ["sleep", "3600"] };
      const subnet = `10.231.${crypto.getRandomValues(new Uint8Array(1))[0]}.0/24`;
      const write = (name: string, node: object, revision = "old") => {
        const path = join(directory, name);
        writeFileSync(
          path,
          JSON.stringify({
            services: {
              [service]: node,
              peer: {
                image: shipped.image,
                networks: ["test"],
                volumes: [`${gate}:/gate:ro`],
                environment: {
                  SSL_CERT_FILE: "/gate/ca.pem",
                  TS_STATE_DIR: "/tmp/peer-state",
                  TS_AUTHKEY: "${FIXTURE_PEER_KEY:-}",
                  TS_EXTRA_ARGS: `--shields-up ${login}`,
                },
              },
              ...(service === "edge-ts"
                ? {
                    postgres: { ...sleeper, environment: { FIXTURE_REVISION: revision } },
                    api: { ...sleeper, depends_on: ["postgres"] },
                    edge: { ...sleeper, network_mode: "service:edge-ts", depends_on: ["edge-ts", "api"] },
                    "edge-l4": { ...sleeper, network_mode: "service:edge-ts" },
                  }
                : {}),
              hs: {
                image: HEADSCALE,
                command: "serve",
                networks: ["test"],
                volumes: [`${join(directory, "hs")}:/etc/headscale:ro`, "hs:/var/lib/headscale"],
              },
            },
            networks: { test: { internal: true, ipam: { config: [{ subnet }] } } },
            volumes: Object.fromEntries(
              ["hs", ...shipped.volumes.map((volume) => volume.split(":")[0]!)].map((volume) => [volume, {}]),
            ),
          }),
        );
        return path;
      };
      const files = {
        shipped: write("shipped.json", definition),
        old: write("old.json", before72),
        changedDependency: write("diverged.json", definition, "new"),
      };
      const project = `ark-setup-${crypto.randomUUID()}`;
      const compose = (file: string, args: string[], options: RunOptions = {}) =>
        runCommand(["docker", "compose", "-p", project, "-f", file, ...args], {
          env: {
            ...withoutSetupSecrets(process.env),
            [`${variable}_AUTHKEY`]: "",
            [`${variable}_HOSTNAME`]: "kept-name",
            PATH: process.env.PATH,
            ...options.env,
          },
          stdin: options.stdin,
          timeoutMs: 100_000,
        });
      const must = async (file: string, args: string[], options?: RunOptions) => {
        const result = await compose(file, args, options);
        assert.equal(result.status, 0, `${args.join(" ")}: ${result.stderr}`);
        return result.stdout;
      };
      const docker = async (...args: string[]) => {
        const result = await runCommand(["docker", ...args], { env: process.env, timeoutMs: 60_000 });
        assert.equal(result.status, 0, result.stderr);
        return result.stdout.trim();
      };
      const container = async (name = service) => (await must(files.shipped, ["ps", "-aq", name])).trim();
      const until = async <T>(read: () => Promise<T | undefined>) => {
        for (let attempt = 0; attempt < 60; attempt++) {
          const value = await read();
          if (value !== undefined) return value;
          await Bun.sleep(500);
        }
        throw new Error("timed out");
      };
      const self = () =>
        until(async () => {
          const result = await compose(files.shipped, [
            "exec",
            "-T",
            service,
            "tailscale",
            "status",
            "--json",
          ]);
          try {
            const status = JSON.parse(result.stdout);
            return status.BackendState === "Running"
              ? {
                  id: status.Self.ID,
                  key: status.Self.PublicKey,
                  name: status.Self.HostName,
                  tags: status.Self.Tags,
                }
              : undefined;
          } catch {
            return undefined;
          }
        });
      const prefs = async () =>
        JSON.parse(await must(files.shipped, ["exec", "-T", service, "tailscale", "debug", "prefs"]));
      const readState = async () => {
        const id = await container();
        const image = await docker("inspect", "--format", "{{.Image}}", id);
        return runCommand([
          "docker",
          "run",
          "--rm",
          "--network=none",
          "--read-only",
          "--cap-drop=ALL",
          `--volumes-from=${id}:ro`,
          "--entrypoint=/bin/sh",
          image,
          "-c",
          READ_IDENTITY,
        ]);
      };
      const identity = async () => parseStoredIdentity(await readState());
      const local = (...args: string[]) => must(files.shipped, ["exec", "-T", service, ...args]);
      const freshKey = async (...tags: string[]) =>
        JSON.parse(
          await must(files.shipped, [
            "exec",
            "-T",
            "hs",
            "headscale",
            "preauthkeys",
            "create",
            "-u",
            "1",
            ...tags,
            "-o",
            "json",
          ]),
        ).key as string;
      const containerStamp = async (id: string) =>
        docker("inspect", "--format", "{{.Id}} {{.State.Status}} {{.State.StartedAt}}", id);
      try {
        await must(files.shipped, ["up", "-d", "hs", service]);
        // Without a key or an identity tailscaled runs alone, so containerboot's 60 s deadline is not armed.
        expect(
          await until(async () => {
            const value = await prefs().catch(() => undefined);
            return value?.ShieldsUp ? value : undefined;
          }),
        ).toMatchObject({ ShieldsUp: true, CorpDNS: false, WantRunning: false });
        expect(await must(files.shipped, ["exec", "-T", service, "cat", "/proc/1/comm"])).toBe(
          "tailscaled\n",
        );
        expect(await identity()).toBe("none");
        await must(files.shipped, ["stop", service]);
        expect(await docker("inspect", "--format", "{{.State.ExitCode}}", await container())).toBe("0");
        await must(files.shipped, ["start", service]);
        expect(await local("cat", "/proc/1/comm")).toBe("tailscaled\n");

        await until(async () =>
          (await compose(files.shipped, ["exec", "-T", "hs", "headscale", "users", "create", "owner"]))
            .status === 0
            ? true
            : undefined,
        );
        const key = await freshKey("--tags", tag);
        if (service === "edge-ts") {
          await must(
            files.shipped,
            [
              "exec",
              "-T",
              service,
              "sh",
              "-c",
              ENROL_CONTAINER.replace("--shields-up", `--shields-up ${login}`),
              "sh",
              "/var/run/tailscale/tailscaled.sock",
              "kept-name",
            ],
            { stdin: key },
          );
        } else {
          await must(files.shipped, ["up", "-d", service], { env: { TS_BACKUP_AUTHKEY: key } });
          await self();
          expect(await local("cat", "/proc/1/comm")).toBe("containerboot\n");
          await must(files.shipped, ["up", "-d", service]);
        }
        const enrolled = await self();
        expect(enrolled).toMatchObject({ name: "kept-name", tags: [tag] });
        expect(await identity()).toEqual({ hostName: "kept-name", nodeId: enrolled.id });

        await must(files.shipped, ["restart", service]);
        expect(await self()).toEqual(enrolled);
        await must(files.shipped, ["up", "-d", "--force-recreate", service]);
        expect(await self()).toEqual(enrolled);
        // A preference nobody passes as a flag must not stop the next start.
        await must(files.shipped, ["exec", "-T", service, "tailscale", "set", "--accept-routes"]);
        await must(files.shipped, ["restart", service]);
        expect(await self()).toEqual(enrolled);
        expect(await prefs()).toMatchObject({ RouteAll: false, ShieldsUp: true, Hostname: "kept-name" });

        // Exercise inbound TCP with a reachable peer as the positive control. Hold containerboot's
        // CLI call so we can observe the daemon after startup but before any LocalAPI write.
        await must(files.shipped, ["up", "-d", "peer"], { env: { FIXTURE_PEER_KEY: await freshKey() } });
        await until(async () => {
          const result = await compose(files.shipped, ["exec", "-T", "peer", "tailscale", "ip", "-4"]);
          return result.status === 0 && result.stdout.trim() ? true : undefined;
        });
        const address = (await local("tailscale", "ip", "-4")).trim();
        const listen = () =>
          must(files.shipped, ["exec", "-d", service, "nc", "-lk", "-p", "18888", "-e", "/gate/reply"]);
        const probe = async () =>
          (
            await compose(files.shipped, [
              "exec",
              "-T",
              "peer",
              "timeout",
              "3",
              "sh",
              "-c",
              'sleep 3 | tailscale nc "$1" 18888',
              "sh",
              address,
            ])
          ).stdout.includes("fixture-reachable");
        await local("tailscale", "set", "--shields-up=false", "--accept-routes");
        await listen();
        await until(async () => ((await probe()) ? true : undefined));

        const assertStartupShielded = async () => {
          await until(async () =>
            (await compose(files.shipped, ["exec", "-T", service, "test", "-f", "/tmp/up-waiting"]))
              .status === 0
              ? true
              : undefined,
          );
          expect(await prefs()).toMatchObject({ ShieldsUp: true, WantRunning: false });
          await listen();
          expect(await probe()).toBe(false);
          await local("rm", "/tmp/hold-up", "/tmp/up-waiting");
          expect(await self()).toEqual(enrolled);
          expect(await prefs()).toMatchObject({ ShieldsUp: true, WantRunning: true, RouteAll: false });
          expect(await probe()).toBe(false);
        };
        await local("touch", "/tmp/hold-up");
        await must(files.shipped, ["restart", service]);
        await assertStartupShielded();

        // Seed the pinned client's legacy store from its own enrolled preferences, with no
        // current-profile pointer. Migration must happen under the same startup restriction.
        const state = JSON.parse((await readState()).stdout) as Record<string, string>;
        const active = Buffer.from(state["_current-profile"]!, "base64").toString();
        const legacyPrefs = JSON.parse(Buffer.from(state[active]!, "base64").toString());
        legacyPrefs.ShieldsUp = false;
        legacyPrefs.WantRunning = true;
        const legacy = JSON.stringify({
          _machinekey: state["_machinekey"],
          _daemon: encodeState(JSON.stringify(legacyPrefs)),
        });
        await local("touch", "/tmp/hold-up");
        await must(files.shipped, ["stop", service]);
        expect(await docker("inspect", "--format", "{{.State.ExitCode}}", await container())).toBe("0");
        const seed = await runCommand(
          [
            "docker",
            "run",
            "--rm",
            "-i",
            "--network=none",
            "--cap-drop=ALL",
            `--volumes-from=${await container()}`,
            "--entrypoint=sh",
            shipped.image,
            "-c",
            "cat >/var/lib/tailscale/tailscaled.state",
          ],
          { stdin: legacy },
        );
        expect(seed.status).toBe(0);
        expect(await identity()).toEqual({ hostName: "kept-name", nodeId: enrolled.id });
        await must(files.shipped, ["start", service]);
        await assertStartupShielded();

        // The reported failure: a container that does not pass the stored hostname exits on every start.
        await must(files.old, ["up", "-d", service]);
        const looping = await container();
        await until(async () =>
          (await docker("inspect", "--format", "{{.State.Status}}", looping)) === "restarting"
            ? true
            : undefined,
        );
        const logs = await runCommand(["docker", "logs", looping], { env: process.env });
        expect(logs.stdout + logs.stderr).toContain("requires mentioning all");
        expect(await identity()).toEqual({ hostName: "kept-name", nodeId: enrolled.id });
        // The recovery: recreate it from the shipped definition with the stored name and no key.
        if (service === "edge-ts") {
          await must(files.shipped, ["up", "-d", "--no-deps", "api", "postgres"]);
          await must(files.shipped, ["stop", "api"]);
          const dependencies = await Promise.all(
            ["api", "postgres"].map(async (name) => containerStamp(await container(name))),
          );
          await must(files.changedDependency, [
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            service,
            "edge",
            "edge-l4",
          ]);
          expect(
            await Promise.all(["api", "postgres"].map(async (name) => containerStamp(await container(name)))),
          ).toEqual(dependencies);
          for (const proxy of ["edge", "edge-l4"])
            expect(
              await docker("inspect", "--format", "{{.HostConfig.NetworkMode}}", await container(proxy)),
            ).toBe(`container:${await container()}`);
        } else await must(files.shipped, ["up", "-d", "--force-recreate", "--no-deps", service]);
        expect(await self()).toEqual(enrolled);
      } finally {
        const removed = await compose(files.shipped, ["down", "--volumes", "--remove-orphans"]);
        expect(removed.status).toBe(0);
        rmSync(directory, { recursive: true, force: true });
      }
    },
    240_000,
  );
}

describe("Tailscale API key source", () => {
  const quietUi = (answers: [string, string][] = [], secrets: [string, string][] = []) =>
    new ScriptedUi(true, answers, secrets);
  const gate = (ui: Ui, interactive = false, acceptBroadTailnetPolicy = !interactive) =>
    policyGate({
      ui,
      interactive,
      options: { nonInteractive: !interactive, acceptBroadTailnetPolicy, tailnetPolicyReviewed: false },
      state: { version: 1, answers: {}, steps: {} },
      save: () => {},
      redact: (text) => text,
      resumeCommand: "host:setup",
    });
  const api = (mock: MockTailscale, credential = credentialFromEnv({ TS_API_KEY: API_TOKEN })!) => {
    const seen: string[] = [];
    return {
      seen,
      api: new TailscaleApi(credential, {
        base: mock.url,
        secret: (value) => seen.push(value),
        log: () => {},
      }),
      credential,
    };
  };

  test("interactive: shows the diff and honours a refusal even with approval preset", async () => {
    const mock = new MockTailscale();
    const ui = quietUi([
      ["Type accept to continue", "accept"],
      ["Apply this change to the tailnet policy", "no"],
    ]);
    const { api: client, credential } = api(mock);
    const source = apiKeySource(client, credential, {
      ui,
      gate: gate(ui, true),
      interactive: true,
      approve: true,
      backup: false,
    });
    await expect(
      source.acquire({ tag: "tag:ark-vps", variable: "TS_VPS_AUTHKEY", optional: false }),
    ).rejects.toThrow("declined");
    expect(ui.output.join("\n")).toContain("Proposed tailnet policy change");
    expect(mock.writes()).toEqual([]);
  });

  test("an unchanged policy is neither validated nor rewritten", async () => {
    const mock = new MockTailscale();
    mock.policy = mergeArkPolicy(NARROWED_POLICY, {
      tags: ["tag:ark-vps", "tag:ark-edge"],
      owners: ["autogroup:admin"],
    }).text;
    const ui = quietUi();
    const { api: client, credential } = api(mock);
    const source = apiKeySource(client, credential, {
      ui,
      gate: gate(ui, true),
      interactive: true,
      approve: false,
      backup: false,
    });
    await source.preparePolicy!();
    expect(ui.output.join("\n")).toContain("already has the Ark tag owners");
    expect(mock.requests.map((request) => request.method + " " + request.path)).toEqual([
      "GET /api/v2/tailnet/-/acl",
    ]);
  });

  test("a policy edited elsewhere meanwhile (If-Match mismatch) is not overwritten", async () => {
    const mock = new MockTailscale();
    mock.raceOnRead = true;
    const { api: client, credential } = api(mock);
    const source = apiKeySource(client, credential, {
      ui: quietUi(),
      gate: gate(quietUi()),
      interactive: false,
      approve: true,
      backup: false,
    });
    await expect(source.preparePolicy!()).rejects.toThrow("changed while setup was showing it");
    expect(mock.policy).toContain("edited elsewhere");
    expect(mock.policy).not.toContain("tag:ark-vps");
  });

  test("a policy Tailscale rejects is not applied", async () => {
    const mock = new MockTailscale();
    mock.validateProblem = "test(s) failed";
    const { api: client, credential } = api(mock);
    const source = apiKeySource(client, credential, {
      ui: quietUi(),
      gate: gate(quietUi()),
      interactive: false,
      approve: true,
      backup: false,
    });
    await expect(source.preparePolicy!()).rejects.toThrow("Tailscale rejected the merged policy");
    expect(mock.writes()).toEqual([]);
  });

  test("an OAuth client exchanges its secret, owns the Ark tags through its tag and mints with the token", async () => {
    const mock = new MockTailscale();
    mock.policy = '{"tagOwners":{"tag:ark-setup":["autogroup:admin"]}}';
    const credential = credentialFromEnv({ TS_OAUTH_CLIENT_SECRET: OAUTH_SECRET })!;
    expect(credential).toMatchObject({ kind: "oauth", clientId: "kOAU5678CNTRL", tag: "tag:ark-setup" });
    const { api: client, seen } = api(mock, credential);
    const source = apiKeySource(client, credential, {
      ui: quietUi(),
      gate: gate(quietUi()),
      interactive: false,
      approve: true,
      backup: false,
    });
    const key = await source.acquire({ tag: "tag:ark-edge", variable: "TS_EDGE_AUTHKEY", optional: true });
    expect(key).toMatchObject({ key: EDGE_KEY, inMemoryOnly: true });
    const policy = parseHujson(mock.policy) as any;
    expect(policy.tagOwners).toEqual({
      "tag:ark-setup": ["autogroup:admin"],
      "tag:ark-vps": ["autogroup:admin", "tag:ark-setup"],
      "tag:ark-edge": ["autogroup:admin", "tag:ark-setup"],
    });
    expect(
      mock.requests.filter((request) => request.path.startsWith("/api/v2/tailnet")).map((r) => r.auth),
    ).toEqual(expect.arrayContaining([`Bearer ${OAUTH_ACCESS}`]));
    expect(mock.requests.some((request) => request.auth.includes(OAUTH_SECRET))).toBe(false);
    expect(seen).toEqual(expect.arrayContaining([OAUTH_SECRET, OAUTH_ACCESS, EDGE_KEY]));
    await key!.release!();
    expect(mock.keys.get("k1")!.revoked).toBe(true);
    expect(mock.keys.get("k1")!.body.expirySeconds).toBe(KEY_EXPIRY_SECONDS);
  });

  test.each(["devices:posture_attributes", "devices:core:read"])(
    "rejects OAuth without %s with scope guidance",
    async (scope) => {
      const mock = new MockTailscale();
      mock.oauthScopes = mock.oauthScopes.filter((allowed) => allowed !== scope);
      const credential = credentialFromEnv({ TS_OAUTH_CLIENT_SECRET: OAUTH_SECRET })!;
      const { api: client } = api(mock, credential);
      const source = apiKeySource(client, credential, {
        ui: quietUi(),
        gate: gate(quietUi()),
        interactive: false,
        approve: true,
        backup: false,
      });
      await expect(source.preparePolicy!()).rejects.toThrow(scope);
      expect(mock.requests).toHaveLength(1);
      expect(mock.keys.size).toBe(0);
    },
  );

  test("the automatic source asks once for a credential and falls back to the manual steps on Enter", async () => {
    const ui = quietUi(
      [["policy is saved", "yes"]],
      [
        ["Tailscale API access token", ""],
        ["tag:ark-edge key", EDGE_KEY],
      ],
    );
    const source = automaticKeySource({
      env: {},
      ui,
      gate: gate(ui, true),
      interactive: true,
      approve: false,
      backup: false,
      secret: () => {},
      log: () => {},
    });
    await source.preparePolicy!();
    expect(ui.output.join("\n")).toContain("make sure the tailnet policy file has:");
    expect(
      await source.acquire({ tag: "tag:ark-edge", variable: "TS_EDGE_AUTHKEY", optional: true }),
    ).toEqual({
      key: EDGE_KEY,
    });
  });

  test("rejects malformed credentials", () => {
    expect(() => credentialFromEnv({ TS_API_KEY: "nope" })).toThrow("tskey-api-");
    expect(() => credentialFromEnv({ TS_OAUTH_CLIENT_SECRET: "nope" })).toThrow("tskey-client-");
    expect(() => credentialFromEnv({ TS_API_KEY: API_TOKEN, TS_OAUTH_CLIENT_SECRET: OAUTH_SECRET })).toThrow(
      "only one",
    );
    expect(credentialFromEnv({})).toBeUndefined();
  });
});

describe("tailnet policy merge", () => {
  /** Every added line is where its `@@ line` says it is. */
  function expectInsertedOnly(before: string, merged: ReturnType<typeof mergeArkPolicy>) {
    const after = merged.text.split("\n");
    let at = 0;
    let added = 0;
    for (const line of merged.inserted) {
      const header = /^@@ line (\d+)$/.exec(line);
      if (header) at = Number(header[1]);
      else {
        expect(after[at++ - 1]).toBe(line.slice(2));
        added++;
      }
    }
    expect(after.length - before.split("\n").length).toBe(added);
  }

  const request = { tags: ["tag:ark-vps", "tag:ark-edge"], owners: ["autogroup:admin"] };
  const grant = { src: ["autogroup:owner"], dst: ["tag:ark-vps"], ip: ["tcp:22"] };
  const acceptRule = { action: "accept", src: grant.src, dst: grant.dst, users: ["autogroup:nonroot"] };

  test("generates an owner-only check with the provider default period and preserves existing accept rules", () => {
    const merged = mergeArkPolicy(JSON.stringify({ grants: [grant], ssh: [acceptRule] }), request);
    const policy = parseHujson(merged.text) as { grants: unknown[]; ssh: unknown[] };
    expect(policy.grants).toEqual([grant]);
    expect(policy.ssh).toEqual([acceptRule, { ...acceptRule, action: "check" }]);
    expect(merged.text).not.toContain("checkPeriod");
    expect(mergeArkPolicy(merged.text, request).changed).toBe(false);
  });

  test.each([
    { grants: [{ ...grant, srcPosture: ["posture:managed"] }] },
    { ssh: [{ ...acceptRule, action: "check", srcPosture: ["posture:managed"] }] },
    { defaultSrcPosture: ["posture:managed"] },
  ])("refuses to bypass a posture constraint on the owner path (%j)", (policy) => {
    expect(() => mergeArkPolicy(JSON.stringify(policy), request)).toThrow(
      "manual setup flow with a compliant device",
    );
  });

  test("adds only the Ark entries, keeps comments and is idempotent", () => {
    const merged = mergeArkPolicy(DEFAULT_POLICY, request);
    expect(merged.changed).toBe(true);
    expect(merged.additions).toHaveLength(4);
    expect(merged.inserted.some((line) => line.startsWith('+ \t\t{ "src": ["autogroup:owner"]'))).toBe(true);
    expectInsertedOnly(DEFAULT_POLICY, merged);
    const again = mergeArkPolicy(merged.text, request);
    expect(again).toMatchObject({ changed: false, additions: [] });
    expect(again.text).toBe(merged.text);
  });

  test("keeps an existing tag entry, adds a missing one inline and handles one-line containers", () => {
    const text = `{"tagOwners": {"tag:ark-vps": ["group:ops"], /* keep */ "tag:other": ["autogroup:admin"]}, "grants": [], "ssh": []}`;
    const merged = mergeArkPolicy(text, request);
    const policy = parseHujson(merged.text) as any;
    expect(policy.tagOwners).toEqual({
      "tag:ark-vps": ["group:ops"],
      "tag:other": ["autogroup:admin"],
      "tag:ark-edge": ["autogroup:admin"],
    });
    expect(merged.text).toContain("/* keep */");
    expect(policy.grants).toHaveLength(1);
    expect(policy.ssh).toHaveLength(1);
  });

  test("an empty policy and a policy without the sections get them", () => {
    for (const text of ["", "{\n  // nothing yet\n}\n"]) {
      const policy = parseHujson(mergeArkPolicy(text, request).text) as any;
      expect(Object.keys(policy.tagOwners)).toEqual(["tag:ark-vps", "tag:ark-edge"]);
      expect(policy.grants).toHaveLength(1);
    }
  });

  test("a very large policy still gets a short list of added lines", () => {
    const hosts = Array.from(
      { length: 3000 },
      (_, index) => `    "host-${index}": "100.64.${index >> 8}.${index & 255}",`,
    );
    const text = `{\n  "grants": [\n    { "src": ["group:ops"], "dst": ["host-1"], "ip": ["tcp:443"] },\n  ],\n  "hosts": {\n${hosts.join("\n")}\n  },\n}\n`;
    const merged = mergeArkPolicy(text, request);
    expect(merged.inserted.filter((line) => line.startsWith("+ ")).length).toBeGreaterThan(5);
    expect(merged.inserted.length).toBeLessThan(40);
    expectInsertedOnly(text, merged);
  });

  test("the added lines never repeat the owner's own content, whatever the policy's layout", () => {
    for (const text of [
      '{"tagOwners": {"tag:ark-vps": ["group:private"]}, "grants": [{"src": ["group:private"], "dst": ["tag:private"], "ip": ["*"]}], "ssh": []}',
      '{\n  "grants": [\n    {"src": ["group:private"], "dst": ["tag:private"], "ip": ["*"]} // private\n  ],\n  "hosts": {"private": "100.64.0.9"}\n}\n',
    ]) {
      const merged = mergeArkPolicy(text, { ...request, requiredOwner: "tag:ark-setup" });
      expect(merged.changed).toBe(true);
      expect(merged.inserted.join("\n")).not.toContain("private");
      expect(merged.inserted.join("\n")).toContain("tag:ark-setup");
    }
  });

  test("refuses a policy it cannot merge safely", () => {
    expect(() => mergeArkPolicy("[]", request)).toThrow("not a JSON object");
    expect(() => mergeArkPolicy('{"grants": {}}', request)).toThrow('"grants" is not a list');
    expect(() => mergeArkPolicy('{"grants": [', request)).toThrow("not valid HuJSON");
  });
});

describe("catch-all tailnet policy detection", () => {
  const all = ["tag:ark-edge", "tag:ark-vps", "tag:ark-backup"];
  const grant = (src: string[], dst: string[], ip: string[] = ["*"]) => ({ grants: [{ src, dst, ip }] });
  const acl = (src: string[], dst: string[]) => ({ acls: [{ action: "accept", src, dst }] });

  test.each([
    ["the default grant", grant(["*"], ["*"]), all],
    ["one port only", grant(["*"], ["*"], ["tcp:22"]), all],
    ["among other selectors", grant(["group:ops", "*"], ["tag:db", "*"]), all],
    [
      "a conditional rule",
      { grants: [{ src: ["*"], dst: ["*"], ip: ["*"], srcPosture: ["posture:x"] }] },
      all,
    ],
    ["an accept ACL", acl(["*"], ["*:*"]), all],
    ["an accept ACL on one port", acl(["*"], ["*:443"]), all],
    ["old-style ACL fields", { ACLs: [{ Action: "accept", Users: ["*"], Ports: ["*:*"] }] }, all],
    ["every tagged machine", grant(["autogroup:tagged"], ["*"]), all],
    ["everyone", grant(["autogroup:danger-all"], ["*"]), all],
    ["the edge tag", grant(["tag:ark-edge"], ["*"]), ["tag:ark-edge"]],
    ["the host tag in an ACL", acl(["tag:ark-vps"], ["*:22"]), ["tag:ark-vps"]],
    ["the backup tag", grant(["tag:ark-backup", "group:ops"], ["*"]), ["tag:ark-backup"]],
    ["the tailnet's IPv4 range", grant(["100.64.0.0/10"], ["*"]), all],
    ["every IPv4 address", grant(["0.0.0.0/0"], ["0.0.0.0/0"]), all],
    ["two halves of the range", grant(["100.64.0.0/11", "100.96.0.0/11"], ["*"]), all],
    ["an address range", grant(["100.64.0.0-100.127.255.255"], ["*"]), all],
    ["the tailnet's IPv6 range", grant(["fd7a:115c:a1e0::/48"], ["::/0"]), all],
    ["an IPv6 ACL destination", acl(["*"], ["fd7a:115c:a1e0::/48:*"]), all],
    ["a bracketed ACL destination", acl(["*"], ["[::/0]:443"]), all],
    ["a range ACL destination", acl(["tag:ark-edge"], ["100.64.0.0/10:*"]), ["tag:ark-edge"]],
    ["every member and tagged device", grant(["*"], ["autogroup:member", "autogroup:tagged"]), all],
    [
      "a host alias of a range",
      { hosts: { everything: "100.64.0.0/10" }, ...grant(["*"], ["everything"]) },
      all,
    ],
  ] as [string, unknown, string[]][])("finds %s", (_name, policy, tags) => {
    expect(catchAllRules(policy).map((rule) => rule.tags as string[])).toEqual([tags]);
  });

  test.each([
    ["members", grant(["autogroup:member"], ["*"])],
    ["a member ACL", acl(["autogroup:member"], ["*:*"])],
    ["a group", grant(["group:ops", "alice@example.com"], ["*"])],
    ["another tag", grant(["tag:ci"], ["*"])],
    ["part of the range as source", grant(["100.64.0.0/11"], ["*"])],
    ["part of the range as destination", grant(["*"], ["100.64.0.0/11"])],
    ["a single device", grant(["*"], ["100.64.0.5"])],
    ["tagged devices only", grant(["*"], ["autogroup:tagged"])],
    ["exit nodes", grant(["*"], ["autogroup:internet"])],
    ["own devices", grant(["*"], ["autogroup:self"])],
    ["a non-accept ACL", { acls: [{ action: "deny", src: ["*"], dst: ["*:*"] }] }],
    [
      "capabilities without network access",
      { grants: [{ src: ["*"], dst: ["*"], app: { "example.com/cap": [{}] } }] },
    ],
    ["malformed content", { grants: [null, "x", { src: "y" }], acls: {} }],
    ["no rules", {}],
  ] as [string, unknown][])("ignores %s", (_name, policy) => {
    expect(catchAllRules(policy)).toEqual([]);
  });

  test("ignores everything Ark itself generates", () => {
    const merged = mergeArkPolicy("", { tags: ["tag:ark-vps", "tag:ark-edge"], owners: ["autogroup:admin"] });
    expect(catchAllRules(parseHujson(merged.text))).toEqual([]);
    const snippet = generateTailnetAcl({
      routes: [
        {
          id: "r1",
          kind: "http",
          hostname: "app.example.com",
          listenPort: 443,
          targetIp: "100.64.0.9",
          targetPort: 8080,
          targetNodeStableId: "nApp",
        },
      ],
      backupTargets: [{ id: "b1", name: "home", ip: "100.64.0.10", port: 8000 }],
    });
    expect(snippet.policy.grants).toHaveLength(2);
    expect(catchAllRules(snippet.policy)).toEqual([]);
  });

  test("suggests a narrower source and hides capability parameters", () => {
    const suggest = (policy: unknown) => catchAllRules(policy)[0]!.replacement;
    expect(suggest(grant(["*"], ["*"]))).toBe('{"src": ["autogroup:member"], "dst": ["*"], "ip": ["*"]}');
    expect(suggest(acl(["*", "tag:ark-edge", "tag:ci"], ["*:22"]))).toBe(
      '{"action": "accept", "src": ["autogroup:member", "tag:ci"], "dst": ["*:22"]}',
    );
    expect(suggest(grant(["autogroup:tagged", "group:ops"], ["*"]))).toContain('"src": ["group:ops"]');
    expect(suggest(grant(["tag:ark-edge"], ["*"]))).toBeUndefined();
    const [rule] = catchAllRules({
      grants: [{ src: ["*"], dst: ["*"], ip: ["*"], app: { "example.com/cap": [{ token: "private" }] } }],
    });
    expect(rule!.text).toBe('{"src": ["*"], "dst": ["*"], "ip": ["*"]}');
    expect(rule!.replacement).toBeUndefined();
    expect(rule!.sourceEdit).toBe('{"src": ["autogroup:member"]}');
  });

  test("the digest ignores rule and key order and notices every change", () => {
    const a = { src: ["*"], dst: ["*"], ip: ["*"] };
    const b = { src: ["autogroup:tagged"], dst: ["*"], ip: ["tcp:22"] };
    const digest = (...grants: unknown[]) => rulesDigest(catchAllRules({ grants }));
    expect(digest(a, b)).toBe(digest(b, { ip: ["*"], dst: ["*"], src: ["*"] }));
    expect(digest(a, b)).not.toBe(digest(a));
    expect(digest(a)).not.toBe(digest({ ...a, ip: ["tcp:443"] }));
    expect(digest({ ...a, srcPosture: ["posture:x"] })).not.toBe(digest(a));
    expect(digest({ ...a, app: { "example.com/cap": [{}] } })).not.toBe(digest(a));
  });
});

describe("host:setup with a catch-all tailnet policy", () => {
  const RULE = '{"src": ["*"], "dst": ["*"], "ip": ["*"]}';
  const ACCEPT = "--accept-broad-tailnet-policy";
  const SCRIPTED = FULL.filter((flag) => flag !== "--tailnet-policy-reviewed");
  const APPROVED = [...SCRIPTED, "--approve-tailnet-policy"];
  const API = { TS_API_KEY: API_TOKEN };
  const TAILNET_ID = "T123456CNTRL";
  const NAMED_API = { ...API, TS_TAILNET: TAILNET_ID };
  /** Owner content that must never leave the policy: rules, comments, hosts and groups. */
  const PRIVATE = ["private-host", "100.64.9.9", "group:private", "private comment", "autogroup:self"];
  const PRIVATE_POLICY = DEFAULT_POLICY.replace(
    '\t"ssh": [',
    `\t// private comment
\t"groups": {"group:private": ["alice@example.com"]},
\t"hosts": {"private-host": "100.64.9.9"},
\t"ssh": [`,
  );

  function broad(policy = PRIVATE_POLICY) {
    const mock = new MockTailscale();
    mock.tailnets.push(TAILNET_ID);
    mock.policy = policy;
    return mock;
  }

  /** An interactive run's answers: the settings, then `answers` for the policy step and later. */
  function interactive(answers: [string, string][], secrets: [string, string][] = []) {
    return new ScriptedUi(
      true,
      [
        ["Your domain", "example.com"],
        ["Admin hostname", "<default>"],
        ["Let's Encrypt", "ops@example.com"],
        ["trusted Let's Encrypt", "<default>"],
        ["incoming mail", "<default>"],
        ["Shared SNI", "<default>"],
        ["reboot time", "<default>"],
        ["local (non-root) user", "alice"],
        ["Tailscale machine name", "<default>"],
        ["Continue with these settings", "<default>"],
        ...answers,
      ],
      [["Cloudflare", ""], ...secrets],
    );
  }
  const FINISH: [string, string][] = [
    ["session works", "yes"],
    ["Type yes once they are applied", "yes"],
  ];
  const INTERACTIVE = ["--keep-public-ssh"];
  const FINISHED = ["--keep-public-ssh", "--tailscale-ssh-confirmed", "--provider-firewall-applied"];

  type Result = Awaited<ReturnType<typeof setup>>;
  function expectPrivate(f: Fixture, result: Result) {
    for (const secret of [...SECRETS, ...PRIVATE]) {
      expect(result.text).not.toContain(secret);
      expect(result.log).not.toContain(secret);
      expect(JSON.stringify(result.state)).not.toContain(secret);
    }
    expect(filesWithSecrets(f.root, [...SECRETS.filter((s) => s !== EDGE_KEY), ...PRIVATE])).toEqual([]);
  }
  const enrolments = (f: Fixture) =>
    f.host.calls.filter((call) => call.includes("--enroll-vps") || call.includes("up -d"));
  function expectNothingDone(f: Fixture, mock?: MockTailscale) {
    expect(mock?.writes() ?? []).toEqual([]);
    expect(enrolments(f)).toEqual([]);
    expect(f.host.enrolled).toBe(false);
  }
  function enrolled(f: Fixture) {
    f.host.enrolled = f.host.runSsh = true;
    f.host.edge = { running: true, tags: ["tag:ark-edge"], hostName: "ark-edge" };
    f.host.startupNames.set("edge-ts", "ark-edge");
  }
  const summaryOf = (result: Result) => result.text.slice(result.text.indexOf("Ark Stack is installed."));

  test.each(["", "y", "yes", "YES", "accept it"])(
    "API, interactive, fresh: %p shows the rule and pauses before any change",
    async (answer) => {
      const f = fixture();
      const mock = broad();
      const ui = interactive([["Type accept to continue", answer]]);
      const result = await setup(f, INTERACTIVE, API, { ...tsApi(mock), scripted: ui });
      expect(result.code).toBe(2);
      expect(result.text).toContain(`grant ${RULE}`);
      expect(result.text).toContain(
        "This lets the internet-facing edge (tag:ark-edge) open connections to every device",
      );
      expect(result.text).toContain('{"src": ["autogroup:member"], "dst": ["*"], "ip": ["*"]}');
      expect(result.text).toContain("Other tagged machines lose the access");
      expect(result.text).toContain("autogroup:internet");
      expect(result.text).toContain('"deny": ["tag:ark-vps:22"]');
      expect(result.text).toContain(`sudo mise run host:setup --keep-public-ssh`);
      expect(result.text).not.toContain("Proposed tailnet policy change");
      expectNothingDone(f, mock);
      expect(mock.keys.size).toBe(0);
      expectPrivate(f, result);
    },
  );

  test("API, interactive: the word continues, is remembered, and a changed rule asks again", async () => {
    const f = fixture();
    const mock = broad();
    const ui = interactive([["Type accept to continue", "accept"], ["Apply this change", "yes"], ...FINISH]);
    const result = await setup(f, INTERACTIVE, NAMED_API, { ...tsApi(mock), scripted: ui });
    expect(result.code, result.text).toBe(0);
    expect(ui.prompts.filter((prompt) => prompt.includes("Type accept"))).toHaveLength(1);
    expect(summaryOf(result)).toContain("you accepted a catch-all rule");
    expect(summaryOf(result)).toContain(`grant ${RULE}`);
    expect(result.state.tailnetPolicy).toMatchObject({ status: "accepted", read: true });
    expectPrivate(f, result);

    // The same rules, with unrelated edits around them.
    mock.policy = `// edited elsewhere\n${mock.policy}`;
    const same = interactive([]);
    const second = await setup(f, FINISHED, NAMED_API, { ...tsApi(mock), scripted: same });
    expect(second.code, second.text).toBe(0);
    expect(same.prompts.some((prompt) => prompt.includes("Type accept"))).toBe(false);
    expect(summaryOf(second)).toContain("you accepted a catch-all rule");

    // Enrolled nodes: a changed rule asks again, and a refusal does not block.
    mock.policy = mock.policy.replace('"dst": ["*"], "ip": ["*"]}', '"dst": ["*"], "ip": ["tcp:22"]}');
    const changed = interactive([["Type accept to continue", "no"]]);
    const third = await setup(f, FINISHED, NAMED_API, { ...tsApi(mock), scripted: changed });
    expect(third.code, third.text).toBe(0);
    expect(summaryOf(third)).toContain("Still to do:");
    expect(summaryOf(third)).toContain('grant {"src": ["*"], "dst": ["*"], "ip": ["tcp:22"]}');
    expect(third.state.tailnetPolicy.status).toBe("unconfirmed");
    expectPrivate(f, third);
  });

  test("API: a rule narrowed after the pause continues without asking", async () => {
    const f = fixture();
    const mock = broad();
    const paused = await setup(f, APPROVED, API, tsApi(mock));
    expect(paused.code).toBe(2);
    mock.policy = NARROWED_POLICY;
    const ui = interactive([["Apply this change", "yes"], ...FINISH]);
    const result = await setup(f, INTERACTIVE, API, { ...tsApi(mock), scripted: ui });
    expect(result.code, result.text).toBe(0);
    expect(result.text).not.toContain("catch-all");
    expect(result.state.tailnetPolicy).toMatchObject({ status: "clear", read: true });
    expect(result.state.tailnetPolicy.rules).toBeUndefined();
  });

  test("API, scripted: --approve-tailnet-policy and the reviewed flag do not accept the rule", async () => {
    const f = fixture();
    const mock = broad();
    const result = await setup(f, [...APPROVED, "--tailnet-policy-reviewed"], API, tsApi(mock));
    expect(result.code).toBe(2);
    expect(result.text).toContain(`--approve-tailnet-policy --tailnet-policy-reviewed ${ACCEPT}`);
    expectNothingDone(f, mock);
    expectPrivate(f, result);
  });

  test.each([
    [[ACCEPT], {}],
    [[], { ARK_SETUP_ACCEPT_BROAD_TAILNET_POLICY: "1" }],
  ] as [string[], Record<string, string>][])(
    "API, scripted: %j %j accepts the rule and the summary says so",
    async (flags, env) => {
      const f = fixture();
      const mock = broad();
      const result = await setup(f, [...APPROVED, ...flags], { ...NAMED_API, ...env }, tsApi(mock));
      expect(result.code, result.text).toBe(0);
      expect(summaryOf(result)).toContain("you accepted a catch-all rule");
      expect(summaryOf(result)).toContain(`grant ${RULE}`);
      expectPrivate(f, result);
      // Remembered: the flag is not needed again.
      const rerun = await setup(f, APPROVED, NAMED_API, tsApi(mock));
      expect(rerun.code).toBe(0);
      expect(rerun.text).toContain("you accepted a catch-all rule");
    },
  );

  test("API: redirected input does not make the flag count, and it is ignored interactively", async () => {
    const f = fixture();
    const mock = broad();
    const redirected = await setup(f, [...APPROVED.slice(1), ACCEPT], API, tsApi(mock));
    expect(redirected.code).toBe(2);
    expect(redirected.text).toContain(`--non-interactive ${ACCEPT}`);
    expectNothingDone(f, mock);
    const ui = interactive([["Type accept to continue", ""]]);
    expect((await setup(f, [ACCEPT], API, { ...tsApi(mock), scripted: ui })).code).toBe(2);
    expectNothingDone(f, mock);
  });

  test("API, scripted, everything enrolled: not blocked, listed as unfinished", async () => {
    const f = fixture();
    enrolled(f);
    const mock = broad();
    const result = await setup(f, SCRIPTED, API, tsApi(mock));
    expect(result.code, result.text).toBe(0);
    expect(summaryOf(result)).toContain("Still to do:");
    expect(summaryOf(result)).toContain(`grant ${RULE}`);
    expect(summaryOf(result)).toContain(ACCEPT);
    expect(summaryOf(result)).toContain("Ark policy additions are awaiting approval");
    expect(mock.writes()).toEqual([]);
    expect(mock.keys.size).toBe(0);
    expectPrivate(f, result);
  });

  test("API, interactive, everything enrolled: declining policy additions leaves them pending", async () => {
    const f = fixture();
    enrolled(f);
    const mock = broad();
    const ui = interactive([
      ["Type accept to continue", ""],
      ["Apply this change", "no"],
    ]);
    const result = await setup(f, FINISHED, API, { ...tsApi(mock), scripted: ui });
    expect(result.code, result.text).toBe(0);
    expect(summaryOf(result)).toContain("Ark policy additions are awaiting approval");
    expect(summaryOf(result)).toContain(`grant ${RULE}`);
    expect(mock.writes()).toEqual([]);
    expect(mock.requests.every((request) => request.method === "GET")).toBe(true);
  });

  test.each([{ skip: true }, { skip: false }])(
    "a stopped keyed edge is gated before docker start (skip edge: $skip)",
    async ({ skip }) => {
      const f = fixture();
      f.host.enrolled = f.host.runSsh = true;
      const mock = broad();
      f.host.startupNames.set("edge-ts", "ark-edge");
      f.host.stoppedContainers.add("edge-ts");
      f.host.configuredKeys.set("edge-ts", EDGE_KEY);
      const args = skip ? [...APPROVED, "--skip-edge"] : APPROVED;
      const result = await setup(f, args, API, tsApi(mock));
      expect(result.code, result.text).toBe(skip ? 0 : 2);
      expect(result.text).toContain(skip ? "was not accepted" : "Stopped before enrolling tag:ark-edge");
      expect(f.host.calls).not.toContain("docker start edge-ts");
      expect(f.host.firstContainerJoins).toEqual([]);
      if (!skip) {
        const resumed = await setup(f, [...args, ACCEPT], API, tsApi(mock));
        expect(resumed.code, resumed.text).toBe(0);
        expect(f.host.calls).toContain("docker start edge-ts");
        expect(f.host.firstContainerJoins).toEqual([["edge-ts", "ark-edge"]]);
      }
    },
  );

  test.each(["minted", "supplied"])("a mid-install policy edit holds back a %s edge key", async (kind) => {
    const f = fixture();
    const mock = new MockTailscale();
    const run = f.host.run;
    f.host.run = async (argv, options) => {
      const result = await run(argv, options);
      if (argv.includes("--harden-vps") && f.host.installModes.at(-1) === "platform") {
        mock.policy = mock.policy.replace('"src": ["autogroup:member"]', '"src": ["*"]');
        mock.etag = '"edited-mid-install"';
      }
      return result;
    };
    const env = kind === "supplied" ? { ...API, TS_EDGE_AUTHKEY: EDGE_KEY } : API;
    const result = await setup(f, [...APPROVED, "--tailnet-policy-reviewed"], env, tsApi(mock));
    expect(result.code, result.text).toBe(2);
    expect(result.text).toContain("Stopped before enrolling tag:ark-edge");
    expect(f.host.enrolled).toBe(true);
    expect(f.host.firstContainerJoins).toEqual([]);
    expect(mock.keys.size).toBe(1);
    expect(readFileSync(f.host.envPath, "utf8")).not.toContain(EDGE_KEY);
  });

  test.each(["different ID", "unverified default"])(
    "API acceptance cannot authorise an enrolment with a %s",
    async (target) => {
      const f = fixture();
      const mock = broad();
      const firstApi = target === "different ID" ? NAMED_API : API;
      const first = await setup(f, [...APPROVED, ACCEPT, "--skip-edge"], firstApi, tsApi(mock));
      expect(first.code, first.text).toBe(0);
      const otherId = "T654321CNTRL";
      mock.tailnets.push(otherId);
      // Both tailnets return identical rules and ETags.
      const nextApi = target === "different ID" ? { ...API, TS_TAILNET: otherId } : API;
      const next = await setup(f, APPROVED, nextApi, tsApi(mock));
      expect(next.code, next.text).toBe(2);
      expect(next.state.tailnetPolicy.digest).toBe(first.state.tailnetPolicy.digest);
      expect(f.host.firstContainerJoins).toEqual([]);
      expect(mock.keys.size).toBe(1);
    },
  );

  test("API: an edge that has not joined yet is gated before the policy changes", async () => {
    const f = fixture();
    f.host.enrolled = f.host.runSsh = true;
    const mock = broad();
    const result = await setup(f, APPROVED, API, tsApi(mock));
    expect(result.code).toBe(2);
    expect(result.text).toContain("Stopped before enrolling tag:ark-edge");
    expect(result.text).toContain("--skip-edge");
    expect(mock.writes()).toEqual([]);
    expect(f.host.firstContainerJoins).toEqual([]);
    // Left out, nothing is blocked.
    const skipped = await setup(f, [...APPROVED, "--skip-edge"], API, tsApi(mock));
    expect(skipped.code, skipped.text).toBe(0);
    expect(summaryOf(skipped)).toContain("was not accepted");
  });

  test("API: a rule gates only the nodes it concerns once the VPS has joined", async () => {
    const f = fixture();
    enrolled(f);
    const mock = broad(DEFAULT_POLICY.replace('"src": ["*"]', '"src": ["tag:ark-edge"]'));
    const args = [...APPROVED, "--backup-node"];
    const result = await setup(f, args, API, tsApi(mock));
    expect(result.code, result.text).toBe(0);
    expect([...mock.keys.values()].map((key) => key.body.capabilities.devices.create.tags)).toEqual([
      ["tag:ark-backup"],
    ]);
    expect(summaryOf(result)).toContain("was not accepted");
    mock.policy = mock.policy.replace('"src": ["tag:ark-edge"]', '"src": ["tag:ark-backup"]');
    f.host.backup = { running: false, tags: [], hostName: "" };
    const gated = await setup(f, args, API, tsApi(mock));
    expect(gated.code).toBe(2);
    expect(gated.text).toContain("This lets the backup node (tag:ark-backup)");
    expect(mock.keys.size).toBe(1);
  });

  test.each([
    ["yes", "clear"],
    ["accept", "accepted"],
  ])("pasted keys, interactive: %s continues and is remembered for the summary", async (answer, status) => {
    const f = fixture();
    const ui = interactive(
      [["policy is saved and contains no such rule", answer], ...FINISH],
      [["Tailscale API access token", ""]],
    );
    const result = await setup(f, INTERACTIVE, KEYS, { scripted: ui });
    expect(result.code, result.text).toBe(0);
    expect(result.text).toContain(RULE);
    expect(result.text).toContain("internet-facing edge");
    expect(ui.prompts.some((prompt) => prompt.includes("Press Enter"))).toBe(false);
    expect(result.state.tailnetPolicy).toMatchObject({ status, read: false });
    expect(summaryOf(result).includes("you accepted a catch-all rule")).toBe(status === "accepted");
    expect(summaryOf(result)).not.toContain("Tailnet policy: not confirmed");

    const again = interactive([]);
    const rerun = await setup(f, FINISHED, {}, { scripted: again });
    expect(rerun.code, rerun.text).toBe(0);
    expect(summaryOf(rerun).includes("you accepted a catch-all rule")).toBe(status === "accepted");
  });

  test.each(["", "y", "no"])("pasted keys, interactive, fresh: %p pauses", async (answer) => {
    const f = fixture();
    const ui = interactive(
      [["policy is saved and contains no such rule", answer]],
      [["Tailscale API access token", ""]],
    );
    const result = await setup(f, INTERACTIVE, KEYS, { scripted: ui });
    expect(result.code).toBe(2);
    expect(result.text).toContain("sudo mise run host:setup --keep-public-ssh");
    expectNothingDone(f);
  });

  test("pasted keys, scripted: a first enrolment needs one of the flags", async () => {
    const f = fixture();
    const stopped = await setup(f, [...SCRIPTED, "--approve-tailnet-policy"], KEYS);
    expect(stopped.code).toBe(2);
    expect(stopped.text).toContain("--tailnet-policy-reviewed");
    expect(stopped.text).toContain(ACCEPT);
    expectNothingDone(f);
    for (const [flag, env, accepted] of [
      ["--tailnet-policy-reviewed", {}, false],
      [ACCEPT, {}, true],
      [undefined, { ARK_SETUP_TAILNET_POLICY_REVIEWED: "1" }, false],
      [undefined, { ARK_SETUP_ACCEPT_BROAD_TAILNET_POLICY: "true" }, true],
    ] as [string | undefined, Record<string, string>, boolean][]) {
      const fresh = fixture();
      const result = await setup(fresh, [...SCRIPTED, ...(flag ? [flag] : [])], { ...KEYS, ...env });
      expect(result.code, result.text).toBe(0);
      expect(summaryOf(result).includes("you accepted a catch-all rule")).toBe(accepted);
      expect((await setup(fresh, SCRIPTED, {})).code).toBe(0);
    }
  });

  test("pasted keys, everything enrolled before this check existed: asks or lists, never blocks", async () => {
    const f = fixture();
    enrolled(f);
    const scripted = await setup(f, SCRIPTED, {});
    expect(scripted.code, scripted.text).toBe(0);
    expect(summaryOf(scripted)).toContain("Tailnet policy: not confirmed");
    expect(summaryOf(scripted)).toContain("--tailnet-policy-reviewed");
    const ui = interactive([["policy is saved and contains no such rule", ""]]);
    const declined = await setup(f, FINISHED, {}, { scripted: ui });
    expect(declined.code, declined.text).toBe(0);
    expect(summaryOf(declined)).toContain("Tailnet policy: not confirmed");
    const confirmed = await setup(f, [...SCRIPTED, "--tailnet-policy-reviewed"], {});
    expect(confirmed.code).toBe(0);
    expect(summaryOf(confirmed)).not.toContain("Tailnet policy:");
  });

  test.each(["environment", ".env"])("pasted keys: an edge key in the %s is gated too", async (where) => {
    const f = fixture();
    f.host.enrolled = f.host.runSsh = true;
    if (where === ".env") writeFileSync(f.host.envPath, `TS_EDGE_AUTHKEY=${EDGE_KEY}\n`, { mode: 0o600 });
    const env: Record<string, string> = where === ".env" ? {} : { TS_EDGE_AUTHKEY: EDGE_KEY };
    const result = await setup(f, SCRIPTED, env);
    expect(result.code).toBe(2);
    expect(result.text).toContain("Stopped before enrolling tag:ark-edge");
    expect(f.host.firstContainerJoins).toEqual([]);
    // Without any key the edge cannot join in this run, so nothing is blocked.
    const other = fixture();
    other.host.enrolled = other.host.runSsh = true;
    const skipped = await setup(other, SCRIPTED, {});
    expect(skipped.code, skipped.text).toBe(0);
    expect(skipped.state.steps.edge.status).toBe("skipped");
  });

  test("pasted keys never use what the API read earlier to enrol a new node", async () => {
    const f = fixture();
    const mock = broad();
    expect((await setup(f, [...APPROVED, ACCEPT, "--skip-edge"], NAMED_API, tsApi(mock))).code).toBe(0);
    const result = await setup(f, SCRIPTED, { TS_EDGE_AUTHKEY: EDGE_KEY });
    expect(result.code).toBe(2);
    expect(f.host.edge.running).toBe(false);
    // The acceptance of the rules setup read still stands.
    expect(result.state.tailnetPolicy).toMatchObject({ status: "accepted", read: true });
    expect((await setup(f, APPROVED, NAMED_API, tsApi(mock))).code).toBe(0);
  });

  test.each(["edge", "backup", "vps"])(
    "a prior manual answer cannot authorise a new %s join",
    async (node) => {
      const f = fixture();
      const args = [...SCRIPTED, "--skip-edge"];
      const first = await setup(f, [...args, node === "vps" ? ACCEPT : "--tailnet-policy-reviewed"], {
        TS_VPS_AUTHKEY: VPS_KEY,
      });
      expect(first.code, first.text).toBe(0);
      if (node === "vps") f.host.enrolled = f.host.runSsh = false;
      const options = node === "edge" ? SCRIPTED : node === "backup" ? [...args, "--backup-node"] : args;
      const result = await setup(f, options, { ...KEYS, TS_BACKUP_AUTHKEY: BACKUP_KEY });
      expect(result.code, result.text).toBe(2);
      expect(result.text).toContain(`Stopped before enrolling tag:ark-${node}`);
      expect(f.host.firstContainerJoins).toEqual([]);
      expect(f.host.enrolled).toBe(node !== "vps");
    },
  );

  test.each(["environment", "key file", ".env"])(
    "a clean API tailnet cannot authorise an independently supplied key from %s",
    async (where) => {
      const f = fixture();
      const mock = new MockTailscale();
      const env: Record<string, string> = { ...API };
      if (where === "environment") env.TS_VPS_AUTHKEY = VPS_KEY;
      if (where === "key file") {
        env.TS_VPS_AUTHKEY_FILE = join(f.root, "vps-key");
        writeFileSync(env.TS_VPS_AUTHKEY_FILE, VPS_KEY, { mode: 0o600 });
      }
      if (where === ".env") {
        f.host.enrolled = f.host.runSsh = true;
        writeFileSync(f.host.envPath, `TS_EDGE_AUTHKEY=${EDGE_KEY}\n`, { mode: 0o600 });
      }
      const result = await setup(f, APPROVED, env, tsApi(mock));
      expect(result.code, result.text).toBe(2);
      expect(result.text).toContain("cannot verify which tailnet each supplied key will join");
      expect(enrolments(f)).toEqual([]);
      expect(mock.writes()).toEqual([]);
    },
  );

  test("matching selectors and mixed-grant guidance redact credentials on pause and rerun", async () => {
    const f = fixture();
    const selectorSecret = "tskey-api-synthetic-selector";
    const appSecret = "private-app-parameter";
    const mock = broad(
      JSON.stringify({
        grants: [
          {
            src: ["*", `tag:${selectorSecret}`, "group:retained"],
            dst: ["*"],
            ip: ["*"],
            app: { "example.com/cap": [{ token: appSecret }] },
          },
        ],
      }),
    );
    const paused = await setup(f, APPROVED, NAMED_API, tsApi(mock));
    const resumed = await setup(f, [...APPROVED, ACCEPT], NAMED_API, tsApi(mock));
    expect(paused.code).toBe(2);
    expect(resumed.code, resumed.text).toBe(0);
    expect(paused.text).toContain("change only the source field in the existing grant");
    expect(paused.text).toContain('"src": ["autogroup:member", "tag:<redacted>", "group:retained"]');
    expect(paused.text).not.toContain("Suggested replacement:");
    expect(resumed.state.tailnetPolicy.digest).toBe(paused.state.tailnetPolicy.digest);
    for (const result of [paused, resumed]) {
      expect(result.text).not.toContain(selectorSecret);
      expect(result.text).not.toContain(appSecret);
      expect(result.log).not.toContain(selectorSecret);
      expect(result.log).not.toContain(appSecret);
      expect(JSON.stringify(result.state)).not.toContain(selectorSecret);
      expect(JSON.stringify(result.state)).not.toContain(appSecret);
    }
  });

  test.each(["read", "validate", "write"])(
    "policy %s errors omit private API diagnostics",
    async (operation) => {
      const f = fixture();
      const mock = new MockTailscale();
      if (operation === "validate") {
        mock.validateProblem = "policy test for private-host failed";
        mock.validateData = { failed: ["group:private"] };
      } else {
        mock.policyError = { method: operation === "read" ? "GET" : "POST", message: "private-host" };
      }
      const result = await setup(f, APPROVED, API, tsApi(mock));
      expect(result.code).toBe(1);
      expect(result.text).toContain(
        operation === "validate" ? "Tailscale rejected the merged policy" : "HTTP 400",
      );
      expect(f.host.enrolled).toBe(false);
      expect(mock.keys.size).toBe(0);
      expectPrivate(f, result);
    },
  );

  test("a supplied key is checked again before it enrols a node that lost its identity during install", async () => {
    const f = fixture();
    enrolled(f);
    const mock = broad();
    const run = f.host.run;
    f.host.run = async (argv, options) => {
      const result = await run(argv, options);
      if (argv.includes("--harden-vps") && f.host.installModes.at(-1) === "platform")
        f.host.edge = { running: false, tags: [], hostName: "" };
      return result;
    };
    const result = await setup(f, APPROVED, { ...API, TS_EDGE_AUTHKEY: EDGE_KEY }, tsApi(mock));
    expect(result.code, result.text).toBe(2);
    expect(result.text).toContain("Stopped before enrolling tag:ark-edge");
    expect(f.host.containerKeys).toEqual([]);
    expect(f.host.edge.running).toBe(false);
    expectPrivate(f, result);
    expect(readFileSync(f.host.envPath, "utf8")).not.toContain(EDGE_KEY);
  });

  test("a key source without its own policy step asks the same question", async () => {
    const f = fixture();
    const ui = interactive([["policy is saved and contains no such rule", ""]]);
    const keys: SetupDependencies["keys"] = (input) => {
      const { policyInstructions, acquire } = manualKeySource(input);
      return { id: "custom", policyInstructions, acquire };
    };
    const result = await setup(f, INTERACTIVE, KEYS, { scripted: ui, keys });
    expect(result.code).toBe(2);
    expectNothingDone(f);
  });
});

describe("Hetzner Cloud provider firewall", () => {
  const firewallArgs = [...BASE, "--tailscale-ssh-confirmed", "--verify-ssh-cutover"];
  const firewallContext = (): FirewallContext => ({
    ui: new ScriptedUi(false),
    interactive: false,
    env: { HCLOUD_TOKEN },
    publicAddresses: { ipv4: ["203.0.113.10"], ipv6: [] },
    confirmed: false,
    approved: true,
  });
  const arkFirewall = (): HetznerFirewall => ({
    id: 100,
    name: "ark-stack-4242",
    labels: { "managed-by": "ark-stack" },
    rules: hetznerRules(PROVIDER_RULES),
    applied_to: [{ type: "server", server: { id: 4242 } }],
  });

  test("creates one Ark firewall for this server after approval, leaves others alone; a rerun changes nothing", async () => {
    const f = fixture();
    const hetzner = new MockHetzner();
    hetzner.timeline = f.host.calls;
    const own: HetznerFirewall = {
      id: 7,
      name: "user-fw",
      labels: {},
      rules: [{ direction: "in", protocol: "tcp", port: "8080", source_ips: ["0.0.0.0/0"] }],
      applied_to: [
        { type: "server", server: { id: 4242 } },
        { type: "server", server: { id: 9 } },
      ],
    };
    hetzner.firewalls.push(structuredClone(own));
    const deps = { firewalls: [hetzner.adapter(), manualProviderFirewall] };
    const env = { ...KEYS, HCLOUD_TOKEN };
    const result = await setup(f, [...firewallArgs, "--approve-provider-firewall"], env, deps);
    expect(result.code).toBe(0);
    expect(result.state.steps["provider-firewall"].status).toBe("done");
    expect(result.text).toContain("Create the Hetzner Cloud firewall ark-stack-4242");
    expect(result.text).toContain('Note: firewall "user-fw" (id 7) also applies to this server');

    const created = hetzner.firewalls.find((firewall) => firewall.name === "ark-stack-4242")!;
    expect(created.labels).toMatchObject({ "managed-by": "ark-stack", "ark-stack-server": "4242" });
    expect(created.applied_to).toEqual([{ type: "server", server: { id: 4242 } }]);
    const rules = created.rules.map(
      (rule: HetznerRule) => `${rule.protocol} ${rule.port ?? "-"} ${rule.source_ips!.join(",")}`,
    );
    expect(rules).toEqual([
      ...["25", "80", "443", "465", "587", "993", "5432"].map((port) => `tcp ${port} 0.0.0.0/0,::/0`),
      "udp 41641-41642 0.0.0.0/0,::/0",
      "icmp - 0.0.0.0/0,::/0",
    ]);
    expect(rules.some((rule) => rule.startsWith("tcp 22 "))).toBe(false);
    expect(hetzner.firewalls.find((firewall) => firewall.id === 7)).toEqual(own);
    expect(hetzner.writes().some((request) => request.path.startsWith("/v1/firewalls/7"))).toBe(false);
    // The local audit runs after the provider change, not before it.
    const createdAt = f.host.calls.indexOf("hetzner POST /v1/firewalls");
    const auditAt = f.host.calls.lastIndexOf(AUDIT);
    expect(createdAt).toBeGreaterThan(-1);
    expect(auditAt).toBeGreaterThan(createdAt);
    for (const output of [result.text, result.log]) expect(output).not.toContain(HCLOUD_TOKEN);
    expect(filesWithSecrets(f.root, [HCLOUD_TOKEN])).toEqual([]);

    const writes = hetzner.writes().length;
    const again = await setup(f, firewallArgs, env, deps);
    expect(again.code).toBe(0);
    expect(hetzner.writes()).toHaveLength(writes);
    expect(again.text).toContain("provider already matches (Hetzner Cloud API)");
    expect(again.text).toContain('Note: firewall "user-fw" (id 7) also applies to this server');
  });

  test("reuses the verified Hetzner result for the same inputs when the token is removed", async () => {
    const f = fixture();
    const hetzner = new MockHetzner();
    const deps = { firewalls: [hetzner.adapter(), manualProviderFirewall] };
    const initial = await setup(
      f,
      [...firewallArgs, "--approve-provider-firewall"],
      { ...KEYS, HCLOUD_TOKEN },
      deps,
    );
    const requestCount = hetzner.requests.length;
    const again = await setup(f, firewallArgs, KEYS, deps);
    expect(again.code).toBe(0);
    expect(again.state.steps["provider-firewall"]).toMatchObject({
      status: "done",
      fingerprint: initial.state.steps["provider-firewall"].fingerprint,
    });
    expect(again.text).toContain("HCLOUD_TOKEN needed to re-verify at the provider");
    expect(again.text).not.toContain("printed but not confirmed");
    expect(hetzner.requests).toHaveLength(requestCount);
  });

  test.each(["attachments", "rules", "ownership"])(
    "refuses a change to %s during approval",
    async (change) => {
      const hetzner = new MockHetzner();
      const firewall = arkFirewall();
      firewall.rules.pop();
      hetzner.firewalls.push(firewall);
      const adapter = hetzner.adapter();
      const context = { ...firewallContext(), interactive: true };
      context.ui.ask = async () => {
        if (change === "attachments") firewall.applied_to!.push({ type: "server", server: { id: 7 } });
        if (change === "rules") firewall.rules.pop();
        if (change === "ownership") firewall.labels = {};
        return "yes";
      };
      expect(await adapter.detect(context)).toBe(true);
      const plan = await adapter.plan(PROVIDER_RULES, context);
      await expect(adapter.apply(plan, context)).rejects.toThrow("changed after it was planned");
      expect(hetzner.writes()).toEqual([]);
    },
  );

  test("defers the audit until the provider reports the association applied", async () => {
    const f = fixture();
    const hetzner = new MockHetzner();
    hetzner.associationStatus = "pending";
    const deps = { firewalls: [hetzner.adapter(), manualProviderFirewall] };
    const env = { ...KEYS, HCLOUD_TOKEN };
    const created = await setup(f, [...firewallArgs, "--approve-provider-firewall"], env, deps);
    const pending = await setup(f, firewallArgs, env, deps);
    for (const result of [created, pending]) {
      expect(result.code).toBe(0);
      expect(result.state.steps["provider-firewall"].status).toBe("pending");
      expect(result.text).toContain("has yet to report firewall");
    }
    expect(f.host.calls).not.toContain(AUDIT);
    hetzner.associationStatus = "applied";
    const verified = await setup(f, firewallArgs, env, deps);
    expect(verified.state.steps["provider-firewall"].status).toBe("done");
    expect(f.host.calls).toContain(AUDIT);
    expect(hetzner.writes()).toHaveLength(1);
  });

  test.each([
    ["error", "provider refused the action", 1],
    ["running", "did not finish within two minutes", 120],
  ] as const)("reports action polling status '%s' without claiming apply", async (status, message, polls) => {
    const hetzner = new MockHetzner();
    hetzner.actionStatus = status;
    const f = fixture();
    const result = await setup(
      f,
      [...firewallArgs, "--approve-provider-firewall"],
      { ...KEYS, HCLOUD_TOKEN },
      {
        firewalls: [hetzner.adapter(), manualProviderFirewall],
      },
    );
    expect(result.code).toBe(1);
    expect(result.text).toContain(message);
    expect(result.state.steps["provider-firewall"].status).toBe("failed");
    expect(f.host.calls).not.toContain(AUDIT);
    expect(hetzner.requests.filter(({ path }) => path === "/v1/actions/1")).toHaveLength(polls);
  });

  test("keeps TCP 22 open while public SSH is retained, and removes it once SSH is closed", async () => {
    const f = fixture();
    const hetzner = new MockHetzner();
    const deps = { firewalls: [hetzner.adapter(), manualProviderFirewall] };
    const env = { ...KEYS, HCLOUD_TOKEN };
    const kept = await setup(
      f,
      [...firewallArgs, "--keep-public-ssh", "--approve-provider-firewall"],
      env,
      deps,
    );
    expect(kept.code).toBe(0);
    const firewall = () => hetzner.firewalls.find((item) => item.name === "ark-stack-4242")!;
    expect(firewall().rules).toContainEqual(expect.objectContaining({ protocol: "tcp", port: "22" }));
    const closed = await setup(f, [...firewallArgs, "--approve-provider-firewall"], env, deps);
    expect(closed.code).toBe(0);
    expect(closed.text).toContain("- inbound TCP 22 from 0.0.0.0/0, ::/0");
    expect(firewall().rules.some((rule) => rule.port === "22")).toBe(false);
    expect(hetzner.writes().map((request) => request.path)).toEqual([
      "/v1/firewalls",
      "/v1/firewalls/100/actions/set_rules",
    ]);
  });

  test("scripted runs without --approve-provider-firewall show the plan and leave it pending", async () => {
    const f = fixture();
    const hetzner = new MockHetzner();
    const result = await setup(
      f,
      firewallArgs,
      { ...KEYS, HCLOUD_TOKEN },
      {
        firewalls: [hetzner.adapter(), manualProviderFirewall],
      },
    );
    expect(result.code).toBe(0);
    expect(result.state.steps["provider-firewall"].status).toBe("pending");
    expect(result.text).toContain("+ inbound TCP 443 from 0.0.0.0/0, ::/0");
    expect(result.text).toContain("--approve-provider-firewall");
    expect(hetzner.writes()).toEqual([]);
    expect(f.host.calls).not.toContain(AUDIT);
  });

  test("without a token, or off Hetzner, the print-the-rules adapter is used", async () => {
    const f = fixture();
    const hetzner = new MockHetzner();
    const noToken = await setup(f, FULL, KEYS, { firewalls: [hetzner.adapter(), manualProviderFirewall] });
    expect(noToken.code).toBe(0);
    expect(noToken.text).toContain("rules applied (any provider (manual))");
    const offHetzner = hetznerProviderFirewall({
      metadataBase: "http://127.0.0.1:9",
      apiBase: `${hetzner.url}/v1`,
    });
    const context = {
      ui: new ScriptedUi(false),
      interactive: false,
      env: { HCLOUD_TOKEN },
      publicAddresses: { ipv4: ["203.0.113.10"], ipv6: [] },
      confirmed: false,
    } satisfies FirewallContext;
    expect((await selectProviderFirewall([offHetzner, manualProviderFirewall], context)).id).toBe("manual");
    expect(hetzner.writes()).toEqual([]);
  });

  test("refuses a same-named firewall Ark did not create, one attached elsewhere, or another server", async () => {
    const hetzner = new MockHetzner();
    const context = {
      ui: new ScriptedUi(false),
      interactive: false,
      env: { HCLOUD_TOKEN },
      publicAddresses: { ipv4: ["203.0.113.10"], ipv6: [] },
      confirmed: false,
      approved: true,
    } satisfies FirewallContext;
    const adapter = hetzner.adapter();
    expect(await adapter.detect(context)).toBe(true);
    hetzner.firewalls.push({ id: 5, name: "ark-stack-4242", labels: {}, rules: [], applied_to: [] });
    await expect(adapter.plan(PROVIDER_RULES, context)).rejects.toThrow("lacks Ark ownership");
    hetzner.firewalls[0] = {
      id: 5,
      name: "ark-stack-4242",
      labels: { "managed-by": "ark-stack" },
      rules: [],
      applied_to: [{ type: "label_selector", label_selector: { selector: "env=prod" } }],
    };
    await expect(adapter.plan(PROVIDER_RULES, context)).rejects.toThrow("also applied to other resources");
    hetzner.serverIpv4 = "198.51.100.99";
    await expect(adapter.detect(context)).rejects.toThrow("Nothing was changed");
    await expect(
      adapter.detect({ ...context, env: { HCLOUD_TOKEN: "wrong-token-0123456789" } }),
    ).rejects.toThrow("HTTP 401");
    expect(hetzner.writes()).toEqual([]);
  });

  test("rule helpers: ranges, both address families and ICMP", () => {
    expect(portRanges([443, 80, 20001, 20002, 20003, 80])).toEqual(["80", "443", "20001-20003"]);
    expect(
      hetznerRules([{ protocol: "udp", ports: [41642, 41641], sourceCidrs: ["::/0", "0.0.0.0/0"] }]),
    ).toEqual([
      {
        direction: "in",
        protocol: "udp",
        port: "41641-41642",
        source_ips: ["0.0.0.0/0", "::/0"],
        description: "Ark Stack UDP 41641-41642",
      },
      {
        direction: "in",
        protocol: "icmp",
        source_ips: ["0.0.0.0/0", "::/0"],
        description: "Ark Stack ICMP and ICMPv6",
      },
    ]);
  });
});

describe("front policy acknowledgement in the host inventory", () => {
  const id = "0f4c2c1e-7d0b-4f4e-9a55-2d1c1c7b9e01";
  function front(status?: string) {
    const root = mkdtempSync(join(tmpdir(), "ark-inventory-"));
    const dir = join(root, "tmp", "edge-l4", "front-ingress");
    mkdirSync(dir, { recursive: true });
    const rules = "table inet ark_front {}\n";
    writeFileSync(join(dir, "policy.nft"), rules);
    writeFileSync(join(dir, "policy.request"), JSON.stringify({ id, hash: sha256Hex(rules) }));
    if (status !== undefined)
      writeFileSync(join(dir, "policy.status"), status.replaceAll("HASH", sha256Hex(rules)));
    return root;
  }
  const env = { ARK_MAIL_ENABLED: "0", ARK_EDGE_SNI_PORTS: "" };

  function writeFront(root: string, ports: number[] = []) {
    const dir = join(root, "tmp", "edge-l4", "front-ingress");
    mkdirSync(dir, { recursive: true });
    const rules = renderFrontIngress(
      ports.map((port) => ({ id: `rt_${port}`, listenPort: port, sourceCidrs: [], allowInternet: true })),
    );
    writeFileSync(join(dir, "policy.nft"), rules);
    const hash = sha256Hex(rules);
    return {
      request: () => writeFileSync(join(dir, "policy.request"), JSON.stringify({ id, hash })),
      acknowledge: (error = "") =>
        writeFileSync(
          join(dir, "policy.status"),
          `applied=${!error}\npolicy_hash=${hash}\nrequest_id=${id}\nerror=${error}\n`,
        ),
    };
  }

  test("a resumed setup restarts a stopped reconciler before waiting for its pending policy", async () => {
    const f = fixture();
    const args = [...FULL, "--no-mail", "--keep-public-ssh"];
    const policy = writeFront(f.root, [20001]);
    policy.request();
    policy.acknowledge();
    f.host.routes = [{ port: 20001, policy: "internet" }];
    expect((await setup(f, args, KEYS)).code).toBe(0);
    const store = new StateStore(f.stateDir);
    const legacyState = store.load();
    delete legacyState.steps.harden;
    store.save(legacyState);
    f.host.reconcilerRunning = false;
    f.host.installModes = [];
    f.host.sleeps = [];
    const pending = writeFront(f.root, [20001]);
    pending.request();
    pending.acknowledge("the reconciler stopped before applying the policy");
    f.host.onPlatformRestart = () => pending.acknowledge();

    const result = await setup(f, args);
    expect(result.code, result.text).toBe(0);
    expect(f.host.installModes).toEqual(["harden", "platform"]);
    expect(f.host.reconcilerRunning).toBe(true);
    expect(f.host.sleeps).not.toContain(2000);
    expect(result.state.steps.audit.status).toBe("done");
  });

  test("the final audit waits for the first request and retries a failed acknowledgement", async () => {
    const f = fixture();
    let advance = () => {};
    const delays: number[] = [];
    f.host.onPlatformRestart = () => {
      const policy = writeFront(f.root);
      advance = () => {
        if (delays.length === 1) {
          policy.request();
          policy.acknowledge("temporary nftables failure");
        } else policy.acknowledge();
      };
    };
    const result = await setup(f, [...FULL, "--keep-public-ssh"], KEYS, {
      sleep: async (ms) => {
        if (ms !== 2000) return;
        delays.push(ms);
        advance();
      },
    });
    expect(result.code, result.text).toBe(0);
    expect(delays).toEqual([2000, 2000]);
    expect(result.log).toContain("request not yet published");
    expect(result.log).toContain("temporary nftables failure");
    expect(result.state.steps.audit.status).toBe("done");
  });

  test("the acknowledgement wait is bounded and retains the last reconciler error", async () => {
    const f = fixture();
    f.host.onPlatformRestart = () => {
      const policy = writeFront(f.root);
      policy.request();
      policy.acknowledge("nftables rejected the policy");
    };
    const result = await setup(f, [...FULL, "--keep-public-ssh"], KEYS);
    expect(result.code).toBe(1);
    expect(f.host.sleeps.filter((ms) => ms === 2000)).toHaveLength(30);
    expect(f.host.calls.filter((call) => call === `${AUDIT} --retain-ssh`)).toHaveLength(31);
    expect(result.state.steps.audit.error).toContain("Timed out");
    expect(result.state.steps.audit.error).toContain("nftables rejected the policy");
  });

  test("a changed dedicated port set reopens provider verification and lists the exact rule delta", async () => {
    const f = fixture();
    const earlier = writeFront(f.root, [20001]);
    earlier.request();
    earlier.acknowledge();
    f.host.onPlatformRestart = () => {
      const later = writeFront(f.root, [20002]);
      later.request();
      later.acknowledge();
    };
    const result = await setup(f, FULL, KEYS);
    expect(result.code, result.text).toBe(0);
    expect(result.state.steps["provider-firewall"].status).toBe("pending");
    expect(result.state.steps.audit.status).toBe("pending");
    expect(result.text).toContain("allow TCP 20002 from 0.0.0.0/0 and ::/0");
    expect(result.text).toContain("remove TCP 20001 from 0.0.0.0/0 and ::/0");
    expect(result.text).not.toContain("Local audit passed");
    expect(readFileSync(join(f.root, "tmp", "ark-host-inventory.json"), "utf8")).toContain("20002");
    const resumed = await setup(f, FULL, KEYS);
    expect(resumed.code, resumed.text).toBe(0);
    expect(resumed.state.steps["provider-firewall"].status).toBe("done");
    expect(resumed.state.steps.audit.status).toBe("done");
  });

  test("without a front policy it returns the configured ports", async () => {
    const root = mkdtempSync(join(tmpdir(), "ark-inventory-"));
    expect(await appliedHostConfig(root, env)).toEqual({ mailEnabled: false, sniPorts: [] });
  });

  test("a request without its acknowledgement yet is reported as awaiting", async () => {
    for (const status of [
      undefined,
      `applied=true\npolicy_hash=HASH\nrequest_id=${"1".repeat(36)}\nerror=\n`,
    ]) {
      await expect(appliedHostConfig(front(status), env)).rejects.toThrow(
        "awaiting firewall acknowledgement",
      );
    }
  });

  test("a failed acknowledgement of the current request reports the reconciler's error", async () => {
    const root = front(
      `applied=false\npolicy_hash=HASH\nrequest_id=${id}\nerror=nft: Could not process rule: No such file or directory\n`,
    );
    const error = await appliedHostConfig(root, env).catch((failure: Error) => failure.message);
    expect(error).toContain("database-ingress could not apply the front policy");
    expect(error).toContain("nft: Could not process rule: No such file or directory");
    expect(error).toContain(frontPolicyPending);
  });
});
