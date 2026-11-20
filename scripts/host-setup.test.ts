// The guided setup (scripts/host-setup.ts) against a simulated Ubuntu host: every system command is
// answered by a stub, so nothing here touches the machine running the tests.
import { afterEach, describe, expect, test } from "bun:test";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  type Dirent,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  generateInstallSecrets,
  mergeInstallEnv,
  parseEnvFile,
  parseHujson,
  parseSniPorts,
  readHostSshAccess,
  renderHostFirewall,
  replaceHostSshAccess,
  type HostSshAccess,
} from "@ark-stack/shared";

import { runSetup, type SetupDependencies } from "./host-setup.ts";
import { parseFlags, resolveOptions } from "./host-setup/answers.ts";
import { desiredConfiguration, setEnvValues } from "./host-setup/env-file.ts";
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
import { detectSessionOrigin, publicSshListeners, publicUfwSshRules } from "./host-setup/steps.ts";
import { Redactor, type RunOptions, type RunResult, type Ui } from "./host-setup/system.ts";
import { lineDiff, mergeArkPolicy } from "./host-setup/tailnet-policy.ts";
import {
  KEY_EXPIRY_SECONDS,
  TailscaleApi,
  apiKeySource,
  automaticKeySource,
  credentialFromEnv,
} from "./host-setup/tailscale-api.ts";
import { manualKeySource } from "./host-setup/tailscale-keys.ts";

const repoRoot = join(import.meta.dir, "..");
const BUN = "/test/bun";
const VPS_KEY = "tskey-auth-kVPS1234CNTRL-vpsSecretValue0123456789";
const EDGE_KEY = "tskey-auth-kEDGE5678CNTRL-edgeSecretValue0123456789";
const RECOVERY_IP = "198.51.100.23";
const DNS_TOKEN = "cfDnsToken_0123456789abcdefghijABCDEFGHIJ";
const PROVIDER_RULES = [
  { protocol: "tcp", ports: [25, 80, 443, 465, 587, 993, 5432], sourceCidrs: ["0.0.0.0/0", "::/0"] },
  { protocol: "udp", ports: [41641, 41642], sourceCidrs: ["0.0.0.0/0", "::/0"] },
];

const ok = (stdout = ""): RunResult => ({ status: 0, stdout, stderr: "" });
const fail = (stderr = "", status = 1): RunResult => ({ status, stdout: "", stderr });

/** A simulated Ubuntu VPS. Each stub mutates this state the way the real command would. */
class FakeHost {
  calls: string[] = [];
  enrolled = false;
  runSsh = false;
  healthy = false;
  ssh = { service: { enabled: true, active: true }, socket: { enabled: false, active: false } };
  edge = { running: false, tags: [] as string[] };
  edgeJoinTags = ["tag:ark-edge"];
  backup = { running: false, tags: [] as string[] };
  /** Every key a container was started with, and where it came from. */
  containerKeys: { service: string; key: string; from: "env" | ".env" }[] = [];
  /** Keys still present in a container's configuration. */
  configuredKeys = new Map<string, string>();
  ufw: string | undefined;
  failInstall = 0;
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

  constructor(
    readonly root: string,
    readonly firewallPath: string,
  ) {}

  get envPath() {
    return join(this.root, ".env");
  }

  run = async (argv: string[], options: RunOptions = {}): Promise<RunResult> => {
    const line = argv.join(" ");
    this.calls.push(line);
    const result = await this.respond(argv, line, options);
    for (const output of `${result.stdout}${result.stderr}`.split("\n")) if (output) options.onLine?.(output);
    return result;
  };

  private async respond(argv: string[], line: string, options: RunOptions): Promise<RunResult> {
    if (argv[0] === "sh" && argv[2] === 'command -v "$1"') return ok(`/usr/bin/${argv[4]}\n`);
    if (line === "docker compose version" || line.startsWith("docker info")) return ok("v2\n");
    if (line.startsWith("getent passwd ")) return ok();
    if (line === "tailscale status --json") {
      return ok(
        JSON.stringify({
          BackendState: this.enrolled ? "Running" : "NeedsLogin",
          TUN: true,
          Self: {
            ID: this.nodeId,
            Online: this.enrolled,
            Tags: this.enrolled ? ["tag:ark-vps"] : [],
            DNSName: "ark-vps.tail1234.ts.net.",
            TailscaleIPs: ["100.100.1.2", "fd7a:115c:a1e0::1"],
          },
        }),
      );
    }
    if (line === "tailscale debug prefs") return ok(JSON.stringify({ RunSSH: this.runSsh }));
    if (line === "systemctl is-active tailscaled.service") return ok("active\n");
    if (line.startsWith(`${BUN} scripts/install.ts --enroll-vps`)) {
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
      if (this.failInstall > 0) {
        this.failInstall--;
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
      this.liveFirewall = firewall.split("\n").slice(2).join("\n");
      this.healthy = true;
      return ok(`Ark Stack host install ready.\nSetup token: ${values.ARK_SETUP_TOKEN}\n`);
    }
    if (line.startsWith("curl -fsS")) return this.healthy ? ok("{}") : fail("", 7);
    if (line.startsWith("git -C")) return ok("0123abc\n");
    if (line.includes("exec -T edge-ts")) {
      if (!this.edge.running) {
        const key =
          this.configuredKeys.get("edge-ts") ??
          (existsSync(this.envPath) && parseEnvFile(readFileSync(this.envPath, "utf8")).TS_EDGE_AUTHKEY);
        if (
          key &&
          key === this.rejectEdgeKey &&
          this.calls.some((call) => call.endsWith("up -d edge-ts edge edge-l4"))
        ) {
          return ok(JSON.stringify({ BackendState: "NeedsLogin", Health: ["invalid auth key"] }));
        }
        return fail("service edge-ts is not running");
      }
      return ok(JSON.stringify({ BackendState: "Running", Self: { Tags: this.edge.tags } }));
    }
    if (line.endsWith("up -d edge-ts edge edge-l4")) {
      const fromFile = parseEnvFile(readFileSync(this.envPath, "utf8")).TS_EDGE_AUTHKEY;
      const key = options.env?.TS_EDGE_AUTHKEY || fromFile;
      if (key) {
        this.containerKeys.push({
          service: "edge-ts",
          key,
          from: options.env?.TS_EDGE_AUTHKEY ? "env" : ".env",
        });
        this.configuredKeys.set("edge-ts", key);
      }
      if (key && key !== this.rejectEdgeKey) {
        this.edge = { running: true, tags: this.edgeJoinTags };
      }
      return ok();
    }
    if (line.endsWith("up -d edge-ts") || line.endsWith("up -d backup-ts")) {
      // Compose recreates the container with whatever key the environment or .env now gives it.
      const service = argv.at(-1)!;
      const variable = service === "edge-ts" ? "TS_EDGE_AUTHKEY" : "TS_BACKUP_AUTHKEY";
      const key = options.env?.[variable] || parseEnvFile(readFileSync(this.envPath, "utf8"))[variable] || "";
      if (key) {
        this.containerKeys.push({ service, key, from: options.env?.[variable] ? "env" : ".env" });
        this.configuredKeys.set(service, key);
      } else this.configuredKeys.delete(service);
      if (service === "backup-ts" && (key || this.backup.running))
        this.backup = { running: true, tags: ["tag:ark-backup"] };
      return ok();
    }
    if (line.includes("exec -T backup-ts")) {
      if (!this.backup.running) return ok(JSON.stringify({ BackendState: "NeedsLogin" }));
      return ok(JSON.stringify({ BackendState: "Running", Self: { Tags: this.backup.tags } }));
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
      if (this.ssh.service.active && this.privateSsh)
        return ok('LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n');
      return ok(
        this.ssh.service.active
          ? 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))\nLISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=900,fd=4))\n'
          : 'LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:* users:(("docker-proxy",pid=1,fd=4))\n',
      );
    }
    if (line === "ufw status numbered")
      return this.ufw === undefined ? fail("ufw: not found", 127) : ok(this.ufw);
    if (argv[0] === "ufw") return this.failUfwDelete ? fail("ufw delete failed") : ok();
    if (line === `${BUN} scripts/host-audit.ts --inventory`) {
      return ok(
        JSON.stringify({
          config: {
            mailEnabled: parseEnvFile(readFileSync(this.envPath, "utf8")).ARK_MAIL_ENABLED !== "0",
            sniPorts: parseSniPorts(parseEnvFile(readFileSync(this.envPath, "utf8")).ARK_EDGE_SNI_PORTS),
          },
          providerRules: PROVIDER_RULES,
        }),
      );
    }
    if (line.startsWith(`${BUN} scripts/host-audit.ts`)) {
      if (this.failAudit > 0) {
        this.failAudit--;
        return fail("Unexpected TCP 0.0.0.0:22 listening on the host.");
      }
      const retained = argv.includes("--retain-ssh");
      if (
        this.ssh.service.active &&
        !this.privateSsh &&
        (!retained || !readHostSshAccess(this.liveFirewall).ports.includes(22))
      ) {
        return fail("Unexpected TCP 0.0.0.0:22 listening on the host.");
      }
      return ok("Host listeners, Docker publications and ark_host match the public inventory.\n");
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
  constructor(
    readonly interactive: boolean,
    private answers: [string, string][] = [],
    private secrets: [string, string][] = [],
  ) {}
  print(line = "") {
    this.output.push(line);
  }
  private take(list: [string, string][], question: string) {
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
  const stateDir = join(root, "tmp", "host-setup");
  return { root, host, stateDir, osRelease };
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
    paths: { osRelease: f.osRelease, hostFirewall: f.host.firewallPath },
    isRoot: true,
    platform: "linux",
    bun: BUN,
    stdinIsTty: Boolean(ui?.interactive),
    sleep: async () => {
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

const BASE = ["--non-interactive", "--domain", "example.com", "--acme-email", "ops@example.com"];
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
        ["Continue", "<default>"],
        ["policy is saved", ""],
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

describe("host:setup full run", () => {
  test("installs end to end without editing files; summary has the token, the log does not", async () => {
    const f = fixture();
    f.host.ufw = `Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n[ 2] 80/tcp                     ALLOW IN    Anywhere\n[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n`;
    const result = await setup(f, [...FULL, "--ssh-user", "alice"], { ...KEYS, DNS_API_TOKEN: DNS_TOKEN });
    expect(result.code).toBe(0);
    const order = [
      `${BUN} scripts/install.ts --enroll-vps --key-stdin`,
      `${BUN} scripts/install.ts --harden-vps`,
      "up -d edge-ts edge edge-l4",
      "scripts/edge-namespace.ts",
      "up --wait --wait-timeout 120 api domain-worker",
      "systemctl stop ssh.service",
      `${BUN} scripts/host-audit.ts --inventory`,
      `${BUN} scripts/host-audit.ts`,
    ].map((needle) => f.host.calls.findIndex((call) => call === needle || call.endsWith(needle)));
    expect(order.every((index) => index >= 0)).toBe(true);
    expect(order).toEqual(order.toSorted((a, b) => a - b));
    // UFW: only the SSH rules are removed, highest number first.
    expect(f.host.calls.filter((call) => call.startsWith("ufw --force delete"))).toEqual([
      "ufw --force delete 3",
      "ufw --force delete 1",
    ]);

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
    expect(first.state.steps["provider-firewall"].status).toBe("failed");
    expect(first.text).toContain(`cd ${f.root} && sudo mise run host:setup`);
    const secrets = parseEnvFile(readFileSync(f.host.envPath, "utf8"));
    f.host.calls = [];
    const second = await setup(f, FULL, {});
    expect(second.code).toBe(0);
    expect(f.host.calls).not.toContain(`${BUN} scripts/install.ts --enroll-vps --key-stdin`);
    expect(f.host.calls).not.toContain(`${BUN} scripts/install.ts --harden-vps`);
    expect(f.host.calls).toContain(`${BUN} scripts/host-audit.ts`);
    const after = parseEnvFile(readFileSync(f.host.envPath, "utf8"));
    for (const key of ["ARK_ROOT_KEY", "BETTER_AUTH_SECRET", "ARK_SETUP_TOKEN", "ARK_CONTROL_DB_PASSWORD"]) {
      expect(after[key]).toBe(secrets[key]!);
    }
  });

  test("a failed install resumes at the install step without enrolling again", async () => {
    const f = fixture();
    f.host.failInstall = 1;
    const first = await setup(f, FULL, KEYS);
    expect(first.code).toBe(1);
    expect(first.state.steps.install.status).toBe("failed");
    expect(first.state.steps.tailscale.status).toBe("done");
    f.host.calls = [];
    expect((await setup(f, FULL, { TS_EDGE_AUTHKEY: EDGE_KEY })).code).toBe(0);
    expect(f.host.calls).not.toContain(`${BUN} scripts/install.ts --enroll-vps --key-stdin`);
    expect(f.host.calls).toContain(`${BUN} scripts/install.ts --harden-vps`);
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
    expect(f.host.calls).toContain(`${BUN} scripts/host-audit.ts --retain-ssh`);
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

describe("host:setup provider firewall", () => {
  test("without confirmation (non-interactive) the rules are printed, audited and left pending", async () => {
    const f = fixture();
    const result = await setup(f, [...BASE, "--tailscale-ssh-confirmed"], KEYS);
    expect(result.code).toBe(0);
    expect(result.state.steps["provider-firewall"].status).toBe("pending");
    expect(result.text).toContain("allow UDP 41641, 41642 from 0.0.0.0/0 and ::/0");
    expect(result.text).toContain("--provider-firewall-applied");
    expect(f.host.calls).toContain(`${BUN} scripts/host-audit.ts --retain-ssh`);
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

const servers: { stop: (force?: boolean) => unknown }[] = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});

/** A mock of the Tailscale API v2 endpoints the setup uses. */
class MockTailscale {
  policy = DEFAULT_POLICY;
  etag = '"etag-1"';
  requests: { method: string; path: string; auth: string; body: string; ifMatch?: string }[] = [];
  keys = new Map<string, { key: string; body: Record<string, any>; revoked: boolean }>();
  validateProblem?: string;
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
      return Response.json({ access_token: OAUTH_ACCESS, token_type: "Bearer", expires_in: 3600 });
    }
    if (auth !== `Bearer ${API_TOKEN}` && auth !== `Bearer ${OAUTH_ACCESS}`)
      return Response.json({ message: "unauthorized" }, { status: 401 });
    const base = "/api/v2/tailnet/-";
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
      return this.validateProblem ? Response.json({ message: this.validateProblem }) : new Response("");
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
      const key = tag === "tag:ark-vps" ? VPS_KEY : tag === "tag:ark-edge" ? EDGE_KEY : BACKUP_KEY;
      const id = `k${this.keys.size + 1}`;
      this.keys.set(id, { key, body: parsed, revoked: false });
      return Response.json({ id, key, keyType: "auth", capabilities: parsed.capabilities });
    }
    const revoke = new RegExp(`^${base}/keys/(k\\d+)$`).exec(url.pathname);
    if (request.method === "DELETE" && revoke) {
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
              .map((firewall) => ({ id: firewall.id, status: "applied" })),
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
      return Response.json({ actions: [this.action()] }, { status: 201 });
    }
    const action = /^\/v1\/actions\/(\d+)$/.exec(path);
    if (action) return Response.json({ action: { id: Number(action[1]), status: "success" } });
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

describe("host:setup with a Tailscale API credential", () => {
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
    for (const line of DEFAULT_POLICY.split("\n")) expect(mock.policy).toContain(line);
    const policy = parseHujson(mock.policy) as Record<string, any>;
    expect(policy.tagOwners).toEqual({
      "tag:ark-vps": ["autogroup:admin"],
      "tag:ark-edge": ["autogroup:admin"],
    });
    expect(policy.grants).toContainEqual({ src: ["autogroup:admin"], dst: ["tag:ark-vps"], ip: ["tcp:22"] });
    expect(policy.ssh).toHaveLength(2);
    expect(result.text).toContain('+ \t"tagOwners"');
    expect(result.text).toContain("catch-all grant");
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
    // The edge key reaches Compose through the environment only, and edge-ts is recreated without it.
    expect(f.host.containerKeys).toEqual([{ service: "edge-ts", key: EDGE_KEY, from: "env" }]);
    expect(f.host.configuredKeys.has("edge-ts")).toBe(false);
    expect(at("up -d edge-ts")).toBeLessThan(at("api DELETE /api/v2/tailnet/-/keys/k2"));
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
    expect(f.host.containerKeys).toContainEqual({ service: "backup-ts", key: BACKUP_KEY, from: "env" });
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
});

describe("Tailscale API key source", () => {
  const quietUi = (answers: [string, string][] = [], secrets: [string, string][] = []) =>
    new ScriptedUi(true, answers, secrets);
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

  test("interactive: shows the diff and a 'no' applies nothing and mints nothing", async () => {
    const mock = new MockTailscale();
    const ui = quietUi([["Apply this change to the tailnet policy", "no"]]);
    const { api: client, credential } = api(mock);
    const source = apiKeySource(client, credential, { ui, interactive: true, approve: false, backup: false });
    await expect(
      source.acquire({ tag: "tag:ark-vps", variable: "TS_VPS_AUTHKEY", optional: false }),
    ).rejects.toThrow("declined");
    expect(ui.output.join("\n")).toContain("Proposed tailnet policy change");
    expect(mock.writes()).toEqual([]);
  });

  test("an unchanged policy is neither validated nor rewritten", async () => {
    const mock = new MockTailscale();
    mock.policy = mergeArkPolicy(DEFAULT_POLICY, {
      tags: ["tag:ark-vps", "tag:ark-edge"],
      owners: ["autogroup:admin"],
    }).text;
    const ui = quietUi();
    const { api: client, credential } = api(mock);
    const source = apiKeySource(client, credential, { ui, interactive: true, approve: false, backup: false });
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
      interactive: false,
      approve: true,
      backup: false,
    });
    await expect(source.preparePolicy!()).rejects.toThrow("Tailscale rejected the merged policy");
    expect(mock.writes()).toEqual([]);
  });

  test("an OAuth client exchanges its secret, owns the Ark tags through its tag and mints with the token", async () => {
    const mock = new MockTailscale();
    const credential = credentialFromEnv({ TS_OAUTH_CLIENT_SECRET: OAUTH_SECRET })!;
    expect(credential).toMatchObject({ kind: "oauth", clientId: "kOAU5678CNTRL", tag: "tag:ark-setup" });
    const { api: client, seen } = api(mock, credential);
    const source = apiKeySource(client, credential, {
      ui: quietUi(),
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

  test("the automatic source asks once for a credential and falls back to the manual steps on Enter", async () => {
    const ui = quietUi(
      [["policy is saved", ""]],
      [
        ["Tailscale API access token", ""],
        ["tag:ark-edge key", EDGE_KEY],
      ],
    );
    const source = automaticKeySource({
      env: {},
      ui,
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
  const request = { tags: ["tag:ark-vps", "tag:ark-edge"], owners: ["autogroup:admin"] };

  test("adds only the Ark entries, keeps comments and is idempotent", () => {
    const merged = mergeArkPolicy(DEFAULT_POLICY, request);
    expect(merged.changed).toBe(true);
    expect(merged.additions).toHaveLength(4);
    const diff = lineDiff(DEFAULT_POLICY, merged.text);
    expect(diff.filter((line) => line.startsWith("- "))).toEqual([]);
    expect(diff.some((line) => line.startsWith('+ \t\t{ "src": ["autogroup:admin"]'))).toBe(true);
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

  test("a very large policy still gets an insert-only diff", () => {
    const hosts = Array.from(
      { length: 3000 },
      (_, index) => `    "host-${index}": "100.64.${index >> 8}.${index & 255}",`,
    );
    const text = `{\n  "grants": [\n    { "src": ["group:ops"], "dst": ["host-1"], "ip": ["tcp:443"] },\n  ],\n  "hosts": {\n${hosts.join("\n")}\n  },\n}\n`;
    const merged = mergeArkPolicy(text, request);
    const diff = lineDiff(text, merged.text);
    expect(diff.filter((line) => line.startsWith("- "))).toEqual([]);
    expect(diff.filter((line) => line.startsWith("+ ")).length).toBeGreaterThan(5);
    expect(diff.length).toBeLessThan(40);
  });

  test("refuses a policy it cannot merge safely", () => {
    expect(() => mergeArkPolicy("[]", request)).toThrow("not a JSON object");
    expect(() => mergeArkPolicy('{"grants": {}}', request)).toThrow('"grants" is not a list');
    expect(() => mergeArkPolicy('{"grants": [', request)).toThrow("not valid HuJSON");
  });
});

describe("Hetzner Cloud provider firewall", () => {
  const firewallArgs = [...BASE, "--tailscale-ssh-confirmed", "--verify-ssh-cutover"];

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
    const auditAt = f.host.calls.lastIndexOf(`${BUN} scripts/host-audit.ts`);
    expect(createdAt).toBeGreaterThan(-1);
    expect(auditAt).toBeGreaterThan(createdAt);
    for (const output of [result.text, result.log]) expect(output).not.toContain(HCLOUD_TOKEN);
    expect(filesWithSecrets(f.root, [HCLOUD_TOKEN])).toEqual([]);

    const writes = hetzner.writes().length;
    const again = await setup(f, firewallArgs, env, deps);
    expect(again.code).toBe(0);
    expect(hetzner.writes()).toHaveLength(writes);
    expect(again.text).toContain("provider already matches (Hetzner Cloud API)");
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
    await expect(adapter.plan(PROVIDER_RULES as never, context)).rejects.toThrow("Ark did not create it");
    hetzner.firewalls[0] = {
      id: 5,
      name: "ark-stack-4242",
      labels: { "managed-by": "ark-stack" },
      rules: [],
      applied_to: [{ type: "label_selector", label_selector: { selector: "env=prod" } }],
    };
    await expect(adapter.plan(PROVIDER_RULES as never, context)).rejects.toThrow(
      "also applied to other resources",
    );
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
