// The guided setup's questions. Each answer comes from a flag, else its environment variable, else
// the installed `.env`, else the previous run (state file), else a default; interactive runs then
// confirm it at a prompt. `--non-interactive` never prompts and fails naming any missing answer.
import { normalizeHostname, parseSniPorts } from "@ark-stack/shared";
import { isIP } from "node:net";

import { automaticUpdatesConfig } from "../install-host-hardening.ts";
import type { StoredAnswers } from "./state.ts";
import type { Ui } from "./system.ts";

export type Options = {
  nonInteractive: boolean;
  keepPublicSsh: boolean;
  sshRecoverySource?: string;
  verifySshCutover: boolean;
  skipEdge: boolean;
  tailscaleSshConfirmed: boolean;
  providerFirewallApplied: boolean;
  providerFirewall?: string;
  /** Apply an API adapter's provider firewall plan without asking. */
  approveProviderFirewall: boolean;
  /** Apply the Tailscale API source's policy change without asking. */
  approveTailnetPolicy: boolean;
  /** Enrol the backup node (backup-ts, tag:ark-backup) for a home backup target. */
  backupNode: boolean;
  help: boolean;
};

export type Answers = StoredAnswers & {
  /** A new Cloudflare token to write; `undefined` keeps whatever `.env` has. Never stored in state. */
  dnsApiToken?: string;
};

type Flags = Map<string, string | true>;

const VALUE_FLAGS = new Set([
  "--domain",
  "--admin-host",
  "--acme-email",
  "--sni-ports",
  "--reboot-time",
  "--ssh-user",
  "--ssh-recovery-source",
  "--provider-firewall",
]);
const BOOLEAN_FLAGS = new Set([
  "--non-interactive",
  "--keep-public-ssh",
  "--verify-ssh-cutover",
  "--skip-edge",
  "--tailscale-ssh-confirmed",
  "--provider-firewall-applied",
  "--approve-provider-firewall",
  "--approve-tailnet-policy",
  "--backup-node",
  "--mail",
  "--no-mail",
  "--trusted-certificates",
  "--staging-certificates",
  "--help",
  "-h",
]);

export const USAGE = `Usage: mise run host:setup [options]

Guided production install on an Ubuntu VPS (run as root). Every answer can be given as a flag or
environment variable; --non-interactive never prompts and fails naming any missing answer.

Questions:
  --domain NAME                 ARK_SETUP_DOMAIN            Your domain (required)
  --admin-host NAME             ARK_SETUP_ADMIN_HOST        Admin hostname (default admin.<domain>)
  --acme-email ADDRESS          ARK_ACME_EMAIL              Let's Encrypt account email
  --trusted-certificates | --staging-certificates
                                ARK_ACME_STAGING=0|1        Trusted (default with an email) or staging
  --mail | --no-mail            ARK_MAIL_ENABLED=1|0        Incoming mail (default on)
  --sni-ports LIST              ARK_EDGE_SNI_PORTS          Shared SNI ports from 8883,5671,636,6380
  (environment only)            DNS_API_TOKEN               Optional Cloudflare DNS token
  --reboot-time HH:MM           ARK_HOST_REBOOT_TIME        Automatic reboot time (default 04:00)
  --ssh-user NAME               ARK_SETUP_SSH_USER          Your local user for Tailscale SSH

Tailscale (environment only; read without echo otherwise):
  TS_API_KEY                              API access token: setup merges the policy and mints the keys
  TS_OAUTH_CLIENT_SECRET                  or an OAuth client (scopes policy_file, auth_keys,
                                         devices:posture_attributes and devices:core:read)
    [TS_OAUTH_CLIENT_ID, TS_OAUTH_TAG]    tag tag:ark-setup; TS_TAILNET picks the tailnet (default -)
  TS_VPS_AUTHKEY or TS_VPS_AUTHKEY_FILE   or a one-off key for tag:ark-vps, pasted or given here
  TS_EDGE_AUTHKEY                         one-off key for tag:ark-edge
  TS_BACKUP_AUTHKEY                       one-off key for tag:ark-backup (with --backup-node)
  --approve-tailnet-policy      ARK_SETUP_APPROVE_TAILNET_POLICY=1   Preapprove the shown change with --non-interactive
  --backup-node                 ARK_SETUP_BACKUP_NODE=1              Also enrol backup-ts (tag:ark-backup)

Provider firewall:
  --provider-firewall ID        ARK_SETUP_PROVIDER_FIREWALL          Adapter: hetzner or manual (default: detect)
  (environment only)            HCLOUD_TOKEN                         Hetzner Cloud API token (Read & Write)
  --approve-provider-firewall   ARK_SETUP_APPROVE_PROVIDER_FIREWALL=1  Preapprove the shown change with --non-interactive
  --provider-firewall-applied   ARK_SETUP_PROVIDER_FIREWALL_APPLIED=1  You applied the printed rules (manual)

Steps and safety:
  --non-interactive             ARK_SETUP_NON_INTERACTIVE=1          Never prompt
  --tailscale-ssh-confirmed     ARK_SETUP_TAILSCALE_SSH_CONFIRMED=1  You checked Tailscale SSH works
  --skip-edge                   ARK_SETUP_SKIP_EDGE=1                Enrol the edge node later
  --keep-public-ssh             ARK_SETUP_KEEP_PUBLIC_SSH=1          Leave OpenSSH listening
  --ssh-recovery-source IP      ARK_SETUP_SSH_RECOVERY_SOURCE         IP allowed to reconnect during SSH cutover
  --verify-ssh-cutover           ARK_SETUP_VERIFY_SSH_CUTOVER=1       Wait for off-host proof in scripted mode
`;

export function parseFlags(argv: string[]): Flags {
  const flags: Flags = new Map();
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    const eq = arg.indexOf("=");
    const name = eq > 0 ? arg.slice(0, eq) : arg;
    if (VALUE_FLAGS.has(name)) {
      const value = eq > 0 ? arg.slice(eq + 1) : argv[++index];
      if (value === undefined || (eq < 0 && value.startsWith("--")))
        throw new Error(`${name} needs a value.`);
      flags.set(name, value);
    } else if (BOOLEAN_FLAGS.has(name) && eq < 0) {
      flags.set(name, true);
    } else {
      throw new Error(`Unknown option ${arg}. Run mise run host:setup --help.`);
    }
  }
  if (flags.has("--mail") && flags.has("--no-mail"))
    throw new Error("Give only one of --mail and --no-mail.");
  if (flags.has("--trusted-certificates") && flags.has("--staging-certificates")) {
    throw new Error("Give only one of --trusted-certificates and --staging-certificates.");
  }
  return flags;
}

const truthy = (value: string | undefined) => /^(?:1|true|yes)$/i.test(value?.trim() ?? "");

export function resolveOptions(flags: Flags, env: Record<string, string | undefined>): Options {
  const flag = (name: string, variable: string) => flags.has(name) || truthy(env[variable]);
  const firewall = flags.get("--provider-firewall") ?? env.ARK_SETUP_PROVIDER_FIREWALL;
  const recovery = flags.get("--ssh-recovery-source") ?? env.ARK_SETUP_SSH_RECOVERY_SOURCE;
  if (typeof recovery === "string" && (!isIP(recovery) || recovery.includes("%")))
    throw new Error("--ssh-recovery-source needs a single IP address.");
  return {
    nonInteractive: flag("--non-interactive", "ARK_SETUP_NON_INTERACTIVE"),
    keepPublicSsh: flag("--keep-public-ssh", "ARK_SETUP_KEEP_PUBLIC_SSH"),
    sshRecoverySource: typeof recovery === "string" ? recovery : undefined,
    verifySshCutover: flag("--verify-ssh-cutover", "ARK_SETUP_VERIFY_SSH_CUTOVER"),
    skipEdge: flag("--skip-edge", "ARK_SETUP_SKIP_EDGE"),
    tailscaleSshConfirmed: flag("--tailscale-ssh-confirmed", "ARK_SETUP_TAILSCALE_SSH_CONFIRMED"),
    providerFirewallApplied: flag("--provider-firewall-applied", "ARK_SETUP_PROVIDER_FIREWALL_APPLIED"),
    providerFirewall: typeof firewall === "string" && firewall.trim() ? firewall.trim() : undefined,
    approveProviderFirewall: flag("--approve-provider-firewall", "ARK_SETUP_APPROVE_PROVIDER_FIREWALL"),
    approveTailnetPolicy: flag("--approve-tailnet-policy", "ARK_SETUP_APPROVE_TAILNET_POLICY"),
    backupNode: flag("--backup-node", "ARK_SETUP_BACKUP_NODE"),
    help: flags.has("--help") || flags.has("-h"),
  };
}

export function validateDomain(value: string) {
  return normalizeHostname(value);
}

export function validateEmail(value: string) {
  const email = value.trim();
  if (email && !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(email)) {
    throw new Error(`"${email}" is not an email address.`);
  }
  return email;
}

export function validateRebootTime(value: string) {
  automaticUpdatesConfig(value.trim());
  return value.trim();
}

export function validateSshUser(value: string) {
  const user = value.trim();
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(user) || user === "root") {
    throw new Error("Supply a non-root local SSH user (--ssh-user or ARK_SETUP_SSH_USER).");
  }
  return user;
}

export function validateDnsToken(value: string) {
  const token = value.trim();
  if (token && !/^[A-Za-z0-9_-]{20,}$/.test(token)) {
    throw new Error("DNS_API_TOKEN does not look like a Cloudflare API token; it was not used.");
  }
  return token;
}

function parseBool(value: string, name: string) {
  if (/^(?:1|y|yes|true|on)$/i.test(value.trim())) return true;
  if (/^(?:0|n|no|false|off)$/i.test(value.trim())) return false;
  throw new Error(`${name}: answer yes or no.`);
}

export type AnswerSources = {
  flags: Flags;
  env: Record<string, string | undefined>;
  previous: Partial<StoredAnswers>;
  /** The installed `.env`, if any. */
  dotenv: Record<string, string>;
  interactive: boolean;
  ui: Ui;
};

function adminHostFromEnv(dotenv: Record<string, string>) {
  try {
    const url = new URL(dotenv.BETTER_AUTH_URL ?? "");
    return url.protocol === "https:" ? url.hostname : undefined;
  } catch {
    return undefined;
  }
}

/** Resolves every answer. In non-interactive mode a missing required answer fails, naming it. */
export async function resolveAnswers(sources: AnswerSources): Promise<Answers> {
  const { flags, env, previous, dotenv, interactive, ui } = sources;
  const given = (flag: string | undefined, variable: string | undefined) => {
    const fromFlag = flag ? flags.get(flag) : undefined;
    if (typeof fromFlag === "string") return fromFlag;
    const fromEnv = variable ? env[variable] : undefined;
    return fromEnv !== undefined && fromEnv.trim() !== "" ? fromEnv : undefined;
  };

  async function text<T>(
    question: string,
    explicit: string | undefined,
    fallback: string | undefined,
    validate: (value: string) => T,
    missing?: string,
  ): Promise<T> {
    // A flag or variable answers the question outright, in either mode.
    if (explicit !== undefined) return validate(explicit);
    if (!interactive) {
      if ((fallback === undefined || fallback.trim() === "") && missing) {
        throw new Error(`Missing required answer: ${missing}.`);
      }
      return validate(fallback ?? "");
    }
    for (;;) {
      const value = await ui.ask(question, fallback ?? "");
      if (!value.trim() && missing) {
        ui.print("  An answer is required.");
        continue;
      }
      try {
        return validate(value);
      } catch (error) {
        ui.print(`  ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  const domain = await text(
    "Your domain (for example example.com)",
    given("--domain", "ARK_SETUP_DOMAIN"),
    previous.domain,
    validateDomain,
    "the domain (--domain or ARK_SETUP_DOMAIN)",
  );
  const adminHost = await text(
    "Admin hostname",
    given("--admin-host", "ARK_SETUP_ADMIN_HOST"),
    [adminHostFromEnv(dotenv)].find((host) => host?.endsWith(`.${domain}`)) ??
      (previous.domain === domain ? previous.adminHost : undefined) ??
      `admin.${domain}`,
    validateDomain,
    "the admin hostname (--admin-host or ARK_SETUP_ADMIN_HOST)",
  );
  const acmeEmail = await text(
    "Let's Encrypt account email (empty: certificates cannot be issued yet)",
    given("--acme-email", "ARK_ACME_EMAIL"),
    dotenv.ARK_ACME_EMAIL ?? previous.acmeEmail,
    validateEmail,
  );

  const certFlag = flags.has("--trusted-certificates")
    ? true
    : flags.has("--staging-certificates")
      ? false
      : env.ARK_ACME_STAGING?.trim()
        ? !parseBool(env.ARK_ACME_STAGING, "ARK_ACME_STAGING")
        : undefined;
  const installedPreference = dotenv.ARK_ACME_EMAIL?.trim()
    ? !parseBool(dotenv.ARK_ACME_STAGING?.trim() || "1", "ARK_ACME_STAGING")
    : undefined;
  let certificatePreference =
    certFlag ??
    installedPreference ??
    previous.certificatePreference ??
    (dotenv.ARK_ACME_EMAIL === undefined && previous.acmeEmail ? previous.trustedCertificates : undefined);
  if (acmeEmail && interactive) {
    certificatePreference = await text(
      "Issue trusted Let's Encrypt certificates? (no: staging, untrusted, for testing)",
      certFlag === undefined ? undefined : certFlag ? "yes" : "no",
      (certificatePreference ?? true) ? "yes" : "no",
      (value) => parseBool(value, "Trusted certificates"),
    );
  }
  const trustedCertificates = Boolean(acmeEmail && (certificatePreference ?? true));

  const mailFlag = flags.has("--mail")
    ? "yes"
    : flags.has("--no-mail")
      ? "no"
      : env.ARK_MAIL_ENABLED?.trim() || undefined;
  const previousMail = dotenv.ARK_MAIL_ENABLED?.trim()
    ? parseBool(dotenv.ARK_MAIL_ENABLED, "ARK_MAIL_ENABLED")
    : previous.mailEnabled;
  const mailEnabled = await text(
    "Enable incoming mail (Stalwart on TCP 25, 465, 587 and 993)?",
    mailFlag,
    (previousMail ?? true) ? "yes" : "no",
    (value) => parseBool(value, "Mail"),
  );

  const sniPorts = await text(
    "Shared SNI ports for TLS-TCP routes, comma-separated from 8883, 5671, 636, 6380 (empty: 443 only)",
    given("--sni-ports", "ARK_EDGE_SNI_PORTS"),
    dotenv.ARK_EDGE_SNI_PORTS ?? previous.sniPorts?.join(",") ?? "",
    (value) => parseSniPorts(value),
  );

  let dnsApiToken: string | undefined;
  const dnsFromEnv = env.DNS_API_TOKEN?.trim();
  if (dnsFromEnv) dnsApiToken = validateDnsToken(dnsFromEnv);
  else if (interactive) {
    const existing = Boolean(dotenv.DNS_API_TOKEN?.trim());
    for (;;) {
      const value = await ui.askSecret(
        existing
          ? "Cloudflare DNS API token (Enter keeps the one already in .env)"
          : "Cloudflare DNS API token for automatic DNS publishing (Enter to skip)",
      );
      try {
        dnsApiToken = validateDnsToken(value) || undefined;
        break;
      } catch (error) {
        ui.print(`  ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  const rebootTime = await text(
    "Daily automatic reboot time for security updates (HH:MM, server time)",
    given("--reboot-time", "ARK_HOST_REBOOT_TIME"),
    dotenv.ARK_HOST_REBOOT_TIME ?? previous.rebootTime ?? "04:00",
    validateRebootTime,
  );

  const sudoUser = env.SUDO_USER && env.SUDO_USER !== "root" ? env.SUDO_USER : undefined;
  const sshUser = await text(
    "Your local (non-root) user on this VPS for Tailscale SSH",
    given("--ssh-user", "ARK_SETUP_SSH_USER"),
    previous.sshUser ?? sudoUser,
    validateSshUser,
    "the local SSH user (--ssh-user or ARK_SETUP_SSH_USER)",
  );

  return {
    domain,
    adminHost,
    acmeEmail,
    trustedCertificates,
    certificatePreference,
    mailEnabled,
    sniPorts,
    rebootTime,
    sshUser,
    dnsApiToken,
  };
}

export function storedAnswers(answers: Answers): StoredAnswers {
  const { dnsApiToken: _secret, ...stored } = answers;
  return stored;
}

export function describeAnswers(answers: Answers, dotenv: Record<string, string>) {
  return [
    `  Domain:              ${answers.domain}`,
    `  Admin hostname:      ${answers.adminHost} (https://${answers.adminHost})`,
    `  ACME email:          ${answers.acmeEmail || "(none: certificates cannot be issued yet)"}`,
    `  Certificates:        ${answers.trustedCertificates ? "trusted (ARK_ACME_STAGING=0)" : "staging, untrusted (ARK_ACME_STAGING=1)"}`,
    `  Incoming mail:       ${answers.mailEnabled ? "on" : "off"}`,
    `  Shared SNI ports:    ${answers.sniPorts.length ? answers.sniPorts.join(", ") : "none (443 only)"}`,
    `  Cloudflare DNS:      ${answers.dnsApiToken ? "token supplied" : dotenv.DNS_API_TOKEN?.trim() ? "keep the token in .env" : "none (manual DNS records)"}`,
    `  Reboot time:         ${answers.rebootTime}`,
    `  Tailscale SSH user:  ${answers.sshUser || "(not given)"}`,
  ];
}
