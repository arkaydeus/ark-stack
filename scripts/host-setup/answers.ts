// The guided setup's questions. Each answer comes from a flag, else its environment variable, else
// the previous run (state file), else the installed `.env`, else a default; interactive runs then
// confirm it at a prompt. `--non-interactive` never prompts and fails naming any missing answer.
import { normalizeHostname, parseSniPorts } from "@ark-stack/shared";

import { automaticUpdatesConfig } from "../install-host-hardening.ts";
import type { StoredAnswers } from "./state.ts";
import type { Ui } from "./system.ts";

export type Options = {
  nonInteractive: boolean;
  keepPublicSsh: boolean;
  skipEdge: boolean;
  tailscaleSshConfirmed: boolean;
  providerFirewallApplied: boolean;
  providerFirewall?: string;
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
  "--provider-firewall",
]);
const BOOLEAN_FLAGS = new Set([
  "--non-interactive",
  "--keep-public-ssh",
  "--skip-edge",
  "--tailscale-ssh-confirmed",
  "--provider-firewall-applied",
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

Tailscale keys (environment only; read without echo otherwise):
  TS_VPS_AUTHKEY or TS_VPS_AUTHKEY_FILE   one-off key for tag:ark-vps
  TS_EDGE_AUTHKEY                         one-off key for tag:ark-edge

Steps and safety:
  --non-interactive             ARK_SETUP_NON_INTERACTIVE=1          Never prompt
  --tailscale-ssh-confirmed     ARK_SETUP_TAILSCALE_SSH_CONFIRMED=1  You checked Tailscale SSH works
  --skip-edge                   ARK_SETUP_SKIP_EDGE=1                Enrol the edge node later
  --keep-public-ssh             ARK_SETUP_KEEP_PUBLIC_SSH=1          Leave OpenSSH listening
  --provider-firewall ID        ARK_SETUP_PROVIDER_FIREWALL          Firewall adapter (default: manual)
  --provider-firewall-applied   ARK_SETUP_PROVIDER_FIREWALL_APPLIED=1  You applied the printed rules
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
  return {
    nonInteractive: flag("--non-interactive", "ARK_SETUP_NON_INTERACTIVE"),
    keepPublicSsh: flag("--keep-public-ssh", "ARK_SETUP_KEEP_PUBLIC_SSH"),
    skipEdge: flag("--skip-edge", "ARK_SETUP_SKIP_EDGE"),
    tailscaleSshConfirmed: flag("--tailscale-ssh-confirmed", "ARK_SETUP_TAILSCALE_SSH_CONFIRMED"),
    providerFirewallApplied: flag("--provider-firewall-applied", "ARK_SETUP_PROVIDER_FIREWALL_APPLIED"),
    providerFirewall: typeof firewall === "string" && firewall.trim() ? firewall.trim() : undefined,
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
  if (user && !/^[a-z_][a-z0-9_-]{0,31}$/.test(user)) throw new Error(`"${user}" is not a local user name.`);
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
    (previous.domain === domain ? previous.adminHost : undefined) ??
      [adminHostFromEnv(dotenv)].find((host) => host?.endsWith(`.${domain}`)) ??
      `admin.${domain}`,
    validateDomain,
    "the admin hostname (--admin-host or ARK_SETUP_ADMIN_HOST)",
  );
  const acmeEmail = await text(
    "Let's Encrypt account email (empty: certificates cannot be issued yet)",
    given("--acme-email", "ARK_ACME_EMAIL"),
    previous.acmeEmail ?? dotenv.ARK_ACME_EMAIL,
    validateEmail,
  );

  let trustedCertificates: boolean;
  const certFlag = flags.has("--trusted-certificates")
    ? true
    : flags.has("--staging-certificates")
      ? false
      : env.ARK_ACME_STAGING?.trim()
        ? !parseBool(env.ARK_ACME_STAGING, "ARK_ACME_STAGING")
        : undefined;
  if (!acmeEmail) trustedCertificates = false;
  else if (!interactive) trustedCertificates = certFlag ?? previous.trustedCertificates ?? true;
  else {
    trustedCertificates = await text(
      "Issue trusted Let's Encrypt certificates? (no: staging, untrusted, for testing)",
      certFlag === undefined ? undefined : certFlag ? "yes" : "no",
      (previous.trustedCertificates ?? true) ? "yes" : "no",
      (value) => parseBool(value, "Trusted certificates"),
    );
  }

  const mailFlag = flags.has("--mail")
    ? "yes"
    : flags.has("--no-mail")
      ? "no"
      : env.ARK_MAIL_ENABLED?.trim() || undefined;
  const previousMail =
    previous.mailEnabled ??
    (dotenv.ARK_MAIL_ENABLED === undefined ? undefined : dotenv.ARK_MAIL_ENABLED !== "0");
  const mailEnabled = await text(
    "Enable incoming mail (Stalwart on TCP 25, 465, 587 and 993)?",
    mailFlag,
    (previousMail ?? true) ? "yes" : "no",
    (value) => parseBool(value, "Mail"),
  );

  const sniPorts = await text(
    "Shared SNI ports for TLS-TCP routes, comma-separated from 8883, 5671, 636, 6380 (empty: 443 only)",
    given("--sni-ports", "ARK_EDGE_SNI_PORTS"),
    previous.sniPorts?.join(",") ?? dotenv.ARK_EDGE_SNI_PORTS ?? "",
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
    previous.rebootTime ?? dotenv.ARK_HOST_REBOOT_TIME ?? "04:00",
    validateRebootTime,
  );

  const sudoUser = env.SUDO_USER && env.SUDO_USER !== "root" ? env.SUDO_USER : undefined;
  const sshUser = await text(
    "Your local (non-root) user on this VPS for Tailscale SSH",
    given("--ssh-user", "ARK_SETUP_SSH_USER"),
    previous.sshUser ?? sudoUser,
    validateSshUser,
  );

  return {
    domain,
    adminHost,
    acmeEmail,
    trustedCertificates,
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
