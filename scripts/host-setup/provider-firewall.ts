// Provider firewall adapters for the guided setup.
//
// The setup derives the inbound rules from `host:audit --inventory` and hands them to the first
// adapter whose `detect` succeeds (or the one named by --provider-firewall). The manual adapter works
// for every provider: it prints the exact rules and waits for the owner to confirm. An API adapter
// (part 2: Hetzner) implements the same three calls and is listed before the manual one, so the
// setup flow does not change.
import type { Ui } from "./system.ts";

/** One `providerRules` entry from `host:audit --inventory`. */
export type ProviderRule = { protocol: "tcp" | "udp"; ports: number[]; sourceCidrs: string[] };

export type FirewallContext = {
  ui: Ui;
  interactive: boolean;
  env: Record<string, string | undefined>;
  /** The VPS's public addresses, for adapters that look the server up. */
  publicAddresses: { ipv4: string[]; ipv6: string[] };
  /** The owner already said the rules are applied (--provider-firewall-applied). */
  confirmed: boolean;
};

export type FirewallPlan = {
  adapter: string;
  /** True when the provider already matches the rules (nothing to apply). */
  inSync: boolean;
  /** Human-readable changes or instructions, printed before `apply`. */
  changes: string[];
};

export type FirewallResult =
  | { status: "applied" }
  /** The rules still have to be applied; `finish` says how. */
  | { status: "pending"; note: string; finish: string };

export interface ProviderFirewall {
  readonly id: string;
  readonly label: string;
  /** Whether this adapter can manage this VPS (credentials present, server found). */
  detect(context: FirewallContext): Promise<boolean>;
  /** The changes needed, or a diff against the provider's current rules. */
  plan(rules: ProviderRule[], context: FirewallContext): Promise<FirewallPlan>;
  apply(plan: FirewallPlan, context: FirewallContext): Promise<FirewallResult>;
}

export function describeProviderRules(rules: ProviderRule[]) {
  const lines = ["Inbound rules for this VPS (IPv4 and IPv6; everything else inbound denied):"];
  for (const rule of rules) {
    if (!rule.ports.length) continue;
    lines.push(
      `  allow ${rule.protocol.toUpperCase()} ${rule.ports.join(", ")} from ${rule.sourceCidrs.join(" and ")}`,
    );
  }
  lines.push("  keep the provider's required ICMP and ICMPv6 allowances");
  lines.push("  remove any inbound TCP 22 (SSH) rule: administration is over Tailscale SSH");
  return lines;
}

export const manualProviderFirewall: ProviderFirewall = {
  id: "manual",
  label: "any provider (manual)",
  async detect() {
    return true;
  },
  async plan(rules) {
    return { adapter: "manual", inSync: false, changes: describeProviderRules(rules) };
  },
  async apply(_plan, context) {
    if (context.confirmed) return { status: "applied" };
    const finish =
      "Apply the rules above in your provider's firewall, then re-run host:setup with --provider-firewall-applied.";
    if (!context.interactive) {
      return {
        status: "pending",
        note: "The provider firewall rules were printed but not confirmed.",
        finish,
      };
    }
    context.ui.print("Apply these rules in your provider's firewall (console or infrastructure code) now.");
    const answer = await context.ui.ask("Type yes once they are applied, or skip to finish this later", "");
    if (/^y(?:es)?$/i.test(answer.trim())) return { status: "applied" };
    return { status: "pending", note: "The provider firewall rules were not confirmed.", finish };
  },
};

/** Adapters in priority order. Part 2 adds API adapters before the manual fallback. */
export const providerFirewalls: ProviderFirewall[] = [manualProviderFirewall];

export async function selectProviderFirewall(
  adapters: ProviderFirewall[],
  context: FirewallContext,
  requested?: string,
) {
  if (requested) {
    const adapter = adapters.find((candidate) => candidate.id === requested);
    if (!adapter) {
      throw new Error(
        `Unknown provider firewall "${requested}". Available: ${adapters.map((item) => item.id).join(", ")}.`,
      );
    }
    if (!(await adapter.detect(context))) {
      throw new Error(`The ${adapter.label} firewall adapter cannot manage this VPS (detect failed).`);
    }
    return adapter;
  }
  for (const adapter of adapters) {
    if (await adapter.detect(context)) return adapter;
  }
  return manualProviderFirewall;
}
