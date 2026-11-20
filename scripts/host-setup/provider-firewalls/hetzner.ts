// Hetzner Cloud provider firewall adapter for the guided setup (ProviderFirewall, ../provider-firewall.ts).
//
// detect: the Hetzner metadata service names this server, and a Hetzner Cloud API token (HCLOUD_TOKEN,
//   or asked for interactively) can read it; its public IPv4 must be this host's.
// plan:   one firewall named `ark-stack-<server id>`, labelled managed-by=ark-stack, with exactly the
//   inventory's inbound rules (IPv4 and IPv6) plus ICMP and ICMPv6, applied to this server only.
//   The plan is a diff against that firewall's current rules and attachments.
// apply:  after a yes (or --approve-provider-firewall), creates or updates that one firewall and
//   attaches it to this server. Other firewalls are never modified, detached or deleted; any that
//   also apply to this server are reported, because Hetzner allows what any of them allows.
//
// The token is held in memory only and registered with the redactor.
import type { FirewallContext, FirewallPlan, ProviderFirewall, ProviderRule } from "../provider-firewall.ts";
import { approveProviderChange, errorText, portRanges } from "./common.ts";

export const HETZNER_API = "https://api.hetzner.cloud/v1";
export const HETZNER_METADATA = "http://169.254.169.254";
const MAX_RULES = 50;
const LABELS = { "managed-by": "ark-stack" };

export type HetznerRule = {
  direction: "in" | "out";
  protocol: "tcp" | "udp" | "icmp" | "esp" | "gre";
  port?: string | null;
  source_ips?: string[];
  destination_ips?: string[];
  description?: string | null;
};

type Attachment = {
  type: "server" | "label_selector";
  server?: { id: number };
  label_selector?: { selector: string };
};

export type HetznerFirewall = {
  id: number;
  name: string;
  labels?: Record<string, string>;
  rules: HetznerRule[];
  applied_to?: Attachment[];
};

type HetznerServer = {
  id: number;
  name: string;
  public_net?: {
    ipv4?: { ip: string } | null;
    ipv6?: { ip: string } | null;
    firewalls?: { id: number; status?: string }[];
  };
};

type Action = { id: number; status: "running" | "success" | "error"; error?: { message?: string } | null };

type PlanState = {
  name: string;
  existing?: HetznerFirewall;
  desired: HetznerRule[];
  rulesMatch: boolean;
  attached: boolean;
};

export type HetznerOptions = {
  apiBase?: string;
  metadataBase?: string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
};

const ruleKey = (rule: HetznerRule) =>
  [
    rule.direction,
    rule.protocol,
    rule.port ?? "",
    [...(rule.source_ips ?? [])].toSorted().join(","),
    [...(rule.destination_ips ?? [])].toSorted().join(","),
  ].join("|");

const describeRule = (rule: HetznerRule) =>
  `${rule.direction === "in" ? "inbound" : "outbound"} ${rule.protocol.toUpperCase()}${rule.port ? ` ${rule.port}` : ""} ${
    rule.direction === "in" ? "from" : "to"
  } ${(rule.direction === "in" ? rule.source_ips : rule.destination_ips)?.join(", ") ?? ""}`;

/** The Hetzner rules for the inventory's provider rules: one per port or contiguous range, plus ICMP. */
export function hetznerRules(rules: ProviderRule[]): HetznerRule[] {
  const out = new Map<string, HetznerRule>();
  for (const rule of rules) {
    for (const port of portRanges(rule.ports)) {
      const entry: HetznerRule = {
        direction: "in",
        protocol: rule.protocol,
        port,
        source_ips: [...new Set(rule.sourceCidrs)].toSorted(),
        description: `Ark Stack ${rule.protocol.toUpperCase()} ${port}`,
      };
      out.set(ruleKey(entry), entry);
    }
  }
  // Path MTU discovery, IPv6 neighbour discovery and diagnostics need ICMP and ICMPv6.
  const icmp: HetznerRule = {
    direction: "in",
    protocol: "icmp",
    source_ips: ["0.0.0.0/0", "::/0"],
    description: "Ark Stack ICMP and ICMPv6",
  };
  out.set(ruleKey(icmp), icmp);
  return [...out.values()];
}

export function sameRules(current: HetznerRule[], desired: HetznerRule[]) {
  const a = current.map(ruleKey).toSorted();
  const b = desired.map(ruleKey).toSorted();
  return a.length === b.length && a.every((key, index) => key === b[index]);
}

export function hetznerProviderFirewall(options: HetznerOptions = {}): ProviderFirewall {
  const apiBase = (options.apiBase ?? HETZNER_API).replace(/\/$/, "");
  const metadataBase = (options.metadataBase ?? HETZNER_METADATA).replace(/\/$/, "");
  const fetcher = options.fetch ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => Bun.sleep(ms));
  let session: { token: string; server: HetznerServer; log: (line: string) => void } | undefined;

  async function serverId() {
    try {
      const response = await fetcher(`${metadataBase}/hetzner/v1/metadata/instance-id`, {
        signal: AbortSignal.timeout(2000),
      });
      const text = (await response.text()).trim();
      return response.ok && /^\d+$/.test(text) ? Number(text) : undefined;
    } catch {
      return undefined;
    }
  }

  async function call<T>(
    method: string,
    path: string,
    body?: unknown,
    what = `${method} ${path}`,
  ): Promise<T> {
    if (!session) throw new Error("The Hetzner adapter was used before it detected the server.");
    const response = await fetcher(`${apiBase}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${session.token}`,
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    session.log(`Hetzner Cloud API ${method} ${path.split("?")[0]} -> ${response.status}`);
    const json = (await response.json().catch(() => ({}))) as T & {
      error?: { code?: string; message?: string };
    };
    if (!response.ok) {
      const hint =
        response.status === 401
          ? " Use a Read & Write API token from the Hetzner Cloud project that holds this server."
          : response.status === 403
            ? " The token must have Read & Write permission."
            : "";
      throw new Error(
        `Hetzner Cloud API: ${what} failed (HTTP ${response.status}${json.error?.message ? `: ${json.error.message}` : ""}).${hint}`,
      );
    }
    return json;
  }

  async function waitFor(actions: Action[] | undefined) {
    for (const action of actions ?? []) {
      let current = action;
      for (let attempt = 0; current.status === "running"; attempt++) {
        if (attempt >= 120)
          throw new Error(`Hetzner Cloud action ${action.id} did not finish within two minutes.`);
        await sleep(1000);
        current = (await call<{ action: Action }>("GET", `/actions/${action.id}`)).action;
      }
      if (current.status === "error")
        throw new Error(
          `Hetzner Cloud action ${action.id} failed: ${current.error?.message ?? "unknown error"}.`,
        );
    }
  }

  const attachedTo = (firewall: HetznerFirewall, id: number) =>
    (firewall.applied_to ?? []).some((item) => item.type === "server" && item.server?.id === id);

  return {
    id: "hetzner",
    label: "Hetzner Cloud API",

    async detect(context: FirewallContext) {
      session = undefined;
      const id = await serverId();
      if (id === undefined) return false;
      let token = context.env.HCLOUD_TOKEN?.trim();
      if (!token && context.interactive) {
        context.ui.print(`      This VPS is Hetzner Cloud server ${id}.`);
        token = (
          await context.ui.askSecret(
            "Hetzner Cloud API token (Read & Write) to manage an Ark firewall for this server (Enter to apply the rules by hand)",
          )
        ).trim();
      }
      if (!token) return false;
      context.secret?.(token);
      session = { token, server: { id, name: String(id) }, log: context.log ?? (() => {}) };
      try {
        session.server = (
          await call<{ server: HetznerServer }>("GET", `/servers/${id}`, undefined, `reading server ${id}`)
        ).server;
      } catch (error) {
        session = undefined;
        throw error;
      }
      const ipv4 = session.server.public_net?.ipv4?.ip;
      if (ipv4 && context.publicAddresses.ipv4.length && !context.publicAddresses.ipv4.includes(ipv4)) {
        session = undefined;
        throw new Error(
          `Hetzner Cloud server ${id} has the public IPv4 ${ipv4}, but this host has ${context.publicAddresses.ipv4.join(", ")}. Nothing was changed.`,
        );
      }
      return true;
    },

    async plan(rules: ProviderRule[]): Promise<FirewallPlan> {
      if (!session) throw new Error("The Hetzner adapter was used before it detected the server.");
      const { server } = session;
      const desired = hetznerRules(rules);
      if (desired.length > MAX_RULES) {
        throw new Error(
          `The inventory needs ${desired.length} Hetzner firewall rules, more than the ${MAX_RULES} a firewall can hold. Apply them by hand (--provider-firewall manual).`,
        );
      }
      const name = `ark-stack-${server.id}`;
      const { firewalls } = await call<{ firewalls: HetznerFirewall[] }>(
        "GET",
        `/firewalls?name=${encodeURIComponent(name)}`,
        undefined,
        "listing firewalls",
      );
      const existing = firewalls.find((firewall) => firewall.name === name);
      if (existing && existing.labels?.["managed-by"] !== LABELS["managed-by"]) {
        throw new Error(
          `A Hetzner Cloud firewall named ${name} exists but Ark did not create it (no managed-by=ark-stack label). Setup never changes other firewalls: rename or remove it, then re-run.`,
        );
      }
      const elsewhere = (existing?.applied_to ?? []).filter(
        (item) => !(item.type === "server" && item.server?.id === server.id),
      );
      if (existing && elsewhere.length) {
        throw new Error(
          `The Hetzner Cloud firewall ${name} is also applied to other resources (${elsewhere
            .map((item) =>
              item.type === "server" ? `server ${item.server?.id}` : `label ${item.label_selector?.selector}`,
            )
            .join(
              ", ",
            )}). Ark manages it for server ${server.id} only: remove those attachments, then re-run.`,
        );
      }
      const attached = existing ? attachedTo(existing, server.id) : false;
      const rulesMatch = existing ? sameRules(existing.rules, desired) : false;
      const changes: string[] = [];
      if (!existing) {
        changes.push(
          `Create the Hetzner Cloud firewall ${name} (label managed-by=ark-stack) with these rules:`,
        );
        for (const rule of desired) changes.push(`  + ${describeRule(rule)}`);
      } else if (!rulesMatch) {
        changes.push(`Update the rules of the Hetzner Cloud firewall ${name} (id ${existing.id}):`);
        const want = new Set(desired.map(ruleKey));
        const have = new Set(existing.rules.map(ruleKey));
        for (const rule of existing.rules)
          if (!want.has(ruleKey(rule))) changes.push(`  - ${describeRule(rule)}`);
        for (const rule of desired) if (!have.has(ruleKey(rule))) changes.push(`  + ${describeRule(rule)}`);
      }
      if (!attached) changes.push(`Apply ${name} to this server only: ${server.name} (id ${server.id}).`);
      changes.push("Inbound traffic no rule allows is dropped; outbound traffic stays unrestricted.");
      for (const other of server.public_net?.firewalls ?? []) {
        if (other.id === existing?.id) continue;
        let label = `id ${other.id}`;
        try {
          const found = await call<{ firewall: HetznerFirewall }>("GET", `/firewalls/${other.id}`);
          label = `"${found.firewall.name}" (id ${other.id})`;
        } catch (error) {
          session.log(`Could not read firewall ${other.id}: ${errorText(error)}`);
        }
        changes.push(
          `Note: firewall ${label} also applies to this server and is left unchanged. Hetzner allows whatever any applied firewall allows, so review its rules.`,
        );
      }
      const state: PlanState = { name, existing, desired, rulesMatch, attached };
      return { adapter: "hetzner", inSync: Boolean(existing && rulesMatch && attached), changes, state };
    },

    async apply(plan, context) {
      if (!session) throw new Error("The Hetzner adapter was used before it detected the server.");
      const { server } = session;
      const state = plan.state as PlanState;
      const refused = await approveProviderChange(context, "Hetzner Cloud");
      if (refused) return refused;
      const target: Attachment[] = [{ type: "server", server: { id: server.id } }];
      let id = state.existing?.id;
      if (!state.existing) {
        const created = await call<{ firewall: HetznerFirewall; actions?: Action[] }>(
          "POST",
          "/firewalls",
          {
            name: state.name,
            labels: { ...LABELS, "ark-stack-server": String(server.id) },
            rules: state.desired,
            apply_to: target,
          },
          `creating the firewall ${state.name}`,
        );
        id = created.firewall.id;
        await waitFor(created.actions);
      } else {
        if (!state.rulesMatch) {
          const result = await call<{ actions?: Action[] }>(
            "POST",
            `/firewalls/${id}/actions/set_rules`,
            { rules: state.desired },
            `updating the rules of ${state.name}`,
          );
          await waitFor(result.actions);
        }
        if (!state.attached) {
          const result = await call<{ actions?: Action[] }>(
            "POST",
            `/firewalls/${id}/actions/apply_to_resources`,
            { apply_to: target },
            `applying ${state.name} to server ${server.id}`,
          );
          await waitFor(result.actions);
        }
      }
      const { firewall } = await call<{ firewall: HetznerFirewall }>("GET", `/firewalls/${id}`);
      if (!sameRules(firewall.rules, state.desired) || !attachedTo(firewall, server.id)) {
        throw new Error(
          `The Hetzner Cloud firewall ${state.name} does not match the plan after applying it.`,
        );
      }
      context.ui.print(`      Hetzner Cloud firewall ${state.name} applied to server ${server.name}.`);
      return { status: "applied" };
    },
  };
}
