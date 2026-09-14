import { createHash } from "node:crypto";

export type StalwartUpsert = {
  "@type": "upsert" | "delete";
  object: string;
  matchOn: string;
  value: Record<string, Record<string, unknown>>;
};

export function stalwartRef(prefix: string, value: string) {
  return `${prefix}-${createHash("sha256").update(value).digest("hex").slice(0, 16)}`;
}

export function buildStalwartPlan(input: {
  hostname: string;
  domains: Array<{ name: string; enabled: boolean }>;
  mailboxes: Array<{
    address: string;
    displayName: string;
    quotaGb: number;
    password?: string;
    lifecycle: string;
    nativeId?: string;
  }>;
  aliases: Array<{ address: string; targets: string[] }>;
  removedAliases?: Array<{ address: string; nativeId: string }>;
  smtpUsername?: string;
  outboundPaused: boolean;
}) {
  const plan: StalwartUpsert[] = [];
  const domainValue: Record<string, Record<string, unknown>> = {};
  for (const domain of input.domains) {
    domainValue[stalwartRef("domain", domain.name)] = {
      name: domain.name,
      isEnabled: domain.enabled,
      allowRelaying: false,
      description: "Managed by Ark Stack",
    };
  }
  plan.push({ "@type": "upsert", object: "Domain", matchOn: "name", value: domainValue });
  const accounts: Record<string, Record<string, unknown>> = {};
  for (const mailbox of input.mailboxes.filter((item) => item.lifecycle !== "purged")) {
    accounts[stalwartRef("account", mailbox.address)] = {
      name: mailbox.address,
      description: mailbox.displayName,
      ...(mailbox.password ? { secrets: [mailbox.password] } : {}),
      quota: mailbox.quotaGb * 1024 * 1024 * 1024,
      email: [mailbox.address],
      ...(mailbox.nativeId ? { $nativeId: mailbox.nativeId } : {}),
      isEnabled: mailbox.lifecycle === "active",
    };
  }
  plan.push({ "@type": "upsert", object: "Account", matchOn: "name", value: accounts });
  const removedAccounts: Record<string, Record<string, unknown>> = {};
  for (const mailbox of input.mailboxes.filter((item) => item.lifecycle === "purged")) {
    removedAccounts[stalwartRef("account", mailbox.address)] = {
      name: mailbox.address,
      ...(mailbox.nativeId ? { $nativeId: mailbox.nativeId } : {}),
    };
  }
  if (Object.keys(removedAccounts).length) {
    plan.push({ "@type": "delete", object: "Account", matchOn: "name", value: removedAccounts });
  }
  const aliasValues: Record<string, Record<string, unknown>> = {};
  for (const alias of input.aliases) {
    aliasValues[stalwartRef("alias", alias.address)] = {
      name: alias.address,
      emails: alias.targets,
      isEnabled: true,
    };
  }
  plan.push({ "@type": "upsert", object: "Alias", matchOn: "name", value: aliasValues });
  if (input.removedAliases?.length) {
    plan.push({
      "@type": "delete",
      object: "Alias",
      matchOn: "nativeId",
      value: Object.fromEntries(
        input.removedAliases.map((alias) => [
          stalwartRef("alias", alias.address),
          { $nativeId: alias.nativeId },
        ]),
      ),
    });
  }
  return {
    plan,
    outbound: {
      provider: "ses",
      hostname: input.hostname,
      username: input.smtpUsername ?? null,
      paused: input.outboundPaused || !input.smtpUsername,
    },
  };
}

export function jmapCall(name: string, arguments_: Record<string, unknown>) {
  const capability = name.startsWith("x:") ? "urn:stalwart:jmap" : "urn:ietf:params:jmap:mail";
  return {
    using: ["urn:ietf:params:jmap:core", capability],
    methodCalls: [[name, arguments_, "op"]],
  };
}
