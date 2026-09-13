export type MailDesiredState = {
  version: 1;
  domains: Array<{
    name: string;
    enabled: boolean;
    mailFrom: string;
    dmarcPolicy: string;
  }>;
  mailboxes: Array<{
    address: string;
    displayName: string;
    quotaGb: number;
    lifecycle: string;
  }>;
  aliases: Array<{ address: string; targets: string[] }>;
  outbound: { provider: "ses"; paused: boolean };
};

export function mailReadiness(input: {
  domainVerified: boolean;
  mailboxProvisioned: boolean;
  listenerReady: boolean;
  certificateReady: boolean;
  sesProduction: boolean;
  relayCredential: boolean;
}) {
  const inbound =
    input.domainVerified && input.mailboxProvisioned && input.listenerReady && input.certificateReady
      ? "ready"
      : "pending";
  const outbound = input.sesProduction && input.relayCredential ? "ready" : "paused";
  return {
    inbound,
    outbound,
    client: input.certificateReady && input.mailboxProvisioned ? "ready" : "pending",
    independent: inbound === "ready" && outbound === "paused",
  };
}

export function buildMailDocuments(state: MailDesiredState) {
  return {
    "domains.yaml": { domains: state.domains },
    "mailboxes.yaml": { mailboxes: state.mailboxes.filter((item) => item.lifecycle !== "purged") },
    "aliases.yaml": { aliases: state.aliases },
    "platform.yaml": {
      outbound: state.outbound,
      note: "Receiving starts without SES. Direct outbound delivery is never a fallback.",
    },
  };
}
