import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import { buildMailDocuments, mailReadiness, type MailDesiredState } from "@ark-stack/shared";

import { applyStalwart } from "./providers.ts";

export async function writeMailDesiredState(state: MailDesiredState) {
  const dir = process.env.ARK_MAIL_STATE_DIR ?? join(process.cwd(), "tmp", "mail-state");
  await mkdir(dir, { recursive: true });
  const documents = buildMailDocuments(state);
  for (const [name, body] of Object.entries(documents)) {
    await Bun.write(join(dir, name), JSON.stringify(body, null, 2));
  }
  return { dir, documents };
}

export function currentMailStatus(input: {
  domainVerified: boolean;
  mailboxCount: number;
  certificateReady: boolean;
  sesReady: boolean;
  listenerReady?: boolean;
}) {
  return mailReadiness({
    domainVerified: input.domainVerified,
    mailboxProvisioned: input.mailboxCount > 0,
    listenerReady: input.listenerReady ?? false,
    certificateReady: input.certificateReady,
    sesProduction: input.sesReady,
    relayCredential: input.sesReady,
  });
}

export async function reconcileMailEngine(input: {
  hostname: string;
  domains: MailDesiredState["domains"];
  mailboxes: Array<MailDesiredState["mailboxes"][number] & { password?: string; nativeId?: string }>;
  aliases: MailDesiredState["aliases"];
  sesReady: boolean;
  smtpUsername?: string;
}) {
  const state: MailDesiredState = {
    version: 1,
    domains: input.domains,
    mailboxes: input.mailboxes,
    aliases: input.aliases,
    outbound: { provider: "ses", paused: !input.sesReady },
  };
  const written = await writeMailDesiredState(state);
  const applied = await applyStalwart({
    hostname: input.hostname,
    domains: input.domains.map((item) => ({ name: item.name, enabled: item.enabled })),
    mailboxes: input.mailboxes.map((item) => ({
      address: item.address,
      displayName: item.displayName,
      quotaGb: item.quotaGb,
      password: item.password,
      lifecycle: item.lifecycle,
      nativeId: item.nativeId,
    })),
    aliases: input.aliases,
    smtpUsername: input.smtpUsername,
    outboundPaused: !input.sesReady,
  });
  return { ...written, ...applied };
}
