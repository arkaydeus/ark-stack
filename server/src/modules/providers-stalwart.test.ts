import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { applyStalwart } from "./providers.ts";

const originalFetch = globalThis.fetch;
const saved = {
  url: process.env.STALWART_URL,
  address: process.env.STALWART_ADMIN_ADDRESS,
  password: process.env.STALWART_ADMIN_PASSWORD,
  state: process.env.ARK_MAIL_STATE_DIR,
};
const temporaryDirectories: string[] = [];

afterEach(async () => {
  globalThis.fetch = originalFetch;
  for (const [key, value] of Object.entries({
    STALWART_URL: saved.url,
    STALWART_ADMIN_ADDRESS: saved.address,
    STALWART_ADMIN_PASSWORD: saved.password,
    ARK_MAIL_STATE_DIR: saved.state,
  })) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  for (const directory of temporaryDirectories.splice(0)) await rm(directory, { recursive: true });
});

describe("native Stalwart desired-state reconciliation", () => {
  test("creates domains, accounts, and aliases through versioned JMAP extension methods", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ark-stalwart-test-"));
    temporaryDirectories.push(directory);
    process.env.ARK_MAIL_STATE_DIR = directory;
    process.env.STALWART_URL = "http://stalwart:8080";
    process.env.STALWART_ADMIN_ADDRESS = "admin";
    process.env.STALWART_ADMIN_PASSWORD = "secret";
    const requests: Array<{ name: string; arguments: Record<string, unknown> }> = [];
    globalThis.fetch = (async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        methodCalls: Array<[string, Record<string, unknown>, string]>;
      };
      const [name, methodArguments, callId] = body.methodCalls[0]!;
      requests.push({ name, arguments: methodArguments });
      if (name.endsWith("/query")) {
        return Response.json({ methodResponses: [[name, { ids: [] }, callId]] });
      }
      const create = (methodArguments.create ?? {}) as Record<string, unknown>;
      const prefix = name.includes("Domain") ? "dom" : name.includes("Account") ? "acc" : "list";
      const created = Object.fromEntries(
        Object.keys(create).map((reference, index) => [reference, { id: `${prefix}-${index + 1}` }]),
      );
      return Response.json({ methodResponses: [[name, { created }, callId]] });
    }) as typeof fetch;

    const result = await applyStalwart({
      hostname: "mail.example.com",
      domains: [{ name: "example.com", enabled: true }],
      mailboxes: [
        {
          address: "owner@example.com",
          displayName: "Owner",
          quotaGb: 10,
          password: "mailbox-password",
          lifecycle: "active",
        },
      ],
      aliases: [{ address: "hello@example.com", targets: ["owner@example.com"] }],
      outboundPaused: true,
    });

    expect(result.applied).toBe(true);
    expect(result.nativeIds.mailboxes["owner@example.com"]).toBe("acc-1");
    expect(result.nativeIds.aliases["hello@example.com"]).toBe("list-1");
    expect(requests.map((item) => item.name)).toEqual([
      "x:Domain/query",
      "x:Domain/set",
      "x:Account/query",
      "x:Account/set",
      "x:MailingList/query",
      "x:MailingList/set",
    ]);
    const accountSet = requests.find((item) => item.name === "x:Account/set")!;
    expect(JSON.stringify(accountSet.arguments)).toContain("mailbox-password");
    const listSet = requests.find((item) => item.name === "x:MailingList/set")!;
    expect(JSON.stringify(listSet.arguments)).toContain("owner@example.com");
  });

  test("rejects a partial native set response", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ark-stalwart-test-"));
    temporaryDirectories.push(directory);
    process.env.ARK_MAIL_STATE_DIR = directory;
    process.env.STALWART_URL = "http://stalwart:8080";
    process.env.STALWART_ADMIN_ADDRESS = "admin";
    process.env.STALWART_ADMIN_PASSWORD = "secret";
    globalThis.fetch = (async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        methodCalls: Array<[string, Record<string, unknown>, string]>;
      };
      const [name, , callId] = body.methodCalls[0]!;
      if (name.endsWith("/query")) {
        return Response.json({ methodResponses: [[name, { ids: [] }, callId]] });
      }
      return Response.json({
        methodResponses: [[name, { notCreated: { domain: { type: "invalidProperties" } } }, callId]],
      });
    }) as typeof fetch;

    await expect(
      applyStalwart({
        hostname: "mail.example.com",
        domains: [{ name: "example.com", enabled: true }],
        mailboxes: [],
        aliases: [],
        outboundPaused: true,
      }),
    ).rejects.toThrow(/partial notCreated/);
  });
});
