import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { jmapCall } from "@ark-stack/shared";
import { applyStalwart, applyStalwartDevice } from "../server/src/modules/providers.ts";

const image = "stalwartlabs/stalwart@sha256:388dcb75a70727c5b551249a6d34b1f1321294852489e4fa3a4e6be698b7c4f0";
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const container = `ark-fix1-stalwart-${suffix}`;
const adminPassword = `admin-${randomBytes(18).toString("base64url")}`;
const mailboxPassword = `mail-${randomBytes(18).toString("base64url")}`;
const domain = "example.com";
const address = `owner@${domain}`;
const alias = `hello@${domain}`;
const stateDirectory = await mkdtemp(resolve(tmpdir(), `ark-stalwart-integration-${suffix}-`));

async function docker(...args: string[]) {
  const process = Bun.spawn(["docker", ...args], { stdout: "pipe", stderr: "pipe" });
  const [exitCode, stdout, stderr] = await Promise.all([
    process.exited,
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
  ]);
  if (exitCode !== 0) throw new Error(`docker ${args[0]} failed: ${stderr.trim().slice(0, 2000)}`);
  return stdout.trim();
}

async function waitUntilReady(url: string) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const response = await fetch(`${url}/`, { signal: AbortSignal.timeout(2_000) }).catch(() => null);
    if (response?.ok) return;
    await Bun.sleep(250);
  }
  throw new Error("Disposable Stalwart did not become ready within 60 seconds.");
}

async function publishedPort() {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const published = await docker("port", container, "8080/tcp").catch(() => "");
    const match = published.match(/127\.0\.0\.1:(\d+)/);
    if (match) return match[1];
    await Bun.sleep(100);
  }
  throw new Error("Disposable Stalwart did not expose its loopback management port.");
}

async function authenticates(url: string, username: string, password: string) {
  const response = await fetch(`${url}/jmap`, {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(jmapCall("x:Account/query", { filter: {} })),
    signal: AbortSignal.timeout(5_000),
  });
  return response.ok;
}

let started = false;
try {
  if (process.env.STALWART_URL || process.env.ARK_ALLOW_PRODUCTION_INTEGRATION === "1") {
    throw new Error(
      "This test refuses ambient Stalwart endpoints and production-integration overrides; it only creates its own disposable container.",
    );
  }
  await docker("version", "--format", "{{.Server.Version}}");
  await docker(
    "run",
    "-d",
    "--rm",
    "--name",
    container,
    "--label",
    "com.ark-stack.test=stalwart-integration",
    "--publish",
    "127.0.0.1::8080",
    "--cap-drop",
    "ALL",
    "--cap-add",
    "NET_BIND_SERVICE",
    "--security-opt",
    "no-new-privileges=true",
    "--pids-limit",
    "256",
    "--env",
    `STALWART_RECOVERY_ADMIN=admin:${adminPassword}`,
    "--volume",
    `${resolve("infra/mail/config.json")}:/etc/stalwart/config.json:ro`,
    image,
  );
  started = true;
  const port = await publishedPort();
  const url = `http://127.0.0.1:${port}`;
  await waitUntilReady(url);

  process.env.STALWART_URL = url;
  process.env.STALWART_ADMIN_ADDRESS = "admin";
  process.env.STALWART_ADMIN_PASSWORD = adminPassword;
  process.env.ARK_MAIL_STATE_DIR = stateDirectory;

  const base = {
    hostname: `mail.${domain}`,
    domains: [{ name: domain, enabled: true }],
    outboundPaused: true,
  };
  const created = await applyStalwart({
    ...base,
    mailboxes: [
      {
        address,
        displayName: "Integration Owner",
        quotaGb: 1,
        password: mailboxPassword,
        lifecycle: "active",
      },
    ],
    aliases: [{ address: alias, targets: [address] }],
  });
  const mailboxId = created.nativeIds.mailboxes[address];
  const aliasId = created.nativeIds.aliases[alias];
  if (!mailboxId || !aliasId) throw new Error("Native mailbox and alias IDs were not returned.");
  if (!(await authenticates(url, address, mailboxPassword))) {
    throw new Error("New native mailbox could not authenticate.");
  }

  const device = await applyStalwartDevice({
    address,
    password: mailboxPassword,
    action: "create",
    label: "integration",
  });
  if (!(await authenticates(url, address, device.secret))) {
    throw new Error("Native app password could not authenticate.");
  }
  await applyStalwartDevice({
    address,
    password: mailboxPassword,
    action: "revoke",
    nativeId: device.nativeId,
  });
  if (await authenticates(url, address, device.secret)) {
    throw new Error("Revoked native app password still authenticates.");
  }

  await applyStalwart({
    ...base,
    mailboxes: [
      {
        address,
        displayName: "Integration Owner",
        quotaGb: 1,
        nativeId: mailboxId,
        lifecycle: "suspended",
      },
    ],
    aliases: [],
    removedAliases: [{ address: alias, nativeId: aliasId }],
  });
  if (await authenticates(url, address, mailboxPassword)) {
    throw new Error("Suspended native mailbox still authenticates.");
  }

  await applyStalwart({
    ...base,
    mailboxes: [
      {
        address,
        displayName: "Integration Owner",
        quotaGb: 1,
        password: mailboxPassword,
        nativeId: mailboxId,
        lifecycle: "active",
      },
    ],
    aliases: [],
  });
  if (!(await authenticates(url, address, mailboxPassword))) {
    throw new Error("Restored native mailbox could not authenticate.");
  }

  await applyStalwart({
    ...base,
    mailboxes: [
      {
        address,
        displayName: "Integration Owner",
        quotaGb: 1,
        nativeId: mailboxId,
        lifecycle: "purged",
      },
    ],
    aliases: [],
  });
  if (await authenticates(url, address, mailboxPassword)) {
    throw new Error("Purged native mailbox still authenticates.");
  }
  console.log("Disposable native Stalwart lifecycle integration passed.");
} finally {
  delete process.env.STALWART_URL;
  delete process.env.STALWART_ADMIN_ADDRESS;
  delete process.env.STALWART_ADMIN_PASSWORD;
  delete process.env.ARK_MAIL_STATE_DIR;
  if (started) await docker("rm", "-f", container).catch(() => undefined);
  await rm(stateDirectory, { recursive: true, force: true });
}
