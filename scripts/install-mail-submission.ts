import { join } from "node:path";

import { jmapCall, mailEnabled } from "@ark-stack/shared";

import { hostCommand } from "./install-host-hardening.ts";

type Credential = { user: string; password: string };
type Listener = {
  protocol: string;
  bind: Record<string, boolean>;
  useTls: boolean;
  tlsImplicit: boolean;
};

export async function ensureMailSubmission(
  exec: string[],
  { user, password }: Credential,
  restart: () => Promise<unknown>,
) {
  if (!user || !password) throw new Error("Stalwart needs the installer recovery administrator credential.");
  async function jmap<T>(name: string, args: Record<string, unknown>) {
    // Stalwart already has curl for its health check. Keep the credential off the command line.
    const config = [
      'url = "http://127.0.0.1:8080/jmap"',
      `header = "Authorization: Basic ${Buffer.from(`${user}:${password}`).toString("base64")}"`,
      'header = "Content-Type: application/json"',
      `data = ${JSON.stringify(JSON.stringify(jmapCall(name, args)))}`,
    ].join("\n");
    const output = await hostCommand(
      "docker",
      [...exec, "curl", "-fsS", "--max-time", "10", "--config", "-"],
      config,
    );
    const [reply] = (JSON.parse(output) as { methodResponses: [string, T][] }).methodResponses;
    if (reply?.[0] !== name) throw new Error(`Stalwart did not accept ${name}.`);
    return reply[1];
  }

  const { list } = await jmap<{ list: Listener[] }>("x:NetworkListener/get", {
    properties: ["protocol", "bind", "useTls", "tlsImplicit"],
  });
  const submission = list.filter((listener) =>
    Object.entries(listener.bind).some(([address, bound]) => bound && address.endsWith(":587")),
  );
  if (
    submission.some((listener) => listener.protocol !== "smtp" || !listener.useTls || listener.tlsImplicit)
  ) {
    throw new Error("Stalwart port 587 must be configured as SMTP submission with STARTTLS.");
  }
  if (!submission.length) {
    const { created } = await jmap<{ created?: { submission?: { id: string } } }>("x:NetworkListener/set", {
      create: {
        submission: {
          name: "submission",
          protocol: "smtp",
          bind: { "[::]:587": true },
          useTls: true,
          tlsImplicit: false,
        },
      },
    });
    if (!created?.submission?.id)
      throw new Error("Stalwart could not create the TCP 587 submission listener.");
  }

  const probe = () =>
    hostCommand("docker", [
      ...exec,
      "curl",
      "-fsS",
      "--max-time",
      "5",
      "--ssl-reqd",
      "--insecure",
      "--request",
      "NOOP",
      "smtp://127.0.0.1:587",
    ]);
  if (
    submission.length &&
    (await probe().then(
      () => true,
      () => false,
    ))
  )
    return;
  await restart();
  // Listener changes in the pinned image take effect at startup.
  const deadline = Date.now() + 30_000;
  do {
    if (
      await probe().then(
        () => true,
        () => false,
      )
    )
      return;
    await Bun.sleep(250);
  } while (Date.now() < deadline);
  throw new Error("Stalwart did not answer SMTP STARTTLS on port 587 after startup.");
}

export async function startLocalMail(root: string, credential: Credential) {
  const compose = ["compose", "-f", join(root, "infra", "mail", "docker-compose.yml")];
  await hostCommand("docker", [...compose, "up", "-d", "--wait", "--wait-timeout", "120"]);
  await ensureMailSubmission([...compose, "exec", "-T", "stalwart"], credential, () =>
    hostCommand("docker", [...compose, "restart", "stalwart"]),
  );
}

if (import.meta.main) {
  if (!mailEnabled(process.env.ARK_MAIL_ENABLED)) {
    throw new Error(
      "Enable mail in .env and run host:install to update the public firewall and start Stalwart.",
    );
  }
  await startLocalMail(join(import.meta.dir, ".."), {
    user: process.env.STALWART_ADMIN_ADDRESS ?? "admin",
    password: process.env.STALWART_ADMIN_PASSWORD ?? "",
  });
  console.log("Stalwart is running with STARTTLS submission on TCP 587.");
}
