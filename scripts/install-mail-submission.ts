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
  container: string,
  { user, password }: Credential,
  restart: () => Promise<unknown>,
) {
  if (!user || !password) throw new Error("Stalwart needs the installer recovery administrator credential.");
  const exec = ["exec", "-i", container];
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
  const networks = JSON.parse(
    await hostCommand("docker", ["inspect", "--format", "{{json .NetworkSettings.Networks}}", container]),
  ) as Record<string, { IPAddress: string; GlobalIPv6Address: string }>;
  const addresses = Object.values(networks)
    .flatMap(({ IPAddress, GlobalIPv6Address }) => [IPAddress, GlobalIPv6Address])
    .filter(Boolean)
    .map((address) => (address.includes(":") ? `[${address}]` : address));
  if (!addresses.length) throw new Error("Stalwart has no Docker network address for the TCP 587 check.");
  const binds = new Set(
    submission.flatMap(({ bind }) => Object.keys(bind).filter((key) => bind[key] && key.endsWith(":587"))),
  );
  if (
    submission.length &&
    addresses.some(
      (address) =>
        !binds.has("[::]:587") &&
        !binds.has(`${address}:587`) &&
        !(address.startsWith("[") === false && binds.has("0.0.0.0:587")),
    )
  ) {
    throw new Error(
      "Stalwart port 587 must bind its Docker network addresses. A loopback-only bind cannot serve the publication.",
    );
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
    Promise.all(
      addresses.map((address) =>
        hostCommand("docker", [
          ...exec,
          "curl",
          "-fsS",
          "--noproxy",
          "*",
          "--max-time",
          "5",
          "--ssl-reqd",
          "--insecure",
          "--request",
          "NOOP",
          `smtp://${address}:587`,
        ]),
      ),
    );
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
  throw new Error("Stalwart did not answer SMTP STARTTLS on its Docker network addresses on port 587.");
}

export async function startLocalMail(root: string, credential: Credential) {
  const compose = ["compose", "-f", join(root, "infra", "mail", "docker-compose.yml")];
  await hostCommand("docker", [...compose, "up", "-d", "--wait", "--wait-timeout", "120"]);
  const container = (await hostCommand("docker", [...compose, "ps", "-q", "stalwart"])).trim();
  if (!container) throw new Error("Stalwart container not found after Compose startup.");
  await ensureMailSubmission(container, credential, () =>
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
