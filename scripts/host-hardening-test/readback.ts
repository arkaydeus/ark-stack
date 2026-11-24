// Runs from scripts/test-db-ingress.ts. The host's nft creates ark_host and the nft in the shipped
// database-ingress image verifies it, as on a hardened VPS. The two are different nft versions and
// only the host has /etc/protocols, so they can print the same kernel rules differently.
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  assertHostFirewall,
  readHostSshAccess,
  renderDbIngress,
  renderFrontIngress,
  renderHostFirewall,
  sha256Hex,
  type HostPortConfig,
  type HostSshAccess,
} from "@ark-stack/shared";

type Docker = (
  args: string[],
  options?: { stdin?: string; allowFailure?: boolean },
) => Promise<{ status: number; stdout: string; stderr: string }>;
type Check = (condition: boolean, claim: string, observed: string) => void;

const listArgs = ["nft", "-s", "-y", "list", "table", "inet", "ark_host"];
const numericArgs = ["nft", "-s", "-y", "-p", "list", "table", "inet", "ark_host"];
const caps = ["--user", "0:0", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "DAC_OVERRIDE"];
const sshSource = "198.51.100.23";
const route = { id: "rt_t003", listenPort: 20003, sourceCidrs: [], allowInternet: true };

const cases: [string, HostPortConfig, HostSshAccess][] = [
  ["mail on, no SSH access", { mailEnabled: true, sniPorts: [] }, { ports: [] }],
  ["mail off, open SSH", { mailEnabled: false, sniPorts: [8883] }, { ports: [22, 2222] }],
  ["IPv4 SSH source", { mailEnabled: true, sniPorts: [] }, { ports: [22], source: sshSource }],
  [
    "IPv6 SSH source and a route",
    { mailEnabled: true, sniPorts: [], routes: [{ port: 20001, policy: "internet" }] },
    { ports: [22], source: "2001:db8:0:0:0:0:0:17" },
  ],
];

const icmpRule = "meta l4proto { icmp, ipv6-icmp } accept";
const tcpRule = "meta l4proto tcp ct original proto-dst @public_tcp return";
const udpRule = "meta l4proto udp ct original proto-dst @public_udp return";
const loRule = 'iifname "lo" accept';
// Every replacement loads, and must be refused in either listing.
const tampering: [string, string, string][] = [
  ["an added rule", loRule, `${loRule}\n    tcp dport 8080 accept`],
  ["a removed rule", "    jump ssh_access\n", ""],
  ["reordered rules", `${tcpRule}\n    ${udpRule}`, `${udpRule}\n    ${tcpRule}`],
  ["an open input policy", "priority -5; policy drop;", "priority -5; policy accept;"],
  ["a moved hook", "hook forward priority -5;", "hook forward priority -4;"],
  ["a different hook", "type filter hook forward", "type filter hook output"],
  ["a removed protocol", icmpRule, "meta l4proto ipv6-icmp accept"],
  ["an added protocol", icmpRule, "meta l4proto { icmp, ipv6-icmp, sctp } accept"],
  ["a changed set protocol", icmpRule, "meta l4proto { icmp, sctp } accept"],
  ["a changed rule protocol", tcpRule, tcpRule.replace("tcp", "sctp")],
  ["a negated protocol", udpRule, udpRule.replace("udp", "!= udp")],
  ["an added port", "elements = { 25,", "elements = { 24, 25,"],
  ["a mixed-source SSH chain", "chain ssh_access {\n", "chain ssh_access {\n    tcp dport 2200 accept\n"],
  ["a non-allow rule in the SSH chain", "chain ssh_access {\n", "chain ssh_access {\n    counter drop\n"],
  ["an added chain", "  chain published {", "  chain extra {\n    accept\n  }\n  chain published {"],
];

function replaceOnce(text: string, from: string, to: string) {
  if (text.split(from).length !== 2) throw new Error(`The baseline does not contain "${from}" exactly once.`);
  return text.replace(from, to);
}

export async function waitForHostFirewallAcknowledgement(
  readStatus: () => Promise<string>,
  { id, hash }: { id: string; hash: string },
  applied: boolean,
  timeoutMs = 15_000,
) {
  const deadline = performance.now() + timeoutMs;
  for (;;) {
    const status = await readStatus();
    const fields = status.split("\n");
    if (
      fields.includes(`request_id=${id}`) &&
      fields.includes(`policy_hash=${hash}`) &&
      fields.includes(`applied=${applied}`)
    )
      return status;
    const remaining = deadline - performance.now();
    if (remaining <= 0)
      throw new Error(`Timed out waiting for firewall request ${id} with applied=${applied}.`);
    await Bun.sleep(Math.min(250, remaining));
  }
}

/**
 * Builds the Dockerfile's database-ingress stages with the bundled reconciler as their only content.
 * The named context replaces just the stage that compiles the app, so the base image and packages,
 * and therefore nft, are the shipped ones.
 */
export async function buildIngressImage(
  docker: (args: string[]) => Promise<unknown>,
  root: string,
  directory: string,
  image: string,
) {
  await mkdir(join(directory, "app"), { recursive: true });
  const built = await Bun.build({
    entrypoints: [join(root, "scripts", "database-ingress.ts")],
    outdir: join(directory, "app"),
    target: "bun",
  });
  if (!built.success) throw new Error(`bundling database-ingress.ts failed: ${built.logs.join("\n")}`);
  await docker([
    "buildx",
    "build",
    "--load",
    "--quiet",
    "--target",
    "database-ingress",
    "--build-context",
    `build=${directory}`,
    "-t",
    image,
    root,
  ]);
}

export async function checkHostFirewallReadback(options: {
  docker: Docker;
  check: Check;
  root: string;
  directory: string;
  suffix: string;
  /** Appended to as resources are created, for the caller's cleanup. */
  containers: string[];
  images: string[];
  volumes: string[];
}) {
  const { docker, check, root, directory, suffix, containers } = options;
  const hostImage = `ark-host-nft-test:${suffix}`;
  const ingressImage = `ark-database-ingress-test:${suffix}`;
  const protocols = join(directory, "protocols");
  const protocolMount = ["-v", `${protocols}:/etc/protocols:ro`];
  const ingressApp = join(directory, "ingress-app");

  options.images.push(hostImage, ingressImage);
  await buildIngressImage(docker, root, ingressApp, ingressImage);
  await docker([
    "build",
    "--quiet",
    "--target",
    "nft",
    "-t",
    hostImage,
    join(root, "scripts", "host-hardening-test"),
  ]);

  const volume = `ark-host-nft-state-${suffix}`;
  options.volumes.push(volume);
  await docker(["volume", "create", volume]);
  const host = `ark-host-nft-${suffix}`;
  containers.push(host);
  await docker([
    "run",
    "-d",
    "--init",
    "--name",
    host,
    "--network",
    "none",
    "--cap-add",
    "NET_ADMIN",
    "-v",
    `${volume}:/state`,
    hostImage,
    "sleep",
    "infinity",
  ]);
  const onHost = async (...args: string[]) => (await docker(["exec", host, ...args])).stdout;
  await Bun.write(protocols, await onHost("cat", "/etc/protocols"));
  const ingress = async (args: string[], mounts: string[] = []) =>
    (
      await docker([
        "run",
        "--rm",
        "--network",
        `container:${host}`,
        ...caps,
        ...mounts,
        ingressImage,
        ...args,
      ])
    ).stdout;
  const load = (rules: string) => docker(["exec", "-i", host, "nft", "-f", "-"], { stdin: rules });

  const hostVersion = (await onHost("nft", "--version")).trim();
  const ingressVersion = (await ingress(["nft", "--version"])).trim();
  check(
    hostVersion.startsWith("nftables v1.0.9 "),
    "the table is created by Ubuntu 24.04's nft",
    hostVersion,
  );
  console.log(`  The shipped image has ${ingressVersion}`);

  const listings = async () => {
    const named = await onHost(...listArgs);
    // Remove the file for one command, in this disposable container only.
    const unnamed = await onHost(
      "sh",
      "-c",
      `mv /etc/protocols /etc/p; ${listArgs.join(" ")}; s=$?; mv /etc/p /etc/protocols; exit $s`,
    );
    return new Map([
      ["Ubuntu with /etc/protocols", named],
      ["Ubuntu without /etc/protocols", unnamed],
      ["Ubuntu, numeric", await onHost(...numericArgs)],
      ["shipped image as built", await ingress(listArgs)],
      ["shipped image with /etc/protocols", await ingress(listArgs, protocolMount)],
      ["shipped image, numeric", await ingress(numericArgs)],
    ]);
  };
  const problem = (listing: string, config: HostPortConfig, bootSsh?: HostSshAccess) => {
    try {
      const ssh = bootSsh ?? (/\bchain ssh_access \{/.test(listing) ? readHostSshAccess(listing) : undefined);
      assertHostFirewall(listing, config, ssh);
      return "";
    } catch (error) {
      return String(error);
    }
  };

  for (const [name, config, ssh] of cases) {
    await load(renderHostFirewall(config, ssh));
    for (const [source, listing] of await listings()) {
      const error = problem(listing, config, ssh) || problem(listing, config);
      check(!error, `${name}: accepted as listed by ${source}`, error || "accepted");
    }
  }
  const baselineListings = await listings();
  const withNumericProtocols = (listing: string) =>
    listing
      .replace("l4proto { icmp, ipv6-icmp }", "l4proto { 1, 58 }")
      .replace("l4proto tcp ", "l4proto 6 ")
      .replace("l4proto udp ", "l4proto 17 ");
  for (const [image, named, numeric] of [
    ["Ubuntu", baselineListings.get("Ubuntu with /etc/protocols")!, baselineListings.get("Ubuntu, numeric")!],
    [
      "shipped image",
      baselineListings.get("shipped image with /etc/protocols")!,
      await ingress(numericArgs, protocolMount),
    ],
  ]) {
    check(
      named.includes("l4proto { icmp, ipv6-icmp }") &&
        named.includes("l4proto tcp ") &&
        named.includes("l4proto udp ") &&
        withNumericProtocols(named) === numeric,
      `${image}: -p changes only the protocol names with /etc/protocols present`,
      numeric.match(/l4proto[^\n]*/g)?.join("; ") ?? "no protocol rules",
    );
    const withoutProtocols = baselineListings.get(
      image === "Ubuntu" ? "Ubuntu without /etc/protocols" : "shipped image, numeric",
    );
    check(
      numeric === withoutProtocols,
      `${image}: numeric readback matches without /etc/protocols`,
      "full table",
    );
  }

  const [, config, ssh] = cases[2]!;
  const baseline = renderHostFirewall(config, ssh);
  for (const [name, from, to] of tampering) {
    await load(replaceOnce(baseline, from, to));
    const errors = [...(await listings()).values()].map((listing) => problem(listing, config));
    check(
      errors.every((error) => error && !error.includes(sshSource)),
      `${name} is refused in every listing, without the SSH source`,
      errors[0] || "accepted",
    );
  }

  const bootSsh = { ports: [] };
  const openSsh = renderHostFirewall(config, { ports: [2200] });
  await load(openSsh);
  for (const [source, listing] of await listings()) {
    check(
      !problem(listing, config) && Boolean(problem(listing, config, bootSsh)),
      `${source}: well-formed unsourced SSH passes reconciliation and differs from the boot rules`,
      "one unsourced SSH allow rule",
    );
  }

  // The shipped reconciler applies and acknowledges a front policy in the same namespace.
  const policy = renderDbIngress() + "\n" + renderFrontIngress([route], []);
  const hash = sha256Hex(policy);
  const request = async () => {
    const id = crypto.randomUUID();
    const body = JSON.stringify({ id, hash });
    await docker(
      [
        "exec",
        "-i",
        host,
        "sh",
        "-ec",
        "mkdir -p /state/front /state/pgbouncer /state/metrics; cat >/state/front/p; mv /state/front/p /state/front/policy.nft",
      ],
      { stdin: policy },
    );
    await docker(
      ["exec", "-i", host, "sh", "-ec", "cat >/state/front/r; mv /state/front/r /state/front/policy.request"],
      { stdin: body },
    );
    return { id, hash };
  };
  const readStatus = () => onHost("sh", "-c", "cat /state/front/policy.status 2>/dev/null || true");
  const acknowledgement = (pending: Awaited<ReturnType<typeof request>>, applied: boolean) =>
    waitForHostFirewallAcknowledgement(readStatus, pending, applied);
  const guarded = async () => (await onHost("nft", "list", "tables")).includes("ark_front_guard");
  const reachable = async () =>
    (
      await docker(
        ["exec", host, "bash", "-c", "timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/80' 2>/dev/null"],
        {
          allowFailure: true,
        },
      )
    ).status === 0;

  // Gate just the host table readback. The front policy transaction has already finished
  // when this process starts, so the test can observe the guard during recovery.
  const nftWrapper = join(directory, "nft");
  await writeFile(
    nftWrapper,
    `#!/bin/sh
set -eu
if [ "$*" = "${numericArgs.slice(1).join(" ")}" ] && [ -e /state/hold-host-readback ]; then
  touch /state/host-readback-paused
  while [ -e /state/hold-host-readback ]; do sleep 0.05; done
fi
exec /usr/sbin/nft "$@"
`,
    { mode: 0o755 },
  );
  const startReconciler = async (image: string, name: string, mounts: string[] = []) => {
    containers.push(name);
    await docker([
      "run",
      "-d",
      "--name",
      name,
      "--network",
      `container:${host}`,
      ...caps,
      "--security-opt",
      "no-new-privileges:true",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,nodev,size=64m",
      "-v",
      `${volume}:/state`,
      "-v",
      `${nftWrapper}:/test-bin/nft:ro`,
      ...mounts,
      ...[
        "ARK_HOST_HARDENING=1",
        "ARK_MAIL_ENABLED=1",
        "ARK_EDGE_SNI_PORTS=",
        "ARK_PGBOUNCER_DIR=/state/pgbouncer",
        "ARK_DB_INGRESS_METRICS_DIR=/state/metrics",
        "ARK_FRONT_INGRESS_DIR=/state/front",
      ].flatMap((value) => ["-e", value]),
      image,
      "sh",
      "-ec",
      'export PATH="/test-bin:$PATH"; exec bun /app/database-ingress.js',
    ]);
  };

  await docker([
    "exec",
    "-d",
    host,
    "bun",
    "-e",
    'Bun.serve({ port: 80, hostname: "127.0.0.1", fetch: () => new Response("ok") })',
  ]);
  const reconciler = `ark-host-nft-reconciler-${suffix}`;
  let pending = await request();
  await startReconciler(ingressImage, reconciler);
  const showStatus = (status: string) => status.trim().replace(/\n/g, " ");
  let status = await acknowledgement(pending, true);
  check(
    !(await guarded()),
    "the shipped reconciler accepts the host's table with unsourced SSH and installs no guard",
    showStatus(status),
  );
  check(await reachable(), "port 80 is reachable after the acknowledgement", "TCP 80 over loopback");

  await load(replaceOnce(baseline, icmpRule, "meta l4proto { icmp, sctp } accept"));
  pending = await request();
  status = await acknowledgement(pending, false);
  check(
    /chain input is missing .*ipv6-icmp/.test(status) &&
      status.includes("chain input has 1 unexpected entry") &&
      !status.includes(sshSource),
    "a different protocol is refused and the missing baseline rule is named in the status",
    showStatus(status),
  );
  check(
    (await guarded()) && !(await reachable()),
    "the drop guard blocks port 80 on a real mismatch",
    "TCP 80 over loopback",
  );

  const liveBaseline = renderHostFirewall(
    { ...config, routes: [{ port: route.listenPort, policy: "internet" }] },
    ssh,
  );
  await onHost("touch", "/state/hold-host-readback");
  try {
    await onHost(
      "timeout",
      "15",
      "sh",
      "-ec",
      "until [ -e /state/host-readback-paused ]; do sleep 0.05; done",
    );
    await load(liveBaseline);
    check(
      (await guarded()) && !(await reachable()) && (await readStatus()) === status,
      "the retry keeps the guard and TCP 80 blocked while host readback is paused",
      "the rejected acknowledgement remains current",
    );
  } finally {
    await onHost("rm", "-f", "/state/hold-host-readback", "/state/host-readback-paused");
  }
  status = await acknowledgement(pending, true);
  check(
    !(await guarded()) && (await reachable()),
    "the same request is retried and the guard removed once the table matches",
    showStatus(status),
  );

  const addressParts = [sshSource, "198_51_100_23", "198-51-100-23", "0xc6336417"];
  const privateRules = replaceOnce(
    replaceOnce(
      liveBaseline,
      "  chain published {",
      `  set admin_198_51_100_23 {
    type ipv4_addr
    elements = { ${sshSource} }
  }
  map admin_0xc6336417 {
    type ipv4_addr : verdict
  }
  chain allow_198_51_100_23 {
    return
  }
  chain published {`,
    ),
    loRule,
    `${loRule}
    ip saddr ${sshSource} log prefix "admin_0xc6336417" accept comment "from 198-51-100-23.isp.example"
    ip saddr @admin_198_51_100_23 jump allow_198_51_100_23`,
  );
  const checkPrivateStatus = async (image: string, listing: string) => {
    check(
      listing.includes(`ip saddr ${sshSource} log prefix`) &&
        addressParts.every((part) => listing.includes(part)),
      `${image}: nft lists all address forms in the drift fixture`,
      "a source, identifiers, a log prefix and a comment",
    );
    const privateRequest = await request();
    const privateStatus = await acknowledgement(privateRequest, false);
    check(
      privateStatus.includes("chain input has 2 unexpected entries") &&
        privateStatus.includes("the listing has 3 unexpected sections") &&
        !addressParts.some((part) => privateStatus.includes(part)),
      `${image}: live status reports the drift without any address forms`,
      showStatus(privateStatus),
    );
    await load(liveBaseline);
    await acknowledgement(privateRequest, true);
  };

  // Install and read the same fixture using each nft version. Run the same bundled
  // reconciler with Ubuntu's nft so both listings go through the real status writer.
  await docker(["exec", "-i", reconciler, "/usr/sbin/nft", "-f", "-"], {
    stdin: withNumericProtocols(privateRules),
  });
  await checkPrivateStatus("shipped image", await ingress(numericArgs));
  await docker(["rm", "-f", reconciler]);
  await load(privateRules);
  await startReconciler(hostImage, `${reconciler}-ubuntu`, ["-v", `${join(ingressApp, "app")}:/app:ro`]);
  await checkPrivateStatus("Ubuntu", await onHost(...numericArgs));
}
