import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { MAIL_PUBLIC_TCP } from "@ark-stack/shared";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";

const root = resolve(import.meta.dir, "..");
const suffix = crypto.randomUUID().slice(0, 12);
const name = `ark-fd20-${suffix}`;
const image = `${name}:vps`;
const vps = `${name}-vps`;
const scanner = `${name}-scanner`;
const directory = await mkdtemp(join(tmpdir(), `${name}-`));
const runtime = new EdgeTestRuntime(directory, `${name}-wan`);
const stopSignalHandlers = runtime.installSignalHandlers();
const docker = runtime.docker.bind(runtime);
const exec = (container: string, ...args: string[]) => docker("exec", container, ...args);
const host = (...args: string[]) => exec(vps, ...args);
const nested = (...args: string[]) => host("docker", ...args);
const scan = (...args: string[]) => exec(scanner, ...args);
const env = ["-e", "ARK_MAIL_ENABLED=1", "-e", "ARK_EDGE_SNI_PORTS=8883"];
const fixture = "/work/scripts/inside.js";
const audit = "/work/scripts/host-audit.js";
const ingress = "/work/scripts/database-ingress.js";
const platformDir = join(root, "infra/platform");
const platformFile = "/work/infra/platform/docker-compose.yml";
const mailFile = "/work/infra/mail/docker-compose.yml";

async function ready<T>(check: () => Promise<T>, label: string, timeout = 30_000) {
  let error: unknown;
  const deadline = Date.now() + timeout;
  do {
    try {
      return await check();
    } catch (failure) {
      error = failure;
      await Bun.sleep(250);
    }
  } while (Date.now() < deadline);
  throw new Error(`${label} did not become ready.`, { cause: error });
}

async function applyPolicy(mode: "on" | "off") {
  const id = await host("bun", fixture, "policy");
  await docker(
    "exec",
    "-e",
    `ARK_MAIL_ENABLED=${mode === "on" ? 1 : 0}`,
    "-w",
    "/work",
    vps,
    "docker",
    "compose",
    "-f",
    platformFile,
    "up",
    "-d",
    "database-ingress",
  );
  await ready(async () => {
    const status = await host("cat", "/work/tmp/edge-l4/front-ingress/policy.status");
    assert.match(status, /applied=true/);
    assert.ok(status.includes(`request_id=${id}`), status);
  }, "Host firewall reconciliation");
}

async function composeFixtures(fixtureImage: string, haproxyPin: string, mailImage: string) {
  const files = join(directory, "install-fixture");
  await Bun.write(
    join(files, "infra/platform/docker-compose.yml"),
    `name: ark-platform
services:
  database-ingress:
    image: ${fixtureImage}
    network_mode: host
    cap_add: [NET_ADMIN]
    working_dir: /work
    volumes: [/work:/work]
    environment:
      ARK_HOST_HARDENING: "1"
      ARK_MAIL_ENABLED: \${ARK_MAIL_ENABLED:-1}
      ARK_EDGE_SNI_PORTS: "8883"
      ARK_FRONT_INGRESS_DIR: /work/tmp/edge-l4/front-ingress
    command: [bun, ${ingress}]
    restart: unless-stopped
  api:
    image: ${fixtureImage}
    command: [sleep, infinity]
    restart: unless-stopped
  mail-worker:
    image: ${fixtureImage}
    command: [sleep, infinity]
    restart: unless-stopped
  edge-l4:
    image: ${haproxyPin}
`,
  );
  await Bun.write(
    join(files, "infra/mail/docker-compose.yml"),
    `name: ark-mail
services:
  stalwart:
    image: ${mailImage}
    container_name: mail
    ports: [${MAIL_PUBLIC_TCP.map((port) => `"${port}:${port}"`).join(", ")}]
    volumes: [/tmp/stalwart.json:/etc/stalwart/config.json:ro]
    environment:
      STALWART_RECOVERY_ADMIN: "admin:fixture-only"
    restart: unless-stopped
`,
  );
  await Promise.all(
    ["Caddyfile", "serve.json"].map((file) =>
      Bun.write(join(files, "infra/platform", file), Bun.file(join(platformDir, file))),
    ),
  );
  await Bun.write(join(files, "Dockerfile"), Bun.file(join(root, "Dockerfile")));
  await Bun.write(join(files, ".env"), "ARK_MAIL_ENABLED=1\n");
  await Bun.write(
    join(files, "bin/docker"),
    `#!/bin/sh
set -eu
case "$*" in
  *"id -u"*)
    case "$*" in *"haproxy:"*) uid=99 ;; *) uid=1000 ;; esac
    printf '%s\\n' "$uid" ---
    exit 0 ;;
esac
if [ "\${1:-}" = compose ] && [ "\${4:-}" = build ]; then
  bun ${fixture} policy >/tmp/upgrade-request
  sleep 2
  echo "Injected build failure after publishing a fresh front request." >&2
  exit 42
fi
exec /usr/bin/docker "$@"
`,
  );
  await docker("cp", `${files}/.`, `${vps}:/work/`);
  await host("chmod", "700", "/work/bin/docker");
}

async function interruptedMailOff(addresses: string[]) {
  await nested("rm", "-f", "-v", "mail");
  await nested("compose", "-f", mailFile, "up", "-d", "stalwart");
  await ready(
    () => nested("exec", "mail", "curl", "-fsS", "http://127.0.0.1:8080/"),
    "Compose-managed Stalwart",
  );
  await nested("compose", "-f", platformFile, "up", "-d", "api", "mail-worker");
  const install = () =>
    docker(
      "exec",
      "-e",
      "ARK_MAIL_ENABLED=0",
      "-e",
      "ARK_EDGE_SNI_PORTS=8883",
      "-e",
      "ARK_INSTALL_NONINTERACTIVE=1",
      vps,
      "env",
      "PATH=/work/bin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin",
      "bun",
      "/work/scripts/install.js",
    );
  await assert.rejects(install(), /Injected build failure/);
  assert.match(await host("cat", "/work/.env"), /^ARK_MAIL_ENABLED=0$/m);
  assert.match(await host("cat", "/work/.env"), /^ARK_HOST_HARDENING=1$/m);
  const running = await nested("ps", "--format", "{{.Names}}");
  assert.doesNotMatch(running, /(?:^mail$|database-ingress|mail-worker|-api-)/m);
  const request = await host("cat", "/tmp/upgrade-request");
  assert.ok(request);
  assert.doesNotMatch(
    await host("cat", "/work/tmp/edge-l4/front-ingress/policy.status"),
    new RegExp(request),
  );
  const rules = await host("nft", "-s", "-y", "list", "table", "inet", "ark_host");
  assert.match(rules, /\b20001\b/);
  assert.doesNotMatch(rules, /\b(?:25|465|587|993)\b/);
  for (const address of addresses) {
    const result = await scan(
      "nmap",
      ...(address.includes(":") ? ["-6"] : []),
      "-n",
      "-Pn",
      "-p",
      "25,465,587,993",
      address,
    );
    assert.doesNotMatch(result, /\/tcp\s+open/);
  }
  await assert.rejects(install(), /Injected build failure/);
  assert.doesNotMatch(
    await host("nft", "-s", "-y", "list", "table", "inet", "ark_host"),
    /\b(?:20001|20007|587)\b/,
    "The installer leaves dedicated ports closed when the previous request was not acknowledged.",
  );
  await nested(
    "compose",
    "-f",
    platformFile,
    "up",
    "-d",
    "--no-build",
    "--pull",
    "never",
    "--wait",
    "--scale",
    "mail-worker=0",
    "api",
    "mail-worker",
  );
  assert.doesNotMatch(await nested("ps", "--format", "{{.Names}}"), /mail-worker/);
  console.log("A mail-off build failure left Stalwart, its worker and the stale ingress writer stopped.");
}

async function externalAudit(addresses: string[], mailEnabled: boolean) {
  const args = ["-e", `ARK_MAIL_ENABLED=${mailEnabled ? 1 : 0}`, "-e", "ARK_EDGE_SNI_PORTS=8883"];
  const inventory = await docker("exec", ...args, vps, "bun", audit, "--inventory");
  const { providerRules } = JSON.parse(inventory);
  assert.deepEqual(providerRules, [
    {
      protocol: "tcp",
      ports: [...(mailEnabled ? MAIL_PUBLIC_TCP : []), 80, 443, 5432, 8883, 20001, 20007].toSorted(
        (a, b) => a - b,
      ),
      sourceCidrs: ["0.0.0.0/0", "::/0"],
    },
    { protocol: "udp", ports: [41641, 41642], sourceCidrs: ["0.0.0.0/0", "::/0"] },
  ]);
  await writeFile(join(directory, "inventory.json"), inventory);
  await docker("cp", join(directory, "inventory.json"), `${scanner}:/work/`);
  return scan("bun", fixture, "audit-external", "/work/inventory.json", ...addresses);
}

async function loadNestedImage(pin: string, role: string) {
  await docker("image", "inspect", "--format", "{{.Id}}", pin).catch(() => docker("pull", pin));
  // Let the outer daemon handle registry auth and TLS. The nested daemon gets only the pinned image.
  const tag = `${name}:${role}`;
  await docker("image", "tag", pin, tag);
  try {
    const archive = join(directory, `${role}.tar`);
    await docker("image", "save", "-o", archive, tag);
    await docker("cp", archive, `${vps}:/tmp/${role}.tar`);
    await nested("image", "load", "-i", `/tmp/${role}.tar`);
    await host("rm", `/tmp/${role}.tar`);
    return tag;
  } finally {
    await docker("image", "rm", tag);
  }
}

async function checkDhcpv6() {
  await host(
    "sh",
    "-eu",
    "-c",
    `ip netns add fd20-dhcp
ip link add fd20-client type veth peer name fd20-server
ip link set fd20-server netns fd20-dhcp
ip -n fd20-dhcp address add fd20::1/64 dev fd20-server
ip -n fd20-dhcp link set fd20-server up
mkdir -p /etc/systemd/network
cat >/etc/systemd/network/10-fd20-dhcp.network <<'EOF'
[Match]
Name=fd20-client
[Network]
DHCP=ipv6
IPv6AcceptRA=no
[DHCPv6]
WithoutRA=solicit
UseDNS=no
EOF`,
  );
  await docker(
    "exec",
    "-d",
    vps,
    "ip",
    "netns",
    "exec",
    "fd20-dhcp",
    "dnsmasq",
    "--keep-in-foreground",
    "--port=0",
    "--interface=fd20-server",
    "--bind-interfaces",
    "--dhcp-range=fd20::100,fd20::1ff,64,2m",
    "--dhcp-leasefile=/tmp/fd20-dhcp.leases",
    "--log-dhcp",
    "--log-facility=/tmp/fd20-dhcp.log",
  );
  await host("systemctl", "start", "dbus");
  await host("systemctl", "start", "systemd-networkd");
  const acquired = await ready(dhcpv6LeaseExpiry, "DHCPv6 lease with the boot firewall in place");
  console.log("Ubuntu networkd acquired a DHCPv6 address under the boot firewall.");
  return acquired;
}

async function dhcpv6LeaseExpiry() {
  const [link] = JSON.parse(await host("ip", "-6", "-j", "address", "show", "dev", "fd20-client")) as {
    addr_info: { local: string; valid_life_time: number }[];
  }[];
  const lease = link?.addr_info.find(({ local }) => /^fd20::1[\da-f]{2}$/.test(local));
  assert.ok(lease && lease.valid_life_time > 0, "The DHCPv6 client has a live lease.");
  return Date.now() + lease.valid_life_time * 1000;
}

async function checkDhcpv6Renewal(acquired: number) {
  await ready(
    async () => {
      const log = await host("cat", "/tmp/fd20-dhcp.log");
      assert.match(log, /DHCP(?:RENEW|REBIND)/);
      assert.ok((await dhcpv6LeaseExpiry()) > acquired + 30_000, "The client extended its DHCPv6 lease.");
    },
    "DHCPv6 renewal",
    90_000,
  );
  console.log("The DHCPv6 lease renewed through the host firewall.");
}

let builtImage = false;
try {
  const result = await Bun.build({
    entrypoints: [
      join(import.meta.dir, "host-audit.ts"),
      join(import.meta.dir, "database-ingress.ts"),
      join(import.meta.dir, "install.ts"),
      join(import.meta.dir, "host-hardening-test", "inside.ts"),
    ],
    naming: "[name].js",
    outdir: join(directory, "scripts"),
    target: "bun",
  });
  if (!result.success) throw new Error(result.logs.join("\n"));
  await docker(
    "build",
    "--quiet",
    "--target",
    "vps",
    "-t",
    image,
    join(import.meta.dir, "host-hardening-test"),
  );
  builtImage = true;
  // The scanner shares only the simulated VPS's WAN link. The nested daemon has its
  // own socket, data, bridges and nftables, and publishes no ports on the build machine.
  try {
    await docker("network", "create", "--ipv6", runtime.network);
  } catch (error) {
    if (!/ipv6.*(?:disabled|not supported|unavailable)/i.test(String(error))) throw error;
    console.log("Local IPv6 probes skipped. Docker reports IPv6 is unavailable.");
    await docker("network", "create", runtime.network);
  }
  runtime.networkCreated = true;
  for (const container of [vps, scanner]) {
    runtime.containers.push(container);
    await docker(
      "run",
      "-d",
      "--name",
      container,
      "--network",
      runtime.network,
      ...(container === vps
        ? ["--privileged", "--cgroupns", "private", "--tmpfs", "/run", "--tmpfs", "/run/lock"]
        : ["--init"]),
      image,
      ...(container === vps ? ["/sbin/init"] : ["sleep", "infinity"]),
    );
    await exec(container, "mkdir", "-p", "/work");
    await docker("cp", join(directory, "scripts"), `${container}:/work/`);
  }
  const wan = JSON.parse(await docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", vps))[
    runtime.network
  ];
  const addresses: string[] = [wan.IPAddress, wan.GlobalIPv6Address].filter(Boolean);
  assert.ok(wan.IPAddress);
  if (!wan.GlobalIPv6Address) console.log("Local IPv6 probes skipped. The test WAN has no IPv6 address.");

  console.log("Installing the VPS baseline and boot units in the isolated systemd guest.");
  await ready(() => host("systemctl", "show", "--property", "SystemState"), "Systemd");
  await host(
    "sh",
    "-eu",
    "-c",
    `cat >/usr/local/bin/tailscale <<'EOF'
#!/bin/sh
set -eu
case "$1" in
  status)
    if [ -f /tmp/tailscale-enrolled ]; then
      echo '{"BackendState":"Running","TUN":true,"Self":{"Online":true,"Tags":["tag:ark-vps"]}}'
    else
      echo '{"BackendState":"NeedsLogin","TUN":true}'
    fi ;;
  up)
    test "$2" = "--auth-key=file:/tmp/vps-auth-key"
    test "$3" = "--advertise-tags=tag:ark-vps"
    touch /tmp/tailscale-enrolled ;;
  set) test "$2" = "--ssh"; touch /tmp/tailscale-ssh ;;
  debug) test -f /tmp/tailscale-ssh; echo '{"RunSSH":true}' ;;
  *) exit 1 ;;
esac
EOF
chmod +x /usr/local/bin/tailscale
cat >/etc/systemd/system/tailscaled.service <<'EOF'
[Service]
ExecStart=/usr/bin/sleep infinity
[Install]
WantedBy=multi-user.target
EOF
install -m 600 /dev/null /tmp/vps-auth-key
systemctl daemon-reload
mkdir -p /etc/docker
printf '%s\\n' '{"storage-driver":"vfs"}' >/etc/docker/daemon.json
systemctl unmask docker.service docker.socket
rm -f /etc/apt/apt.conf.d/docker-disable-periodic-update
`,
  );
  await assert.rejects(
    docker("exec", "-e", "TS_VPS_AUTHKEY_FILE=/nonexistent", vps, "bun", fixture, "enroll"),
    /Set TS_VPS_AUTHKEY_FILE to a private absolute key file/,
  );
  console.log(
    await docker("exec", "-e", "TS_VPS_AUTHKEY_FILE=/tmp/vps-auth-key", vps, "bun", fixture, "enroll"),
  );
  await host(
    "sh",
    "-eu",
    "-c",
    `cat >/etc/apt/apt.conf.d/99ark-fixture <<'EOF'
APT::Periodic::Unattended-Upgrade "0";
#clear Unattended-Upgrade::Allowed-Origins;
EOF`,
  );
  await assert.rejects(
    docker("exec", ...env, vps, "bun", fixture, "harden"),
    /Effective apt configuration:.*APT::Periodic::Unattended-Upgrade.*Allowed-Origins/,
  );
  await host("rm", "/etc/apt/apt.conf.d/99ark-fixture");
  await docker("exec", ...env, vps, "bun", fixture, "harden");
  console.log(await host("bun", fixture, "reboot-metric"));
  const dhcpv6Expiry = await checkDhcpv6();
  assert.match(
    await host("systemctl", "show", "docker.service", "-p", "Requires"),
    /ark-host-firewall\.service/,
  );
  assert.match(
    await host("systemctl", "show", "docker.service", "-p", "After"),
    /ark-host-firewall\.service/,
  );
  await host("systemctl", "enable", "--now", "docker.service");
  await ready(() => nested("info"), "Nested Docker daemon");
  await nested("network", "create", "mail");
  const platform = await readFile(join(platformDir, "docker-compose.yml"), "utf8");
  const haproxyPin = /^    image: (haproxy:\S+)$/m.exec(platform)?.[1];
  assert.ok(haproxyPin);
  const haproxyImage = await loadNestedImage(haproxyPin, "haproxy");
  const fixtureImage = await loadNestedImage(image, "worker");
  await nested(
    "run",
    "-d",
    "--name",
    "test-edge-udp",
    "--network",
    "mail",
    "-p",
    "41642:41642/udp",
    "-v",
    "/work/scripts:/work/scripts:ro",
    fixtureImage,
    "bun",
    fixture,
    "udp-echo",
  );
  const startHaproxy = () =>
    nested(
      "run",
      "-d",
      "--name",
      "test-haproxy",
      "--network",
      "mail",
      "-p",
      "5432:5432",
      "--group-add",
      "4400",
      "--tmpfs",
      "/var/run/haproxy:uid=99,gid=4400,mode=770",
      "-v",
      "/work/test-haproxy:/work/test-haproxy:ro",
      "-e",
      "ARK_EDGE_L4_GENERATION=/work/test-haproxy",
      haproxyImage,
      "haproxy",
      "-db",
      "-f",
      "/work/test-haproxy/haproxy.cfg",
    );
  await host("bun", fixture, "edge-generation", "fresh");
  await startHaproxy();
  for (const address of addresses) {
    await ready(() => scan("bun", fixture, "pg-fresh", address), `Fresh PostgreSQL listener at ${address}`);
  }
  const mailCompose = await readFile(join(root, "infra/mail/docker-compose.yml"), "utf8");
  const mailImage = /^    image: (\S+)$/m.exec(mailCompose)?.[1];
  assert.ok(mailImage && mailImage.startsWith("stalwartlabs/stalwart@sha256:"));
  const mailImageId = await loadNestedImage(mailImage, "mail");
  await composeFixtures(fixtureImage, haproxyPin, mailImageId);
  const published = /ports: \[([^\]]+)\]/.exec(mailCompose)?.[1]?.match(/\d+:\d+/g);
  assert.deepEqual(
    published,
    MAIL_PUBLIC_TCP.map((port) => `${port}:${port}`),
  );
  await docker("cp", join(root, "infra/mail/config.json"), `${vps}:/tmp/stalwart.json`);
  const mailPassword = crypto.randomUUID();
  const mailArgs = [
    "run",
    "-d",
    "--name",
    "mail",
    "--network",
    "mail",
    "--cap-drop",
    "ALL",
    "--cap-add",
    "NET_BIND_SERVICE",
    "--security-opt",
    "no-new-privileges=true",
    "-e",
    `STALWART_RECOVERY_ADMIN=admin:${mailPassword}`,
    "-v",
    "/tmp/stalwart.json:/etc/stalwart/config.json:ro",
    ...published!.flatMap((port) => ["-p", port]),
  ];
  await nested(...mailArgs, "-p", "24444:8080", mailImageId);
  await ready(
    () => nested("exec", "mail", "curl", "-fsS", "http://127.0.0.1:8080/"),
    "Stalwart and unexpected Docker publication",
    60_000,
  );
  const configureMail = (mode = "configure-mail") =>
    docker("exec", "-e", `ARK_FD20_TEST_MAIL_PASSWORD=${mailPassword}`, vps, "bun", fixture, mode);
  await configureMail("mail-loopback");
  await configureMail();
  await docker(
    "exec",
    "-d",
    vps,
    "bun",
    "-e",
    `const child = Bun.spawn(["bun", "${fixture}", "listen"], { stderr: Bun.file("/tmp/listeners.log") });
     process.exit(await child.exited);`,
  );
  await docker("exec", "-d", vps, "bun", fixture, "listen", "22");
  await ready(async () => {
    const sockets = await host("ss", "-H", "-lnt");
    assert.match(sockets, /:22\s/);
    assert.match(sockets, /:80\s/);
  }, "Simulated VPS listeners");
  await applyPolicy("on");
  await assert.rejects(
    docker("exec", ...env, vps, "bun", audit),
    /Unexpected TCP .*24444 published[\s\S]+Unexpected TCP .*22 listening/,
  );
  console.log(
    "Local audit rejected both the unexpected Docker publication and the host's public SSH listener.",
  );
  console.log(await externalAudit(addresses, true));
  await checkDhcpv6Renewal(dhcpv6Expiry);
  await nested(
    "run",
    "-d",
    "--name",
    "pgbouncer-public",
    "--network",
    "mail",
    "-v",
    "/work/scripts:/work/scripts:ro",
    fixtureImage,
    "bun",
    fixture,
    "pg-target",
  );
  await nested("rm", "-f", "test-haproxy");
  await host("bun", fixture, "edge-generation", "active");
  await startHaproxy();
  for (const address of addresses) {
    await ready(() => scan("bun", fixture, "pg-active", address), `Active PostgreSQL listener at ${address}`);
  }
  await host("nft", "add", "table", "inet", "test_provider");
  await host(
    "nft",
    "add",
    "chain",
    "inet",
    "test_provider",
    "input",
    "{ type filter hook input priority -10; policy accept; }",
  );
  await host("nft", "add", "rule", "inet", "test_provider", "input", "udp", "dport", "41641", "drop");
  await docker("exec", "-d", vps, "bun", fixture, "unexpected-udp");
  await host("nft", "insert", "rule", "inet", "ark_host", "input", "udp", "dport", "161", "accept");
  const udpPid = await ready(async () => {
    const sockets = await host("ss", "-H", "-lunp", "sport", "=", ":161");
    const pid = /:161\s[^\n]*pid=(\d+)/.exec(sockets)?.[1];
    assert.ok(pid);
    return pid;
  }, "Unexpected UDP listener");
  try {
    await assert.rejects(
      externalAudit([wan.IPAddress], true),
      /unexpected UDP 161, UDP reachability unverified for 41641/i,
    );
  } finally {
    await host("nft", "delete", "table", "inet", "test_provider");
  }
  await host("kill", udpPid);
  await applyPolicy("on");
  await Promise.all(
    addresses.map(async (address) => console.log(await scan("bun", fixture, "mail", address))),
  );

  await nested("rm", "-f", "-v", "mail");
  await nested(...mailArgs, mailImageId);
  await ready(
    () => nested("exec", "mail", "curl", "-fsS", "http://127.0.0.1:8080/"),
    "Stalwart after withdrawal",
  );
  await configureMail();
  const sshPid = /:22\s[^\n]*pid=(\d+)/.exec(await host("ss", "-H", "-lntp", "sport", "=", ":22"))?.[1];
  assert.ok(sshPid);
  await host("kill", sshPid);
  console.log(await docker("exec", ...env, vps, "bun", audit));

  await interruptedMailOff(addresses);
  await docker("restart", vps);
  await ready(() => nested("info"), "Docker startup after firewall boot");
  assert.doesNotMatch(
    await host("nft", "-s", "-y", "list", "table", "inet", "ark_host"),
    /\b(?:20001|20007|587)\b/,
  );
  await applyPolicy("off");
  assert.match(await host("nft", "-s", "-y", "list", "table", "inet", "ark_host"), /\b20001\b/);
  console.log("Boot restored the mail-off baseline. The reconciler replayed acknowledged dedicated ports.");

  const monitoring = await readFile(join(root, "infra/monitoring/docker-compose.yml"), "utf8");
  const promImage = /^    image: (\S+)$/m.exec(monitoring)?.[1];
  assert.ok(promImage);
  console.log(
    await docker(
      "run",
      "--rm",
      "--network",
      "none",
      "--entrypoint",
      "promtool",
      "-v",
      `${join(root, "infra/monitoring/alerts.yml")}:/alerts.yml:ro`,
      "-v",
      `${join(import.meta.dir, "host-hardening-test/reboot-alert.test.yml")}:/test.yml:ro`,
      promImage,
      "test",
      "rules",
      "/test.yml",
    ),
  );
} catch (error) {
  if (builtImage) {
    const logs = await nested("logs", "--tail", "30", "mail").catch(() => "");
    if (logs) console.error(logs);
    const listenerLogs = await host("cat", "/tmp/listeners.log").catch(() => "");
    if (listenerLogs) console.error(listenerLogs);
    const status = await host("ss", "-H", "-lntup").catch(() => "");
    if (status) console.error(status);
  }
  throw error;
} finally {
  await runtime.cleanup();
  if (builtImage) await hostImageRemove();
  stopSignalHandlers();
}

async function hostImageRemove() {
  const child = Bun.spawn(["docker", "image", "rm", image], { stdout: "ignore", stderr: "inherit" });
  if (await child.exited) console.error(`Unable to remove disposable test image ${image}.`);
}
