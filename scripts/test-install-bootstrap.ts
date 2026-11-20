// install.sh in disposable containers (mise run test:install-bootstrap; needs Docker and network
// access). Each case runs in its own throwaway container that is removed afterwards:
//   - non-root, piped: nothing is installed, the sudo one-liner is printed, exit non-zero;
//   - Debian (unsupported OS) as root: refused, nothing installed;
//   - Ubuntu with the distribution docker.io and no Compose v2: refused, no docker-ce;
//   - fresh Ubuntu as root: real apt installs of the base packages, Docker Engine with Compose v2
//     from Docker's repository, mise (extrepo) and Tailscale, then mise install, bun install and the
//     hand-off to host:setup (which stops at its first question in --non-interactive mode); a second
//     run installs nothing.
// The containers have no systemd, so nothing is enrolled, hardened or started.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { renderHostFirewall, updateHostFirewallPorts, updateHostSshAccess } from "@ark-stack/shared";

const UBUNTU = "ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8";
const SUPPORTED_UBUNTU = [
  UBUNTU,
  "ubuntu:22.04@sha256:f64b2ffc2f10ab8f8505aa56b2664bd846cbb9df87c7e2532e30f7667021c0e6",
  "ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db",
];
const DEBIAN = "debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc";
const root = join(import.meta.dir, "..");

if (Bun.spawnSync(["docker", "info"], { stdout: "ignore", stderr: "ignore" }).exitCode !== 0) {
  console.error("test:install-bootstrap needs a running Docker daemon.");
  process.exit(1);
}

// The working tree (tracked and new files, no node_modules) as a tarball the containers unpack.
const work = mkdtempSync(join(tmpdir(), "ark-install-bootstrap-"));
const files = Bun.spawnSync(["git", "ls-files", "-co", "--exclude-standard", "-z"], { cwd: root });
assert.equal(files.exitCode, 0, "git ls-files failed");
const tar = Bun.spawnSync(["tar", "-cf", join(work, "repo.tar"), "--null", "-T", "-"], {
  cwd: root,
  stdin: files.stdout,
});
assert.equal(tar.exitCode, 0, tar.stderr.toString());

/** Asserts on the output, reporting its tail (apt output is long) on failure. */
function expectOutput(output: string, pattern: RegExp, present = true) {
  if (pattern.test(output) !== present) {
    throw new Error(
      `Expected the output ${present ? "" : "not "}to match ${pattern}. Output tail:\n${output.slice(-4000)}`,
    );
  }
}

const UNPACK =
  "mkdir -p /work/ark-stack && tar --warning=no-unknown-keyword -xf /src/repo.tar -C /work/ark-stack";

function container(image: string, script: string, user?: string, capabilities: string[] = []) {
  const name = `ark-install-bootstrap-${crypto.randomUUID().slice(0, 8)}`;
  const args = ["docker", "run", "--rm", "--name", name, "-v", `${work}:/src:ro`];
  if (user) args.push("--user", user);
  for (const capability of capabilities) args.push("--cap-add", capability);
  if (capabilities.includes("SYS_ADMIN")) args.push("--security-opt", "apparmor=unconfined");
  args.push(image, "bash", "-c", script);
  console.log(`--- ${image.split("@")[0]}${user ? ` (user ${user})` : ""}`);
  const result = Bun.spawnSync(args, { stdout: "pipe", stderr: "pipe" });
  const output = `${result.stdout.toString()}${result.stderr.toString()}`;
  return { status: result.exitCode, output };
}

try {
  // Non-root, piped exactly like the one-liner.
  {
    const { output } = container(
      UBUNTU,
      `${UNPACK}; useradd -m tester; su tester -c "bash < /work/ark-stack/install.sh"; echo "EXIT=$?"`,
    );
    expectOutput(output, /nothing has been changed/);
    expectOutput(output, /\| sudo bash/);
    expectOutput(output, /\[ok\] {3}operating system: Ubuntu 24\.04/);
    expectOutput(output, /EXIT=1/);
    console.log("ok   non-root: nothing changed, sudo command printed");
  }

  // Unsupported OS as root.
  {
    const { output } = container(
      DEBIAN,
      `${UNPACK}; bash /work/ark-stack/install.sh; echo "EXIT=$?"; command -v docker || echo NO_DOCKER`,
    );
    expectOutput(output, /Unsupported operating system/);
    expectOutput(output, /EXIT=1/);
    expectOutput(output, /NO_DOCKER/);
    console.log("ok   Debian: refused, nothing installed");
  }

  // Distribution docker.io without Compose v2.
  {
    const { output } = container(
      UBUNTU,
      `${UNPACK}; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq docker.io >/dev/null;
       bash /work/ark-stack/install.sh; echo "EXIT=$?"; dpkg-query -W docker-ce 2>/dev/null || echo NO_DOCKER_CE;
       test -e /etc/apt/sources.list.d/docker.sources || echo NO_DOCKER_REPO`,
    );
    expectOutput(output, /without the Compose v2 plugin/);
    expectOutput(output, /EXIT=1/);
    expectOutput(output, /NO_DOCKER_CE/);
    expectOutput(output, /NO_DOCKER_REPO/);
    console.log("ok   docker.io without Compose v2: refused, nothing changed");
  }

  {
    const { output } = container(
      UBUNTU,
      `set -e; ${UNPACK}
       export DEBIAN_FRONTEND=noninteractive
       apt-get update -qq
       for pkg in runc containerd; do
         apt-get install -y -qq --no-install-recommends "$pkg" >/dev/null
         command -v docker && exit 1
         find /etc/apt -type f -exec sha256sum {} + | sort > /tmp/apt-before
         dpkg-query -W > /tmp/pkg-before
         if bash /work/ark-stack/install.sh; then exit 1; fi
         find /etc/apt -type f -exec sha256sum {} + | sort | cmp /tmp/apt-before
         dpkg-query -W | cmp /tmp/pkg-before
         echo "unchanged after $pkg refusal"
       done`,
    );
    expectOutput(output, /unchanged after runc refusal/);
    expectOutput(output, /unchanged after containerd refusal/);
    console.log("ok   standalone containerd and runc: packages and apt configuration unchanged");
  }

  for (const image of SUPPORTED_UBUNTU) {
    const { status, output } = container(
      image,
      `${UNPACK}; cd /work/ark-stack;
       bash ./install.sh --non-interactive; echo "FIRST=$?";
       docker compose version && mise --version && tailscale version | head -n1 && git --version && jq --version && openssl version && command -v ip && command -v ss || exit 1;
       bash ./install.sh --non-interactive > /tmp/second.log 2>&1; echo "SECOND=$?";
       cat /tmp/second.log
       if [ "${image}" = "${UBUNTU}" ]; then
         # The first process holds the actual Linux lock on the existing empty lock file.
         cat >/tmp/contend <<'SH'
set -eu
expect_lock() {
  if "$@" > /tmp/locked 2>&1; then cat /tmp/locked; exit 1; fi
  grep -q 'Another Ark host setup, install or signed maintenance run is in progress' /tmp/locked
}
expect_lock bash ./install.sh --non-interactive
expect_lock mise exec -- bun --no-env-file scripts/host-setup.ts --non-interactive
expect_lock mise exec -- bun --no-env-file scripts/install.ts --harden-vps
expect_lock env ARK_MAINTENANCE_EXECUTE=1 mise exec -- bun --no-env-file scripts/maintain.ts
SH
         flock --nonblock /run/ark-stack/deployment.lock bash /tmp/contend || exit 1
         echo "deployment contention refused"
         # Remove only the plugin from this disposable test container to exercise the repair path.
         dpkg --remove docker-compose-plugin || exit 1
         docker compose version >/dev/null 2>&1 && exit 1
         bash ./install.sh --non-interactive > /tmp/compose.log 2>&1; echo "COMPOSE=$?"
         cat /tmp/compose.log
         docker compose version || exit 1
       fi`,
    );
    if (status !== 0) throw new Error(output.slice(-6000));
    expectOutput(output, /Installing (?:\S+ )*iproute2/);
    expectOutput(output, /Installing Docker Engine and the Compose v2 plugin/);
    expectOutput(output, /Docker Compose version v?\d/);
    expectOutput(output, /Missing required answer: the domain \(--domain or ARK_SETUP_DOMAIN\)/);
    expectOutput(output, /FIRST=1/);
    expectOutput(output, /SECOND=1/);
    const second = output.slice(output.indexOf("SECOND=")).split("COMPOSE=")[0]!;
    expectOutput(second, /==> Installing (git|Docker|Tailscale)|Adding/, false);
    expectOutput(second, /Docker with Compose v2 is present/);
    if (image === UBUNTU) {
      expectOutput(output, /deployment contention refused/);
      const repair = output.slice(output.indexOf("COMPOSE="));
      expectOutput(repair, /COMPOSE=1/);
      expectOutput(repair, /Installing the Docker Compose v2 plugin/);
      expectOutput(repair, /Installing Docker Engine/, false);
      expectOutput(repair, /Docker Compose version v?\d/);
    }
    console.log("ok   fresh Ubuntu: prerequisites installed, setup started; second run installed nothing");
  }

  // Make fresh SSH connections in a disposable network namespace. The recovery script uses
  // a shim for systemd, but the OpenSSH process, source addresses and nftables are real.
  const baseline = { mailEnabled: false, sniPorts: [] };
  writeFileSync(
    join(work, "recovery.nft"),
    renderHostFirewall(baseline, { ports: [22], source: "192.0.2.2" }),
  );
  writeFileSync(join(work, "ports.nft"), updateHostFirewallPorts({ ...baseline, sniPorts: [8883] }));
  writeFileSync(join(work, "cutover.nft"), updateHostSshAccess({ ports: [] }));
  const recovery = container(
    UBUNTU,
    `set -eu
    ${UNPACK}
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends iproute2 netbase nftables openssh-server openssh-client >/dev/null
    ip netns add owner
    ip link add ark-host-veth type veth peer name ark-peer-veth
    ip link set ark-peer-veth netns owner
    ip address add 192.0.2.1/24 dev ark-host-veth
    ip link set ark-host-veth up
    ip -n owner address add 192.0.2.2/24 dev ark-peer-veth
    ip -n owner address add 192.0.2.3/24 dev ark-peer-veth
    ip -n owner link set ark-peer-veth up
    mkdir -p /run/sshd /tmp/ark-recovery/bin /tmp/ark-recovery/transaction
    ssh-keygen -q -t ed25519 -N '' -f /tmp/ark-recovery/client
    cat >/tmp/ark-recovery/sshd-config <<'CONF'
ListenAddress 192.0.2.1:22
PidFile /tmp/ark-recovery/sshd.pid
AuthorizedKeysFile /tmp/ark-recovery/client.pub
StrictModes no
PermitRootLogin prohibit-password
PasswordAuthentication no
UsePAM yes
CONF
    cat >/tmp/ark-recovery/bin/systemctl <<'SH'
#!/bin/sh
case "$1" in
  is-enabled) echo enabled ;;
  enable) exit 0 ;;
  start) /usr/sbin/sshd -f /tmp/ark-recovery/sshd-config ;;
  is-active) kill -0 "$(cat /tmp/ark-recovery/sshd.pid)" ;;
  *) exit 1 ;;
esac
SH
    chmod +x /tmp/ark-recovery/bin/systemctl
    export PATH="/tmp/ark-recovery/bin:$PATH"
    connect() {
      ip netns exec owner ssh -b "$1" -i /tmp/ark-recovery/client \\
        -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=accept-new \\
        -o UserKnownHostsFile=/tmp/ark-recovery/known_hosts root@192.0.2.1 true
    }
    nft -f /src/recovery.nft
    nft -f /src/ports.nft
    systemctl start ssh.service
    connect 192.0.2.2
    if connect 192.0.2.3; then exit 1; fi
    kill "$(cat /tmp/ark-recovery/sshd.pid)"
    if connect 192.0.2.2; then exit 1; fi
    txn=/tmp/ark-recovery/transaction
    flock "$txn/lock" sh /work/ark-stack/scripts/host-setup/restore-ssh.sh "$txn" timed /etc/ufw ssh.service:enabled:true
    connect 192.0.2.2
    nft -f /src/cutover.nft
    if connect 192.0.2.2; then exit 1; fi
    echo "scoped OpenSSH preserved across reconciliation, restored on rollback and closed after cutover"
  `,
    undefined,
    ["NET_ADMIN", "SYS_ADMIN"],
  );
  assert.equal(recovery.status, 0, recovery.output.slice(-5000));
  expectOutput(
    recovery.output,
    /scoped OpenSSH preserved across reconciliation, restored on rollback and closed after cutover/,
  );
  console.log("ok   scoped SSH recovery: fresh connections observed in an isolated network namespace");
  console.log("test:install-bootstrap passed.");
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  rmSync(work, { recursive: true, force: true });
}
