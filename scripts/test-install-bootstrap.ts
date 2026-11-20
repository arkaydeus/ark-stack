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
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const UBUNTU = "ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8";
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

const UNPACK = "mkdir -p /work/ark-stack && tar -xf /src/repo.tar -C /work/ark-stack";

function container(image: string, script: string, user?: string) {
  const name = `ark-install-bootstrap-${crypto.randomUUID().slice(0, 8)}`;
  const args = ["docker", "run", "--rm", "--name", name, "-v", `${work}:/src:ro`];
  if (user) args.push("--user", user);
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

  // Fresh Ubuntu as root: the full prerequisite path and the hand-off, twice.
  {
    const { output } = container(
      UBUNTU,
      `${UNPACK}; cd /work/ark-stack;
       bash ./install.sh --non-interactive; echo "FIRST=$?";
       docker compose version && mise --version && tailscale version | head -n1 && git --version && jq --version && openssl version;
       bash ./install.sh --non-interactive > /tmp/second.log 2>&1; echo "SECOND=$?";
       grep -c "apt-get\\|Installing" /tmp/second.log || true; cat /tmp/second.log`,
    );
    expectOutput(output, /Installing git curl ca-certificates jq openssl/);
    expectOutput(output, /Installing Docker Engine and the Compose v2 plugin/);
    expectOutput(output, /Docker Compose version v?\d/);
    expectOutput(output, /Missing required answer: the domain \(--domain or ARK_SETUP_DOMAIN\)/);
    expectOutput(output, /FIRST=1/);
    expectOutput(output, /SECOND=1/);
    const second = output.slice(output.indexOf("SECOND="));
    expectOutput(second, /==> Installing (git|Docker|Tailscale)|Adding/, false);
    expectOutput(second, /Docker with Compose v2 is present/);
    console.log("ok   fresh Ubuntu: prerequisites installed, setup started; second run installed nothing");
  }
  console.log("test:install-bootstrap passed.");
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  rmSync(work, { recursive: true, force: true });
}
