// Runs only inside the disposable, network-isolated Ubuntu guest.
import assert from "node:assert/strict";
import { mkdir, rm, writeFile } from "node:fs/promises";

import { runSetup } from "../host-setup.ts";
import { manualProviderFirewall } from "../host-setup/provider-firewall.ts";
import { runCommand } from "../host-setup/system.ts";
import { enrollVps, hostCommand, installHostHardening } from "../install-host-hardening.ts";

const root = "/work";
const password = "disposable-fixture-password";
const sshd = "/usr/sbin/sshd";
const controlUser = "ark_control";
const newUser = "ark_protected";

async function setup(user: string, passwordExpected: boolean) {
  const lines: string[] = [];
  const code = await runSetup({
    root,
    argv: ["--domain", "example.com", "--ssh-user", user],
    env: process.env,
    stateDir: `/work/setup-${user}`,
    paths: { osRelease: "/etc/os-release", hostFirewall: "/work/never-created.nft" },
    isRoot: true,
    platform: process.platform,
    bun: process.execPath,
    stdinIsTty: true,
    firewalls: [manualProviderFirewall],
    ui: () => ({
      interactive: true,
      print: (line) => lines.push(line ?? ""),
      ask: async (question, fallback = "") =>
        question.startsWith("Create ") ? "yes" : question.includes("session works") ? "no" : fallback,
      askSecret: async () => "",
      askPassword: async () => {
        assert.ok(passwordExpected, "The installer prompted for a password before verifying the listener.");
        return password;
      },
    }),
    run: async (argv, options) => {
      const command = argv.join(" ");
      if (command === "tailscale status --json") {
        return {
          status: 0,
          stderr: "",
          stdout: JSON.stringify({
            BackendState: "Running",
            TUN: true,
            Self: { ID: "fixture", Online: true, Tags: ["tag:ark-vps"], DNSName: "test.example.test." },
          }),
        };
      }
      if (command === "tailscale debug prefs") return { status: 0, stdout: '{"RunSSH":true}', stderr: "" };
      if (command === "systemctl is-active tailscaled.service")
        return { status: 0, stdout: "active", stderr: "" };
      if (argv[0] === "docker" || argv[2] === 'command -v "$1"')
        return { status: 0, stdout: "fixture", stderr: "" };
      return runCommand(argv, options);
    },
  });
  return { code, text: lines.join("\n") };
}

const sshEnv = { ...process.env, SSHPASS: password };

function loginCommand(user: string, method = "password", port = "22", command = "id -un") {
  return [
    "sshpass",
    "-e",
    "ssh",
    "-F",
    "/dev/null",
    "-o",
    "ConnectTimeout=3",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "NumberOfPasswordPrompts=1",
    "-o",
    `PreferredAuthentications=${method}`,
    "-p",
    port,
    `${user}@127.0.0.1`,
    command,
  ];
}

function login(user: string, method?: string, port?: string) {
  return runCommand(loginCommand(user, method, port), { env: sshEnv });
}

async function expectLogin(user: string, method?: string, port?: string) {
  const loginResult = await login(user, method, port);
  assert.equal(loginResult.status, 0, loginResult.stderr);
  assert.equal(loginResult.stdout.trim(), user);
}

async function expectRefusal(user: string) {
  const result = await setup(user, false);
  assert.equal(result.code, 1, result.text);
  assert.match(result.text, /provision a protected local account manually/);
  assert.equal((await runCommand(["getent", "passwd", user])).status, 2);
}

if (process.argv[2] === "ssh") {
  await hostCommand("systemctl", ["stop", "ssh.service", "ssh.socket"]);
  await hostCommand("useradd", ["--create-home", "--shell", "/bin/bash", controlUser]);
  await hostCommand("chpasswd", [], `${controlUser}:${password}\n`);
  await writeFile(
    "/etc/ssh/sshd_config.d/90-fixture.conf",
    "PasswordAuthentication yes\nKbdInteractiveAuthentication yes\n",
  );
  await hostCommand("systemctl", ["start", "ssh.service"]);
  await expectLogin(controlUser);
  await expectLogin(controlUser, "keyboard-interactive");

  const recovery = Bun.spawn(loginCommand(controlUser, "password", "22", "echo ready; cat"), {
    env: sshEnv,
    stdin: "pipe",
    stdout: "pipe",
    stderr: "inherit",
  });
  try {
    const reader = recovery.stdout.getReader();
    const ready = await reader.read();
    assert.equal(new TextDecoder().decode(ready.value), "ready\n");
    const created = await setup(newUser, true);
    assert.equal(created.code, 2, created.text);
    assert.match(created.text, /OpenSSH password login remains disabled/);
    recovery.stdin.write("still connected\n");
    recovery.stdin.end();
    let echo = "";
    for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
      echo += new TextDecoder().decode(chunk.value);
    }
    assert.equal(echo, "still connected\n");
    assert.equal(await recovery.exited, 0);
  } finally {
    recovery.kill();
    await recovery.exited;
  }
  assert.match(await hostCommand("id", ["-nG", newUser]), /\bsudo\b/);
  for (const method of ["password", "keyboard-interactive"]) {
    const denied = await login(newUser, method);
    assert.notEqual(denied.status, 0);
    assert.match(denied.stderr, /Permission denied \(publickey\)/);
    await expectLogin(controlUser, method);
  }

  // The disk now looks safe. Start the service with a different config, then restore the
  // service definition on disk while the listener still uses the alternate config.
  await writeFile(
    "/etc/ssh/sshd_config.d/90-fixture.conf",
    "PasswordAuthentication no\nKbdInteractiveAuthentication no\n",
  );
  const alternate = "/work/sshd_config.alternate";
  await writeFile(alternate, "Port 2222\nListenAddress 127.0.0.1\nUsePAM yes\nPasswordAuthentication yes\n");
  const override = "/etc/systemd/system/ssh.service.d";
  await mkdir(override, { recursive: true });
  await writeFile(
    `${override}/fixture.conf`,
    `[Service]\nExecStart=\nExecStart=${sshd} -D -f ${alternate}\n`,
  );
  await hostCommand("systemctl", ["daemon-reload"]);
  await hostCommand("systemctl", ["restart", "ssh.service"]);
  await rm(`${override}/fixture.conf`);
  await hostCommand("systemctl", ["daemon-reload"]);
  await expectLogin(controlUser);
  await expectRefusal("ark_alternate");

  await hostCommand("systemctl", ["stop", "ssh.service", "ssh.socket"]);
  await mkdir("/run/sshd", { recursive: true });
  const standalone = Bun.spawn([sshd, "-D", "-f", alternate], { stdout: "ignore", stderr: "ignore" });
  try {
    await Bun.sleep(150);
    await expectLogin(controlUser, "password", "2222");
    await expectRefusal("ark_unmanaged");
  } finally {
    standalone.kill();
    await standalone.exited;
  }

  await hostCommand("systemctl", ["start", "ssh.socket"]);
  const idle = await setup("ark_socket", true);
  assert.equal(idle.code, 2, idle.text);
  assert.equal((await runCommand(["systemctl", "is-active", "ssh.service"])).stdout.trim(), "inactive");
  const denied = await login("ark_socket");
  assert.notEqual(denied.status, 0);
  assert.match(denied.stderr, /Permission denied \(publickey\)/);
} else {
  const bin = "/work/bin";
  await mkdir(bin);
  await writeFile(`${bin}/systemctl`, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  await writeFile(`${bin}/apt-get`, "#!/bin/sh\necho fixture-reached-apt >&2\nexit 42\n", { mode: 0o755 });
  await writeFile(
    `${bin}/tailscale`,
    `#!/bin/sh
set -eu
cd /work
case "$1" in
  status)
    if [ ! -e enrolled ]; then
      echo '{"BackendState":"NeedsLogin","TUN":true}'
    elif [ -e offline ]; then
      rm offline
      echo '{"BackendState":"Running","TUN":true,"Self":{"Online":false,"Tags":["tag:ark-vps"]}}'
    else
      echo '{"BackendState":"Running","TUN":true,"Self":{"Online":true,"Tags":["tag:ark-vps"]}}'
    fi ;;
  up) touch enrolled offline ;;
  set) test "$2" = "--ssh"; test -e enrolled; test ! -e offline; touch ssh-enabled ;;
  debug) test -e ssh-enabled; echo '{"RunSSH":true}' ;;
  *) exit 1 ;;
esac
`,
    { mode: 0o755 },
  );
  await enrollVps(async () => "tskey-auth-fixture");
  await writeFile("/work/offline", "");
  // Reaching the apt step proves the real hardening function waited for the node to come online.
  await assert.rejects(
    installHostHardening(async () => {
      throw new Error("Unexpected configuration read");
    }),
    /apt-get exited 42.*fixture-reached-apt/,
  );
}
