// Opt-in: the one-command installer on a scratch Ubuntu VPS (mise run test:install-live).
// It skips unless the scratch VPS and scratch-tailnet details are supplied. Never point it at a
// production host: it hardens the VPS and closes its public SSH.
//
//   ARK_TEST_INSTALL_VPS          root@<public-address> of a fresh scratch Ubuntu VPS (key-based SSH)
//   ARK_TEST_INSTALL_TS_SSH       <user>@<magicdns-name> the runner reaches with `tailscale ssh` once
//                                 the VPS has joined (the user needs passwordless sudo)
//   ARK_TEST_INSTALL_DOMAIN       a scratch domain
//   ARK_TEST_INSTALL_VPS_AUTHKEY  a one-off, pre-approved key for tag:ark-vps
//   ARK_TEST_INSTALL_EDGE_AUTHKEY optional one-off key for tag:ark-edge (the edge step is skipped without it)
//   ARK_TEST_INSTALL_ACME_EMAIL   optional; ARK_TEST_INSTALL_REF optional branch or tag (default main)
//
// Phases: (1) piped install.sh without the Tailscale SSH confirmation must stop with exit 2 before
// hardening, with OpenSSH still running and no ark_host table; (2) the resumed setup over Tailscale
// SSH must finish; (3) public SSH must refuse new connections while Tailscale SSH answers, the
// local audit must pass and the setup log must hold no auth key; (4) a re-run must skip every step.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const required = [
  "ARK_TEST_INSTALL_VPS",
  "ARK_TEST_INSTALL_TS_SSH",
  "ARK_TEST_INSTALL_DOMAIN",
  "ARK_TEST_INSTALL_VPS_AUTHKEY",
] as const;
const missing = required.filter((key) => !process.env[key]?.trim());
if (missing.length) {
  console.log(
    `test:install-live skipped. Supply a scratch Ubuntu VPS and scratch tailnet via ${missing.join(", ")}.`,
  );
  process.exit(0);
}
const [vps, tsSsh, domain, vpsKey] = required.map((key) => process.env[key]!.trim()) as [
  string,
  string,
  string,
  string,
];
const edgeKey = process.env.ARK_TEST_INSTALL_EDGE_AUTHKEY?.trim();
const email = process.env.ARK_TEST_INSTALL_ACME_EMAIL?.trim();
const ref = process.env.ARK_TEST_INSTALL_REF?.trim() || "main";
assert.match(vps, /^root@[A-Za-z0-9.:[\]-]+$/, "ARK_TEST_INSTALL_VPS must be root@<address>.");
assert.match(
  tsSsh,
  /^[a-z_][a-z0-9_-]*@[A-Za-z0-9.-]+$/,
  "ARK_TEST_INSTALL_TS_SSH must be <user>@<magicdns-name>.",
);
assert.match(domain, /^[a-z0-9.-]+\.[a-z]{2,}$/, "ARK_TEST_INSTALL_DOMAIN must be a domain.");
assert.match(ref, /^[A-Za-z0-9][A-Za-z0-9._/-]*$/);

const script = readFileSync(join(import.meta.dir, "..", "install.sh"));
const sshOptions = [
  "-o",
  "BatchMode=yes",
  "-o",
  "ConnectTimeout=15",
  "-o",
  "StrictHostKeyChecking=accept-new",
];

function sh(args: string[], stdin?: Uint8Array | string) {
  const result = Bun.spawnSync(args, {
    stdin:
      stdin === undefined ? "ignore" : typeof stdin === "string" ? new TextEncoder().encode(stdin) : stdin,
    stdout: "pipe",
    stderr: "pipe",
    timeout: 45 * 60_000,
  });
  return { status: result.exitCode, output: `${result.stdout.toString()}${result.stderr.toString()}` };
}
const publicSsh = (command: string, stdin?: Uint8Array | string) =>
  sh(["ssh", ...sshOptions, vps, command], stdin);
const tailnetSsh = (command: string) => sh(["tailscale", "ssh", tsSsh, command]);
const secretCheck = (output: string) => {
  for (const secret of [vpsKey, edgeKey].filter(Boolean))
    assert.ok(!output.includes(secret!), "a key reached the output");
};

const answers = [
  "--non-interactive",
  "--domain",
  domain,
  ...(email ? ["--acme-email", email] : []),
  ...(edgeKey ? [] : ["--skip-edge"]),
  "--ssh-user",
  tsSsh.split("@")[0]!,
].join(" ");

// Keys travel on stdin into root-only files, never on a command line.
assert.equal(publicSsh("umask 077; cat > /root/ark-test-vps-key", `${vpsKey}\n`).status, 0);
if (edgeKey) assert.equal(publicSsh("umask 077; cat > /root/ark-test-edge-key", `${edgeKey}\n`).status, 0);

console.log("1. piped install without the Tailscale SSH confirmation must pause before hardening");
const first = publicSsh(
  `ARK_REF=${ref} TS_VPS_AUTHKEY_FILE=/root/ark-test-vps-key bash -s -- ${answers}`,
  script,
);
secretCheck(first.output);
assert.equal(first.status, 2, first.output.slice(-3000));
assert.match(first.output, /Stopped before hardening/);
assert.notEqual(publicSsh("nft list table inet ark_host").status, 0, "ark_host must not exist yet");
assert.equal(publicSsh("systemctl is-active ssh.service ssh.socket | grep -q '^active'").status, 0);

console.log("2. Tailscale SSH works, so resume over it");
assert.equal(tailnetSsh("true").status, 0, "tailscale ssh to the scratch VPS failed");
const resume = tailnetSsh(
  `cd /opt/ark-stack && sudo -n bash -c 'rm -f /root/ark-test-vps-key; ${edgeKey ? "TS_EDGE_AUTHKEY=$(cat /root/ark-test-edge-key) " : ""}mise run host:setup ${answers} --tailscale-ssh-confirmed --provider-firewall-applied; status=$?; rm -f /root/ark-test-edge-key; exit $status'`,
);
secretCheck(resume.output);
assert.equal(resume.status, 0, resume.output.slice(-3000));
assert.match(resume.output, /Ark Stack is installed/);

console.log("3. public SSH refuses new connections; Tailscale SSH answers; audit passes; log is clean");
assert.notEqual(publicSsh("true").status, 0, "public SSH still accepts connections");
assert.equal(tailnetSsh("true").status, 0);
assert.equal(tailnetSsh("cd /opt/ark-stack && sudo -n mise run host:audit").status, 0);
assert.equal(tailnetSsh("sudo -n grep -c tskey- /opt/ark-stack/tmp/host-setup/setup.log").output.trim(), "0");

console.log("4. a re-run verifies and skips");
const again = tailnetSsh(
  `cd /opt/ark-stack && sudo -n mise run host:setup ${answers} --provider-firewall-applied`,
);
assert.equal(again.status, 0, again.output.slice(-3000));
assert.match(again.output, /already hardened and installed with these settings/);
console.log("test:install-live passed. Remove the scratch VPS and its tailnet devices, and revoke the keys.");
