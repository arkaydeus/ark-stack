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
//   ARK_TEST_INSTALL_TS_API_KEY   optional scratch-tailnet API access token instead of both keys: setup
//                                 merges the policy (--approve-tailnet-policy), mints and revokes the keys
//   ARK_TEST_INSTALL_HCLOUD_TOKEN optional Read & Write token of the scratch Hetzner Cloud project that
//                                 holds the VPS: the Hetzner adapter applies the firewall
//                                 (--approve-provider-firewall) and the rerun must change nothing
//   ARK_TEST_INSTALL_ACME_EMAIL   optional; ARK_TEST_INSTALL_REF optional branch or tag (default main)
//
// Test the pre-hardening gate, a timed-out cutover that restores fresh public SSH, a successful
// cutover with a fresh off-host proof, and an idempotent rerun. With the API credentials it also
// checks that every minted key is revoked and that no credential or key reached the checkout.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { join } from "node:path";

const tsApiKey = process.env.ARK_TEST_INSTALL_TS_API_KEY?.trim();
const hcloudToken = process.env.ARK_TEST_INSTALL_HCLOUD_TOKEN?.trim();
const required = [
  "ARK_TEST_INSTALL_VPS",
  "ARK_TEST_INSTALL_TS_SSH",
  "ARK_TEST_INSTALL_DOMAIN",
  ...(tsApiKey ? [] : ["ARK_TEST_INSTALL_VPS_AUTHKEY"]),
] as const;
const missing = required.filter((key) => !process.env[key]?.trim());
if (missing.length) {
  console.log(
    `test:install-live skipped. Supply a scratch Ubuntu VPS and scratch tailnet via ${missing.join(", ")}.`,
  );
  process.exit(0);
}
const [vps, tsSsh, domain] = required.map((key) => process.env[key]!.trim()) as [string, string, string];
const vpsKey = tsApiKey ? undefined : process.env.ARK_TEST_INSTALL_VPS_AUTHKEY!.trim();
const edgeKey = tsApiKey ? undefined : process.env.ARK_TEST_INSTALL_EDGE_AUTHKEY?.trim();
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
  "-o",
  "ControlPath=none",
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
const tailnetArgs = ["tailscale", "ssh", tsSsh, "-o", "ControlPath=none"];
const tailnetSsh = (command: string) => sh([...tailnetArgs, command]);
const secretCheck = (output: string) => {
  for (const secret of [vpsKey, edgeKey, tsApiKey, hcloudToken].filter(Boolean))
    assert.ok(!output.includes(secret!), "a key or credential reached the output");
  assert.ok(!/tskey-(?:auth|api|client)-[A-Za-z0-9]{6,}/.test(output), "a Tailscale key reached the output");
};
// Credentials travel like the keys: on stdin into root-only files that the setup command reads.
const credentialEnv = [
  ...(tsApiKey ? ['TS_API_KEY="$(cat /root/ark-test-ts-api-key)"'] : []),
  ...(hcloudToken ? ['HCLOUD_TOKEN="$(cat /root/ark-test-hcloud-token)"'] : []),
].join(" ");
const firewallFlag = hcloudToken ? "--approve-provider-firewall" : "--provider-firewall-applied";

const answers = [
  "--non-interactive",
  "--domain",
  domain,
  ...(email ? ["--acme-email", email] : []),
  ...(edgeKey || tsApiKey ? [] : ["--skip-edge"]),
  ...(tsApiKey ? ["--approve-tailnet-policy"] : []),
  "--ssh-user",
  tsSsh.split("@")[0]!,
].join(" ");

// Keys travel on stdin into root-only files, never on a command line.
if (vpsKey) assert.equal(publicSsh("umask 077; cat > /root/ark-test-vps-key", `${vpsKey}\n`).status, 0);
if (edgeKey) assert.equal(publicSsh("umask 077; cat > /root/ark-test-edge-key", `${edgeKey}\n`).status, 0);
if (tsApiKey)
  assert.equal(publicSsh("umask 077; cat > /root/ark-test-ts-api-key", `${tsApiKey}\n`).status, 0);
if (hcloudToken)
  assert.equal(publicSsh("umask 077; cat > /root/ark-test-hcloud-token", `${hcloudToken}\n`).status, 0);

console.log("1. piped install without the Tailscale SSH confirmation must pause before hardening");
const first = publicSsh(
  `ARK_REF=${ref} ${vpsKey ? 'TS_VPS_AUTHKEY="$(cat /root/ark-test-vps-key)" ' : ""}${credentialEnv} bash -s -- ${answers}`,
  script,
);
secretCheck(first.output);
assert.equal(first.status, 2, first.output.slice(-3000));
assert.match(first.output, /Stopped before hardening/);
assert.notEqual(publicSsh("nft list table inet ark_host").status, 0, "ark_host must not exist yet");
assert.equal(publicSsh("systemctl is-active ssh.service ssh.socket | grep -q '^active'").status, 0);

console.log(
  "2. Resume over Tailscale. Withhold the fresh proof and check the original client can reconnect.",
);
assert.equal(tailnetSsh("true").status, 0, "tailscale ssh to the scratch VPS failed");
const recoverySource = publicSsh('printf "%s\\n" "$SSH_CONNECTION"').output.trim().split(/\s+/)[0]!;
assert.ok(isIP(recoverySource), "Could not determine the public SSH client's recovery IP");
const setup = `${credentialEnv} mise run host:setup ${answers} --ssh-recovery-source ${recoverySource} ${firewallFlag}`;
const resume = `cd /opt/ark-stack && sudo -n bash -c 'rm -f /root/ark-test-vps-key; ${edgeKey ? "TS_EDGE_AUTHKEY=$(cat /root/ark-test-edge-key) " : ""}${setup} --tailscale-ssh-confirmed --verify-ssh-cutover; status=$?; rm -f /root/ark-test-edge-key; exit $status'`;
const denied = tailnetSsh(resume);
secretCheck(denied.output);
assert.equal(denied.status, 1, denied.output.slice(-3000));
assert.match(denied.output, /Timed out waiting for a fresh off-host Tailscale SSH login/);
assert.equal(
  publicSsh("true").status,
  0,
  "OpenSSH was not reachable from its original client after rollback",
);

const paused = tailnetSsh(`cd /opt/ark-stack && sudo -n bash -c '${setup} --tailscale-ssh-confirmed'`);
assert.equal(paused.status, 2, paused.output.slice(-3000));

console.log("3. Supply a fresh off-host proof while OpenSSH is stopped.");
const closing = Bun.spawn(
  [
    ...tailnetArgs,
    `cd /opt/ark-stack && sudo -n bash -c '${setup} --tailscale-ssh-confirmed --verify-ssh-cutover'`,
  ],
  { stdout: "pipe", stderr: "pipe", timeout: 10 * 60_000 },
);
const stderr = new Response(closing.stderr).text();
let output = "";
let proofSeen = false;
const reader = closing.stdout.pipeThrough(new TextDecoderStream()).getReader();
for (;;) {
  const chunk = await reader.read();
  if (chunk.done) break;
  output += chunk.value;
  const proof = /\/opt\/ark-stack\/tmp\/host-setup\/ssh-cutover-[A-Za-z0-9]+\/proof/.exec(output)?.[0];
  if (!proofSeen && proof) {
    proofSeen = true;
    assert.notEqual(publicSsh("true").status, 0, "OpenSSH was listening during verification");
    assert.equal(tailnetSsh(`sudo -n touch -- ${proof}`).status, 0, "Could not provide fresh proof");
  }
}
output += await stderr;
secretCheck(output);
assert.equal(await closing.exited, 0, output.slice(-3000));
assert.ok(proofSeen);
assert.match(output, /Ark Stack is installed/);

console.log("4. Public SSH refuses new connections, Tailscale SSH answers, and the audit passes.");
assert.notEqual(publicSsh("true").status, 0, "public SSH still accepts connections");
assert.equal(tailnetSsh("true").status, 0);
assert.equal(tailnetSsh("cd /opt/ark-stack && sudo -n mise run host:audit").status, 0);
assert.equal(tailnetSsh("sudo -n grep -c tskey- /opt/ark-stack/tmp/host-setup/setup.log").output.trim(), "0");
for (const file of ["/root/ark-test-ts-api-key", "/root/ark-test-hcloud-token"]) {
  // Neither credential may appear anywhere in the checkout (.env, state, log, inventory).
  const found = tailnetSsh(
    `sudo -n sh -c 'test ! -s ${file} || ! grep -rqF -f ${file} /opt/ark-stack/.env /opt/ark-stack/tmp'`,
  );
  assert.equal(found.status, 0, `a credential from ${file} was written to the checkout`);
}

console.log("5. A rerun verifies and skips.");
const again = tailnetSsh(
  `cd /opt/ark-stack && sudo -n bash -c '${credentialEnv} mise run host:setup ${answers} ${firewallFlag}'`,
);
secretCheck(again.output);
assert.equal(again.status, 0, again.output.slice(-3000));
assert.match(again.output, /already hardened and installed with these settings/);
if (hcloudToken) assert.match(again.output, /provider already matches \(Hetzner Cloud API\)/);
tailnetSsh("sudo -n rm -f /root/ark-test-ts-api-key /root/ark-test-hcloud-token");

if (tsApiKey) {
  console.log("6. Every key setup minted is revoked.");
  const response = await fetch("https://api.tailscale.com/api/v2/tailnet/-/keys?all=true", {
    headers: { authorization: `Bearer ${tsApiKey}` },
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(response.status, 200, `listing keys failed: HTTP ${response.status}`);
  const { keys } = (await response.json()) as { keys: { id: string; description?: string }[] };
  for (const { id, description } of keys) {
    if (!description?.startsWith("ark-stack setup")) continue;
    const lookup: Response = await fetch(`https://api.tailscale.com/api/v2/tailnet/-/keys/${id}`, {
      headers: { authorization: `Bearer ${tsApiKey}` },
      signal: AbortSignal.timeout(30_000),
    });
    const detail = (await lookup.json().catch(() => ({}))) as { invalid?: boolean; revoked?: string };
    assert.ok(lookup.status === 404 || detail.invalid || detail.revoked, `minted key ${id} is still valid`);
  }
}
console.log("test:install-live passed. Remove the scratch VPS and its tailnet devices, and revoke the keys.");
