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
//                                 (either way it passes --accept-broad-tailnet-policy: scratch tailnets only)
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

const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

// Bash reads only these lines before executing the payload, which may itself be on stdin.
const readCredentials = `set -eu
IFS= read -r ts_api_key
IFS= read -r hcloud_token
IFS= read -r vps_key
IFS= read -r edge_key
`;
const setupEnv =
  'TS_API_KEY="$ts_api_key" HCLOUD_TOKEN="$hcloud_token" TS_VPS_AUTHKEY="$vps_key" TS_EDGE_AUTHKEY="$edge_key"';

export function withStreamedCredentials(command: string, prepare = "") {
  return `${readCredentials}${prepare}${setupEnv} exec ${command}`;
}

export function credentialsOnStdin(values: (string | undefined)[], rest = "") {
  for (const value of values) assert.ok(!/[\r\n]/.test(value ?? ""), "credentials must fit on one line");
  return `${values.join("\n")}\n${rest}`;
}

export async function verifyMintedKeyRevocations(
  outputs: string[],
  expectedTags: string[],
  lookup: (id: string) => Promise<Response>,
) {
  const minted = new Map<string, string>();
  for (const output of outputs) {
    for (const [, tag, id] of output.matchAll(
      /Minted a one-off (tag:ark-\w+) key through the Tailscale API \(ID ([A-Za-z0-9_-]+),/g,
    )) {
      minted.set(id!, tag!);
    }
  }
  for (const tag of expectedTags) {
    assert.ok([...minted.values()].includes(tag), `setup did not report a minted key ID for ${tag}`);
  }
  for (const [id, tag] of minted) {
    const response = await lookup(id);
    if (response.status === 404) continue;
    assert.equal(response.status, 200, `reading key ${id} failed: HTTP ${response.status}`);
    const detail = (await response.json()) as { invalid?: boolean; revoked?: string };
    assert.ok(detail.invalid === true || detail.revoked, `minted ${tag} key ${id} is still valid`);
  }
}

async function main() {
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

  const script = readFileSync(join(import.meta.dir, "..", "install.sh"), "utf8");
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
  const sshEnv = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith("ARK_TEST_INSTALL_")),
  );

  function sh(args: string[], stdin?: Uint8Array | string) {
    const result = Bun.spawnSync(args, {
      env: sshEnv,
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
  const tailnetSsh = (command: string, stdin?: string) => sh([...tailnetArgs, command], stdin);
  const secretCheck = (output: string) => {
    for (const secret of [vpsKey, edgeKey, tsApiKey, hcloudToken].filter(Boolean))
      assert.ok(!output.includes(secret!), "a key or credential reached the output");
    assert.ok(
      !/tskey-(?:auth|api|client)-[A-Za-z0-9]{6,}/.test(output),
      "a Tailscale key reached the output",
    );
  };
  const firewallFlag = hcloudToken ? "--approve-provider-firewall" : "--provider-firewall-applied";

  const answers = [
    "--non-interactive",
    "--domain",
    domain,
    ...(email ? ["--acme-email", email] : []),
    ...(edgeKey || tsApiKey ? [] : ["--skip-edge"]),
    ...(tsApiKey ? ["--approve-tailnet-policy"] : []),
    // The scratch tailnet may still have Tailscale's default allow-all rule.
    "--accept-broad-tailnet-policy",
    "--ssh-user",
    tsSsh.split("@")[0]!,
  ];
  const legacyFiles = "test ! -e /root/ark-test-ts-api-key && test ! -e /root/ark-test-hcloud-token";
  assert.equal(
    publicSsh(legacyFiles).status,
    0,
    "Legacy API credential files exist on the scratch VPS. Remove them and revoke the corresponding credentials.",
  );

  console.log("1. piped install without the Tailscale SSH confirmation must pause before hardening");
  const first = publicSsh(
    `bash -c ${shellQuote(withStreamedCredentials('bash -s -- "$@"', `export ARK_REF=${shellQuote(ref)}\n`))} bash ${answers.map(shellQuote).join(" ")}`,
    credentialsOnStdin([tsApiKey, hcloudToken, vpsKey, undefined], script),
  );
  assert.equal(publicSsh(legacyFiles).status, 0, "API credential files appeared on the scratch VPS");
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
  const setup = (flags: string[]) => {
    const wrapper = withStreamedCredentials(
      '"$bun" --no-env-file scripts/host-setup.ts "$@" </dev/null',
      'bun="$(mise which bun)"\n',
    );
    return `cd /opt/ark-stack && sudo -n bash -c ${shellQuote(wrapper)} bash ${[...answers, firewallFlag, ...flags].map(shellQuote).join(" ")}`;
  };
  const credentials = credentialsOnStdin([tsApiKey, hcloudToken, undefined, edgeKey]);
  const cutover = [
    "--ssh-recovery-source",
    recoverySource,
    "--tailscale-ssh-confirmed",
    "--verify-ssh-cutover",
  ];
  const denied = tailnetSsh(setup(cutover), credentials);
  secretCheck(denied.output);
  assert.equal(denied.status, 1, denied.output.slice(-3000));
  assert.match(denied.output, /Timed out waiting for a fresh off-host Tailscale SSH login/);
  assert.equal(
    publicSsh("true").status,
    0,
    "OpenSSH was not reachable from its original client after rollback",
  );

  const paused = tailnetSsh(setup(["--tailscale-ssh-confirmed"]), credentials);
  secretCheck(paused.output);
  assert.equal(paused.status, 2, paused.output.slice(-3000));

  console.log("3. Supply a fresh off-host proof while OpenSSH is stopped.");
  const closing = Bun.spawn([...tailnetArgs, setup(cutover)], {
    env: sshEnv,
    stdin: new TextEncoder().encode(credentials),
    stdout: "pipe",
    stderr: "pipe",
    timeout: 10 * 60_000,
  });
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
  assert.equal(
    tailnetSsh("sudo -n grep -c tskey- /opt/ark-stack/tmp/host-setup/setup.log").output.trim(),
    "0",
  );
  assert.equal(tailnetSsh(`sudo -n sh -c ${shellQuote(legacyFiles)}`).status, 0);
  const apiCredentials = [tsApiKey, hcloudToken].filter((value): value is string => Boolean(value));
  if (apiCredentials.length) {
    const scan = 'grep -rqF -f - /opt/ark-stack/.env /opt/ark-stack/tmp; test "$?" -eq 1';
    assert.equal(
      tailnetSsh(`sudo -n sh -c ${shellQuote(scan)}`, `${apiCredentials.join("\n")}\n`).status,
      0,
      "An API credential appeared in the checkout or the checkout scan failed",
    );
  }

  console.log("5. A rerun verifies and skips.");
  const again = tailnetSsh(setup([]), credentials);
  secretCheck(again.output);
  assert.equal(again.status, 0, again.output.slice(-3000));
  assert.match(again.output, /already hardened and installed with these settings/);
  if (hcloudToken) assert.match(again.output, /provider already matches \(Hetzner Cloud API\)/);

  if (tsApiKey) {
    console.log("6. Every key setup minted is revoked.");
    await verifyMintedKeyRevocations(
      [first.output, denied.output, paused.output, output, again.output],
      ["tag:ark-vps", "tag:ark-edge"],
      (id) =>
        fetch(`https://api.tailscale.com/api/v2/tailnet/-/keys/${encodeURIComponent(id)}`, {
          headers: { authorization: `Bearer ${tsApiKey}` },
          signal: AbortSignal.timeout(30_000),
        }),
    );
  }
  console.log(
    "test:install-live passed. Remove the scratch VPS and its tailnet devices, and revoke the keys.",
  );
}

if (import.meta.main) await main();
