// Run from outside the scratch VPS. Credentials and scratch targets must be explicitly supplied.
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { resolve4, resolve6 } from "node:dns/promises";
import { stat } from "node:fs/promises";

import { ipv6ProbeRequest, legoArgs, normalizeHostname, publicIpv6, signIpv6Report } from "@ark-stack/shared";
import { runIpv6Probe, type ProbeCredential } from "./ipv6-preflight-probe.ts";

const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";

function configured(name: string, keys: string[]) {
  const missing = keys.filter((key) => !process.env[key]?.trim());
  if (!missing.length) return true;
  console.log(`${name} skipped. Supply scratch test settings via ${missing.join(", ")}.`);
  return false;
}

async function privateFile(path: string) {
  const info = await stat(path);
  assert.ok(info.isFile() && (info.mode & 0o077) === 0, "Scratch credential files must be private.");
  return Bun.file(path);
}

async function testVps() {
  if (
    !configured("Real dual-stack VPS preflight", [
      "ARK_TEST_IPV6_VPS_ORIGIN",
      "ARK_TEST_IPV6_VPS_SESSION_FILE",
      "ARK_TEST_IPV6_VPS_ADDRESS",
      "ARK_IPV6_PROBE_CREDENTIALS",
    ])
  )
    return;
  const origin = new URL(process.env.ARK_TEST_IPV6_VPS_ORIGIN!);
  const address = publicIpv6(process.env.ARK_TEST_IPV6_VPS_ADDRESS);
  assert.ok(
    address && origin.protocol === "https:",
    "Use the scratch admin HTTPS origin and its public IPv6 literal.",
  );
  const cookie = (await (await privateFile(process.env.ARK_TEST_IPV6_VPS_SESSION_FILE!)).text()).trim();
  const credentials = (await (await privateFile(process.env.ARK_IPV6_PROBE_CREDENTIALS!)).json()) as Record<
    string,
    ProbeCredential
  >;
  const path = "/api/settings/ipv6/preflight";
  async function call(suffix = "", body?: unknown, authenticated = true) {
    const response = await fetch(new URL(path + suffix, origin), {
      method: body === undefined ? "GET" : "POST",
      headers: {
        ...(authenticated ? { cookie, origin: origin.origin } : {}),
        "content-type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error(`Scratch VPS preflight returned HTTP ${response.status}.`);
    return response.json();
  }
  const { operationId } = await call("", {});
  const deadline = Date.now() + 180_000;
  let expected = operationId;
  let submitted = false;
  while (Date.now() < deadline) {
    const state = await call("?operationId=" + encodeURIComponent(operationId));
    assert.equal(
      publicIpv6(state.address),
      address,
      "Scratch VPS does not have the expected IPv6 address configured.",
    );
    if (state.manual && !submitted) {
      const request = ipv6ProbeRequest.parse(state.manual.request);
      assert.equal(publicIpv6(request.address), address);
      const report = await runIpv6Probe(request, credentials);
      const submittedResult = await call(
        "/result",
        {
          signature: signIpv6Report(report, state.manual.token),
          report,
        },
        false,
      );
      expected = submittedResult.operationId;
      submitted = true;
    }
    if (state.evidence?.operationId === expected && (submitted || !state.manual)) {
      assert.equal(state.status, "passed", state.evidence.reason ?? "The live preflight did not pass.");
      assert.ok(
        state.evidence.checks.every(
          ({ outcome, source }: { outcome: string; source: string }) =>
            outcome === "passed" && publicIpv6(source),
        ),
        "The edge did not corroborate all probe sources.",
      );
      console.log("Real dual-stack VPS preflight passed.");
      return;
    }
    await Bun.sleep(1000);
  }
  throw new Error("The real dual-stack VPS did not finish its preflight in time.");
}

async function testStaging() {
  if (
    !configured("Let's Encrypt staging IPv6 HTTP-01", [
      "ARK_TEST_IPV6_STAGING_HOSTNAME",
      "ARK_TEST_IPV6_STAGING_ADDRESS",
      "ARK_TEST_IPV6_STAGING_EMAIL",
      "ARK_TEST_IPV6_STAGING_SSH",
      "ARK_TEST_IPV6_STAGING_WEBROOT",
    ])
  )
    return;
  const hostname = normalizeHostname(process.env.ARK_TEST_IPV6_STAGING_HOSTNAME!);
  const address = publicIpv6(process.env.ARK_TEST_IPV6_STAGING_ADDRESS);
  const target = process.env.ARK_TEST_IPV6_STAGING_SSH!;
  const webroot = process.env.ARK_TEST_IPV6_STAGING_WEBROOT!;
  const email = process.env.ARK_TEST_IPV6_STAGING_EMAIL!;
  assert.ok(
    address && webroot.startsWith("/") && /^[a-z_][a-z0-9_-]*@[a-zA-Z0-9.-]+$/.test(target),
    "Use a scratch VPS SSH user and DNS name, absolute ACME webroot and public IPv6 address.",
  );
  assert.deepEqual((await resolve6(hostname)).map(publicIpv6), [address]);
  const a = await resolve4(hostname).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENODATA" || error.code === "ENOTFOUND") return [];
    throw error;
  });
  assert.deepEqual(a, [], "Use a scratch hostname with only AAAA to prove IPv6 validation.");
  const deployment = legoArgs({ email, hostname, webroot, path: "__TEMP__", staging: true });
  const args = deployment.map((arg) => (arg === "__TEMP__" ? '"$state"' : quote(arg))).join(" ");
  const command = `set -eu
state=$(mktemp -d)
trap 'rm -rf -- "$state"' EXIT
lego ${args}
cat "$state"/certificates/${quote(hostname + ".crt")}`;
  const child = Bun.spawn(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target, command], {
    stdout: "pipe",
    stderr: "inherit",
    signal: AbortSignal.timeout(180_000),
  });
  const [status, pem] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  assert.equal(status, 0, "Let's Encrypt staging order failed.");
  const cert = new X509Certificate(pem);
  assert.match(cert.issuer, /STAGING/i);
  assert.equal(cert.checkHost(hostname), hostname);
  console.log("Let's Encrypt staging issued an HTTP-01 certificate for the AAAA-only scratch hostname.");
}

await testVps();
await testStaging();
