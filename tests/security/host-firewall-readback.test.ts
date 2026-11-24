import { expect, test } from "bun:test";

import { waitForHostFirewallAcknowledgement } from "../../scripts/host-hardening-test/readback.ts";

const request = { id: crypto.randomUUID(), hash: "a".repeat(64) };
const status = (id: string, hash: string, applied: boolean) =>
  `applied=${applied}\npolicy_hash=${hash}\nrequest_id=${id}\nerror=\n`;

test("host firewall readback rejects stale or nonmatching statuses at the deadline", async () => {
  for (const stale of [
    status(crypto.randomUUID(), request.hash, true),
    status(`${request.id}-old`, request.hash, true),
    status(request.id, `${request.hash}b`, true),
    status(request.id, request.hash, false),
  ]) {
    await expect(waitForHostFirewallAcknowledgement(async () => stale, request, true, 0)).rejects.toThrow(
      "Timed out waiting for firewall request",
    );
  }
});

test("host firewall readback waits for an acknowledgement of the requested policy and outcome", async () => {
  const expected = status(request.id, request.hash, false);
  const statuses = [status(request.id, "b".repeat(64), false), expected];
  await expect(
    waitForHostFirewallAcknowledgement(async () => statuses.shift() ?? "", request, false),
  ).resolves.toBe(expected);
});
