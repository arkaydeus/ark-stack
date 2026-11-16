import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { dbIngressAllowlistEnforced, sha256Hex } from "@ark-stack/shared";

import { applyDatabaseAllowlist } from "./modules/providers.ts";

test("provider enforcement matches the written marker, including all-invalid and mixed CIDRs", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ark-ingress-provider-"));
  const saved = { ARK_ALLOWLIST_HELPER: process.env.ARK_ALLOWLIST_HELPER };
  process.env.ARK_ALLOWLIST_HELPER = "/usr/bin/true";
  try {
    for (const cidrs of [["not-a-cidr"], [], ["not-a-cidr", "192.0.2.0/24"]]) {
      const result = await applyDatabaseAllowlist(dir, cidrs);
      const rules = await readFile(result.file, "utf8");
      expect(result.applied).toBe(true);
      expect(result.enforced).toBe(dbIngressAllowlistEnforced(rules));
      expect(result.enforced).toBe(cidrs.includes("192.0.2.0/24"));
    }
    await applyDatabaseAllowlist(dir, [], 5432, {
      limits: { maxConnectionsPerSource: 5, newConnectionsPerSecond: 2, newConnectionBurst: 5 },
    });
    const lower = await applyDatabaseAllowlist(dir, [], 5432, {
      limits: { maxConnectionsPerSource: 4, newConnectionsPerSecond: 2, newConnectionBurst: 5 },
    });
    expect(await readFile(lower.file, "utf8")).toContain(
      'ip saddr @active4_5 counter name "drop_conn4" drop',
    );
  } finally {
    if (saved.ARK_ALLOWLIST_HELPER === undefined) delete process.env.ARK_ALLOWLIST_HELPER;
    else process.env.ARK_ALLOWLIST_HELPER = saved.ARK_ALLOWLIST_HELPER;
    await rm(dir, { recursive: true, force: true });
  }
});

test("external worker waits for a host acknowledgement of the exact policy and exposure", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ark-ingress-ack-"));
  const saved = {
    ARK_EMBEDDED_WORKERS: process.env.ARK_EMBEDDED_WORKERS,
    ARK_APPLY_NFT: process.env.ARK_APPLY_NFT,
    ARK_ALLOWLIST_HELPER: process.env.ARK_ALLOWLIST_HELPER,
  };
  process.env.ARK_EMBEDDED_WORKERS = "0";
  process.env.ARK_APPLY_NFT = "1";
  delete process.env.ARK_ALLOWLIST_HELPER;
  try {
    await writeFile(join(dir, "allowlist.status"), "applied=true\nexposed=false\npolicy_hash=old-policy\n");
    let complete = false;
    const pending = applyDatabaseAllowlist(dir, ["192.0.2.0/24"]).then((result) => {
      complete = true;
      return result;
    });
    let rules = "";
    for (let attempt = 0; attempt < 100; attempt++) {
      rules = await readFile(join(dir, "allowlist.nft"), "utf8").catch(() => "");
      if (rules) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(rules).toContain("ark_db_limits");
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(complete).toBe(false);
    // A matching policy with an incorrect listener state is also insufficient.
    await writeFile(
      join(dir, "allowlist.status"),
      `applied=true\nexposed=true\npolicy_hash=${sha256Hex(rules)}\n`,
    );
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(complete).toBe(false);
    await writeFile(
      join(dir, "allowlist.status"),
      `applied=true\nexposed=false\npolicy_hash=${sha256Hex(rules)}\n`,
    );
    expect(await pending).toMatchObject({ applied: true, enforced: true, exposed: false });
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(dir, { recursive: true, force: true });
  }
});
