import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { sha256Hex } from "@ark-stack/shared";

import { applyDatabaseIngress } from "./modules/providers.ts";

test("provider writes rate limits without a CIDR allowlist and retains prior connection sets", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ark-ingress-provider-"));
  const saved = { ARK_ALLOWLIST_HELPER: process.env.ARK_ALLOWLIST_HELPER };
  process.env.ARK_ALLOWLIST_HELPER = "/usr/bin/true";
  try {
    const first = await applyDatabaseIngress(dir, {
      maxConnectionsPerSource: 5,
      newConnectionsPerSecond: 2,
      newConnectionBurst: 5,
    });
    expect(first).toMatchObject({ applied: true, enforced: false });
    expect(await readFile(first.file, "utf8")).not.toContain("jump ark_db_allow");
    const lower = await applyDatabaseIngress(dir, {
      maxConnectionsPerSource: 4,
      newConnectionsPerSecond: 2,
      newConnectionBurst: 5,
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

test("external worker waits for a host acknowledgement of the exact policy", async () => {
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
    await writeFile(join(dir, "allowlist.status"), "applied=true\npolicy_hash=old-policy\n");
    let complete = false;
    const pending = applyDatabaseIngress(dir).then((result) => {
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
    // A matching policy that failed to apply is also insufficient.
    await writeFile(
      join(dir, "allowlist.status"),
      `applied=false\npolicy_hash=${sha256Hex(rules)}\nerror=nft failed\n`,
    );
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(complete).toBe(false);
    await writeFile(join(dir, "allowlist.status"), `applied=true\npolicy_hash=${sha256Hex(rules)}\n`);
    expect(await pending).toMatchObject({ applied: true, enforced: false });
    // There is no exposure toggle any more: 5432 belongs to the edge (FD-26).
    expect(await Bun.file(join(dir, "expose")).exists()).toBe(false);
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(dir, { recursive: true, force: true });
  }
});
