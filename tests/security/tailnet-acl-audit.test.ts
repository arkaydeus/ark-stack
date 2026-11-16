import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { auditTailnetPolicy, generateTailnetAcl } from "../../shared/src/tailnet-acl.ts";

const expected = generateTailnetAcl({ routes: [], knownAddresses: ["100.70.0.9"] });

describe("offline candidate policy audit", () => {
  test("refuses rule conditions and selectors outside the local model", () => {
    for (const rule of [
      { src: ["group:admins"], dst: ["100.70.0.9"], ip: ["tcp:12345"] },
      { src: ["tag:ark-edge"], dst: ["100.70.0.9"], ip: ["tcp:12345"], via: ["tag:router"] },
    ]) {
      expect(() => auditTailnetPolicy(expected.policy, { ...expected.policy, grants: [rule] })).toThrow(
        "cannot model",
      );
    }
  });
  test("CLI accepts matching access and rejects a narrow unsampled leak without credentials", async () => {
    const folder = await mkdtemp(join(tmpdir(), "ark-acl-audit-"));
    const baseline = join(folder, "expected.hujson");
    const candidate = join(folder, "candidate.hujson");
    const run = async () => {
      const child = Bun.spawn(["bun", "scripts/audit-tailnet-policy.ts", baseline, candidate], {
        stdout: "pipe",
        stderr: "pipe",
      });
      const [code, stdout, stderr] = await Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);
      return { code, stdout, stderr };
    };
    try {
      await writeFile(baseline, expected.hujson);
      await writeFile(candidate, expected.hujson);
      expect(await run()).toMatchObject({ code: 0, stderr: "" });
      await writeFile(
        candidate,
        JSON.stringify({
          ...expected.policy,
          grants: [{ src: ["tag:ark-edge"], dst: ["100.70.0.9"], ip: ["tcp:12345"] }],
        }),
      );
      const result = await run();
      expect(result.code).toBe(1);
      expect(result.stderr).toContain("tcp/100.70.0.9:12345");
    } finally {
      await rm(folder, { recursive: true, force: true });
    }
  });
});
