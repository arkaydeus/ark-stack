import { expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bundleDigest, composeDigest, maintenanceSignaturePayload } from "@ark-stack/shared";

test.each([false, true])(
  "signed maintenance initializes edge before up and aborts on initializer failure=%s",
  async (fail) => {
    const dir = await mkdtemp(join(tmpdir(), "ark-maintain-edge-"));
    try {
      const image = `example/worker@sha256:${"a".repeat(64)}`;
      const compose = `services:\n${["domain-worker", "edge", "edge-l4", "edge-watchdog"].map((name) => `  ${name}:\n    image: ${image}`).join("\n")}\n`;
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const bundle = {
        version: "test",
        images: [image],
        digest: bundleDigest([image]),
        composeDigest: composeDigest(compose),
        signature: "",
      };
      bundle.signature = sign(null, Buffer.from(maintenanceSignaturePayload(bundle)), privateKey).toString(
        "base64",
      );
      await Bun.write(join(dir, "compose.yml"), compose);
      await Bun.write(join(dir, "release.json"), JSON.stringify(bundle));
      await mkdir(join(dir, "bin"));
      await Bun.write(
        join(dir, "bin/docker"),
        `#!${process.execPath}\nimport { appendFileSync } from "node:fs";\nconst args = process.argv.slice(2);\nappendFileSync(process.env.TEST_CALLS, JSON.stringify(args)+"\\n");\nif (process.env.TEST_FAIL === "1" && args.includes("scripts/prepare-edge-upgrade.ts")) process.exit(1);\n`,
      );
      await chmod(join(dir, "bin/docker"), 0o755);
      const child = Bun.spawn(
        [
          process.execPath,
          join(import.meta.dir, "maintain.ts"),
          join(dir, "release.json"),
          join(dir, "compose.yml"),
        ],
        {
          env: {
            ...process.env,
            PATH: `${dir}/bin:${process.env.PATH}`,
            ARK_MAINTENANCE_TOKEN: "test-only",
            ARK_RELEASE_PUBLIC_KEY: publicKey.export({ format: "pem", type: "spki" }).toString(),
            ARK_MAINTENANCE_EXECUTE: "1",
            ARK_MAINTENANCE_JOURNAL: join(dir, "journal"),
            TEST_CALLS: join(dir, "calls"),
            TEST_FAIL: fail ? "1" : "0",
          },
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
      expect(code, stderr).toBe(fail ? 1 : 0);
      const calls = (await Bun.file(join(dir, "calls")).text())
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as string[]);
      const stop = calls.findIndex((args) => args.includes("stop"));
      const init = calls.findIndex((args) => args.includes("scripts/prepare-edge-upgrade.ts"));
      const up = calls.findIndex((args) => args.includes("up"));
      expect(stop).toBeGreaterThan(0);
      expect(init).toBeGreaterThan(stop);
      expect(calls[init]).toContain("0:0");
      expect(calls[init]).toContain("CHOWN");
      expect(calls[init]).toContain("FOWNER");
      expect(calls[init]).toContain("DAC_OVERRIDE");
      if (fail) expect(up).toBe(-1);
      else expect(up).toBeGreaterThan(init);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
);
