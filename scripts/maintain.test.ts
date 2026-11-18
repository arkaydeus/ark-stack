import { expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bundleDigest, composeDigest, maintenanceSignaturePayload } from "@ark-stack/shared";

test.each([
  { fail: false, mail: false },
  { fail: false, mail: true },
  { fail: true, mail: true },
])(
  "signed maintenance preserves mail state and stops on an edge initialization error (%p)",
  async ({ fail, mail }) => {
    const dir = await mkdtemp(join(tmpdir(), "ark-maintain-edge-"));
    try {
      const image = `example/worker@sha256:${"a".repeat(64)}`;
      const compose = `services:\n${["domain-worker", "edge", "edge-l4", "edge-watchdog", "mail-worker"].map((name) => `  ${name}:\n    image: ${image}`).join("\n")}\n`;
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
      await Bun.write(join(dir, ".env"), `ARK_MAIL_ENABLED=${mail ? 1 : 0}\n`);
      await mkdir(join(dir, "bin"));
      await mkdir(join(dir, "scripts"));
      await symlink(join(import.meta.dir, "../node_modules"), join(dir, "node_modules"));
      for (const script of [
        "maintain.ts",
        "edge-namespace.ts",
        "host-deployment-lock.ts",
        "install-host-hardening.ts",
      ]) {
        await copyFile(join(import.meta.dir, script), join(dir, "scripts", script));
      }
      await Bun.write(
        join(dir, "bin/docker"),
        `#!${process.execPath}\nimport { appendFileSync } from "node:fs";\nconst args = process.argv.slice(2);\nappendFileSync(process.env.TEST_CALLS, JSON.stringify(args)+"\\n");\nif (process.env.TEST_FAIL === "1" && args.includes("scripts/prepare-edge-upgrade.ts")) process.exit(1);\n`,
      );
      await chmod(join(dir, "bin/docker"), 0o755);
      const child = Bun.spawn(
        [
          process.execPath,
          join(dir, "scripts", "maintain.ts"),
          join(dir, "release.json"),
          join(dir, "compose.yml"),
        ],
        {
          cwd: dir,
          env: {
            ...process.env,
            PATH: `${dir}/bin:${process.env.PATH}`,
            ARK_MAINTENANCE_TOKEN: "test-only",
            ARK_RELEASE_PUBLIC_KEY: publicKey.export({ format: "pem", type: "spki" }).toString(),
            ARK_MAINTENANCE_EXECUTE: "1",
            ARK_MAIL_ENABLED: mail ? "0" : "1",
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
      const stop = calls.findIndex((args) => args.includes("stop") && args.includes("edge-l4"));
      const init = calls.findIndex((args) => args.includes("scripts/prepare-edge-upgrade.ts"));
      const up = calls.findIndex((args) => args.includes("up"));
      expect(stop).toBeGreaterThan(0);
      expect(init).toBeGreaterThan(stop);
      expect(calls[init]).toContain("0:0");
      expect(calls[init]).toContain("CHOWN");
      expect(calls[init]).toContain("FOWNER");
      expect(calls[init]).toContain("DAC_OVERRIDE");
      if (fail) expect(up).toBe(-1);
      else {
        expect(up).toBeGreaterThan(init);
        const mailStop = calls.findIndex((args) => args.includes("stop") && args.includes("mail-worker"));
        if (mail) {
          expect(mailStop).toBe(-1);
          expect(calls[up]).not.toContain("mail-worker=0");
        } else {
          expect(mailStop).toBeGreaterThanOrEqual(0);
          expect(mailStop).toBeLessThan(up);
          expect(calls[up]).toContain("--scale");
          expect(calls[up]).toContain("mail-worker=0");
        }
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
);
