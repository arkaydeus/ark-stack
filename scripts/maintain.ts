import { appendFile } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { bundleDigest, maintenanceArgv, verifyMaintenanceRelease } from "@ark-stack/shared";

import { rejoinNamespaceDependents } from "./edge-namespace.ts";

const token = process.env.ARK_MAINTENANCE_TOKEN ?? "";
if (!token) {
  console.error("ARK_MAINTENANCE_TOKEN is required for the platform maintenance runner.");
  process.exit(1);
}

const file = process.argv[2] ?? join(import.meta.dir, "..", "infra", "platform", "release.json");
const compose = process.argv[3] ?? join(import.meta.dir, "..", "infra", "platform", "docker-compose.yml");
const publicKey = process.env.ARK_RELEASE_PUBLIC_KEY ?? "";
if (!publicKey) {
  console.error("ARK_RELEASE_PUBLIC_KEY is required to verify the maintenance publisher.");
  process.exit(1);
}
const bundle = JSON.parse(await Bun.file(file).text());
const composeSource = await Bun.file(compose).text();
const validated = verifyMaintenanceRelease(bundle, composeSource, publicKey.replaceAll("\\n", "\n"));
const project = "ark-platform";
const argv = maintenanceArgv(project, compose);
const journal = join(process.env.ARK_MAINTENANCE_JOURNAL ?? "tmp/maintenance.jsonl");

await appendFile(
  journal,
  `${JSON.stringify({ at: new Date().toISOString(), digest: bundleDigest(validated.images), composeDigest: bundle.composeDigest, images: validated.images })}\n`,
);

if (process.env.ARK_MAINTENANCE_EXECUTE !== "1") {
  console.log(JSON.stringify({ planned: argv, images: validated.images, executed: false }, null, 2));
  process.exit(0);
}

for (const image of validated.images) {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("docker", ["pull", image], { stdio: "inherit" });
    child.on("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`docker pull failed for an approved digest (${code})`)),
    );
  });
}

// Stop writers and the old public listener before converting persisted Caddy files. The approved
// domain-worker image contains the initializer; only this one-shot process gets ownership capabilities.
if (/^  edge-l4:/m.test(composeSource)) {
  const prefix = ["compose", "-f", compose, "-p", project];
  for (const args of [
    [...prefix, "stop", "domain-worker", "edge", "edge-l4", "edge-watchdog"],
    [
      ...prefix,
      "run",
      "--rm",
      "--no-deps",
      "--user",
      "0:0",
      "--cap-add",
      "CHOWN",
      "--cap-add",
      "FOWNER",
      "--cap-add",
      "DAC_OVERRIDE",
      "--entrypoint",
      "bun",
      "domain-worker",
      "scripts/prepare-edge-upgrade.ts",
    ],
  ]) {
    const code = await Bun.spawn(["docker", ...args], { stdio: ["ignore", "inherit", "inherit"] }).exited;
    if (code !== 0) throw new Error(`Edge maintenance initialization failed (${code})`);
  }
}

await new Promise<void>((resolve, reject) => {
  const child = spawn(argv[0], argv.slice(1), { stdio: "inherit" });
  child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`maintain exited ${code}`))));
});

// Compose recreates `edge` when it recreates `edge-ts`, but not when `edge-ts` was restarted in place
// (a crash or `docker restart`). Either way `edge` must end up in the live edge-ts namespace.
await rejoinNamespaceDependents({ project, composeArgs: ["-f", compose, "-p", project] });
