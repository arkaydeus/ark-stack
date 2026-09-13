import { appendFile } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { bundleDigest, maintenanceArgv, validateMaintenanceBundle } from "@ark-stack/shared";

const token = process.env.ARK_MAINTENANCE_TOKEN ?? "";
if (!token) {
  console.error("ARK_MAINTENANCE_TOKEN is required for the platform maintenance runner.");
  process.exit(1);
}

const file = process.argv[2] ?? join(import.meta.dir, "..", "infra", "platform", "release.json");
const bundle = validateMaintenanceBundle(JSON.parse(await Bun.file(file).text()));
const compose = process.argv[3] ?? join(import.meta.dir, "..", "infra", "platform", "docker-compose.yml");
const argv = maintenanceArgv("ark-platform", compose);
const journal = join(process.env.ARK_MAINTENANCE_JOURNAL ?? "tmp/maintenance.jsonl");

await appendFile(
  journal,
  `${JSON.stringify({ at: new Date().toISOString(), digest: bundleDigest(bundle.images), images: bundle.images })}\n`,
);

if (process.env.ARK_MAINTENANCE_EXECUTE !== "1") {
  console.log(JSON.stringify({ planned: argv, images: bundle.images, executed: false }, null, 2));
  process.exit(0);
}

await new Promise<void>((resolve, reject) => {
  const child = spawn(argv[0], argv.slice(1), { stdio: "inherit" });
  child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`maintain exited ${code}`))));
});
