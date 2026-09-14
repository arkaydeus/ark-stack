import { appendFile } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { bundleDigest, maintenanceArgv, verifyMaintenanceRelease } from "@ark-stack/shared";

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
const argv = maintenanceArgv("ark-platform", compose);
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

await new Promise<void>((resolve, reject) => {
  const child = spawn(argv[0], argv.slice(1), { stdio: "inherit" });
  child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`maintain exited ${code}`))));
});
