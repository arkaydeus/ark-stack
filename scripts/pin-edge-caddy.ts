// `mise run images:pin-edge-caddy -- ghcr.io/<namespace>/ark-edge-caddy[:<tag>]@sha256:<digest>`
// (docs/design/front-door.md FD-23, docs/operating.md "Third-party image pins").
//
// The custom edge Caddy (Caddy 2.11.9 plus the pinned caddy-ratelimit plugin) only has a registry digest
// once `mise run images:publish` has pushed it. This step then pins that digest: it checks that the
// reference exists in the registry with a linux/amd64 image, that it runs Caddy v2.11.9 with the
// rate_limit handler, and rewrites the `edge` service in infra/platform/docker-compose.yml (image line,
// no build section) and the sample release bundle infra/platform/release.json (image list and digest).
// `--no-verify` skips the registry and run checks (for an offline rewrite you verify yourself).
import { join, resolve } from "node:path";

import { bundleDigest } from "@ark-stack/shared";

import { PINNED_EDGE_CADDY, pinComposeEdge, pinReleaseEdge } from "./edge-test/edge-image.ts";

const root = resolve(import.meta.dir, "..");
const args = process.argv.slice(2);
const verify = !args.includes("--no-verify");
const reference = args.find((arg) => !arg.startsWith("--"));
if (!reference || !PINNED_EDGE_CADDY.test(reference)) {
  console.error(
    "Usage: mise run images:pin-edge-caddy -- ghcr.io/<namespace>/ark-edge-caddy[:<tag>]@sha256:<digest> [--no-verify]\n" +
      "Take the edge-caddy line that `mise run images:publish` prints.",
  );
  process.exit(2);
}

async function docker(...command: string[]) {
  const child = Bun.spawn(["docker", ...command], { stdout: "pipe", stderr: "pipe" });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) throw new Error(`docker ${command.join(" ")} failed: ${stderr.trim() || stdout.trim()}`);
  return stdout.trim();
}

if (verify) {
  const inspected = await docker("buildx", "imagetools", "inspect", reference);
  if (!/Platform:\s+linux\/amd64/.test(inspected)) throw new Error(`${reference} has no linux/amd64 image.`);
  await docker("pull", reference);
  const version = await docker("run", "--rm", reference, "caddy", "version");
  if (!version.startsWith("v2.11.9 ")) throw new Error(`${reference} reports ${version}, expected v2.11.9.`);
  const modules = (await docker("run", "--rm", reference, "caddy", "list-modules")).split("\n");
  if (!modules.some((line) => line.trim() === "http.handlers.rate_limit"))
    throw new Error(`${reference} has no http.handlers.rate_limit module.`);
  console.log(`${reference}: ${version.split(" ")[0]} with http.handlers.rate_limit.`);
}

const composePath = join(root, "infra/platform/docker-compose.yml");
await Bun.write(composePath, pinComposeEdge(await Bun.file(composePath).text(), reference));
const releasePath = join(root, "infra/platform/release.json");
const release = (await Bun.file(releasePath).json()) as { images: string[]; digest: string };
release.images = pinReleaseEdge(release.images, reference);
release.digest = bundleDigest(release.images);
await Bun.write(releasePath, `${JSON.stringify(release, null, 2)}\n`);
console.log(
  `Pinned the edge service and the sample release bundle to ${reference}.\n` +
    "Next: run `mise run test:edge` (it pulls and checks the pinned image), then commit both files.",
);
