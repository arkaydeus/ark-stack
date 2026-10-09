import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";

// Builds every platform image defined in docker-bake.hcl and pushes it to GHCR.
//
//   mise run images:publish                          # tag <short-sha> + latest, linux/amd64
//   mise run images:publish -- --tag v0.1.0
//   mise run images:publish -- --platform linux/amd64,linux/arm64
//   mise run images:publish -- --dry-run             # print the resolved bake plan only
//
// Authenticates with GHCR_TOKEN (and optional GHCR_USER), otherwise with the GitHub CLI's token,
// which needs the write:packages scope: `gh auth refresh -h github.com -s write:packages`.

const root = join(import.meta.dir, "..");
const registryHost = "ghcr.io";

const { values } = parseArgs({
  options: {
    tag: { type: "string" },
    platform: { type: "string" },
    "no-latest": { type: "boolean", default: false },
    "allow-dirty": { type: "boolean", default: false },
    "dry-run": { type: "boolean", default: false },
  },
});

async function capture(argv: string[], stdin?: string) {
  const child = Bun.spawn(argv, {
    cwd: root,
    stdin: stdin === undefined ? "ignore" : new Blob([stdin]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== 0)
    throw new Error(`${argv.slice(0, 2).join(" ")} failed: ${stderr.trim().slice(0, 2000)}`);
  return stdout.trim();
}

async function run(argv: string[], env: Record<string, string>) {
  const child = Bun.spawn(argv, {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: ["ignore", "inherit", "inherit"],
  });
  const exitCode = await child.exited;
  if (exitCode !== 0) throw new Error(`${argv.slice(0, 3).join(" ")} exited ${exitCode}`);
}

async function credentials() {
  if (process.env.GHCR_TOKEN) {
    const user = process.env.GHCR_USER ?? (await capture(["gh", "api", "user", "--jq", ".login"]));
    return { user, token: process.env.GHCR_TOKEN };
  }
  const headers = await capture(["gh", "api", "--include", "user"]);
  const scopes =
    /^x-oauth-scopes:(.*)$/im
      .exec(headers)?.[1]
      ?.split(",")
      .map((scope) => scope.trim()) ?? [];
  if (!scopes.includes("write:packages")) {
    throw new Error(
      "The GitHub CLI token cannot push packages. Run `gh auth refresh -h github.com -s write:packages` or set GHCR_TOKEN.",
    );
  }
  const user = await capture(["gh", "api", "user", "--jq", ".login"]);
  return { user, token: await capture(["gh", "auth", "token"]) };
}

const dirty = (await capture(["git", "status", "--porcelain"])) !== "";
if (dirty && !values["allow-dirty"] && !values["dry-run"]) {
  console.error("Working tree has uncommitted changes; commit them or pass --allow-dirty.");
  process.exit(1);
}

const revision = await capture(["git", "rev-parse", "HEAD"]);
const tag = values.tag ?? `${revision.slice(0, 12)}${dirty ? "-dirty" : ""}`;
const tags = values["no-latest"] ? [tag] : [tag, "latest"];
const bakeEnv = {
  REGISTRY: process.env.ARK_IMAGE_REGISTRY ?? `${registryHost}/arkaydeus`,
  TAGS: tags.join(","),
  PLATFORMS: values.platform ?? process.env.ARK_IMAGE_PLATFORMS ?? "linux/amd64",
  REVISION: revision,
};

if (values["dry-run"]) {
  await run(["docker", "buildx", "bake", "--print"], bakeEnv);
  process.exit(0);
}

const { user, token } = await credentials();
await capture(["docker", "login", registryHost, "--username", user, "--password-stdin"], token);

const scratch = await mkdtemp(join(tmpdir(), "ark-publish-"));
try {
  const metadataFile = join(scratch, "metadata.json");
  await run(["docker", "buildx", "bake", "--push", "--metadata-file", metadataFile], bakeEnv);

  // Immutable references, ready for a maintenance release bundle.
  const metadata = (await Bun.file(metadataFile).json()) as Record<string, Record<string, string>>;
  console.log(`\nPushed ${tags.map((t) => `:${t}`).join(" ")} for ${bakeEnv.PLATFORMS}:`);
  for (const [target, entry] of Object.entries(metadata)) {
    const digest = entry["containerimage.digest"];
    const name = entry["image.name"]?.split(",")[0]?.replace(/:[^:/]+$/, "");
    if (digest && name) console.log(`  ${target.padEnd(17)} ${name}@${digest}`);
  }
} finally {
  await rm(scratch, { recursive: true, force: true });
}
