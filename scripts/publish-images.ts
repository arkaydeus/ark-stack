import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";

import { imageSource } from "./check-image-plan.ts";

// Builds every platform image in docker-bake.hcl and pushes it to GHCR.
// Explicit tokens require GHCR_USER; otherwise the GitHub CLI token needs write:packages.
// `--merge <tag>,<tag>` instead combines per-platform tags that were already pushed (one per CI
// runner) into one multi-platform index per image, tagged with --tag (and latest).
const root = join(import.meta.dir, "..");
const registryHost = "ghcr.io";

async function capture(argv: string[], stdin?: string, env: Record<string, string | undefined> = {}) {
  const child = Bun.spawn(argv, {
    cwd: root,
    env: { ...process.env, ...env },
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
    const user = process.env.GHCR_USER?.trim();
    if (!user) throw new Error("GHCR_USER is required when GHCR_TOKEN is set.");
    return { user, token: process.env.GHCR_TOKEN };
  }
  const token = await capture(["gh", "auth", "token", "--hostname", "github.com"]);
  if (!token) throw new Error("GitHub CLI returned an empty token.");
  // Pin both API requests to the same token and host used for Docker login.
  const env = { GH_TOKEN: token, GITHUB_TOKEN: undefined };
  const headers = await capture(
    ["gh", "api", "--hostname", "github.com", "--include", "user"],
    undefined,
    env,
  );
  const scopes =
    /^x-oauth-scopes:(.*)$/im
      .exec(headers)?.[1]
      ?.split(",")
      .map((scope) => scope.trim()) ?? [];
  if (!scopes.includes("write:packages")) {
    throw new Error(
      "The GitHub CLI token cannot push packages. Run `gh auth refresh -h github.com -s write:packages` or set GHCR_TOKEN and GHCR_USER.",
    );
  }
  const user = await capture(
    ["gh", "api", "--hostname", "github.com", "user", "--jq", ".login"],
    undefined,
    env,
  );
  if (!user || !token) throw new Error("GitHub CLI returned empty credentials.");
  return { user, token };
}

export async function isolatedDockerConfig(scratch: string) {
  const original = process.env.DOCKER_CONFIG || join(homedir(), ".docker");
  const configPath = join(original, "config.json");
  let config: { currentContext?: string; cliPluginsExtraDirs?: string[] } = {};
  try {
    config = JSON.parse(await readFile(configPath, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  // A nonempty auths map also disables Docker's automatic native-helper detection.
  // Never copy auths, credsStore or credHelpers from the user's configuration.
  await writeFile(
    join(scratch, "config.json"),
    JSON.stringify({
      auths: { [registryHost]: {} },
      currentContext: config.currentContext,
      cliPluginsExtraDirs: [...(config.cliPluginsExtraDirs ?? []), join(original, "cli-plugins")],
    }),
    { mode: 0o600 },
  );
  try {
    await cp(join(original, "contexts"), join(scratch, "contexts"), { recursive: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return {
    DOCKER_CONFIG: scratch,
    BUILDX_CONFIG: process.env.BUILDX_CONFIG || join(original, "buildx"),
  };
}

export function digestReferences(metadata: unknown): string[] {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new Error("Bake metadata must be an object.");
  }
  const references: string[] = [];
  for (const [target, entry] of Object.entries(metadata)) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`Invalid Bake metadata for ${target}.`);
    }
    const digest: unknown = Reflect.get(entry, "containerimage.digest");
    const names: unknown = Reflect.get(entry, "image.name");
    if (typeof digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(digest) || typeof names !== "string") {
      throw new Error(`Missing or invalid image name/digest for ${target}.`);
    }
    const name = names.split(",")[0]?.replace(/:[^:/]+$/, "");
    if (!name) throw new Error(`Missing image name for ${target}.`);
    references.push(`  ${target.padEnd(17)} ${name}@${digest}`);
  }
  if (!references.length) throw new Error("Bake metadata contains no published images.");
  return references;
}

/** Registry repository per Bake target, from `docker buildx bake --print` with a single tag. */
export function imageNames(plan: unknown, tag: string): [string, string][] {
  const targets: unknown =
    plan && typeof plan === "object" && !Array.isArray(plan) ? Reflect.get(plan, "target") : undefined;
  if (!targets || typeof targets !== "object" || Array.isArray(targets)) {
    throw new Error("Bake plan has no targets.");
  }
  const names: [string, string][] = [];
  for (const [target, entry] of Object.entries(targets)) {
    const tags: unknown = entry && typeof entry === "object" ? Reflect.get(entry, "tags") : undefined;
    const first = Array.isArray(tags) ? tags[0] : undefined;
    if (typeof first !== "string" || !first.endsWith(`:${tag}`)) {
      throw new Error(`Bake target ${target} has no :${tag} tag.`);
    }
    names.push([target, first.slice(0, -tag.length - 1)]);
  }
  if (!names.length) throw new Error("Bake plan has no targets.");
  return names.toSorted(([a], [b]) => a.localeCompare(b));
}

async function mergePlatforms(
  sources: string[],
  tags: string[],
  bakeEnv: Record<string, string>,
  dockerEnv: Record<string, string>,
) {
  const plan = JSON.parse(
    await capture(["docker", "buildx", "bake", "--print"], undefined, { ...bakeEnv, TAGS: sources[0]! }),
  );
  const references: string[] = [];
  for (const [target, name] of imageNames(plan, sources[0]!)) {
    // The index annotation links the merged package to the repository, as Bake's annotation does.
    await run(
      [
        "docker",
        "buildx",
        "imagetools",
        "create",
        "--annotation",
        `index:org.opencontainers.image.source=${imageSource}`,
        ...tags.flatMap((tag) => ["--tag", `${name}:${tag}`]),
        ...sources.map((source) => `${name}:${source}`),
      ],
      dockerEnv,
    );
    const manifest = await capture(
      ["docker", "buildx", "imagetools", "inspect", `${name}:${tags[0]}`, "--format", "{{json .Manifest}}"],
      undefined,
      dockerEnv,
    );
    const digest: unknown = JSON.parse(manifest)?.digest;
    if (typeof digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(digest)) {
      throw new Error(`Missing or invalid merged digest for ${target}.`);
    }
    references.push(`  ${target.padEnd(17)} ${name}@${digest}`);
  }
  return references;
}

async function main() {
  const { values } = parseArgs({
    options: {
      tag: { type: "string" },
      platform: { type: "string" },
      "no-latest": { type: "boolean", default: false },
      "allow-dirty": { type: "boolean", default: false },
      "dry-run": { type: "boolean", default: false },
      merge: { type: "string" },
    },
  });
  const registry = process.env.ARK_IMAGE_REGISTRY ?? `${registryHost}/arkaydeus`;
  if (!/^ghcr\.io\/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/.test(registry)) {
    throw new Error(
      "ARK_IMAGE_REGISTRY must be a ghcr.io/<namespace> prefix (lowercase, no scheme or trailing slash).",
    );
  }
  const validTag = (tag: string) => /^[\w][\w.-]{0,127}$/.test(tag);
  if (values.tag !== undefined && !validTag(values.tag)) throw new Error("Invalid Docker tag.");
  const sources = values.merge?.split(",").map((source) => source.trim());
  if (sources && (sources.length < 2 || !sources.every(validTag) || new Set(sources).size !== sources.length))
    throw new Error("--merge needs at least two distinct, valid source tags.");
  if (sources && values["dry-run"]) throw new Error("--merge cannot be combined with --dry-run.");
  const dirty = (await capture(["git", "status", "--porcelain"])) !== "";
  if (dirty && !values["allow-dirty"] && !values["dry-run"]) {
    throw new Error("Working tree has uncommitted changes; commit them or pass --allow-dirty.");
  }
  if (dirty && values.tag === "latest") throw new Error("Dirty builds cannot publish the latest tag.");
  const revision = await capture(["git", "rev-parse", "HEAD"]);
  const baseTag = values.tag ?? revision.slice(0, 12);
  const tag = dirty && !baseTag.endsWith("-dirty") ? `${baseTag}-dirty` : baseTag;
  if (tag.length > 128) throw new Error("Docker tag exceeds 128 characters after the dirty suffix.");
  const tags = values["no-latest"] || dirty || tag === "latest" ? [tag] : [tag, "latest"];
  if (sources?.some((source) => tags.includes(source)))
    throw new Error("--merge source tags must differ from the published tags.");
  const bakeEnv = {
    REGISTRY: registry,
    TAGS: tags.join(","),
    PLATFORMS: values.platform ?? process.env.ARK_IMAGE_PLATFORMS ?? "linux/amd64",
    REVISION: `${revision}${dirty ? "-dirty" : ""}`,
  };
  if (values["dry-run"]) {
    await run(["docker", "buildx", "bake", "--print"], bakeEnv);
    return;
  }

  const { user, token } = await credentials();
  const scratch = await mkdtemp(join(tmpdir(), "ark-publish-"));
  try {
    const dockerEnv = await isolatedDockerConfig(scratch);
    await capture(
      ["docker", "login", registryHost, "--username", user, "--password-stdin"],
      token,
      dockerEnv,
    );
    if (sources) {
      const references = await mergePlatforms(sources, tags, bakeEnv, dockerEnv);
      console.log(`\nMerged ${sources.join(", ")} into ${tags.map((t) => `:${t}`).join(" ")}:`);
      for (const reference of references) console.log(reference);
      return;
    }
    const metadataFile = join(scratch, "metadata.json");
    await run(["docker", "buildx", "bake", "--push", "--metadata-file", metadataFile], {
      ...bakeEnv,
      ...dockerEnv,
    });
    const references = digestReferences(await Bun.file(metadataFile).json());
    console.log(`\nPushed ${tags.map((t) => `:${t}`).join(" ")} for ${bakeEnv.PLATFORMS}:`);
    for (const reference of references) console.log(reference);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  try {
    await main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
