// Pull-first image install: use the images CI published for this exact commit instead of building
// them on the host. `.github/workflows/publish-images.yml` pushes every Bake target as
// `<registry>/<name>:<first 12 of HEAD>` (amd64 and arm64) on each push to main. The installer pulls
// those, checks each one's revision label is this checkout's full HEAD, and retags them to the local
// names Compose uses (`<name>:${ARK_VERSION:-local}`), so Compose, maintenance and everything else
// see the same image names as after a local build. Anything missing or mismatched means a local build.

export type Exec = (argv: string[]) => Promise<{ status: number; stdout: string; stderr: string }>;

export const defaultImageRegistry = "ghcr.io/arkaydeus";
const registryPattern = /^ghcr\.io\/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;

/** First-party image names Compose builds: `image: <name>:${ARK_VERSION:-local}` beside a `build:`. */
export function composeBuiltImages(compose: string) {
  const names = new Set<string>();
  for (const match of compose.matchAll(/^\s*image:\s*(ark-[a-z0-9-]+):\$\{ARK_VERSION:-local\}\s*$/gm)) {
    names.add(match[1]!);
  }
  if (!names.size) throw new Error("Compose declares no first-party images.");
  return [...names].toSorted();
}

/** Package names the Bake file publishes (`refs("<name>")`). */
export function bakePublishedImages(bake: string) {
  return [...new Set([...bake.matchAll(/refs\("([a-z0-9-]+)"\)/g)].map((match) => match[1]!))].toSorted();
}

export type PullResult = { pulled: true; tag: string } | { pulled: false; reason: string };

export async function pullPublishedImages(input: {
  root: string;
  compose: string;
  version: string;
  env: Record<string, string | undefined>;
  exec: Exec;
  log?: (line: string) => void;
}): Promise<PullResult> {
  const { root, exec, env } = input;
  const log = input.log ?? (() => {});
  if (env.ARK_INSTALL_BUILD_IMAGES === "1") return { pulled: false, reason: "ARK_INSTALL_BUILD_IMAGES=1" };
  const registry = env.ARK_IMAGE_REGISTRY || defaultImageRegistry;
  if (!registryPattern.test(registry)) {
    return {
      pulled: false,
      reason: `ARK_IMAGE_REGISTRY ${JSON.stringify(registry)} is not a ghcr.io/<namespace> prefix`,
    };
  }
  // Root installs read a checkout another user may own; trust it for these read-only commands only.
  const git = ["git", "-c", `safe.directory=${root}`, "-C", root];
  const head = await exec([...git, "rev-parse", "HEAD"]);
  const revision = head.stdout.trim();
  if (head.status !== 0 || !/^[a-f0-9]{40}$/.test(revision)) {
    return { pulled: false, reason: "the checkout's commit could not be read" };
  }
  // Untracked files are outside the published images too, but a modified tracked file is not.
  const status = await exec([...git, "status", "--porcelain", "--untracked-files=no"]);
  if (status.status !== 0) return { pulled: false, reason: "git status failed" };
  if (status.stdout.trim()) return { pulled: false, reason: "the checkout has local changes" };

  const tag = revision.slice(0, 12);
  const names = composeBuiltImages(input.compose);
  log(`Pulling prebuilt images for ${tag} from ${registry}`);
  const pulls = await Promise.all(
    names.map(async (name) => {
      const ref = `${registry}/${name}:${tag}`;
      const pull = await exec(["docker", "pull", "--quiet", ref]);
      if (pull.status !== 0) return `${ref} is not available`;
      const label = await exec([
        "docker",
        "image",
        "inspect",
        "--format",
        '{{index .Config.Labels "org.opencontainers.image.revision"}}',
        ref,
      ]);
      if (label.status !== 0 || label.stdout.trim() !== revision) {
        return `${ref} was built from ${label.stdout.trim() || "an unknown revision"}, not ${revision}`;
      }
      return undefined;
    }),
  );
  const failure = pulls.find(Boolean);
  if (failure) return { pulled: false, reason: failure };
  // Retag only after every image verified, so a partial pull never mixes with a local build.
  for (const name of names) {
    const tagged = await exec(["docker", "tag", `${registry}/${name}:${tag}`, `${name}:${input.version}`]);
    if (tagged.status !== 0) throw new Error(`docker tag ${name} failed: ${tagged.stderr.trim()}`);
  }
  return { pulled: true, tag };
}
