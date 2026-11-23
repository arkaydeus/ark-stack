import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bunImage } from "./test-images.ts";

// Every Bun pin in the repository follows scripts/test-images.ts, so a Bun upgrade changes that
// constant and the literals this test points at, and nothing is left on the old version.
const root = join(import.meta.dir, "..");
const constantFile = "scripts/test-images.ts";

const pinned = /^oven\/bun:(\d+\.\d+\.\d+)-slim@sha256:[0-9a-f]{64}$/.exec(bunImage);
if (!pinned) throw new Error(`${constantFile}: bunImage must be oven/bun:<version>-slim@sha256:<digest>`);
const bunVersion = pinned[1]!;

const trackedFiles = (() => {
  const result = Bun.spawnSync(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) throw new Error(`git ls-files failed: ${result.stderr.toString()}`);
  return result.stdout
    .toString()
    .split("\0")
    .filter((file) => file !== "" && file !== "bun.lock");
})();

const files = new Map<string, string>();
for (const file of trackedFiles) {
  let text: string;
  try {
    text = readFileSync(join(root, file), "utf8");
  } catch {
    continue; // Deleted in the working tree.
  }
  if (!text.includes("\0")) files.set(file, text);
}

type Match = { file: string; line: number; value: string; groups: string[] };

function find(pattern: RegExp, only?: (file: string) => boolean, sources = files): Match[] {
  const matches: Match[] = [];
  for (const [file, text] of sources) {
    if (only && !only(file)) continue;
    for (const match of text.matchAll(new RegExp(pattern.source, `${pattern.flags.replace("g", "")}g`))) {
      matches.push({
        file,
        line: text.slice(0, match.index).split("\n").length,
        value: match[0],
        groups: match.slice(1).map((group) => group ?? ""),
      });
    }
  }
  return matches;
}

const where = (match: Match) => `${match.file}:${match.line} ${match.value}`;

// Match tagged image literals, including slash and dot escapes in regular expression source.
const taggedBunImage = /oven\\?\/bun:((?:[0-9A-Za-z._-]|\\\.)+)(?:@sha256:([0-9a-f]{64}))?/;
const imageReferences = find(taggedBunImage);
const isDockerfile = (file: string) => /(^|\/)Dockerfile[^/]*$/.test(file);

function untaggedDockerImages(sources = files): Match[] {
  return find(
    /^[\t ]*(?:FROM[\t ]+(?:--platform=\S+[\t ]+)?|COPY[\t ]+(?:--\S+[\t ]+)*?--from=)(oven\/bun(?:@\S+)?)(?=\s|$)/im,
    isDockerfile,
    sources,
  );
}

describe("Bun pins", () => {
  test("finds the pins it checks", () => {
    expect(imageReferences.length).toBeGreaterThan(0);
    expect(imageReferences.some((match) => match.file === "Dockerfile")).toBe(true);
  });

  test("TypeScript imports the shared Bun image instead of repeating it", () => {
    const literals = imageReferences.filter(
      (match) => /\.(ts|tsx|js|mjs)$/.test(match.file) && match.file !== constantFile,
    );
    expect(literals.map(where)).toEqual([]);
  });

  test("finds a Bun image in escaped regex source", () => {
    const tag = bunImage.split("@")[0]!.replaceAll("/", "\\/").replaceAll(".", "\\.");
    const source = `expect(image).toMatch(/^${tag}@sha256:[a-f0-9]{64}$/);`;
    expect(find(taggedBunImage, undefined, new Map([["fixture.ts", source]])).map(where)).toEqual([
      `fixture.ts:1 ${tag}`,
    ]);
  });

  test("every literal slim pin matches the shared Bun image", () => {
    const slim = imageReferences.filter((match) => match.groups[0]!.endsWith("-slim"));
    expect(slim.length).toBeGreaterThan(0);
    expect(slim.filter((match) => match.value !== bunImage).map(where)).toEqual([]);
  });

  test("every oven/bun image uses the same Bun version", () => {
    const tagPattern = new RegExp(`^${bunVersion.replaceAll(".", "\\.")}(-[a-z0-9]+)?$`);
    expect(imageReferences.filter((match) => !tagPattern.test(match.groups[0]!)).map(where)).toEqual([]);
  });

  test("Dockerfiles pin every oven/bun image by digest, one digest per tag", () => {
    expect(untaggedDockerImages().map(where)).toEqual([]);
    const dockerfileReferences = imageReferences.filter((match) => isDockerfile(match.file));
    expect(dockerfileReferences.filter((match) => match.groups[1] === "").map(where)).toEqual([]);
    const digests = new Map<string, Set<string>>();
    for (const reference of imageReferences.filter((match) => match.groups[1] !== "")) {
      const tag = reference.groups[0]!;
      digests.set(tag, (digests.get(tag) ?? new Set()).add(reference.groups[1]!));
    }
    const mixed = [...digests]
      .filter(([, set]) => set.size > 1)
      .map(([tag, set]) => `${tag}: ${[...set].join(", ")}`);
    expect(mixed).toEqual([]);
  });

  test("finds untagged Dockerfile sources alongside a pinned stage", () => {
    const source = [
      `FROM ${bunImage} AS pinned`,
      "FROM oven/bun AS unpinned",
      "COPY --chown=1000 --from=oven/bun /usr/local/bin/bun /bin/bun",
    ].join("\n");
    expect(untaggedDockerImages(new Map([["Dockerfile", source]])).map(where)).toEqual([
      "Dockerfile:2 FROM oven/bun",
      "Dockerfile:3 COPY --chown=1000 --from=oven/bun",
    ]);
  });

  test("the toolchain, package manager and CI use the same Bun version", () => {
    const mise = find(/^bun = "([^"]+)"$/m, (file) => file === "mise.toml");
    expect(mise.map((match) => match.groups[0])).toEqual([bunVersion]);

    const packageManager = JSON.parse(files.get("package.json")!).packageManager as string;
    expect(packageManager).toBe(`bun@${bunVersion}`);

    const workflows = find(/bun-version:\s*["']?([^"'\s]+)["']?/, (file) =>
      file.startsWith(".github/workflows/"),
    );
    expect(workflows.length).toBeGreaterThan(0);
    expect(workflows.filter((match) => match.groups[0] !== bunVersion).map(where)).toEqual([]);
  });

  test("the docs name the pinned Bun version", () => {
    // "Bun 1.4.5", "`bun` 1.4.5" and the "| Bun | 1.4.5" toolchain table row.
    const mentions = find(/\bbun`?[\s|]*(\d+\.\d+\.\d+)\b/i, (file) => file.endsWith(".md"));
    expect(mentions.length).toBeGreaterThan(0);
    expect(mentions.filter((match) => match.groups[0] !== bunVersion).map(where)).toEqual([]);
  });
});
