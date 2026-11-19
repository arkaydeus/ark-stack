import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";

const MANIFEST = ".ark-docs-manifest.json";
const BUILD_LOCK = ".ark-docs-build";

export function isWithinDirectory(directory: string, path: string) {
  const child = relative(directory, path);
  return child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child);
}

function entry(path: string) {
  return lstatSync(path, { throwIfNoEntry: false });
}

// Resolve existing ancestors before checking a destination that may not have been created yet.
function canonical(path: string): string {
  return entry(path) ? realpathSync(path) : join(canonical(dirname(path)), basename(path));
}

export function outputDirectory(path: string, root: string, assets: string) {
  const out = canonical(resolve(path));
  root = realpathSync(root);
  if (
    isWithinDirectory(out, root) ||
    [join(root, "docs"), assets].some((source) => {
      source = realpathSync(source);
      return isWithinDirectory(out, source) || isWithinDirectory(source, out);
    })
  ) {
    throw new Error(`Output directory overlaps documentation sources: ${out}`);
  }
  return out;
}

function generatedPath(path: unknown): path is string {
  return (
    typeof path === "string" &&
    !path.includes("\\") &&
    !path.includes("\0") &&
    !path.startsWith("/") &&
    !path.startsWith("../") &&
    posix.normalize(path) === path &&
    (path.endsWith(".html") ||
      [".nojekyll", "assets/site.js", "assets/style.css", "assets/search-index.js"].includes(path))
  );
}

function previousFiles(out: string) {
  const path = join(out, MANIFEST);
  const metadata = entry(path);
  if (!metadata) {
    if (readdirSync(out).some((name) => name !== BUILD_LOCK))
      throw new Error(`Output directory is not empty and has no docs manifest: ${out}`);
    return new Set<string>();
  }
  if (!metadata.isFile()) throw new Error(`Invalid docs manifest: ${path}`);
  const files: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(files) || !files.every(generatedPath)) throw new Error(`Invalid docs manifest: ${path}`);
  return new Set<string>(files);
}

export function writeSite(out: string, files: Map<string, string | Buffer>) {
  mkdirSync(out, { recursive: true });
  const staging = join(out, BUILD_LOCK);
  // A second writer must wait for the current invocation to finish before trying again.
  mkdirSync(staging);
  const pending = join(staging, "file");
  try {
    const previous = previousFiles(out);
    const owned = new Set([...previous, ...files.keys()]);
    for (const path of owned) {
      if (!generatedPath(path)) throw new Error(`Invalid generated file path: ${path}`);
      const target = join(out, path);
      for (let dir = dirname(target); dir !== out; dir = dirname(dir)) {
        const parent = entry(dir);
        if (parent && !parent.isDirectory()) throw new Error(`Unexpected output directory entry: ${dir}`);
      }
      const metadata = entry(target);
      if (metadata && (!previous.has(path) || !metadata.isFile()))
        throw new Error(`Refusing to replace output directory entry: ${target}`);
    }

    // Publish individual files by rename so rebuilding cannot modify the target of a hard link.
    const replace = (path: string, content: string | Buffer) => {
      const target = join(out, path);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(pending, content);
      renameSync(pending, target);
    };
    // Keep ownership of both sets until the build and stale-file cleanup finish so a retry can recover.
    replace(MANIFEST, JSON.stringify([...owned]));
    for (const [path, content] of files) replace(path, content);
    for (const path of previous) {
      const target = join(out, path);
      if (!files.has(path) && entry(target)) unlinkSync(target);
    }
    replace(MANIFEST, JSON.stringify([...files.keys()]));
  } finally {
    if (entry(pending)) unlinkSync(pending);
    rmdirSync(staging);
  }
}

export function previewResponse(out: string, request: Request) {
  let path: string;
  try {
    path = decodeURIComponent(new URL(request.url).pathname);
  } catch {
    return new Response("Invalid request path", { status: 400 });
  }
  if (path.includes("\0")) return new Response("Invalid request path", { status: 400 });
  if (path.endsWith("/")) path += "index.html";
  const candidate = join(out, path);
  if (isWithinDirectory(out, candidate)) {
    try {
      const file = realpathSync(candidate);
      if (
        isWithinDirectory(out, file) &&
        !isWithinDirectory(join(out, BUILD_LOCK), file) &&
        file !== join(out, MANIFEST) &&
        statSync(file).isFile()
      )
        return new Response(Bun.file(file));
    } catch {
      // Missing or unreadable paths receive the same response.
    }
  }
  return new Response("Not found", { status: 404 });
}
