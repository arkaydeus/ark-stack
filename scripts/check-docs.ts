// Documentation drift check (FD-22): the operator docs and guides may only name things that exist.
//
//   bun scripts/check-docs.ts            (also: mise run docs:check)
//
// For every checked Markdown file it verifies:
//   - relative links resolve to a tracked file, and `#anchors` to a heading in it (GitHub slugs);
//   - backticked repository paths exist (a `:line` suffix, globs and `<placeholders>` are allowed);
//   - `mise run <task>` names a task in mise.toml;
//   - backticked `METHOD /api/...` endpoints are registered in server/src/app.ts;
//   - backticked Ark environment variables (ARK_*, TS_*, BETTER_AUTH_*, …) occur in tracked source;
//   - ports named as `TCP n`, `UDP n`, `port n` or a backticked `:n` occur in tracked source.
// The front-door design document is historical, so only its links, paths and tasks are checked.
import { readFileSync } from "node:fs";
import { join, dirname, normalize, relative } from "node:path";

export type Problem = { file: string; line: number; kind: string; detail: string };

/** GitHub's heading anchor: lowercase, drop punctuation except `-` and `_`, spaces to `-`. */
export function slug(heading: string) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/`/g, "")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-");
}

/** Anchors of a Markdown document, with GitHub's `-1`, `-2` suffixes for repeated headings. */
export function anchors(markdown: string) {
  const seen = new Map<string, number>();
  const result = new Set<string>();
  let fenced = false;
  for (const line of markdown.split("\n")) {
    if (/^\s*```/.test(line)) fenced = !fenced;
    if (fenced) continue;
    const match = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (!match) continue;
    const base = slug(match[1]!);
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    result.add(count ? `${base}-${count}` : base);
  }
  return result;
}

/** `/api/a/:id/b` and `/api/a/<x>/b` compare equal; query strings and trailing slashes are dropped. */
export function routeKey(method: string, path: string) {
  const clean = path
    .split("?")[0]!
    .replace(/\/+$/, "")
    .split("/")
    .map((segment) => (/^(:\w+|<[^>]+>|\{[^}]+\})$/.test(segment) ? ":p" : segment))
    .join("/");
  return `${method.toUpperCase()} ${clean}`;
}

const PATH_ROOTS =
  /^(?:docs|scripts|server|shared|workers|web|infra|tests|e2e|agent|templates|\.github)\/|^(?:mise\.toml|Dockerfile|docker-bake\.hcl|package\.json|playwright\.config\.ts|README\.md|\.env\.example)$/;
const ENV_PREFIX =
  /^(?:ARK|TS|BETTER_AUTH|DNS_API|GHCR|STALWART)_[A-Z0-9_*]*[A-Z0-9*]$|^(?:ARK_[A-Z0-9_]+_\*|ARK_\*_[A-Z0-9_]+)$/;
/** Not repository files: host paths and upstream sources the design cites. */
const PATH_EXCEPTIONS = new Set([
  "scripts/test-front-door-design.py", // removed prototype harness, documented as removed (V-21)
  "docs/content/docs/reference/options.mdx", // a path inside the upstream Better Auth repository
]);
/** Variables the docs name only to say they were removed. */
const ENV_EXCEPTIONS = new Set(["ARK_TRUSTED_PROXIES"]);

/** A documented endpoint matches a registered route when every non-parameter segment is equal. */
export function routeMatches(routes: Iterable<string>, documented: string) {
  const [method, path] = documented.split(" ") as [string, string];
  const segments = path.split("/");
  for (const route of routes) {
    const [routeMethod, routePath] = route.split(" ") as [string, string];
    const routeSegments = routePath.split("/");
    if (routeMethod !== method || routeSegments.length !== segments.length) continue;
    if (routeSegments.every((segment, index) => segment === ":p" || segment === segments[index])) return true;
  }
  return false;
}

export type Context = {
  root: string;
  tracked: Set<string>;
  trackedDirs: Set<string>;
  tasks: Set<string>;
  routes: Set<string>;
  source: string;
};

export function context(root: string): Context {
  const listing = Bun.spawnSync(["git", "ls-files"], { cwd: root });
  if (listing.exitCode !== 0) throw new Error("git ls-files failed");
  const files = listing.stdout.toString().trim().split("\n");
  // Files created by this change but not yet committed are also accepted (git ls-files --others).
  const untracked = Bun.spawnSync(["git", "ls-files", "--others", "--exclude-standard"], { cwd: root })
    .stdout.toString()
    .trim()
    .split("\n")
    .filter(Boolean);
  const tracked = new Set([...files, ...untracked]);
  const trackedDirs = new Set<string>();
  for (const file of tracked) {
    const parts = file.split("/");
    for (let index = 1; index < parts.length; index += 1) trackedDirs.add(parts.slice(0, index).join("/"));
  }
  const mise = readFileSync(join(root, "mise.toml"), "utf8");
  const tasks = new Set(
    [...mise.matchAll(/^\[tasks\.(?:"([^"]+)"|([\w-]+))\]/gm)].map((match) => match[1] ?? match[2]!),
  );
  const app = readFileSync(join(root, "server/src/app.ts"), "utf8");
  const constants = new Map(
    [...app.matchAll(/^const (\w+) = "(\/api\/[^"]+)";/gm)].map((match) => [match[1]!, match[2]!]),
  );
  const routes = new Set<string>();
  for (const match of app.matchAll(/app\.(get|post|put|patch|delete)\(\s*(?:"([^"]+)"|`([^`]+)`|(\w+))/g)) {
    let path = match[2] ?? match[3] ?? constants.get(match[4] ?? "") ?? "";
    path = path.replace(/\$\{(\w+)\}/g, (_, name: string) => constants.get(name) ?? "");
    if (path) routes.add(routeKey(match[1]!, path));
  }
  // Source text for env var and port lookups: tracked code and config, never Markdown.
  const source = [...tracked]
    .filter((file) => /\.(ts|tsx|go|yml|yaml|toml|json|sh|hcl|cfg|conf|ini|example)$|Dockerfile$/.test(file))
    .filter((file) => !file.startsWith("docs/") && !file.includes("node_modules/"))
    // The checker and its fixtures name invented settings and ports on purpose.
    .filter((file) => !file.startsWith("scripts/check-docs"))
    .map((file) => {
      try {
        return readFileSync(join(root, file), "utf8");
      } catch {
        return "";
      }
    })
    .join("\n");
  return { root, tracked, trackedDirs, tasks, routes, source };
}

function pathExists(ctx: Context, raw: string) {
  const path = raw.replace(/:\d+(?:-\d+)?(?:,\d+)*$/, "").replace(/\/$/, "");
  if (PATH_EXCEPTIONS.has(path)) return true;
  if (/[<{]/.test(path)) {
    // A placeholder segment: the fixed prefix before it must exist.
    const prefix = path.slice(0, path.search(/[<{]/)).replace(/\/[^/]*$/, "");
    return !prefix || ctx.tracked.has(prefix) || ctx.trackedDirs.has(prefix);
  }
  if (path.includes("*")) {
    const pattern = new RegExp(
      "^" +
        path
          .split("*")
          .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
          .join("[^/]*") +
        "(?:/.*)?$",
    );
    return [...ctx.tracked].some((file) => pattern.test(file));
  }
  return ctx.tracked.has(path) || ctx.trackedDirs.has(path);
}

function envExists(ctx: Context, name: string) {
  if (!name.includes("*")) return new RegExp(`\\b${name}\\b`).test(ctx.source);
  const pattern = new RegExp("\\b" + name.replace(/\*/g, "[A-Z0-9_]+") + "\\b");
  const prefix = name.replace(/\*.*$/, "");
  return pattern.test(ctx.source) || (prefix.length > 4 && ctx.source.includes(prefix));
}

export function checkFile(ctx: Context, file: string, scope: "full" | "links"): Problem[] {
  return checkMarkdown(ctx, file, readFileSync(join(ctx.root, file), "utf8"), scope);
}

/** Check Markdown `text` as if it were the repository file `file` (links resolve from its folder). */
export function checkMarkdown(ctx: Context, file: string, text: string, scope: "full" | "links"): Problem[] {
  const problems: Problem[] = [];
  const lines = text.split("\n");
  const ownAnchors = anchors(text);
  const anchorCache = new Map<string, Set<string>>();
  const report = (line: number, kind: string, detail: string) => problems.push({ file, line, kind, detail });
  let fenced = false;

  lines.forEach((line, index) => {
    const number = index + 1;
    if (/^\s*```/.test(line)) {
      fenced = !fenced;
      return;
    }
    // Links (outside code blocks): [text](target)
    if (!fenced) {
      for (const match of line.matchAll(/\]\(([^)\s]+)\)/g)) {
        const target = match[1]!;
        if (/^(?:https?:|mailto:)/.test(target)) continue;
        const [pathPart, anchor] = target.split("#") as [string, string | undefined];
        if (!pathPart) {
          if (anchor && !ownAnchors.has(anchor)) report(number, "anchor", `#${anchor}`);
          continue;
        }
        const resolved = normalize(join(dirname(file), pathPart));
        if (resolved.startsWith("..") || !(ctx.tracked.has(resolved) || ctx.trackedDirs.has(resolved))) {
          report(number, "link", target);
          continue;
        }
        if (anchor && resolved.endsWith(".md")) {
          if (!anchorCache.has(resolved))
            anchorCache.set(resolved, anchors(readFileSync(join(ctx.root, resolved), "utf8")));
          if (!anchorCache.get(resolved)!.has(anchor)) report(number, "anchor", `${resolved}#${anchor}`);
        }
      }
    }
    // `mise run <task>` anywhere, code blocks included.
    for (const match of line.matchAll(/mise run ([a-z][\w:-]*)/g)) {
      if (!ctx.tasks.has(match[1]!)) report(number, "mise task", match[1]!);
    }
    // Inline code spans, and every whitespace-separated token inside fenced blocks.
    const spans = fenced
      ? line.split(/[\s'"(),;=|]+/)
      : [...line.matchAll(/`([^`]+)`/g)].map((match) => match[1]!);
    for (const span of spans) {
      const token = span.trim();
      if (PATH_ROOTS.test(token) && !/\s/.test(token) && !token.includes("…")) {
        if (!pathExists(ctx, token)) report(number, "path", token);
      }
      if (scope !== "full") continue;
      const api = /^(GET|POST|PUT|PATCH|DELETE)\s+(\/api\/[^\s`…]+)/.exec(token);
      // /api/auth/* is Better Auth's; /api/v2/* is Tailscale's API, quoted in the runbooks.
      if (
        api &&
        !/^\/api\/(?:auth|v2)\//.test(api[2]!) &&
        !routeMatches(ctx.routes, routeKey(api[1]!, api[2]!))
      ) {
        report(number, "endpoint", `${api[1]} ${api[2]}`);
      }
      for (const env of token.matchAll(/\b[A-Z][A-Z0-9_]*(?:_\*)?(?:_[A-Z0-9_]+)?\b\*?/g)) {
        const name = env[0]!;
        if (ENV_PREFIX.test(name) && !ENV_EXCEPTIONS.has(name) && !envExists(ctx, name))
          report(number, "env var", name);
      }
    }
    if (scope === "full" && !fenced) {
      for (const match of line.matchAll(/\b(?:TCP|UDP|ports?)\s+(\d{2,5})\b|`[^`\s]*:(\d{2,5})`/g)) {
        const port = match[1] ?? match[2]!;
        if (!new RegExp(`\\b${port}\\b`).test(ctx.source)) report(number, "port", port);
      }
    }
  });
  return problems;
}

export const FULL = [
  "README.md",
  "docs/architecture.md",
  "docs/operating.md",
  "docs/security-review.md",
  "docs/guides/front-door.md",
  "docs/guides/vercel-database.md",
  "docs/guides/backups.md",
];
export const LINKS_ONLY = ["docs/design/front-door.md"];

export function checkDocs(root = join(import.meta.dir, "..")) {
  const ctx = context(root);
  return [
    ...FULL.flatMap((file) => checkFile(ctx, file, "full")),
    ...LINKS_ONLY.flatMap((file) => checkFile(ctx, file, "links")),
  ];
}

if (import.meta.main) {
  const root = join(import.meta.dir, "..");
  const problems = checkDocs(root);
  for (const problem of problems)
    console.log(
      `${relative(root, join(root, problem.file))}:${problem.line}: ${problem.kind}: ${problem.detail}`,
    );
  console.log(
    problems.length
      ? `\n${problems.length} documentation problem(s).`
      : `Documentation check passed: ${FULL.length + LINKS_ONLY.length} files.`,
  );
  process.exit(problems.length ? 1 : 0);
}
