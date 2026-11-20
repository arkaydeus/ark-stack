// Documentation site generator: renders the Markdown in docs/ (and README.md) into a static HTML site
// with a sidebar of sections, an "On this page" list, previous/next links and offline full-text search.
//
//   bun scripts/docs-site/build.ts build [--out dir]     (also: mise run docs:build, default out dist/docs)
//   bun scripts/docs-site/build.ts serve [--out dir] [--port n]      (also: mise run docs:serve, rebuilds on change)
//
// The navigation is docs/nav.json. Every Markdown file under docs/ must appear in it exactly once.
// Pages keep working on GitHub: links between .md files are rewritten to the generated .html pages,
// and links to other repository files point at the repository on GitHub. Heading anchors use the same
// GitHub slugs as scripts/check-docs.ts, so `page.md#anchor` links resolve on both.
import { existsSync, readFileSync, readdirSync, statSync, watch } from "node:fs";
import { dirname, join, normalize, posix, relative, resolve } from "node:path";

import { headingIds } from "../check-docs.ts";
import { loadNav, type Nav } from "./nav.ts";
import { outputDirectory, previewResponse, writeSite } from "./output.ts";

export { loadNav, type Nav, type NavPage, type NavSection } from "./nav.ts";

export type Heading = { level: number; id: string; text: string };
export type Page = {
  file: string;
  url: string;
  title: string;
  section: string;
  html: string;
  headings: Heading[];
  hasMermaid: boolean;
};
export type SearchEntry = { page: string; section: string; title: string; url: string; text: string };

const ROOT = join(import.meta.dir, "..", "..");
const ASSETS = import.meta.dir;
const MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@11.16.1/dist/mermaid.esm.min.mjs";

/**
 * Ark Stack icon files copied into the site (output path → repository file), all derived from
 * assets/brand/ark-stack-icon.png by `mise run brand:icons`. Markdown images of these repository
 * files (the README's icon) use the copy, so the site does not depend on GitHub for them.
 */
export const BRAND_FILES: Record<string, string> = {
  "favicon.ico": "web/public/favicon.ico",
  "assets/brand/icon-32.png": "web/public/brand/icon-32.png",
  "assets/brand/icon-96.png": "web/public/brand/icon-96.png",
  "assets/brand/ark-stack-icon-256.png": "assets/brand/ark-stack-icon-256.png",
};
const BRAND_COPIES = new Map(Object.entries(BRAND_FILES).map(([out, source]) => [source, out]));

/** Output path of a source file, relative to the site root: docs/a/b.md → a/b.html, README.md → readme.html. */
export function pageUrl(file: string) {
  if (file === "README.md") return "readme.html";
  if (
    !file.startsWith("docs/") ||
    !file.endsWith(".md") ||
    file.includes("\\") ||
    posix.normalize(file) !== file
  )
    throw new Error(`not a docs page: ${file}`);
  return file.slice("docs/".length, -".md".length) + ".html";
}

/** Relative URL from one site page to another site path. */
export function relativeUrl(fromUrl: string, toPath: string) {
  const result = posix.relative(posix.dirname(fromUrl), toPath);
  return result === "" ? posix.basename(toPath) : result;
}

/** Every Markdown file under docs/, relative to the repository root. */
export function docsMarkdown(root = ROOT, dir = "docs"): string[] {
  return readdirSync(join(root, dir)).flatMap((name) => {
    const path = `${dir}/${name}`;
    if (statSync(join(root, path)).isDirectory()) return docsMarkdown(root, path);
    return name.endsWith(".md") ? [path] : [];
  });
}

/** Problems with the navigation: missing files, duplicates and docs/ Markdown left out of it. */
export function navProblems(nav: Nav, root = ROOT) {
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const section of nav.sections) {
    if (!section.pages.length) problems.push(`section "${section.title}" has no pages`);
    for (const page of section.pages) {
      if (seen.has(page.file)) problems.push(`${page.file} is listed twice`);
      seen.add(page.file);
      if (!existsSync(join(root, page.file))) problems.push(`${page.file} does not exist`);
      else if (page.file !== "README.md") {
        try {
          pageUrl(page.file);
        } catch (error) {
          problems.push((error as Error).message);
        }
      }
    }
  }
  if (!seen.has("docs/index.md")) problems.push("docs/index.md (the home page) is not in the navigation");
  for (const file of docsMarkdown(root))
    if (!seen.has(file)) problems.push(`${file} is not in docs/nav.json`);
  return problems;
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'", "#x27": "'" };
export function decodeEntities(text: string) {
  return text.replace(/&(amp|lt|gt|quot|#39|#x27);/g, (_, name: string) => ENTITIES[name]!);
}
export function escapeHtml(text: string) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function stripTags(html: string) {
  return decodeEntities(html.replace(/<[^>]+>/g, ""));
}

const ALERTS: Record<string, string> = {
  NOTE: "Note",
  TIP: "Tip",
  IMPORTANT: "Important",
  WARNING: "Warning",
  CAUTION: "Caution",
};

export type RenderContext = {
  nav: Nav;
  /** Source file → site URL for every page in the navigation. */
  pages: Map<string, string>;
  root: string;
};

/** Rewrite one link target found in `file` (rendered at `url`). */
export function rewriteHref(ctx: RenderContext, file: string, url: string, href: string) {
  if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) return href;
  const separator = href.indexOf("#");
  const pathPart = separator < 0 ? href : href.slice(0, separator);
  const hash = separator < 0 ? "" : href.slice(separator);
  let decoded: string;
  try {
    decoded = decodeURI(pathPart);
  } catch {
    return href;
  }
  const resolved = normalize(join(dirname(file), decoded)).replace(/\\/g, "/");
  const target = ctx.pages.get(resolved);
  if (target) return relativeUrl(url, target) + hash;
  if (resolved.startsWith("..")) return href;
  const kind = existsSync(join(ctx.root, resolved)) && statSync(join(ctx.root, resolved)).isDirectory();
  return `${ctx.nav.repository}/${kind ? "tree" : "blob"}/${ctx.nav.branch}/${resolved}${hash}`;
}

/** Render one Markdown page to its article HTML, collecting headings for the page outline. */
export function renderMarkdown(ctx: RenderContext, file: string, markdown: string) {
  const url = ctx.pages.get(file) ?? pageUrl(file);
  let html = Bun.markdown.html(markdown, { autolinks: { url: true, www: false, email: false } });
  const headings: Heading[] = [];
  const nextId = headingIds();

  // Heading ids are GitHub slugs with -1, -2 suffixes for repeats, like scripts/check-docs.ts anchors().
  html = html.replace(/<h([1-6])>([\s\S]*?)<\/h\1>/g, (_, level: string, inner: string) => {
    const text = stripTags(inner).trim();
    const id = nextId(text);
    headings.push({ level: Number(level), id, text });
    const anchor =
      Number(level) > 1 ? `<a class="anchor" href="#${id}" aria-label="Link to this section">#</a>` : "";
    return `<h${level} id="${id}">${inner}${anchor}</h${level}>`;
  });

  html = html.replace(/<a href="([^"]*)"/g, (_, href: string) => {
    const target = rewriteHref(ctx, file, url, decodeEntities(href));
    const external = /^https?:/.test(target) ? ' rel="noopener"' : "";
    return `<a href="${escapeHtml(target)}"${external}`;
  });
  html = html.replace(/<img src="([^"]*)"/g, (_, src: string) => {
    const decoded = decodeEntities(src);
    const copy = /^[\w./-]+$/.test(decoded)
      ? BRAND_COPIES.get(normalize(join(dirname(file), decoded)).replace(/\\/g, "/"))
      : undefined;
    const target = copy
      ? relativeUrl(url, copy)
      : rewriteHref(ctx, file, url, decoded).replace("/blob/", "/raw/");
    return `<img src="${escapeHtml(target)}"`;
  });

  // GitHub alerts: a blockquote whose first paragraph starts with [!NOTE], [!TIP], …
  html = html.replace(
    /<blockquote>\s*<p>\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*/g,
    (_, kind: string) =>
      `<blockquote class="callout callout-${kind.toLowerCase()}"><p class="callout-title">${ALERTS[kind]}</p><p>`,
  );
  html = html.replace(/<p><\/p>/g, "");

  let hasMermaid = false;
  html = html.replace(
    /<pre><code class="language-mermaid">([\s\S]*?)<\/code><\/pre>/g,
    (_, source: string) => {
      hasMermaid = true;
      return `<div class="diagram"><pre class="mermaid">${source}</pre></div>`;
    },
  );
  html = html.replace(/<pre><code(?: class="language-([\w+-]+)")?>/g, (_, language?: string) =>
    language ? `<pre data-language="${language}"><code class="language-${language}">` : "<pre><code>",
  );
  html = html.replace(/<table>/g, '<div class="table-wrap"><table>').replace(/<\/table>/g, "</table></div>");
  return { html, headings, hasMermaid };
}

/** Split an article into one search entry per heading section, as plain text. */
export function searchEntries(page: Page): SearchEntry[] {
  const entries: SearchEntry[] = [];
  const parts = page.html.split(/(?=<h[1-4] id=")/);
  for (const part of parts) {
    const match = /^<h([1-4]) id="([^"]+)">([\s\S]*?)<\/h\1>/.exec(part);
    const title = match
      ? stripTags(match[3]!.replace(/<a class="anchor"[\s\S]*?<\/a>/, "")).trim()
      : page.title;
    const body = match ? part.slice(match[0].length) : part;
    const text = stripTags(body.replace(/<\/(?:p|li|t[dh]|pre|h[1-6])>/g, " "))
      .replace(/\s+/g, " ")
      .trim();
    if (!text && !match) continue;
    const url = match && match[1] !== "1" ? `${page.url}#${match[2]}` : page.url;
    entries.push({ page: page.title, section: page.section, title, url, text });
  }
  return entries;
}

function sidebar(nav: Nav, pages: Page[], current: Page) {
  const byFile = new Map(pages.map((page) => [page.file, page]));
  return nav.sections
    .map((section) => {
      const items = section.pages
        .map((entry) => {
          const page = byFile.get(entry.file)!;
          const active = page === current;
          return `<li><a href="${relativeUrl(current.url, page.url)}"${active ? ' class="active" aria-current="page"' : ""}>${escapeHtml(entry.title ?? page.title)}</a></li>`;
        })
        .join("");
      return `<details class="nav-section" open data-section="${escapeHtml(section.title)}"><summary>${escapeHtml(section.title)}</summary><ul>${items}</ul></details>`;
    })
    .join("\n");
}

function outline(page: Page) {
  const items = page.headings.filter((heading) => heading.level === 2 || heading.level === 3);
  if (items.length < 2) return "";
  const links = items
    .map(
      (heading) =>
        `<li class="toc-${heading.level}"><a href="#${heading.id}">${escapeHtml(heading.text)}</a></li>`,
    )
    .join("");
  return `<nav class="toc" aria-label="On this page"><p class="toc-title">On this page</p><ul>${links}</ul></nav>`;
}

function pager(pages: Page[], index: number) {
  const current = pages[index]!;
  const link = (page: Page | undefined, rel: "prev" | "next") =>
    page
      ? `<a class="pager-${rel}" rel="${rel}" href="${relativeUrl(current.url, page.url)}"><span>${rel === "prev" ? "Previous" : "Next"}</span>${escapeHtml(page.title)}</a>`
      : "<span></span>";
  return `<nav class="pager" aria-label="Previous and next page">${link(pages[index - 1], "prev")}${link(pages[index + 1], "next")}</nav>`;
}

export function layout(nav: Nav, pages: Page[], index: number) {
  const page = pages[index]!;
  const base = relativeUrl(page.url, "index.html").replace(/index\.html$/, "");
  const source = `${nav.repository}/blob/${nav.branch}/${page.file}`;
  const mermaid = page.hasMermaid ? ` data-mermaid="${MERMAID}"` : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(page.title)} · ${escapeHtml(nav.title)} docs</title>
<meta name="description" content="${escapeHtml(searchEntries(page)[0]?.text.slice(0, 160) ?? page.title)}">
<link rel="icon" href="${base}favicon.ico" sizes="16x16 32x32 48x48">
<link rel="icon" href="${base}assets/brand/icon-32.png" type="image/png" sizes="32x32">
<link rel="stylesheet" href="${base}assets/style.css">
<script>try{var t=localStorage.getItem("ark-docs-theme");if(t)document.documentElement.dataset.theme=t}catch(e){}</script>
</head>
<body data-base="${base}"${mermaid}>
<a class="skip" href="#content">Skip to content</a>
<header class="topbar">
  <button class="menu-toggle" type="button" aria-label="Toggle navigation" aria-controls="sidebar" aria-expanded="false"><span></span></button>
  <a class="brand" href="${base}index.html"><img class="brand-mark" src="${base}assets/brand/icon-96.png" alt="" width="28" height="28">${escapeHtml(nav.title)} <span class="brand-docs">Docs</span></a>
  <div class="search">
    <input id="search" type="search" placeholder="Search the docs" aria-label="Search the docs" autocomplete="off" spellcheck="false">
    <kbd class="search-key" aria-hidden="true">/</kbd>
    <div class="search-results" id="search-results" role="listbox" hidden></div>
  </div>
  <button class="theme-toggle" type="button" aria-label="Toggle dark mode"><span aria-hidden="true"></span></button>
  <a class="repo" href="${nav.repository}" rel="noopener">GitHub</a>
</header>
<div class="shell">
  <aside class="sidebar" id="sidebar"><nav aria-label="Documentation">${sidebar(nav, pages, page)}</nav></aside>
  <main id="content" class="content">
    <p class="breadcrumb">${escapeHtml(page.section)}</p>
    <article class="prose">${page.html}</article>
    <footer class="page-footer">
      <a class="edit" href="${source}" rel="noopener">View this page's source on GitHub</a>
      ${pager(pages, index)}
    </footer>
  </main>
  ${outline(page)}
</div>
<script src="${base}assets/site.js" defer></script>
</body>
</html>
`;
}

/** Render every page in the navigation, in navigation order. */
export function renderSite(root = ROOT) {
  const nav = loadNav(root);
  const problems = navProblems(nav, root);
  if (problems.length) throw new Error(`docs/nav.json:\n  ${problems.join("\n  ")}`);
  const urls = new Map(
    nav.sections.flatMap((section) => section.pages.map((page) => [page.file, pageUrl(page.file)])),
  );
  const ctx: RenderContext = { nav, pages: urls, root };
  const pages: Page[] = nav.sections.flatMap((section) =>
    section.pages.map((entry) => {
      const markdown = readFileSync(join(root, entry.file), "utf8");
      const rendered = renderMarkdown(ctx, entry.file, markdown);
      const h1 = rendered.headings.find((heading) => heading.level === 1)?.text;
      const title = h1 ?? entry.title ?? entry.file;
      return { file: entry.file, url: urls.get(entry.file)!, title, section: section.title, ...rendered };
    }),
  );
  return { nav, pages };
}

export function buildSite(out: string, root = ROOT) {
  out = outputDirectory(out, root, ASSETS);
  const { nav, pages } = renderSite(root);
  const files = new Map<string, string | Buffer>(
    pages.map((page, index) => [page.url, layout(nav, pages, index)]),
  );
  files.set("assets/style.css", readFileSync(join(ASSETS, "style.css")));
  files.set("assets/site.js", readFileSync(join(ASSETS, "site.js")));
  for (const [path, source] of Object.entries(BRAND_FILES)) files.set(path, readFileSync(join(ROOT, source)));
  // Loaded on first search, as a script rather than JSON so the site also works from file://.
  const index = pages.flatMap(searchEntries);
  files.set("assets/search-index.js", `window.ARK_DOCS_INDEX=${JSON.stringify(index)};\n`);
  files.set(".nojekyll", "");
  writeSite(out, files);
  return { pages: pages.length, entries: index.length };
}

function option(args: string[], name: string) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

export function servePreview(out: string, port: number) {
  return Bun.serve({
    hostname: "127.0.0.1",
    port,
    fetch: (request) => previewResponse(out, request),
  });
}

function serve(out: string, port: number) {
  out = outputDirectory(out, ROOT, ASSETS);
  const rebuild = () => {
    const result = buildSite(out);
    console.log(`built ${result.pages} pages`);
  };
  rebuild();
  let timer: Timer | undefined;
  const schedule = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      try {
        rebuild();
      } catch (error) {
        console.error((error as Error).message);
      }
    }, 150);
  };
  watch(join(ROOT, "docs"), { recursive: true }, schedule);
  watch(ASSETS, schedule);
  watch(join(ROOT, "README.md"), schedule);
  const server = servePreview(out, port);
  console.log(`docs site on http://127.0.0.1:${server.port}/ (rebuilds when docs change)`);
}

if (import.meta.main) {
  const [command = "build", ...args] = Bun.argv.slice(2);
  const out = resolve(option(args, "--out") ?? join(ROOT, "dist/docs"));
  if (command === "build") {
    const result = buildSite(out);
    console.log(
      `Built ${result.pages} pages (${result.entries} search entries) in ${relative(process.cwd(), out) || "."}`,
    );
  } else if (command === "serve") {
    serve(out, Number(option(args, "--port") ?? 4321));
  } else {
    console.error("usage: bun scripts/docs-site/build.ts build [--out dir] | serve [--out dir] [--port n]");
    process.exit(2);
  }
}
