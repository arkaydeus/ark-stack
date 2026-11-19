import { describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { anchors } from "../check-docs.ts";
import {
  buildSite,
  loadNav,
  navProblems,
  pageUrl,
  relativeUrl,
  renderMarkdown,
  renderSite,
  rewriteHref,
  searchEntries,
  servePreview,
  type RenderContext,
} from "./build.ts";

import { isWithinDirectory } from "./output.ts";

const root = join(import.meta.dir, "..", "..");
const nav = loadNav(root);
const ctx: RenderContext = {
  nav,
  root,
  pages: new Map([
    ["docs/index.md", "index.html"],
    ["docs/operating.md", "operating.html"],
    ["docs/guides/front-door.md", "guides/front-door.html"],
    ["README.md", "readme.html"],
  ]),
};

describe("docs site paths", () => {
  test("page URLs mirror docs/ and README.md has its own page", () => {
    expect(pageUrl("docs/index.md")).toBe("index.html");
    expect(pageUrl("docs/guides/front-door.md")).toBe("guides/front-door.html");
    expect(pageUrl("README.md")).toBe("readme.html");
    expect(() => pageUrl("scripts/check-docs.ts")).toThrow();
  });

  test("relative URLs between pages", () => {
    expect(relativeUrl("guides/front-door.html", "operating.html")).toBe("../operating.html");
    expect(relativeUrl("index.html", "guides/backups.html")).toBe("guides/backups.html");
    expect(relativeUrl("guides/a.html", "guides/a.html")).toBe("a.html");
  });

  test("links to pages become .html, other repository files go to GitHub", () => {
    const from = ["docs/guides/front-door.md", "guides/front-door.html"] as const;
    expect(rewriteHref(ctx, ...from, "../operating.md#revocation")).toBe("../operating.html#revocation");
    expect(rewriteHref(ctx, ...from, "#contents")).toBe("#contents");
    expect(rewriteHref(ctx, ...from, "https://tailscale.com/kb")).toBe("https://tailscale.com/kb");
    expect(rewriteHref(ctx, ...from, "../../server/src/app.ts")).toBe(
      `${nav.repository}/blob/${nav.branch}/server/src/app.ts`,
    );
    expect(rewriteHref(ctx, ...from, "../../infra")).toBe(`${nav.repository}/tree/${nav.branch}/infra`);
    expect(rewriteHref(ctx, "README.md", "readme.html", "docs/operating.md")).toBe("operating.html");
  });
  test("malformed percent-encoding leaves a relative link unchanged", () => {
    const href = "literal%file.md#section";
    expect(rewriteHref(ctx, "docs/index.md", "index.html", href)).toBe(href);
    expect(renderMarkdown(ctx, "docs/index.md", `[Percent](${href})`).html).toContain(`href="${href}"`);
  });
});

describe("docs site rendering", () => {
  const markdown = [
    "# Title",
    "Lead.",
    "## Setup `mise`",
    "See [runbooks](../operating.md#revocation).",
    "## Setup `mise`",
    "> [!WARNING]",
    "> Keep the console open.",
    "",
    "```mermaid",
    "flowchart LR",
    "  A --> B",
    "```",
    "",
    "```sh",
    "mise run docs:build",
    "```",
    "",
    "| a | b |",
    "| - | - |",
    "| 1 | 2 |",
  ].join("\n");
  const page = renderMarkdown(ctx, "docs/guides/front-door.md", markdown);

  test("headings get GitHub slugs, numbered when repeated", () => {
    expect(page.headings.map((heading) => heading.id)).toEqual(["title", "setup-mise", "setup-mise-1"]);
    expect(page.html).toContain('<h2 id="setup-mise-1">');
  });

  test("callouts, diagrams, code labels and tables", () => {
    expect(page.html).toContain(
      '<blockquote class="callout callout-warning"><p class="callout-title">Warning</p>',
    );
    expect(page.html).toContain('<pre class="mermaid">flowchart LR');
    expect(page.hasMermaid).toBe(true);
    expect(page.html).toContain('<pre data-language="sh">');
    expect(page.html).toContain('<div class="table-wrap"><table>');
    expect(page.html).toContain('href="../operating.html#revocation"');
  });

  test("search entries are split by section", () => {
    const entries = searchEntries({
      ...page,
      file: "docs/guides/front-door.md",
      url: "guides/front-door.html",
      title: "Title",
      section: "Front door",
    });
    expect(entries.map((entry) => entry.url)).toEqual([
      "guides/front-door.html",
      "guides/front-door.html#setup-mise",
      "guides/front-door.html#setup-mise-1",
    ]);
    expect(entries[1]!.text).toBe("See runbooks.");
  });
  test("numbered headings have distinct self-links and search destinations", () => {
    const fixture = "# Title\n## Setup\n## Setup\n## Setup 1\n## Setup";
    const rendered = renderMarkdown(ctx, "docs/index.md", fixture);
    const ids = ["title", "setup", "setup-1", "setup-1-1", "setup-2"];
    expect(rendered.headings.map(({ id }) => id)).toEqual(ids);
    expect([...anchors(fixture)]).toEqual(ids);
    for (const id of ids.slice(1)) {
      expect(rendered.html).toContain(`<h2 id="${id}">`);
      expect(rendered.html).toContain(`href="#${id}"`);
    }
    const entries = searchEntries({
      ...rendered,
      file: "docs/index.md",
      url: "index.html",
      title: "Title",
      section: "Start",
    });
    expect(entries.slice(1).map(({ url }) => url)).toEqual(ids.slice(1).map((id) => `index.html#${id}`));
  });

  test("search indexes commands and the end of a long section", () => {
    const fixture =
      "# Title\n## Commands\n" +
      "before ".repeat(800) +
      "\n\n```sh\nexport SOME_SETTING=ready\n```\n\nlate-reference";
    const rendered = renderMarkdown(ctx, "docs/index.md", fixture);
    const [, commands] = searchEntries({
      ...rendered,
      file: "docs/index.md",
      url: "index.html",
      title: "Title",
      section: "Start",
    });
    expect(commands!.text).toContain("export SOME_SETTING=ready");
    expect(commands!.text).toEndWith("late-reference");
  });
});

describe("the documentation site", () => {
  test("every docs/ Markdown file is in the navigation exactly once, and every listed file exists", () => {
    expect(navProblems(nav, root)).toEqual([]);
  });

  test("rendered heading ids are the anchors the docs check resolves", () => {
    const { pages } = renderSite(root);
    for (const page of pages) {
      const expected = anchors(readFileSync(join(root, page.file), "utf8"));
      expect({ file: page.file, ids: page.headings.map((heading) => heading.id).toSorted() }).toEqual({
        file: page.file,
        ids: [...expected].toSorted(),
      });
    }
  });

  test("every internal link resolves to a generated page and anchor", () => {
    const { pages } = renderSite(root);
    const ids = new Map(pages.map((page) => [page.url, new Set(page.headings.map((heading) => heading.id))]));
    const broken: string[] = [];
    for (const page of pages) {
      for (const [, href] of page.html.matchAll(/<a href="([^"]+)"/g)) {
        if (/^[a-z]+:/i.test(href!)) continue;
        const [path, anchor] = href!.replace(/&amp;/g, "&").split("#") as [string, string | undefined];
        const target = path ? new URL(path, `https://site/${page.url}`).pathname.slice(1) : page.url;
        if (!ids.has(target)) broken.push(`${page.file}: ${href}`);
        else if (anchor && !ids.get(target)!.has(decodeURIComponent(anchor)))
          broken.push(`${page.file}: ${href}`);
      }
    }
    expect(broken).toEqual([]);
  });

  test("builds a static site with assets, search index and every page", () => {
    const out = mkdtempSync(join(tmpdir(), "ark-docs-site-"));
    try {
      const result = buildSite(out, root);
      const files = nav.sections.flatMap((section) => section.pages.map((page) => pageUrl(page.file)));
      expect(result.pages).toBe(files.length);
      for (const file of files) expect(existsSync(join(out, file))).toBe(true);
      for (const asset of ["assets/style.css", "assets/site.js", "assets/search-index.js"])
        expect(existsSync(join(out, asset))).toBe(true);
      const home = readFileSync(join(out, "index.html"), "utf8");
      expect(home).toContain('<aside class="sidebar"');
      expect(home).toContain('aria-current="page"');
      const index = readFileSync(join(out, "assets/search-index.js"), "utf8");
      expect(index.startsWith("window.ARK_DOCS_INDEX=")).toBe(true);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });
});

describe("docs output ownership and preview", () => {
  test("rejects source directories, their parents and aliases without touching data", () => {
    const parent = mkdtempSync(join(tmpdir(), "ark-docs-source-"));
    try {
      const checkout = join(parent, "checkout");
      mkdirSync(join(checkout, "docs"), { recursive: true });
      writeFileSync(join(checkout, "docs/index.md"), "source");
      const alias = join(parent, "alias");
      symlinkSync(join(checkout, "docs"), alias, "dir");
      for (const out of [
        parent,
        checkout,
        join(checkout, "docs"),
        join(checkout, "docs/site"),
        join(alias, "new"),
      ])
        expect(() => buildSite(out, checkout)).toThrow("overlaps documentation sources");
      expect(readFileSync(join(checkout, "docs/index.md"), "utf8")).toBe("source");
      expect(existsSync(join(alias, "new"))).toBe(false);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  test("refuses unmarked output and preserves unowned files on later builds", () => {
    const out = mkdtempSync(join(tmpdir(), "ark-docs-output-"));
    try {
      const sentinel = join(out, "unrelated.txt");
      writeFileSync(sentinel, "keep");
      expect(() => buildSite(out, root)).toThrow("has no docs manifest");
      expect(readFileSync(sentinel, "utf8")).toBe("keep");

      const clean = join(out, "site");
      buildSite(clean, root);
      const later = join(clean, "unrelated.html");
      writeFileSync(later, "keep this too");
      buildSite(clean, root);
      expect(readFileSync(later, "utf8")).toBe("keep this too");
      expect(existsSync(join(clean, "index.html"))).toBe(true);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });

  test("rebuild removes obsolete generated pages while keeping files in the same folder", () => {
    const parent = mkdtempSync(join(tmpdir(), "ark-docs-rebuild-"));
    try {
      const checkout = join(parent, "checkout");
      const out = join(checkout, "dist/docs");
      const guide = "docs/guides/temporary.md";
      mkdirSync(join(checkout, "docs/guides"), { recursive: true });
      writeFileSync(join(checkout, "docs/index.md"), "# Home");
      writeFileSync(join(checkout, guide), "# Temporary");
      const manifest = (paths: string[]) => ({
        ...nav,
        sections: [{ title: "Fixture", pages: paths.map((file) => ({ file })) }],
      });
      writeFileSync(join(checkout, "docs/nav.json"), JSON.stringify(manifest(["docs/index.md", guide])));
      buildSite(out, checkout);
      expect(existsSync(join(out, "guides/temporary.html"))).toBe(true);
      writeFileSync(join(out, "guides/keep.txt"), "keep");
      rmSync(join(checkout, guide));
      writeFileSync(join(checkout, "docs/nav.json"), JSON.stringify(manifest(["docs/index.md"])));
      buildSite(out, checkout);
      expect(existsSync(join(out, "guides/temporary.html"))).toBe(false);
      expect(readFileSync(join(out, "guides/keep.txt"), "utf8")).toBe("keep");
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  test("containment distinguishes a child, a sibling with a common prefix, and a dotted filename", () => {
    const out = join(tmpdir(), "ark-docs");
    expect(isWithinDirectory(out, join(out, "guides/intro.html"))).toBe(true);
    expect(isWithinDirectory(out, join(out, "..notes.html"))).toBe(true);
    expect(isWithinDirectory(out, join(tmpdir(), "ark-docs-private", "intro.html"))).toBe(false);
  });

  test("preview serves nested files and handles missing or invalid paths and out-of-root links", async () => {
    const parent = realpathSync(mkdtempSync(join(tmpdir(), "ark-docs-preview-")));
    const out = join(parent, "site");
    mkdirSync(join(out, "nested"), { recursive: true });
    writeFileSync(join(out, "nested/guide.html"), "guide");
    writeFileSync(join(parent, "other.html"), "another fixture");
    symlinkSync(join(parent, "other.html"), join(out, "shortcut.html"));
    const server = servePreview(out, 0);
    try {
      const response = await fetch(new URL("/nested/guide.html", server.url));
      expect(response.status).toBe(200);
      expect(await response.text()).toBe("guide");
      for (const path of ["/nested/", "/missing.html", "/shortcut.html"])
        expect((await fetch(new URL(path, server.url))).status).toBe(404);
      expect((await fetch(new URL("/invalid%", server.url))).status).toBe(400);
    } finally {
      await server.stop(true);
      rmSync(parent, { recursive: true, force: true });
    }
  });
});
