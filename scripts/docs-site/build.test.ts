import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
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
  type RenderContext,
} from "./build.ts";

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
