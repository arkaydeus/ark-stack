import { readFileSync } from "node:fs";
import { join } from "node:path";

export type NavPage = { file: string; title?: string };
export type NavSection = { title: string; pages: NavPage[] };
export type Nav = { title: string; repository: string; branch: string; sections: NavSection[] };

export function loadNav(root = join(import.meta.dir, "..", "..")): Nav {
  const nav = JSON.parse(readFileSync(join(root, "docs/nav.json"), "utf8")) as Nav;
  if (!nav.title || !nav.repository || !Array.isArray(nav.sections))
    throw new Error("docs/nav.json is malformed");
  return nav;
}
