// Merges the Ark entries into a tailnet policy file (HuJSON) for the guided setup's Tailscale API
// key source (scripts/host-setup/tailscale-api.ts).
//
// The merge is additive and textual: it parses the owner's HuJSON with positions, inserts only the
// missing Ark entries (tag owners, the owner-only SSH grant to tag:ark-vps and its `check` rule from
// `sshPolicyExample`) and leaves every other byte, comment and trailing comma where it was. The
// result is re-parsed and compared with the expected policy, so a bad edit is refused, never applied.
import { isDeepStrictEqual } from "node:util";

import { ARK_VPS_TAG, parseHujson, sshPolicyExample, type TailnetGrant } from "@ark-stack/shared";

type Span = { start: number; end: number };
type JsonNode =
  | (Span & { kind: "object"; members: { key: string; keyStart: number; value: JsonNode }[] })
  | (Span & { kind: "array"; items: JsonNode[] })
  | (Span & { kind: "value" });

class HujsonScanner {
  index = 0;
  constructor(readonly text: string) {}

  skip() {
    const text = this.text;
    for (;;) {
      const char = text[this.index];
      if (char === " " || char === "\t" || char === "\n" || char === "\r") this.index++;
      else if (char === "/" && text[this.index + 1] === "/") {
        const end = text.indexOf("\n", this.index);
        this.index = end < 0 ? text.length : end;
      } else if (char === "/" && text[this.index + 1] === "*") {
        const end = text.indexOf("*/", this.index + 2);
        if (end < 0) throw new Error("The tailnet policy has an unterminated comment.");
        this.index = end + 2;
      } else return;
    }
  }

  fail(what: string): never {
    throw new Error(`The tailnet policy is not valid HuJSON: ${what} at offset ${this.index}.`);
  }

  string() {
    const start = this.index;
    if (this.text[start] !== '"') this.fail("expected a string");
    let index = start + 1;
    while (index < this.text.length && this.text[index] !== '"') index += this.text[index] === "\\" ? 2 : 1;
    if (index >= this.text.length) this.fail("unterminated string");
    this.index = index + 1;
    return { start, end: this.index, value: JSON.parse(this.text.slice(start, this.index)) as string };
  }

  value(): JsonNode {
    this.skip();
    const start = this.index;
    const char = this.text[start];
    if (char === "{") {
      this.index++;
      const members: { key: string; keyStart: number; value: JsonNode }[] = [];
      for (;;) {
        this.skip();
        if (this.text[this.index] === "}") break;
        const key = this.string();
        this.skip();
        if (this.text[this.index] !== ":") this.fail('expected ":"');
        this.index++;
        members.push({ key: key.value, keyStart: key.start, value: this.value() });
        this.skip();
        if (this.text[this.index] === ",") this.index++;
        else if (this.text[this.index] !== "}") this.fail('expected "," or "}"');
      }
      this.index++;
      return { kind: "object", start, end: this.index, members };
    }
    if (char === "[") {
      this.index++;
      const items: JsonNode[] = [];
      for (;;) {
        this.skip();
        if (this.text[this.index] === "]") break;
        items.push(this.value());
        this.skip();
        if (this.text[this.index] === ",") this.index++;
        else if (this.text[this.index] !== "]") this.fail('expected "," or "]"');
      }
      this.index++;
      return { kind: "array", start, end: this.index, items };
    }
    if (char === '"') {
      const { end } = this.string();
      return { kind: "value", start, end };
    }
    const match = /^[^\s,\]}/]+/.exec(this.text.slice(start));
    if (!match) this.fail("expected a value");
    this.index += match[0].length;
    return { kind: "value", start, end: this.index };
  }

  document() {
    const root = this.value();
    this.skip();
    if (this.index !== this.text.length) this.fail("unexpected content after the policy");
    return root;
  }
}

// ---- Text edits ---------------------------------------------------------------------------------

type Edit = { at: number; text: string };

function lineStart(text: string, at: number) {
  return text.lastIndexOf("\n", at - 1) + 1;
}

function lineIndent(text: string, at: number) {
  return /^[ \t]*/.exec(text.slice(lineStart(text, at)))![0];
}

function startsLine(text: string, at: number) {
  return /^[ \t]*$/.test(text.slice(lineStart(text, at), at));
}

/** The next significant character after `at`, skipping whitespace and comments. */
function nextSignificant(text: string, at: number) {
  const scanner = new HujsonScanner(text);
  scanner.index = at;
  scanner.skip();
  return scanner.index;
}

/** The end of this line when only whitespace or a line comment follows `at`; otherwise `at`. */
function lineEndAfter(text: string, at: number) {
  let index = at;
  while (text[index] === " " || text[index] === "\t") index++;
  if (text.startsWith("//", index)) {
    const end = text.indexOf("\n", index);
    return end < 0 ? text.length : end;
  }
  if (index >= text.length || text[index] === "\n" || text[index] === "\r") return index;
  return at;
}

function indentBlock(entry: string, indent: string) {
  return entry.split("\n").join(`\n${indent}`);
}

/** Appends rendered entries (array items or `"key": value` members) to a container. */
function appendEntries(text: string, container: JsonNode, entries: string[], unit: string): Edit[] {
  if (container.kind === "value" || !entries.length) return [];
  const outer = lineIndent(text, container.start);
  const items =
    container.kind === "object"
      ? container.members.map((member) => ({ start: member.keyStart, end: member.value.end }))
      : container.items.map((item) => ({ start: item.start, end: item.end }));
  if (!items.length) {
    const inner = outer + unit;
    return [
      {
        at: container.start + 1,
        text: `${entries.map((entry) => `\n${inner}${indentBlock(entry, inner)}`).join(",")}\n${outer}`,
      },
    ];
  }
  const last = items.at(-1)!;
  const next = nextSignificant(text, last.end);
  const comma = text[next] === ",";
  const close = comma ? nextSignificant(text, next + 1) : next;
  if (!text.slice(last.end, close).includes("\n")) {
    // A one-line container, such as a tag's owner list: append inline.
    if (comma) return [{ at: next + 1, text: entries.map((entry) => ` ${entry},`).join("") }];
    return [{ at: last.end, text: entries.map((entry) => `, ${entry}`).join("") }];
  }
  const inner = startsLine(text, items[0]!.start) ? lineIndent(text, items[0]!.start) : outer + unit;
  const rendered = entries.map((entry) => `\n${inner}${indentBlock(entry, inner)}`);
  if (comma)
    return [{ at: lineEndAfter(text, next + 1), text: rendered.map((entry) => `${entry},`).join("") }];
  const at = lineEndAfter(text, last.end);
  if (at === last.end) return [{ at, text: `,${rendered.join(",")}` }];
  return [
    { at: last.end, text: "," },
    { at, text: rendered.join(",") },
  ];
}

function applyEdits(text: string, edits: Edit[]) {
  let out = text;
  for (const edit of edits.toSorted((a, b) => b.at - a.at)) {
    out = out.slice(0, edit.at) + edit.text + out.slice(edit.at);
  }
  return out;
}

/** Renders a JSON value the way the generated snippets do: short objects and scalar lists inline. */
export function renderValue(value: unknown, unit = "  "): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    if (value.every((item) => item === null || typeof item !== "object")) {
      return `[${value.map((item) => JSON.stringify(item)).join(", ")}]`;
    }
    return `[\n${value.map((item) => `${unit}${indentBlock(renderValue(item, unit), unit)},`).join("\n")}\n]`;
  }
  const entries = Object.entries(value as Record<string, unknown>);
  const inline = `{ ${entries.map(([key, item]) => `${JSON.stringify(key)}: ${renderValue(item, unit)}`).join(", ")} }`;
  if (!inline.includes("\n") && inline.length <= 96) return inline;
  return `{\n${entries
    .map(([key, item]) => `${unit}${JSON.stringify(key)}: ${indentBlock(renderValue(item, unit), unit)},`)
    .join("\n")}\n}`;
}

// ---- The Ark entries ----------------------------------------------------------------------------

export type ArkPolicyRequest = {
  /** The Ark tags the setup will mint keys for. */
  tags: string[];
  /** Owners written for a tag the policy does not declare yet. */
  owners: string[];
  /**
   * An owner every Ark tag must include, even when the owner already declared the tag: the tag of
   * the OAuth client, which may only mint keys for tags it owns.
   */
  requiredOwner?: string;
};

type SshRule = { action?: string; src?: string[]; dst?: string[]; users?: string[] };
type Policy = {
  tagOwners?: Record<string, string[]>;
  grants?: TailnetGrant[];
  ssh?: SshRule[];
  acls?: { action?: string; src?: string[]; dst?: string[] }[];
  [key: string]: unknown;
};

function sshEntries() {
  const example = parseHujson(sshPolicyExample()) as { grants: TailnetGrant[]; ssh: SshRule[] };
  return { grant: example.grants[0]!, rule: example.ssh[0]! };
}

const sameSet = (a: unknown, b: unknown) =>
  Array.isArray(a) &&
  Array.isArray(b) &&
  a.length === b.length &&
  [...a].map(String).toSorted().join("\n") === [...b].map(String).toSorted().join("\n");

function hasGrant(policy: Policy, grant: TailnetGrant) {
  return (policy.grants ?? []).some(
    (item) => sameSet(item?.src, grant.src) && sameSet(item?.dst, grant.dst) && sameSet(item?.ip, grant.ip),
  );
}

function hasSshRule(policy: Policy, rule: SshRule) {
  return (policy.ssh ?? []).some(
    (item) =>
      (item?.action === "check" || item?.action === "accept") &&
      sameSet(item.src, rule.src) &&
      sameSet(item.dst, rule.dst) &&
      sameSet(item.users, rule.users),
  );
}

/** The Ark additions for `policy`, as plain values: what is missing and where it goes. */
function plannedAdditions(policy: Policy, request: ArkPolicyRequest) {
  const tagOwners = policy.tagOwners ?? {};
  const newTags: Record<string, string[]> = {};
  const newOwners: Record<string, string[]> = {};
  const tags = [...request.tags];
  if (request.requiredOwner && !tags.includes(request.requiredOwner)) tags.unshift(request.requiredOwner);
  for (const tag of tags) {
    const isClientTag = tag === request.requiredOwner;
    const wanted = isClientTag
      ? request.owners
      : [...request.owners, ...(request.requiredOwner ? [request.requiredOwner] : [])];
    const existing = tagOwners[tag];
    if (!Array.isArray(existing)) newTags[tag] = [...new Set(wanted)];
    else if (!isClientTag && request.requiredOwner && !existing.includes(request.requiredOwner)) {
      newOwners[tag] = [request.requiredOwner];
    }
  }
  const { grant, rule } = sshEntries();
  return {
    newTags,
    newOwners,
    grant: hasGrant(policy, grant) ? undefined : grant,
    rule: hasSshRule(policy, rule) ? undefined : rule,
  };
}

function expectedPolicy(policy: Policy, additions: ReturnType<typeof plannedAdditions>) {
  const next: Policy = structuredClone(policy);
  if (Object.keys(additions.newTags).length || Object.keys(additions.newOwners).length) {
    next.tagOwners = { ...next.tagOwners };
    for (const [tag, owners] of Object.entries(additions.newOwners))
      next.tagOwners[tag] = [...next.tagOwners[tag]!, ...owners];
    Object.assign(next.tagOwners, additions.newTags);
  }
  if (additions.grant) next.grants = [...(next.grants ?? []), additions.grant];
  if (additions.rule) next.ssh = [...(next.ssh ?? []), additions.rule];
  return next;
}

/** Catch-all rules that would let the Ark identities reach every device. Reported, never edited. */
export function catchAllRules(policy: Policy) {
  const found: string[] = [];
  for (const grant of policy.grants ?? []) {
    if (grant?.src?.includes("*") && grant.dst?.includes("*"))
      found.push(`grant ${JSON.stringify({ src: grant.src, dst: grant.dst, ip: grant.ip })}`);
  }
  for (const acl of policy.acls ?? []) {
    if (acl?.action === "accept" && acl.src?.includes("*") && acl.dst?.some((dst) => dst.startsWith("*:")))
      found.push(`acl ${JSON.stringify({ action: acl.action, src: acl.src, dst: acl.dst })}`);
  }
  return found;
}

export type PolicyMerge = {
  text: string;
  changed: boolean;
  /** One line per Ark entry added. */
  additions: string[];
  /** Owner content the setup does not change but the owner should review. */
  warnings: string[];
};

/** Adds the missing Ark entries to the owner's HuJSON policy, preserving everything else. */
export function mergeArkPolicy(text: string, request: ArkPolicyRequest): PolicyMerge {
  const source = text.trim() ? text : "{}\n";
  const root = new HujsonScanner(source).document();
  if (root.kind !== "object") throw new Error("The tailnet policy is not a JSON object.");
  const policy = parseHujson(source) as Policy;
  for (const key of ["tagOwners", "grants", "ssh"] as const) {
    const member = root.members.find((item) => item.key === key);
    const expected = key === "tagOwners" ? "object" : "array";
    if (member && member.value.kind !== expected)
      throw new Error(
        `The tailnet policy's "${key}" is not ${expected === "object" ? "an object" : "a list"}.`,
      );
  }
  const additions = plannedAdditions(policy, request);
  const firstMember = root.members[0];
  const unit =
    firstMember && startsLine(source, firstMember.keyStart) && lineIndent(source, firstMember.keyStart)
      ? lineIndent(source, firstMember.keyStart)
      : "  ";
  const member = (key: string) => root.members.find((item) => item.key === key)?.value;
  const edits: Edit[] = [];
  const topLevel: string[] = [];
  const lines: string[] = [];

  const tagEntries = Object.entries(additions.newTags);
  const tagOwners = member("tagOwners");
  if (tagEntries.length) {
    const rendered = tagEntries.map(
      ([tag, owners]) => `${JSON.stringify(tag)}: ${renderValue(owners, unit)}`,
    );
    if (tagOwners) edits.push(...appendEntries(source, tagOwners, rendered, unit));
    else topLevel.push(`"tagOwners": ${renderValue(additions.newTags, unit)}`);
    for (const [tag, owners] of tagEntries)
      lines.push(`tagOwners: declare ${tag}, owned by ${owners.join(", ")}`);
  }
  if (tagOwners?.kind === "object") {
    for (const [tag, owners] of Object.entries(additions.newOwners)) {
      const list = tagOwners.members.find((item) => item.key === tag)?.value;
      if (list)
        edits.push(
          ...appendEntries(
            source,
            list,
            owners.map((owner) => JSON.stringify(owner)),
            unit,
          ),
        );
      lines.push(`tagOwners: add ${owners.join(", ")} as an owner of ${tag}`);
    }
  }
  for (const [key, value, line] of [
    ["grants", additions.grant, `grants: the owner-only TCP 22 grant to ${ARK_VPS_TAG}`],
    ["ssh", additions.rule, `ssh: the owner-only Tailscale SSH rule to ${ARK_VPS_TAG} (check mode)`],
  ] as const) {
    if (!value) continue;
    const container = member(key);
    if (container) edits.push(...appendEntries(source, container, [renderValue(value, unit)], unit));
    else topLevel.push(`${JSON.stringify(key)}: ${renderValue([value], unit)}`);
    lines.push(line);
  }
  if (topLevel.length) edits.push(...appendEntries(source, root, topLevel, unit));

  const merged = applyEdits(source, edits);
  const expected = expectedPolicy(policy, additions);
  if (!isDeepStrictEqual(parseHujson(merged), expected)) {
    throw new Error(
      "Could not merge the Ark entries into the tailnet policy without changing other content.",
    );
  }
  const warnings = catchAllRules(policy).map(
    (rule) =>
      `Your policy has a catch-all ${rule}. It lets tag:ark-edge and tag:ark-backup reach every device; narrow it before you create routes (docs/operating.md#tailnet-policy-snippet).`,
  );
  return { text: edits.length ? merged : text, changed: edits.length > 0, additions: lines, warnings };
}

// ---- Diff -----------------------------------------------------------------------------------------

/** A unified-style line diff (`+` added, `-` removed, two lines of context). */
export function lineDiff(before: string, after: string, context = 2): string[] {
  const a = before.split("\n");
  const b = after.split("\n");
  let prefix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix++;
  let suffix = 0;
  while (
    suffix < a.length - prefix &&
    suffix < b.length - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]
  )
    suffix++;
  const midA = a.slice(prefix, a.length - suffix);
  const midB = b.slice(prefix, b.length - suffix);
  const ops: { op: " " | "+" | "-"; line: string; at: number }[] = [];
  for (let index = 0; index < prefix; index++) ops.push({ op: " ", line: a[index]!, at: index + 1 });
  for (const item of middleOps(midA, midB)) ops.push({ ...item, at: prefix + item.at + 1 });
  for (let index = a.length - suffix; index < a.length; index++)
    ops.push({ op: " ", line: a[index]!, at: index - a.length + b.length + 1 });
  const shown = new Set<number>();
  ops.forEach((item, index) => {
    if (item.op === " ") return;
    for (let k = Math.max(0, index - context); k <= Math.min(ops.length - 1, index + context); k++)
      shown.add(k);
  });
  const out: string[] = [];
  let previous = -2;
  for (const index of [...shown].toSorted((x, y) => x - y)) {
    if (index !== previous + 1) out.push(`@@ line ${ops[index]!.at}`);
    out.push(`${ops[index]!.op} ${ops[index]!.line}`);
    previous = index;
  }
  return out;
}

/** The changed middle as operations; `at` is the index in `b`. */
function middleOps(a: string[], b: string[]) {
  const ops: { op: " " | "+" | "-"; line: string; at: number }[] = [];
  let i = 0;
  let j = 0;
  if (a.length * b.length <= 4_000_000) {
    // Longest common subsequence (the merge only inserts, so the middle is usually small).
    const table = Array.from({ length: a.length + 1 }, () => new Int32Array(b.length + 1));
    for (let x = a.length - 1; x >= 0; x--)
      for (let y = b.length - 1; y >= 0; y--)
        table[x]![y] =
          a[x] === b[y] ? table[x + 1]![y + 1]! + 1 : Math.max(table[x + 1]![y]!, table[x]![y + 1]!);
    while (i < a.length || j < b.length) {
      if (i < a.length && j < b.length && a[i] === b[j]) ops.push({ op: " ", line: a[i++]!, at: j++ });
      else if (j < b.length && (i >= a.length || table[i]![j + 1]! >= table[i + 1]![j]!))
        ops.push({ op: "+", line: b[j]!, at: j++ });
      else ops.push({ op: "-", line: a[i++]!, at: j });
    }
    return ops;
  }
  // A very large policy: match each old line to its next occurrence (exact for pure insertions).
  while (i < a.length) {
    const found = b.indexOf(a[i]!, j);
    if (found < 0) {
      ops.push({ op: "-", line: a[i++]!, at: j });
      continue;
    }
    while (j < found) ops.push({ op: "+", line: b[j]!, at: j++ });
    ops.push({ op: " ", line: a[i++]!, at: j++ });
  }
  while (j < b.length) ops.push({ op: "+", line: b[j]!, at: j++ });
  return ops;
}
