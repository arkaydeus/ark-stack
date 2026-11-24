// Merges the Ark entries into a tailnet policy file (HuJSON) for the guided setup's Tailscale API
// key source (scripts/host-setup/tailscale-api.ts).
//
// The merge is additive and textual: it parses the owner's HuJSON with positions, inserts only the
// missing Ark entries (tag owners, the owner-only SSH grant to tag:ark-vps and its `check` rule from
// `sshPolicyExample`) and leaves every other byte, comment and trailing comma where it was. The
// result is re-parsed and compared with the expected policy, so a bad edit is refused, never applied.
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import {
  ARK_BACKUP_TAG,
  ARK_EDGE_TAG,
  ARK_VPS_TAG,
  TAILSCALE_V4,
  TAILSCALE_V6,
  parseHujson,
  parseIpLiteral,
  sshPolicyExample,
  type TailnetGrant,
} from "@ark-stack/shared";

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

type SshRule = { action?: string; src?: string[]; dst?: string[]; users?: string[]; srcPosture?: string[] };
type Policy = {
  tagOwners?: Record<string, string[]>;
  grants?: (TailnetGrant & { srcPosture?: string[]; via?: string[] })[];
  ssh?: SshRule[];
  defaultSrcPosture?: string[];
  acls?: { action?: string; src?: string[]; dst?: string[] }[];
  [key: string]: unknown;
};

function sshEntries() {
  const example = parseHujson(
    sshPolicyExample({ admin: "autogroup:owner", useDefaultCheckPeriod: true }),
  ) as { grants: TailnetGrant[]; ssh: SshRule[] };
  return { grant: example.grants[0]!, rule: example.ssh[0]! };
}

const sameSet = (a: unknown, b: unknown) =>
  Array.isArray(a) &&
  Array.isArray(b) &&
  a.length === b.length &&
  [...a].map(String).toSorted().join("\n") === [...b].map(String).toSorted().join("\n");

function hasGrant(policy: Policy, grant: TailnetGrant) {
  const matches = (policy.grants ?? []).filter(
    (item) => sameSet(item?.src, grant.src) && sameSet(item?.dst, grant.dst) && sameSet(item?.ip, grant.ip),
  );
  if (matches.some((item) => !item.srcPosture?.length && !item.via?.length)) return true;
  if (matches.length) throw sshPolicyConflict("TCP 22 grant", "a source posture or routing restriction");
  return false;
}

function hasSshRule(policy: Policy, rule: SshRule) {
  const matches = (policy.ssh ?? []).filter(
    (item) =>
      sameSet(item?.src, rule.src) && sameSet(item?.dst, rule.dst) && sameSet(item?.users, rule.users),
  );
  if (matches.some((item) => item.action === "check" && !item.srcPosture?.length)) return true;
  if (matches.some((item) => item.srcPosture?.length))
    throw sshPolicyConflict("SSH rule", "a source posture restriction");
  return false;
}

function sshPolicyConflict(entry: string, constraint: string) {
  return new Error(
    `The tailnet policy has ${constraint} on the owner path to tag:ark-vps (${entry}). Review that path in Access controls and use the manual setup flow with a compliant device.`,
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
  if (policy.defaultSrcPosture?.length) {
    throw sshPolicyConflict("TCP 22 grant", "a default source posture restriction");
  }
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

// ---- Catch-all rules -----------------------------------------------------------------------------

/** The Ark identities setup enrols, the internet-facing one first. */
export const ENROLLED_TAGS = [ARK_EDGE_TAG, ARK_VPS_TAG, ARK_BACKUP_TAG] as const;
export type EnrolledTag = (typeof ENROLLED_TAGS)[number];

/** A rule that lets an Ark tag open connections to every device on the tailnet. */
export type CatchAllRule = {
  kind: "grant" | "acl";
  /** The network part of the rule (selectors, ports and conditions), for display. */
  text: string;
  /** The whole rule in a canonical form, so any edit to it changes `rulesDigest`. Never stored or shown. */
  canonical: string;
  /** The Ark tags its source covers. */
  tags: EnrolledTag[];
  /** The same rule with a narrower source, or undefined when no such rule remains. */
  replacement?: string;
  /** The rule covers machines that carry other tags, which a narrower source may leave out. */
  coversOtherTags: boolean;
};

type Fields = Record<string, unknown>;
const isObject = (value: unknown): value is Fields =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Tailscale matches policy keys whatever their case: older policies use "ACLs", "Users" and "Ports". */
function field(object: unknown, ...names: string[]): [key: string, value: unknown] | undefined {
  if (!isObject(object)) return undefined;
  return Object.entries(object).find(([key]) => names.includes(key.toLowerCase()));
}

function strings(value: unknown): string[] {
  const list = Array.isArray(value) ? value : [value];
  return list.filter((item): item is string => typeof item === "string");
}

/** JSON with a space after `:` and `,`, as Tailscale's own policies are written. */
export function inlineJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(inlineJson).join(", ")}]`;
  if (!isObject(value)) return JSON.stringify(value);
  return `{${Object.entries(value)
    .map(([key, item]) => `${JSON.stringify(key)}: ${inlineJson(item)}`)
    .join(", ")}}`;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!isObject(value)) return JSON.stringify(value) ?? "null";
  return `{${Object.keys(value)
    .toSorted()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

type AddressRange = { version: 4 | 6; first: bigint; last: bigint };

function addressNumber(text: string) {
  const parsed = parseIpLiteral(text);
  if (!parsed) return undefined;
  let value = 0n;
  for (const byte of parsed.bytes) value = (value << 8n) | BigInt(byte);
  return { version: parsed.version, value };
}

/** An address, CIDR or `first-last` range. Anything else (tags, groups, IP sets) is undefined. */
function addressRange(selector: string): AddressRange | undefined {
  const [start = "", end, extra] = selector.split("-");
  if (end !== undefined) {
    const first = addressNumber(start);
    const last = addressNumber(end);
    if (extra !== undefined || !first || !last || first.version !== last.version) return undefined;
    return { version: first.version, first: first.value, last: last.value };
  }
  const [network = "", bits] = selector.split("/");
  const base = addressNumber(network);
  if (!base) return undefined;
  const width = base.version === 4 ? 32 : 128;
  if (bits !== undefined && !/^\d{1,3}$/.test(bits)) return undefined;
  const prefix = bits === undefined ? width : Number(bits);
  if (prefix > width) return undefined;
  const size = 1n << BigInt(width - prefix);
  const first = (base.value / size) * size;
  return { version: base.version, first, last: first + size - 1n };
}

/** Every address Tailscale assigns to devices; a rule covers every device through either family. */
const TAILNET_RANGES = [TAILSCALE_V4, TAILSCALE_V6].map((cidr) => addressRange(cidr)!);

/** The selectors whose ranges together cover the whole tailnet. Host aliases are followed. */
function tailnetWideRanges(policy: unknown, selectors: string[]) {
  const hosts = field(policy, "hosts")?.[1];
  const ranges = selectors.flatMap((selector) => {
    const alias = isObject(hosts) && Object.hasOwn(hosts, selector) ? hosts[selector] : selector;
    const range = addressRange(typeof alias === "string" ? alias : selector);
    return range ? [{ selector, ...range }] : [];
  });
  const found = new Set<string>();
  for (const tailnet of TAILNET_RANGES) {
    const inside = ranges
      .filter(
        (range) =>
          range.version === tailnet.version && range.first <= tailnet.last && range.last >= tailnet.first,
      )
      .toSorted((a, b) => (a.first < b.first ? -1 : a.first > b.first ? 1 : 0));
    let next = tailnet.first;
    for (const range of inside) {
      if (range.first > next) break;
      if (range.last >= next) next = range.last + 1n;
    }
    if (next > tailnet.last) for (const range of inside) found.add(range.selector);
  }
  return found;
}

function everyDevice(policy: unknown, destinations: string[]) {
  if (destinations.includes("*")) return true;
  // Every device belongs to a member or carries a tag.
  if (
    destinations.includes("autogroup:tagged") &&
    destinations.some((selector) => /^autogroup:members?$/.test(selector))
  )
    return true;
  return tailnetWideRanges(policy, destinations).size > 0;
}

/** Selectors that cover every Ark tag among others. */
const WIDE_SOURCES = new Set(["*", "autogroup:danger-all", "autogroup:tagged"]);
/** The parts of a rule that decide who may connect where; an `app` value can hold anything. */
const SHOWN_FIELDS = new Set(["action", "src", "users", "proto", "dst", "ports", "ip", "via", "srcposture"]);

function catchAllRule(
  policy: unknown,
  kind: CatchAllRule["kind"],
  rule: unknown,
  destinations: string[],
): CatchAllRule | undefined {
  const source = field(rule, "src", "users");
  if (!source || !everyDevice(policy, destinations)) return undefined;
  const sources = strings(source[1]);
  const ranges = tailnetWideRanges(policy, sources);
  const wide = sources.filter((selector) => WIDE_SOURCES.has(selector) || ranges.has(selector));
  const tags = ENROLLED_TAGS.filter((tag) => wide.length || sources.includes(tag));
  if (!tags.length) return undefined;
  const isArkTag = (selector: string) => (ENROLLED_TAGS as readonly string[]).includes(selector);
  const kept = sources.filter((selector) => !wide.includes(selector) && !isArkTag(selector));
  const everyone = wide.some((selector) => selector !== "autogroup:tagged");
  if (everyone && !kept.includes("autogroup:member")) kept.unshift("autogroup:member");
  const shown = Object.entries(rule as Fields).filter(([key]) => SHOWN_FIELDS.has(key.toLowerCase()));
  const narrowed = shown.map(([key, value]) => [key, key === source[0] ? kept : value] as const);
  return {
    kind,
    text: inlineJson(Object.fromEntries(shown)),
    canonical: `${kind} ${canonicalJson(rule)}`,
    tags,
    replacement: kept.length ? inlineJson(Object.fromEntries(narrowed)) : undefined,
    coversOtherTags: wide.length > 0,
  };
}

/**
 * The grants and accept ACLs that let an Ark tag open connections to every device. Reported, never
 * edited. Not a policy evaluator: IP sets, posture conditions and `via` are not evaluated (a rule
 * with a condition still counts), and rules are judged one at a time.
 */
export function catchAllRules(policy: unknown): CatchAllRule[] {
  const found: (CatchAllRule | undefined)[] = [];
  const list = (name: string) => {
    const value = field(policy, name)?.[1];
    return Array.isArray(value) ? value : [];
  };
  for (const grant of list("grants")) {
    // Application capabilities alone open no connection (grants without `ip` need network access first).
    if (!strings(field(grant, "ip")?.[1]).length && isObject(field(grant, "app")?.[1])) continue;
    found.push(catchAllRule(policy, "grant", grant, strings(field(grant, "dst")?.[1])));
  }
  for (const acl of list("acls")) {
    if (!strings(field(acl, "action")?.[1]).some((action) => /^(?:accept|allow)$/i.test(action))) continue;
    const destinations = strings(field(acl, "dst", "ports")?.[1]).map((entry) =>
      entry.slice(0, entry.includes(":") ? entry.lastIndexOf(":") : undefined).replace(/^\[|\]$/g, ""),
    );
    found.push(catchAllRule(policy, "acl", acl, destinations));
  }
  return found.filter((rule) => rule !== undefined);
}

/** Identifies a set of rules, whatever their order. Any change to one of them changes it. */
export function rulesDigest(rules: CatchAllRule[]) {
  return createHash("sha256")
    .update(
      rules
        .map((rule) => rule.canonical)
        .toSorted()
        .join("\n"),
    )
    .digest("hex");
}

export type PolicyMerge = {
  text: string;
  changed: boolean;
  /** One line per Ark entry added. */
  additions: string[];
  /** The text added, with line numbers. The merge only inserts, so this is the whole change. */
  inserted: string[];
  /** The owner's rules that let an Ark tag reach every device. Setup never changes them. */
  catchAll: CatchAllRule[];
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
  return {
    text: edits.length ? merged : text,
    changed: edits.length > 0,
    additions: lines,
    inserted: insertedLines(source, edits),
    catchAll: catchAllRules(policy),
  };
}

/** The inserted text only, so the owner's own policy content is neither shown nor logged. */
function insertedLines(text: string, edits: Edit[]) {
  const out: string[] = [];
  let added = 0;
  for (const edit of edits.toSorted((a, b) => a.at - b.at)) {
    const breaks = edit.text.split("\n").length - 1;
    // A comma after the owner's last entry.
    if (edit.text.trim() !== ",") {
      const own = edit.text.replace(/^,?\n/, "");
      const line = text.slice(0, edit.at).split("\n").length + added + (own === edit.text ? 0 : 1);
      out.push(`@@ line ${line}`);
      for (const item of own.trimEnd().split("\n")) out.push(`+ ${item}`);
    }
    added += breaks;
  }
  return out;
}
