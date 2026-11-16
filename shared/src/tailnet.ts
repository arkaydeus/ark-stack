// Front-door upstream allowlist (SSRF guard), docs/design/front-door.md §3.2.
//
// A public route may only point at a Tailscale peer that the edge node observed in its latest
// complete netmap snapshot. Targets resolve against that snapshot, never against DNS, and every
// failure is closed: when in doubt, the route is not rendered.

import { ipv4ToInt, parseIpv6, prefixMatch } from "./cidr.ts";
import { normalizeHostname } from "./hostnames.ts";

export const TAILSCALE_V4 = "100.64.0.0/10";
export const TAILSCALE_V6 = "fd7a:115c:a1e0::/48";
// Quad-100 service IP, the ChromeOS range Tailscale avoids, and quad-100's IPv6 service address.
const RESERVED = ["100.100.100.100/32", "100.115.92.0/23", "fd7a:115c:a1e0::53/128"];

/** Tags of the VPS's own nodes. They are always forbidden, whatever the caller passes. */
export const FORBIDDEN_TARGET_TAGS = ["tag:ark-edge", "tag:ark-stack-admin", "tag:ark-vps", "tag:ark-backup"];
/** Ports that need `allowSensitivePort` (plus an `exposure.public` step-up at the API). */
export const SENSITIVE_TARGET_PORTS = [22, 2019, 2375, 2376, 3389, 5900];
/** `edge.observe` runs every 5 minutes; a snapshot is valid for 6 minutes after completion. */
export const SNAPSHOT_VALIDITY_MS = 6 * 60_000;

export type TailnetSource = "edge" | "backup";

/** One row of `tailnet_nodes`. */
export type TailnetNode = {
  source: TailnetSource;
  generation: string;
  stableId: string;
  dnsName: string;
  hostName: string;
  ipv4: string | null;
  ipv6: string | null;
  tags: string[];
  isSelf: boolean;
  online: boolean | null;
};

/** One row of `tailnet_snapshots`; null fields (or no row) mean the snapshot is incomplete. */
export type TailnetSnapshot = {
  source: TailnetSource;
  generation: string;
  completedAt: string | null;
  validUntil: string | null;
};

export type RouteTargetRejection =
  | "snapshot_incomplete"
  | "snapshot_expired"
  | "source_mismatch"
  | "invalid_target"
  | "outside_tailnet_range"
  | "reserved_address"
  | "peer_not_found"
  | "ambiguous_peer"
  | "stale_generation"
  | "peer_without_address"
  | "forbidden_peer"
  | "forbidden_tag"
  | "invalid_port"
  | "sensitive_port";

type Rejected = { ok: false; reason: RouteTargetRejection; message: string };

type SnapshotInput = {
  peers: TailnetNode[];
  snapshot: TailnetSnapshot | null;
  now: string | Date;
  self: TailnetNode | null;
  forbiddenTags?: string[];
  tailnetSuffix: string;
  /** The observation source this caller trusts. Routes use `edge`. */
  source?: TailnetSource;
};

export type RouteTargetInput = SnapshotInput & {
  target: string;
  port: number;
  allowSensitivePort?: boolean;
};

export type RouteTargetResult = { ok: true; stableId: string; ip: string } | Rejected;

export type ParsedIp = { version: 4 | 6; bytes: Uint8Array; canonical: string };

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const IPV6_CHARS = /^[0-9a-f:]+$/i;

function reject(reason: RouteTargetRejection, message: string): Rejected {
  return { ok: false, reason, message };
}

/** Parses a bare IP literal (no brackets, zone, port or prefix) into a canonical form. */
export function parseIpLiteral(value: string): ParsedIp | null {
  if (IPV4.test(value)) {
    const int = ipv4ToInt(value);
    const bytes = new Uint8Array([int >>> 24, (int >>> 16) & 0xff, (int >>> 8) & 0xff, int & 0xff]);
    return { version: 4, bytes, canonical: value };
  }
  if (!IPV6_CHARS.test(value) || !value.includes(":")) return null;
  const bytes = parseIpv6(value);
  return bytes ? { version: 6, bytes, canonical: formatIpv6(bytes) } : null;
}

/** RFC 5952 text form: lowercase, no leading zeros, the longest zero run (2+ groups) as `::`. */
function formatIpv6(bytes: Uint8Array) {
  const groups = Array.from({ length: 8 }, (_, i) => ((bytes[i * 2] ?? 0) << 8) | (bytes[i * 2 + 1] ?? 0));
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = groups.map((group) => group.toString(16));
  if (bestLength < 2) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLength).join(":")}`;
}

function inCidr(ip: ParsedIp, cidr: string) {
  const [network, bits] = cidr.split("/");
  const parsed = parseIpLiteral(network ?? "");
  return parsed?.version === ip.version && prefixMatch(ip.bytes, parsed.bytes, Number(bits));
}

/** Range rule (§3.2 rule 2): inside the Tailscale CGNAT or ULA range, and not reserved. */
export function checkTailnetAddress(ip: ParsedIp): Rejected | null {
  if (!inCidr(ip, ip.version === 4 ? TAILSCALE_V4 : TAILSCALE_V6)) {
    return reject(
      "outside_tailnet_range",
      `${ip.canonical} is not a Tailscale address (${TAILSCALE_V4} or ${TAILSCALE_V6}).`,
    );
  }
  if (RESERVED.some((cidr) => inCidr(ip, cidr))) {
    return reject(
      "reserved_address",
      `${ip.canonical} is reserved by Tailscale and cannot be a route target.`,
    );
  }
  return null;
}

function normalizeName(value: string) {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

function normalizeSuffix(value: string) {
  const name = normalizeName(value);
  return name.startsWith(".") ? name : `.${name}`;
}

function nodeAddresses(node: TailnetNode) {
  return [node.ipv4, node.ipv6]
    .map((value) => (value ? parseIpLiteral(value.trim()) : null))
    .filter((value): value is ParsedIp => value !== null);
}

function parseTime(value: string | Date | null | undefined) {
  if (value === null || value === undefined || value === "") return Number.NaN;
  return value instanceof Date ? value.getTime() : Date.parse(value);
}

/**
 * Checks that the snapshot is complete, unexpired and from one source, then returns the nodes of
 * that source (self included) for identity matching.
 */
function checkSnapshot(input: SnapshotInput): Rejected | { nodes: TailnetNode[]; self: TailnetNode } {
  const { snapshot, self } = input;
  const source = input.source ?? "edge";
  if (!snapshot || !snapshot.generation) {
    return reject("snapshot_incomplete", "No complete tailnet observation is available yet.");
  }
  if (snapshot.source !== source) {
    return reject("source_mismatch", `Expected a ${source} observation, got ${snapshot.source}.`);
  }
  const now = parseTime(input.now);
  const completedAt = parseTime(snapshot.completedAt);
  const validUntil = parseTime(snapshot.validUntil);
  if (
    !Number.isFinite(now) ||
    !Number.isFinite(completedAt) ||
    !Number.isFinite(validUntil) ||
    validUntil <= completedAt ||
    validUntil - completedAt > SNAPSHOT_VALIDITY_MS ||
    completedAt > now
  ) {
    return reject("snapshot_incomplete", "The tailnet observation is incomplete or has an invalid lease.");
  }
  if (now >= validUntil) {
    return reject("snapshot_expired", "The tailnet observation has expired. Run a new observation.");
  }
  const all = self ? [self, ...input.peers] : input.peers;
  if (all.some((node) => node.source !== source)) {
    return reject("source_mismatch", "Tailnet observations from different sources cannot be mixed.");
  }
  if (!self || !self.isSelf || self.generation !== snapshot.generation || !self.stableId) {
    return reject("snapshot_incomplete", "The observation does not include the edge node itself.");
  }
  const suffix = normalizeSuffix(input.tailnetSuffix);
  if (suffix.split(".").length < 3 || !normalizeName(self.dnsName).endsWith(suffix)) {
    return reject("snapshot_incomplete", "The tailnet DNS suffix does not match the edge node's name.");
  }
  const nodes = input.peers.filter((peer) => peer.stableId !== self.stableId);
  return { nodes: [self, ...nodes], self };
}

type ParsedTarget = { kind: "ip"; ip: ParsedIp } | { kind: "name"; name: string };

/** Syntax rule (§3.2 rule 1): an IP literal, or a lowercase FQDN ending in the MagicDNS suffix. */
function parseTarget(target: string, tailnetSuffix: string): ParsedTarget | Rejected {
  const invalid = reject(
    "invalid_target",
    "Enter a Tailscale IP or a MagicDNS name such as home.tail1234.ts.net, without a scheme, port or path.",
  );
  if (typeof target !== "string" || !target || target !== target.trim()) return invalid;
  const ip = parseIpLiteral(target);
  if (ip) return { kind: "ip", ip };
  const name = target.endsWith(".") ? target.slice(0, -1) : target;
  // Lowercase letters, digits, dots and hyphens only: no userinfo, scheme, port, path or brackets.
  if (!/^[a-z0-9.-]+$/.test(name) || /^[\d.]+$/.test(name)) return invalid;
  const suffix = normalizeSuffix(tailnetSuffix);
  if (!name.endsWith(suffix) || name.length === suffix.length) return invalid;
  try {
    if (normalizeHostname(name) !== name) return invalid;
  } catch {
    return invalid;
  }
  return { kind: "name", name };
}

function matches(node: TailnetNode, target: ParsedTarget) {
  if (target.kind === "name") return normalizeName(node.dnsName) === target.name;
  return nodeAddresses(node).some((address) => address.canonical === target.ip.canonical);
}

function forbiddenNode(node: TailnetNode, self: TailnetNode, forbiddenTags: string[] = []): Rejected | null {
  if (node.isSelf || node.stableId === self.stableId) {
    return reject("forbidden_peer", "The edge node itself cannot be a route target.");
  }
  const forbidden = new Set([...FORBIDDEN_TARGET_TAGS, ...forbiddenTags]);
  const tag = node.tags.find((item) => forbidden.has(item));
  if (tag)
    return reject("forbidden_tag", `Peers tagged ${tag} belong to the platform and cannot be exposed.`);
  return null;
}

/** Picks the peer address to pin: the preferred family when it is a valid target, else any valid one. */
function pickAddress(node: TailnetNode, preferVersion: 4 | 6 = 4) {
  const valid = nodeAddresses(node).filter((address) => !checkTailnetAddress(address));
  return valid.find((address) => address.version === preferVersion) ?? valid[0] ?? null;
}

/**
 * Validates a new route target (§3.2 rules 1-5). On success, returns the peer's StableID and the
 * address to pin; only that address is ever rendered.
 */
export function validateRouteTarget(input: RouteTargetInput): RouteTargetResult {
  const observed = checkSnapshot(input);
  if ("ok" in observed) return observed;

  const target = parseTarget(input.target, input.tailnetSuffix);
  if ("ok" in target) return target;

  if (target.kind === "ip") {
    const range = checkTailnetAddress(target.ip);
    if (range) return range;
  }

  const found = observed.nodes.filter((node) => matches(node, target));
  if (found.some((node) => node.generation !== input.snapshot?.generation)) {
    return reject("stale_generation", "The target was only seen in an earlier observation. Observe again.");
  }
  if (found.length === 0) {
    return reject("peer_not_found", `${input.target} is not a peer in the edge node's current tailnet view.`);
  }
  if (found.length > 1) {
    return reject("ambiguous_peer", `${input.target} matches more than one tailnet peer.`);
  }
  const [peer] = found as [TailnetNode];

  const forbidden = forbiddenNode(peer, observed.self, input.forbiddenTags);
  if (forbidden) return forbidden;

  const ip = target.kind === "ip" ? target.ip : pickAddress(peer);
  if (!ip)
    return reject("peer_without_address", `${input.target} has no Tailscale address that can be routed.`);

  if (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535) {
    return reject("invalid_port", "The target port must be an integer from 1 to 65535.");
  }
  if (SENSITIVE_TARGET_PORTS.includes(input.port) && input.allowSensitivePort !== true) {
    return reject(
      "sensitive_port",
      `Port ${input.port} is sensitive. Confirm the override explicitly to expose it publicly.`,
    );
  }
  return { ok: true, stableId: peer.stableId, ip: ip.canonical };
}

export type PinnedRouteTarget = {
  /** As entered: a MagicDNS name or a Tailscale IP. */
  targetInput: string;
  targetNodeStableId: string;
  targetIp: string;
};

export type RouteRevalidation =
  | { ok: true; stableId: string; ip: string; ipChanged: boolean }
  | {
      ok: false;
      status: "awaiting_acl" | "identity_mismatch" | "observation_expired" | "error";
      reason: string;
      message: string;
    };

/**
 * Re-validates a pinned route against the latest snapshot (§3.2 rule 6), on every `edge.apply`
 * and `edge.l4_apply`. Only an `ok` result may be rendered; every other status omits the route.
 */
export function revalidateRouteTarget(
  input: SnapshotInput & { route: PinnedRouteTarget },
): RouteRevalidation {
  const observed = checkSnapshot(input);
  if ("ok" in observed) return { ok: false, status: "observation_expired", ...withoutOk(observed) };
  const generation = input.snapshot?.generation;
  const current = observed.nodes.filter((node) => node.generation === generation);
  const pinned = current.find((node) => node.stableId === input.route.targetNodeStableId) ?? null;

  const target = parseTarget(input.route.targetInput, input.tailnetSuffix);
  if ("ok" in target) return { ok: false, status: "error", ...withoutOk(target) };
  if (target.kind === "name") {
    const named = current.filter((node) => matches(node, target));
    const replaced = named.some((node) => node.stableId !== input.route.targetNodeStableId);
    if (replaced || (pinned && named.length === 0)) {
      return {
        ok: false,
        status: "identity_mismatch",
        reason: "identity_mismatch",
        message: `${target.name} no longer identifies the pinned machine. Re-confirm the target.`,
      };
    }
  }
  if (!pinned) {
    return {
      ok: false,
      status: "awaiting_acl",
      reason: "peer_not_found",
      message: "The pinned machine is not in the edge node's current tailnet view.",
    };
  }

  const forbidden = forbiddenNode(pinned, observed.self, input.forbiddenTags);
  if (forbidden) return { ok: false, status: "error", ...withoutOk(forbidden) };

  const previous = parseIpLiteral(input.route.targetIp);
  const ip = pickAddress(pinned, previous?.version ?? 4);
  if (!ip) {
    return {
      ok: false,
      status: "awaiting_acl",
      reason: "peer_without_address",
      message: "The pinned machine has no routable Tailscale address.",
    };
  }
  return {
    ok: true,
    stableId: pinned.stableId,
    ip: ip.canonical,
    ipChanged: ip.canonical !== previous?.canonical,
  };
}

function withoutOk(rejected: Rejected) {
  return { reason: rejected.reason, message: rejected.message };
}
