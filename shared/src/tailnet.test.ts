import { describe, expect, test } from "bun:test";

import { prefixMatch } from "./cidr.ts";
import {
  FORBIDDEN_TARGET_TAGS,
  parseIpLiteral,
  revalidateRouteTarget,
  validateRouteTarget,
  type RouteTargetInput,
  type TailnetNode,
  type TailnetSnapshot,
} from "./tailnet.ts";

const NOW = "2026-11-16T12:03:00.000Z";
const GENERATION = "gen-2";

function node(overrides: Partial<TailnetNode> & Pick<TailnetNode, "stableId" | "dnsName">): TailnetNode {
  return {
    source: "edge",
    generation: GENERATION,
    hostName: overrides.dnsName.split(".")[0] ?? "",
    ipv4: null,
    ipv6: null,
    tags: [],
    isSelf: false,
    online: true,
    ...overrides,
  };
}

const self = node({
  stableId: "nEdge",
  dnsName: "ark-edge.tail1234.ts.net.",
  ipv4: "100.70.0.1",
  ipv6: "fd7a:115c:a1e0::e",
  tags: ["tag:ark-edge"],
  isSelf: true,
});
const home = node({
  stableId: "nHome",
  dnsName: "home.tail1234.ts.net.",
  ipv4: "100.101.102.103",
  ipv6: "fd7a:115c:a1e0:ab12:4843:cd96:6266:6667",
});
const v6only = node({ stableId: "nV6", dnsName: "v6box.tail1234.ts.net", ipv6: "fd7a:115c:a1e0::1" });
const snapshot: TailnetSnapshot = {
  source: "edge",
  generation: GENERATION,
  completedAt: "2026-11-16T12:00:00.000Z",
  validUntil: "2026-11-16T12:06:00.000Z",
};

function input(overrides: Partial<RouteTargetInput> = {}): RouteTargetInput {
  return {
    target: "home.tail1234.ts.net",
    port: 3000,
    peers: [self, home, v6only],
    snapshot,
    now: NOW,
    self,
    forbiddenTags: FORBIDDEN_TARGET_TAGS,
    tailnetSuffix: ".tail1234.ts.net",
    ...overrides,
  };
}

function reason(overrides: Partial<RouteTargetInput>) {
  const result = validateRouteTarget(input(overrides));
  return result.ok ? "ok" : result.reason;
}

describe("prefixMatch", () => {
  test("is exported and compares bit prefixes", () => {
    const value = parseIpLiteral("100.101.102.103")?.bytes ?? new Uint8Array();
    expect(prefixMatch(value, new Uint8Array([100, 64, 0, 0]), 10)).toBe(true);
    expect(prefixMatch(value, new Uint8Array([100, 128, 0, 0]), 10)).toBe(false);
  });
});

describe("validateRouteTarget: accepted targets", () => {
  test("a MagicDNS name resolves through the snapshot to the peer's StableID and IPv4", () => {
    expect(validateRouteTarget(input())).toEqual({ ok: true, stableId: "nHome", ip: "100.101.102.103" });
    expect(validateRouteTarget(input({ target: "home.tail1234.ts.net." }))).toMatchObject({ ok: true });
  });

  test("a Tailscale IPv4 peer in 100.64.0.0/10", () => {
    expect(validateRouteTarget(input({ target: "100.101.102.103" }))).toEqual({
      ok: true,
      stableId: "nHome",
      ip: "100.101.102.103",
    });
  });

  test("a Tailscale IPv6 peer in fd7a:115c:a1e0::/48, in any spelling", () => {
    for (const target of ["fd7a:115c:a1e0::1", "FD7A:115C:A1E0:0:0:0:0:1", "fd7a:115c:a1e0:0000::0001"]) {
      expect(validateRouteTarget(input({ target }))).toEqual({
        ok: true,
        stableId: "nV6",
        ip: "fd7a:115c:a1e0::1",
      });
    }
    expect(validateRouteTarget(input({ target: "fd7a:115c:a1e0:ab12:4843:cd96:6266:6667" }))).toEqual({
      ok: true,
      stableId: "nHome",
      ip: "fd7a:115c:a1e0:ab12:4843:cd96:6266:6667",
    });
  });

  test("a name whose peer has only IPv6 pins the IPv6 address", () => {
    expect(validateRouteTarget(input({ target: "v6box.tail1234.ts.net" }))).toEqual({
      ok: true,
      stableId: "nV6",
      ip: "fd7a:115c:a1e0::1",
    });
  });

  test("a sensitive port is accepted with the explicit override", () => {
    expect(reason({ port: 22, allowSensitivePort: true })).toBe("ok");
  });
});

describe("validateRouteTarget: rejected addresses", () => {
  test.each([
    ["127.0.0.1", "outside_tailnet_range"],
    ["172.17.0.1", "outside_tailnet_range"],
    ["169.254.169.254", "outside_tailnet_range"],
    ["10.0.0.1", "outside_tailnet_range"],
    ["::1", "outside_tailnet_range"],
    ["fe80::1", "outside_tailnet_range"],
    ["8.8.8.8", "outside_tailnet_range"],
    ["2606:4700:4700::1111", "outside_tailnet_range"],
    ["100.63.255.255", "outside_tailnet_range"],
    ["100.128.0.1", "outside_tailnet_range"],
    ["::ffff:100.101.102.103", "invalid_target"], // IPv4-mapped forms are never accepted
    ["100.100.100.100", "reserved_address"],
    ["100.115.92.7", "reserved_address"],
    ["fd7a:115c:a1e0::53", "reserved_address"],
  ])("%s is rejected (%s)", (target, expected) => {
    expect(reason({ target })).toBe(expected);
  });

  test("an address in range is still rejected when it is not in the snapshot", () => {
    expect(reason({ target: "100.64.0.9" })).toBe("peer_not_found");
  });
});

describe("validateRouteTarget: syntax", () => {
  test.each([
    "localhost",
    "home",
    "home.example.com",
    "Home.tail1234.ts.net",
    "http://home.tail1234.ts.net",
    "home.tail1234.ts.net:3000",
    "user@home.tail1234.ts.net",
    "home.tail1234.ts.net/admin",
    "[fd7a:115c:a1e0::1]",
    "fd7a:115c:a1e0::1%eth0",
    "::fd7a:115c:a1e0:0:0:0:0:1",
    "fd7a:115c:a1e0:0:0:0:0::1",
    "fd7a:115c:a1e0:0:0:0:0:1::",
    "100.101.102.103:3000",
    "100.101.102.103/32",
    "0100.101.102.103",
    " home.tail1234.ts.net",
    ".tail1234.ts.net",
    "home..tail1234.ts.net",
    "",
  ])("%p is rejected as invalid_target", (target) => {
    expect(reason({ target })).toBe("invalid_target");
  });
});

describe("validateRouteTarget: identity", () => {
  test("a name that is not in the snapshot is rejected; DNS is never consulted", () => {
    expect(reason({ target: "nas.tail1234.ts.net" })).toBe("peer_not_found");
  });

  test("an ambiguous name or IP is rejected", () => {
    const twin = node({ stableId: "nTwin", dnsName: "home.tail1234.ts.net", ipv4: "100.101.102.103" });
    expect(reason({ peers: [self, home, twin] })).toBe("ambiguous_peer");
    expect(reason({ peers: [self, home, twin], target: "100.101.102.103" })).toBe("ambiguous_peer");
  });

  test.each(FORBIDDEN_TARGET_TAGS)("a peer tagged %s is rejected", (tag) => {
    const tagged = { ...home, tags: ["tag:server", tag] };
    expect(reason({ peers: [self, tagged] })).toBe("forbidden_tag");
  });

  test("platform tags stay forbidden even when the caller passes none", () => {
    const tagged = { ...home, tags: ["tag:ark-stack-admin"] };
    expect(reason({ peers: [self, tagged], forbiddenTags: [] })).toBe("forbidden_tag");
    expect(reason({ peers: [self, { ...home, tags: ["tag:extra"] }], forbiddenTags: ["tag:extra"] })).toBe(
      "forbidden_tag",
    );
  });

  test("the edge node itself is rejected by name and by IP", () => {
    expect(reason({ target: "ark-edge.tail1234.ts.net" })).toBe("forbidden_peer");
    expect(reason({ target: "100.70.0.1" })).toBe("forbidden_peer");
    expect(reason({ target: "fd7a:115c:a1e0::e" })).toBe("forbidden_peer");
  });
});

describe("validateRouteTarget: ports", () => {
  test.each([22, 2019, 2375, 2376, 3389, 5900])("sensitive port %d needs the override", (port) => {
    expect(reason({ port })).toBe("sensitive_port");
    expect(reason({ port, allowSensitivePort: false })).toBe("sensitive_port");
  });

  test.each([0, -1, 65536, 3000.5, Number.NaN])("port %p is invalid", (port) => {
    expect(reason({ port })).toBe("invalid_port");
  });
});

describe("validateRouteTarget: snapshot", () => {
  test("a missing or incomplete snapshot is rejected", () => {
    expect(reason({ snapshot: null })).toBe("snapshot_incomplete");
    expect(reason({ snapshot: { ...snapshot, completedAt: null } })).toBe("snapshot_incomplete");
    expect(reason({ snapshot: { ...snapshot, validUntil: null } })).toBe("snapshot_incomplete");
    expect(reason({ snapshot: { ...snapshot, generation: "" } })).toBe("snapshot_incomplete");
    expect(reason({ self: null })).toBe("snapshot_incomplete");
    expect(reason({ self: { ...self, generation: "gen-1" } })).toBe("snapshot_incomplete");
    expect(reason({ self: { ...self, isSelf: false } })).toBe("snapshot_incomplete");
    expect(reason({ tailnetSuffix: ".tail9999.ts.net" })).toBe("snapshot_incomplete");
  });

  test("a lease longer than six minutes or completed in the future is rejected", () => {
    expect(reason({ snapshot: { ...snapshot, validUntil: "2026-11-16T12:30:00.000Z" } })).toBe(
      "snapshot_incomplete",
    );
    expect(reason({ now: "2026-11-16T11:59:00.000Z" })).toBe("snapshot_incomplete");
  });

  test("an expired snapshot is rejected", () => {
    expect(reason({ now: "2026-11-16T12:06:00.000Z" })).toBe("snapshot_expired");
    expect(reason({ now: new Date("2026-11-16T13:00:00.000Z") })).toBe("snapshot_expired");
  });

  test("observation sources are never mixed", () => {
    expect(reason({ snapshot: { ...snapshot, source: "backup" } })).toBe("source_mismatch");
    expect(reason({ peers: [self, { ...home, source: "backup" }] })).toBe("source_mismatch");
    expect(reason({ self: { ...self, source: "backup" } })).toBe("source_mismatch");
    // A caller that trusts the backup source rejects an edge snapshot.
    expect(reason({ source: "backup" })).toBe("source_mismatch");
  });

  test("a peer from a previous generation is rejected", () => {
    const stale = { ...home, generation: "gen-1" };
    expect(reason({ peers: [self, stale] })).toBe("stale_generation");
    expect(reason({ peers: [self, stale], target: "100.101.102.103" })).toBe("stale_generation");
  });
});

describe("revalidateRouteTarget", () => {
  const route = {
    targetInput: "home.tail1234.ts.net",
    targetNodeStableId: "nHome",
    targetIp: "100.101.102.103",
  };
  const base = {
    peers: [self, home],
    snapshot,
    now: NOW,
    self,
    forbiddenTags: FORBIDDEN_TARGET_TAGS,
    tailnetSuffix: ".tail1234.ts.net",
    route,
  };

  test("an unchanged peer stays valid", () => {
    expect(revalidateRouteTarget(base)).toEqual({
      ok: true,
      stableId: "nHome",
      ip: "100.101.102.103",
      ipChanged: false,
    });
  });

  test("an IP change with the same StableID updates the pinned IP", () => {
    const moved = { ...home, ipv4: "100.101.102.200" };
    expect(revalidateRouteTarget({ ...base, peers: [self, moved] })).toEqual({
      ok: true,
      stableId: "nHome",
      ip: "100.101.102.200",
      ipChanged: true,
    });
    // An IP-entered route follows the StableID too, keeping the address family.
    const v6Route = { ...route, targetInput: home.ipv6 ?? "", targetIp: home.ipv6 ?? "" };
    const movedV6 = { ...home, ipv6: "fd7a:115c:a1e0::77" };
    expect(revalidateRouteTarget({ ...base, peers: [self, movedV6], route: v6Route })).toEqual({
      ok: true,
      stableId: "nHome",
      ip: "fd7a:115c:a1e0::77",
      ipChanged: true,
    });
  });

  test("a name that now points at a different StableID gives identity_mismatch", () => {
    const impostor = node({ stableId: "nOther", dnsName: "home.tail1234.ts.net", ipv4: "100.101.102.103" });
    expect(revalidateRouteTarget({ ...base, peers: [self, impostor] })).toMatchObject({
      ok: false,
      status: "identity_mismatch",
    });
    const renamed = { ...home, dnsName: "old-home.tail1234.ts.net" };
    expect(revalidateRouteTarget({ ...base, peers: [self, renamed, impostor] })).toMatchObject({
      ok: false,
      status: "identity_mismatch",
    });
  });

  test.each([4, 6])("an IPv%d literal follows its pinned StableID after address reassignment", (family) => {
    const enteredIp = (family === 4 ? home.ipv4 : home.ipv6)!;
    const newIp = family === 4 ? "100.101.102.200" : "fd7a:115c:a1e0::77";
    const address = family === 4 ? "ipv4" : "ipv6";
    const moved = { ...home, [address]: newIp };
    const newOwner = node({ stableId: "nOther", dnsName: "other.tail1234.ts.net", [address]: enteredIp });
    const ipRoute = { ...route, targetInput: enteredIp, targetIp: enteredIp };
    expect(validateRouteTarget(input({ target: enteredIp }))).toMatchObject({ ok: true, stableId: "nHome" });
    expect(validateRouteTarget(input({ target: enteredIp, peers: [self, moved, newOwner] }))).toMatchObject({
      ok: true,
      stableId: "nOther",
    });
    expect(revalidateRouteTarget({ ...base, peers: [self, moved, newOwner], route: ipRoute })).toEqual({
      ok: true,
      stableId: "nHome",
      ip: newIp,
      ipChanged: true,
    });
    expect(revalidateRouteTarget({ ...base, peers: [self, newOwner], route: ipRoute })).toMatchObject({
      ok: false,
      status: "awaiting_acl",
    });
  });

  test("a name that no longer matches the pinned machine gives identity_mismatch", () => {
    const renamed = { ...home, dnsName: "old-home.tail1234.ts.net" };
    expect(revalidateRouteTarget({ ...base, peers: [self, renamed] })).toMatchObject({
      ok: false,
      status: "identity_mismatch",
    });
  });

  test("a missing StableID gives awaiting_acl", () => {
    expect(revalidateRouteTarget({ ...base, peers: [self] })).toMatchObject({
      ok: false,
      status: "awaiting_acl",
    });
    const ipRoute = { ...route, targetInput: "100.101.102.103" };
    expect(revalidateRouteTarget({ ...base, peers: [self], route: ipRoute })).toMatchObject({
      ok: false,
      status: "awaiting_acl",
    });
    // A peer seen only in an earlier generation counts as missing.
    const stale = { ...home, generation: "gen-1" };
    expect(revalidateRouteTarget({ ...base, peers: [self, stale] })).toMatchObject({
      ok: false,
      status: "awaiting_acl",
    });
  });

  test("an expired or incomplete observation withdraws the route", () => {
    expect(revalidateRouteTarget({ ...base, now: "2026-11-16T12:07:00.000Z" })).toMatchObject({
      ok: false,
      status: "observation_expired",
      reason: "snapshot_expired",
    });
    expect(revalidateRouteTarget({ ...base, snapshot: null })).toMatchObject({
      ok: false,
      status: "observation_expired",
    });
  });

  test("a pinned peer that gains a platform tag is withdrawn", () => {
    const tagged = { ...home, tags: ["tag:ark-backup"] };
    expect(revalidateRouteTarget({ ...base, peers: [self, tagged] })).toMatchObject({
      ok: false,
      status: "error",
      reason: "forbidden_tag",
    });
  });
});
