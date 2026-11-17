import { describe, expect, test } from "bun:test";

import {
  SNAPSHOT_VALIDITY_MS,
  backendKey,
  httpStatusLine,
  leaseValidityMs,
  localApiDialRequest,
  parseLocalApiStatus,
  tailnetSuffixOf,
} from "./index.ts";

const status = (overrides: Record<string, unknown> = {}) => ({
  BackendState: "Running",
  Self: {
    ID: "nEDGE1CNTRL",
    HostName: "ark-edge",
    DNSName: "ark-edge.tail1234.ts.net.",
    TailscaleIPs: ["100.64.0.1", "fd7a:115c:a1e0::1"],
    Tags: ["tag:ark-edge"],
    Online: true,
  },
  Peer: {
    "nodekey:b": {
      ID: "nNAS",
      HostName: "nas",
      DNSName: "nas.tail1234.ts.net.",
      TailscaleIPs: ["100.88.1.20"],
    },
    "nodekey:a": {
      ID: "nHOME",
      HostName: "home",
      DNSName: "Home.tail1234.ts.net.",
      TailscaleIPs: ["100.101.102.103", "fd7a:115c:a1e0:0:0:0:0:103"],
      Tags: ["tag:b", "tag:a"],
      Online: false,
    },
  },
  CurrentTailnet: { MagicDNSSuffix: "tail1234.ts.net" },
  ...overrides,
});

describe("parseLocalApiStatus", () => {
  test("turns a complete status into one generation with canonical names, addresses and tags", () => {
    const parsed = parseLocalApiStatus(status(), { generation: "gen_1" });
    if (!parsed.ok) throw new Error(parsed.reason);
    expect(parsed.tailnetSuffix).toBe(".tail1234.ts.net");
    expect(parsed.self).toMatchObject({
      source: "edge",
      generation: "gen_1",
      stableId: "nEDGE1CNTRL",
      dnsName: "ark-edge.tail1234.ts.net",
      ipv4: "100.64.0.1",
      ipv6: "fd7a:115c:a1e0::1",
      isSelf: true,
    });
    expect(parsed.peers.map((peer) => peer.stableId)).toEqual(["nHOME", "nNAS"]);
    expect(parsed.peers[0]).toMatchObject({
      dnsName: "home.tail1234.ts.net",
      ipv6: "fd7a:115c:a1e0::103",
      tags: ["tag:a", "tag:b"],
      online: false,
      isSelf: false,
    });
  });

  test("an empty peer list is complete", () => {
    const parsed = parseLocalApiStatus(status({ Peer: null }), { generation: "gen_1" });
    expect(parsed.ok && parsed.peers).toEqual([]);
  });

  const partial: Array<[string, Record<string, unknown>]> = [
    ["not logged in", { BackendState: "NeedsLogin" }],
    ["stopped", { BackendState: "Stopped" }],
    ["no self", { Self: null }],
    ["self without a StableID", { Self: { ...status().Self, ID: "" } }],
    ["self without an address", { Self: { ...status().Self, TailscaleIPs: [] } }],
    ["peer list not an object", { Peer: [] }],
    [
      "peer without a StableID",
      { Peer: { a: { DNSName: "x.tail1234.ts.net.", TailscaleIPs: ["100.64.0.9"] } } },
    ],
    ["peer that repeats self", { Peer: { a: { ID: "nEDGE1CNTRL", TailscaleIPs: ["100.64.0.9"] } } }],
    [
      "duplicate peers",
      {
        Peer: {
          a: { ID: "nX", TailscaleIPs: ["100.64.0.9"] },
          b: { ID: "nX", TailscaleIPs: ["100.64.0.10"] },
        },
      },
    ],
    ["malformed address", { Peer: { a: { ID: "nX", TailscaleIPs: ["100.64.0"] } } }],
    ["malformed tags", { Peer: { a: { ID: "nX", Tags: "tag:x" } } }],
    ["suffix that does not match self", { CurrentTailnet: { MagicDNSSuffix: "other.ts.net" } }],
  ];
  for (const [name, overrides] of partial) {
    test(`rejects the whole read: ${name}`, () => {
      expect(parseLocalApiStatus(status(overrides), { generation: "gen_1" }).ok).toBe(false);
    });
  }
  test("rejects non-objects", () => {
    for (const value of [null, "x", [], 1]) {
      expect(parseLocalApiStatus(value, { generation: "gen_1" }).ok).toBe(false);
    }
  });
});

describe("helpers", () => {
  test("backend keys are canonical and bracket IPv6", () => {
    expect(backendKey("100.101.102.103", 3000)).toBe("100.101.102.103:3000");
    expect(backendKey("fd7a:115c:a1e0:0:0:0:0:103", 443)).toBe("[fd7a:115c:a1e0::103]:443");
  });

  test("the suffix comes from the edge node's name", () => {
    expect(tailnetSuffixOf({ dnsName: "ark-edge.tail1234.ts.net." })).toBe(".tail1234.ts.net");
  });

  test("probes only dial Tailscale addresses on valid ports", () => {
    const request = localApiDialRequest("fd7a:115c:a1e0:0::103", 8443);
    expect(request).toContain("Upgrade: ts-dial\r\n");
    expect(request).toContain("Dial-Host: fd7a:115c:a1e0::103\r\nDial-Port: 8443\r\n");
    expect(request.endsWith("\r\n\r\n")).toBe(true);
    for (const [ip, port] of [
      ["127.0.0.1", 80],
      ["172.17.0.1", 80],
      ["api", 3000],
      ["100.101.102.103", 0],
    ] as const) {
      expect(() => localApiDialRequest(ip, port)).toThrow();
    }
  });

  test("status lines", () => {
    expect(httpStatusLine("HTTP/1.1 101 Switching Protocols\r\n")).toMatchObject({ status: 101 });
    expect(httpStatusLine("HTTP/1.1 502 Bad")).toBeNull();
    expect(httpStatusLine("garbage\r\n")).toMatchObject({ status: 0 });
  });

  test("the lease can be shortened for tests but never lengthened", () => {
    expect(leaseValidityMs({})).toBe(SNAPSHOT_VALIDITY_MS);
    expect(leaseValidityMs({ ARK_EDGE_LEASE_VALIDITY_MS: "8000" })).toBe(8000);
    expect(leaseValidityMs({ ARK_EDGE_LEASE_VALIDITY_MS: String(SNAPSHOT_VALIDITY_MS * 2) })).toBe(
      SNAPSHOT_VALIDITY_MS,
    );
    expect(leaseValidityMs({ ARK_EDGE_LEASE_VALIDITY_MS: "-1" })).toBe(SNAPSHOT_VALIDITY_MS);
  });
});
