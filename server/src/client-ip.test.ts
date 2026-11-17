// Trusted client address (front door §3.9.3 "Brute force", FD-10).
import { describe, expect, test } from "bun:test";

import { normalizeAddress, trustedClientIp, type ClientIpInput } from "./client-ip.ts";

const token = "genuine-edge-token-0123456789";
const input = (
  overrides: Partial<ClientIpInput> & { forwarded?: string; supplied?: string },
): ClientIpInput => {
  const headers = new Headers();
  if (overrides.forwarded !== undefined) headers.set("x-forwarded-for", overrides.forwarded);
  if (overrides.supplied !== undefined) headers.set("x-ark-edge-token", overrides.supplied);
  return {
    path: "/api/auth/sign-in/email",
    origin: "gate",
    headers,
    peer: "172.18.0.5",
    edgeToken: token,
    edgePeers: [],
    ...overrides,
  };
};

describe("trustedClientIp", () => {
  test("the edge's single X-Forwarded-For is used only with the genuine token on an exact login path", () => {
    expect(trustedClientIp(input({ forwarded: "203.0.113.9", supplied: token }))).toEqual({
      ip: "203.0.113.9",
      source: "edge",
    });
    for (const path of ["/api/auth/sign-in/email/", "/api/auth/sign-up/email", "/api/state", "/gate/login"]) {
      expect(trustedClientIp(input({ path, forwarded: "203.0.113.9", supplied: token })).ip, path).toBe(
        "172.18.0.5",
      );
    }
  });

  test("a forged or missing token, the admin origin or no configured token all key on the peer", () => {
    for (const overrides of [
      { forwarded: "203.0.113.9", supplied: "forged" },
      { forwarded: "203.0.113.9" },
      { forwarded: "203.0.113.9", supplied: token, origin: "admin" as const },
      { forwarded: "203.0.113.9", supplied: "", edgeToken: "" },
    ]) {
      expect(trustedClientIp(input(overrides)), JSON.stringify(overrides)).toEqual({
        ip: "172.18.0.5",
        source: "peer",
      });
    }
  });

  test("a recorded edge peer is an additional check, never a grant on its own", () => {
    const pinned = { edgePeers: ["172.18.0.5"], forwarded: "203.0.113.9" };
    expect(trustedClientIp(input({ ...pinned, supplied: token })).source).toBe("edge");
    expect(trustedClientIp(input({ ...pinned, supplied: token, peer: "172.18.0.6" })).ip).toBe("172.18.0.6");
    expect(trustedClientIp(input({ ...pinned, supplied: "forged" })).ip).toBe("172.18.0.5");
  });

  test("anything but exactly one valid address from the edge is not trusted", () => {
    for (const forwarded of ["203.0.113.9, 198.51.100.1", "", "not-an-ip", "203.0.113.9:443"]) {
      expect(trustedClientIp(input({ forwarded, supplied: token })).ip, forwarded).toBe("172.18.0.5");
    }
  });

  test("normalizes IPv4-mapped peers and refuses non-addresses", () => {
    expect(normalizeAddress("::ffff:127.0.0.1")).toBe("127.0.0.1");
    expect(normalizeAddress("2001:DB8::1")).toBe("2001:db8::1");
    expect(normalizeAddress("example.com")).toBeNull();
    expect(normalizeAddress(undefined)).toBeNull();
  });
});
