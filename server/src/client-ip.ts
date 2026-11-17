// Trusted client address for Better Auth's rate limiter and session records (front door §3.9.3,
// "Brute force", FD-10).
//
// No Docker subnet is trusted any more. The address is:
//
// - the edge's `X-Forwarded-For`, only when the request carries the genuine `X-Ark-Edge-Token`, is
//   for a registered admin or login host and is one of that origin's exact auth API paths. Public
//   Caddy has no `trusted_proxies`: it replaces client input with HAProxy's PROXY v2 address. The
//   loopback-only tailnet gateway trusts only local Tailscale Serve and sends its resolved client IP.
//   Both proxies remove client-forged identity headers before adding their own. When
//   `ARK_EDGE_PEER_ADDRESSES` is set, the transport peer must also be one of
//   those exact addresses (an additional check, never a trust grant on its own);
// - otherwise the transport peer address of the connection, ignoring every forwarding header.
//
// The result is passed to Better Auth in `X-Ark-Client-Ip` (its only `ipAddressHeaders` entry). The
// API overwrites or removes that header on every request it hands to Better Auth, so a client can
// never supply it.

import { isIP } from "node:net";

import { ADMIN_CLIENT_IP_AUTH_PATHS, isGateLoginAuthPath, secureEqual } from "@ark-stack/shared";

import type { SessionOrigin } from "./session-origin.ts";

export const CLIENT_IP_HEADER = "x-ark-client-ip";
export const EDGE_TOKEN_HEADER = "x-ark-edge-token";

/** A plain IP address (IPv4-mapped IPv6 unwrapped), or null. */
export function normalizeAddress(value: string | null | undefined) {
  if (!value) return null;
  const address = value.trim().replace(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i, "$1");
  return isIP(address) ? address.toLowerCase() : null;
}

/** The transport peer from Bun's server (Hono's `c.env`), or null for an in-process request. */
export function transportPeer(server: unknown, request: Request) {
  const requestIP = (server as { requestIP?: (request: Request) => { address?: string } | null } | undefined)
    ?.requestIP;
  if (typeof requestIP !== "function") return null;
  try {
    return normalizeAddress(requestIP.call(server, request)?.address);
  } catch {
    return null;
  }
}

export type ClientIpInput = {
  path: string;
  origin: SessionOrigin;
  headers: Headers;
  peer: string | null;
  edgeToken: string;
  edgePeers: string[];
};

/** Whether the request is a genuine proxy-authenticated auth request (exact paths only). */
export function edgeAuthenticated(input: ClientIpInput) {
  const allowed =
    input.origin === "gate"
      ? isGateLoginAuthPath(input.path)
      : (ADMIN_CLIENT_IP_AUTH_PATHS as readonly string[]).includes(input.path);
  if (!input.edgeToken || !allowed) return false;
  if (!secureEqual(input.headers.get(EDGE_TOKEN_HEADER) ?? "", input.edgeToken)) return false;
  return input.edgePeers.length === 0 || Boolean(input.peer && input.edgePeers.includes(input.peer));
}

export function trustedClientIp(input: ClientIpInput): { ip: string | null; source: "edge" | "peer" } {
  if (edgeAuthenticated(input)) {
    const forwarded = (input.headers.get("x-forwarded-for") ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    // Caddy writes a single address; anything else is not what the edge sends, so it is not trusted.
    const client = forwarded.length === 1 ? normalizeAddress(forwarded[0]) : null;
    if (client) return { ip: client, source: "edge" };
  }
  return { ip: input.peer, source: "peer" };
}
