import { isIPv6 } from "node:net";
import { createHmac } from "node:crypto";
import { networkInterfaces } from "node:os";
import { z } from "zod";

import { parseIpv6 } from "./cidr.ts";

export const IPV6_PREFLIGHT_WEEK_MS = 7 * 24 * 60 * 60_000;
export const IPV6_PREFLIGHT_TICKET_MS = 15 * 60_000;
export const IPV6_HOST_SAMPLE_MS = 45_000;
export const IPV6_PREFLIGHT_HTTP_PATH = "/.well-known/ark-ipv6-preflight/";

export function publicIpv6(address: string | null | undefined) {
  if (!address || !isIPv6(address) || address.includes("%")) return null;
  const ip = parseIpv6(address);
  if (!ip || (ip[0]! & 0xe0) !== 0x20) return null;
  const prefix = new DataView(ip.buffer).getUint32(0);
  if (prefix === 0x20010db8 || prefix >>> 12 === 0x3fff0) return null;
  // Use a single spelling for equality checks, including against IPv6 addresses in logs.
  return new URL(`http://[${address}]`).hostname.slice(1, -1);
}

export function hostPublicIpv6Addresses() {
  return [
    ...new Set(
      Object.values(networkInterfaces()).flatMap((entries) =>
        (entries ?? []).flatMap(({ address, family }) => {
          const canonical = family === "IPv6" ? publicIpv6(address) : null;
          return canonical ? [canonical] : [];
        }),
      ),
    ),
  ].toSorted();
}

const globalIp = z
  .string()
  .max(45)
  .refine((ip) => publicIpv6(ip) !== null);
const name = z
  .string()
  .max(253)
  .regex(/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i);
const checkId = z
  .string()
  .max(120)
  .regex(/^[a-zA-Z0-9_-]+$/);
const tcpPort = z.number().int().min(1).max(65_535);
export const ipv6ProbeCheck = z.object({
  id: checkId,
  port: tcpPort,
  protocol: z.enum(["http", "tls", "postgres-classic", "postgres-direct", "tcp"]),
  hostname: name,
  clientCertificate: z.boolean().optional(),
});
export const ipv6ProbeRequest = z.object({
  id: checkId,
  address: globalIp,
  issuedAt: z.number().int(),
  expiresAt: z.number().int(),
  checks: z.array(ipv6ProbeCheck).min(2).max(512),
});

export const ipv6ProbeReport = z.object({
  id: checkId,
  checks: z
    .array(
      z.discriminatedUnion("outcome", [
        z.object({ id: checkId, outcome: z.literal("passed"), source: globalIp, sourcePort: tcpPort }),
        z.object({
          id: checkId,
          outcome: z.enum(["failed", "unverified"]),
          reason: z.enum(["credentials", "connection", "http", "tls", "postgres"]),
        }),
      ]),
    )
    .max(512),
});

export type Ipv6ProbeCheck = z.infer<typeof ipv6ProbeCheck>;
export type Ipv6ProbeRequest = z.infer<typeof ipv6ProbeRequest>;
export type Ipv6ProbeReport = z.infer<typeof ipv6ProbeReport>;

export function signIpv6Report(report: Ipv6ProbeReport, token: string) {
  return createHmac("sha256", token)
    .update(JSON.stringify(ipv6ProbeReport.parse(report)))
    .digest("base64url");
}

export type Ipv6EdgeLog = {
  at: number;
  source: string;
  sourcePort: number;
} & (
  | { protocol: "http"; path: string; hostname: string }
  | { protocol: "haproxy"; frontend: string; backend: string; server: string; connected: boolean }
);

export type Ipv6DockerState = {
  at: number;
  daemon: string;
  edge: string;
  ipv6: boolean;
  ip6tables: boolean;
  userlandProxy: boolean;
  liveRestore: boolean;
  networkIpv6: boolean;
  edgeAddress: string | null;
};

export function dockerIpv6Ready(state: Ipv6DockerState | undefined, now = Date.now()) {
  return Boolean(
    state &&
    now - state.at >= 0 &&
    now - state.at <= IPV6_HOST_SAMPLE_MS &&
    state.ipv6 === true &&
    state.ip6tables === true &&
    state.userlandProxy === false &&
    state.liveRestore === true &&
    state.networkIpv6 === true &&
    state.edgeAddress &&
    isIPv6(state.edgeAddress),
  );
}

export type Ipv6ExpectedCheck = Ipv6ProbeCheck & {
  frontend?: string;
  backend?: string;
  server?: string;
};

type PortEvidence = Pick<Ipv6ProbeCheck, "id" | "port" | "protocol" | "hostname"> &
  ({ outcome: "passed"; source: string } | { outcome: "failed" | "unverified"; reason: string });

export function evaluateIpv6Report(
  request: Ipv6ProbeRequest,
  expected: Ipv6ExpectedCheck[],
  report: Ipv6ProbeReport,
  logs: Ipv6EdgeLog[],
) {
  const reported = new Map(report.checks.map((result) => [result.id, result]));
  const unique = reported.size === report.checks.length && reported.size === expected.length;
  return expected.map((check): PortEvidence => {
    const { id, port, protocol, hostname } = check;
    const evidence = { id, port, protocol, hostname };
    const result = unique && request.id === report.id ? reported.get(id) : undefined;
    if (!result)
      return { ...evidence, outcome: "unverified", reason: "missing or invalid external evidence" };
    if (result.outcome !== "passed") {
      return { ...evidence, outcome: result.outcome, reason: `external probe: ${result.reason}` };
    }
    const source = publicIpv6(result.source);
    const matched =
      source &&
      source !== publicIpv6(request.address) &&
      logs.some((log) => {
        if (
          log.at < request.issuedAt ||
          log.at > request.expiresAt ||
          log.source !== source ||
          log.sourcePort !== result.sourcePort
        )
          return false;
        if (log.protocol === "http") {
          return (
            protocol === "http" &&
            log.hostname === hostname &&
            log.path === IPV6_PREFLIGHT_HTTP_PATH + request.id
          );
        }
        return (
          protocol !== "http" &&
          log.connected &&
          log.frontend === check.frontend &&
          (!check.backend || log.backend === check.backend) &&
          (!check.server || log.server === check.server)
        );
      });
    if (!matched) {
      return {
        ...evidence,
        outcome: "failed",
        reason: "edge did not log the external IPv6 source and an admitted connection",
      };
    }
    return { ...evidence, outcome: "passed", source };
  });
}
