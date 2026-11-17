// Edge observer (docs/design/front-door.md §3.2, §3.6, FD-06): turns one read of the edge node's
// LocalAPI `GET /localapi/v0/status` into a complete snapshot generation, or refuses it.
//
// A generation is all or nothing. Anything that suggests the read is not the edge node's full,
// current view (not logged in, no self, malformed or duplicate peers) rejects the whole read, so a
// failed or partial observation can never renew the lease or leave absent peers behind.

import { SNAPSHOT_VALIDITY_MS, parseIpLiteral, inTailscaleRange, type TailnetNode } from "./tailnet.ts";

/** `edge.observe` runs this often; the lease (§3.2) lasts `SNAPSHOT_VALIDITY_MS` from completion. */
export const EDGE_OBSERVE_INTERVAL_MS = 5 * 60_000;

/** The Host the LocalAPI expects on its unix socket (`apitype.LocalAPIHost`). */
export const LOCALAPI_HOST = "local-tailscaled.sock";

/**
 * The lease length for a new generation. Tests may shorten it (never lengthen it) with
 * `ARK_EDGE_LEASE_VALIDITY_MS`; the validator rejects anything longer than six minutes.
 */
export function leaseValidityMs(env: Record<string, string | undefined> = process.env) {
  const requested = Number(env.ARK_EDGE_LEASE_VALIDITY_MS ?? "");
  if (Number.isInteger(requested) && requested >= 1_000 && requested < SNAPSHOT_VALIDITY_MS) return requested;
  return SNAPSHOT_VALIDITY_MS;
}

type StatusNode = {
  ID?: unknown;
  HostName?: unknown;
  DNSName?: unknown;
  TailscaleIPs?: unknown;
  Tags?: unknown;
  Online?: unknown;
};

export type ParsedObservation =
  | {
      ok: true;
      self: TailnetNode;
      peers: TailnetNode[];
      /** `.tail1234.ts.net`, learned from the tailnet and checked against the edge node's name. */
      tailnetSuffix: string;
    }
  | { ok: false; reason: string };

function fail(reason: string): ParsedObservation {
  return { ok: false, reason };
}

function text(value: unknown) {
  return typeof value === "string" ? value : null;
}

function dnsName(value: unknown) {
  const name = text(value);
  return name === null ? null : name.trim().toLowerCase().replace(/\.$/, "");
}

function addresses(value: unknown) {
  if (value === undefined || value === null) return { ipv4: null, ipv6: null };
  if (!Array.isArray(value)) return null;
  let ipv4: string | null = null;
  let ipv6: string | null = null;
  for (const item of value) {
    const parsed = typeof item === "string" ? parseIpLiteral(item) : null;
    if (!parsed) return null;
    if (!inTailscaleRange(parsed)) continue;
    if (parsed.version === 4) ipv4 ??= parsed.canonical;
    else ipv6 ??= parsed.canonical;
  }
  return { ipv4, ipv6 };
}

function tags(value: unknown) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) return null;
  return [...(value as string[])].toSorted();
}

function node(raw: StatusNode, input: { generation: string; isSelf: boolean }): TailnetNode | string {
  const stableId = text(raw.ID)?.trim() ?? "";
  if (!stableId) return "a node has no StableNodeID";
  const name = dnsName(raw.DNSName);
  if (name === null && raw.DNSName !== undefined) return `node ${stableId} has an invalid DNS name`;
  const ips = addresses(raw.TailscaleIPs);
  if (!ips) return `node ${stableId} has invalid Tailscale addresses`;
  const nodeTags = tags(raw.Tags);
  if (!nodeTags) return `node ${stableId} has invalid tags`;
  if (raw.Online !== undefined && raw.Online !== null && typeof raw.Online !== "boolean") {
    return `node ${stableId} has an invalid online flag`;
  }
  return {
    source: "edge",
    generation: input.generation,
    stableId,
    dnsName: name ?? "",
    hostName: text(raw.HostName) ?? "",
    ipv4: ips.ipv4,
    ipv6: ips.ipv6,
    tags: nodeTags,
    isSelf: input.isSelf,
    online: typeof raw.Online === "boolean" ? raw.Online : null,
  };
}

/**
 * Parses a LocalAPI status document into one complete `edge` generation. Every rejection is a
 * failed observation: the caller must not touch the stored snapshot.
 */
export function parseLocalApiStatus(status: unknown, input: { generation: string }): ParsedObservation {
  if (!status || typeof status !== "object" || Array.isArray(status)) {
    return fail("The LocalAPI status is not a JSON object.");
  }
  const document = status as {
    BackendState?: unknown;
    Self?: unknown;
    Peer?: unknown;
    MagicDNSSuffix?: unknown;
    CurrentTailnet?: { MagicDNSSuffix?: unknown } | null;
  };
  if (document.BackendState !== "Running") {
    return fail(
      `The edge node is not running on the tailnet (state ${JSON.stringify(document.BackendState ?? null)}).`,
    );
  }
  if (!document.Self || typeof document.Self !== "object") return fail("The status has no self node.");
  const self = node(document.Self as StatusNode, { generation: input.generation, isSelf: true });
  if (typeof self === "string") return fail(`Self: ${self}.`);
  if (!self.dnsName || (!self.ipv4 && !self.ipv6)) {
    return fail("The edge node has no MagicDNS name or Tailscale address yet.");
  }
  const suffixSource =
    dnsName(document.CurrentTailnet?.MagicDNSSuffix) ||
    dnsName(document.MagicDNSSuffix) ||
    self.dnsName.split(".").slice(1).join(".");
  const tailnetSuffix = `.${suffixSource.replace(/^\./, "")}`;
  if (tailnetSuffix.split(".").length < 3 || !self.dnsName.endsWith(tailnetSuffix)) {
    return fail("The tailnet's MagicDNS suffix does not match the edge node's name.");
  }

  const rawPeers = document.Peer ?? {};
  if (typeof rawPeers !== "object" || Array.isArray(rawPeers)) return fail("The peer list is malformed.");
  const peers: TailnetNode[] = [];
  const seen = new Set([self.stableId]);
  for (const raw of Object.values(rawPeers as Record<string, unknown>)) {
    if (!raw || typeof raw !== "object") return fail("A peer entry is malformed.");
    const peer = node(raw as StatusNode, { generation: input.generation, isSelf: false });
    if (typeof peer === "string") return fail(`Peer: ${peer}.`);
    if (seen.has(peer.stableId)) return fail(`StableNodeID ${peer.stableId} appears more than once.`);
    seen.add(peer.stableId);
    peers.push(peer);
  }
  peers.sort((a, b) => a.stableId.localeCompare(b.stableId));
  return { ok: true, self, peers, tailnetSuffix };
}

/** `.tail1234.ts.net` from the edge node's own MagicDNS name. */
export function tailnetSuffixOf(self: Pick<TailnetNode, "dnsName">) {
  const rest = self.dnsName.replace(/\.$/, "").split(".").slice(1).join(".");
  return rest ? `.${rest}` : "";
}

/** `ip:port`, with IPv6 bracketed, in canonical form; the key every allowlist comparison uses. */
export function backendKey(ip: string, port: number) {
  const parsed = parseIpLiteral(ip);
  const host = parsed?.canonical ?? ip;
  return parsed?.version === 6 ? `[${host}]:${port}` : `${host}:${port}`;
}

/**
 * The raw HTTP request for a TCP probe through tailscaled (`POST /localapi/v0/dial`). tailscaled
 * dials from its own network namespace, the one the edge proxies share, so a `101` answer means the
 * edge can open TCP to that exact port. Read-only LocalAPI callers may use it (FD-06 deployment test).
 */
export function localApiDialRequest(ip: string, port: number) {
  const parsed = parseIpLiteral(ip);
  if (!parsed || !inTailscaleRange(parsed)) throw new Error(`${ip} is not a Tailscale address.`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`Invalid probe port ${port}.`);
  return [
    "POST /localapi/v0/dial HTTP/1.1",
    `Host: ${LOCALAPI_HOST}`,
    "Sec-Tailscale: localapi",
    "Connection: upgrade",
    "Upgrade: ts-dial",
    `Dial-Host: ${parsed.canonical}`,
    `Dial-Port: ${port}`,
    "Dial-Network: tcp",
    "Content-Length: 0",
    "",
    "",
  ].join("\r\n");
}

/** Reads the status code from the first line of an HTTP response; null until the line is complete. */
export function httpStatusLine(buffer: string) {
  const end = buffer.indexOf("\r\n");
  if (end === -1) return null;
  const match = /^HTTP\/1\.[01] (\d{3})/.exec(buffer.slice(0, end));
  return match
    ? { status: Number(match[1]), line: buffer.slice(0, end) }
    : { status: 0, line: buffer.slice(0, end) };
}
