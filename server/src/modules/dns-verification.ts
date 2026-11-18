import { clientAllowed, dnsRecordVerified } from "@ark-stack/shared";
import type { CaaRecord } from "node:dns";
import type { StoredDnsRecord } from "./domain-dns.ts";

// https://www.cloudflare.com/ips/ — Cloudflare's public proxy address ranges.
const cloudflareCidrs = [
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "108.162.192.0/18",
  "131.0.72.0/22",
  "141.101.64.0/18",
  "162.158.0.0/15",
  "172.64.0.0/13",
  "173.245.48.0/20",
  "188.114.96.0/20",
  "190.93.240.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "2400:cb00::/32",
  "2606:4700::/32",
  "2803:f800::/32",
  "2405:b500::/32",
  "2405:8100::/32",
  "2a06:98c0::/29",
  "2c0f:f248::/32",
];

export const isCloudflareProxyAddress = (ip: string) => clientAllowed(cloudflareCidrs, ip).allowed;

export async function emptyIfNoDnsData<T>(lookup: Promise<T[]>): Promise<T[]> {
  try {
    return await lookup;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENODATA" || code === "ENOTFOUND") return [];
    throw error;
  }
}

function permitsHttp01(value: string) {
  const [issuer, ...parameters] = value.split(";");
  return (
    issuer.trim().replace(/\.$/, "").toLowerCase() === "letsencrypt.org" &&
    parameters.every((parameter) => {
      const [key, setting] = parameter.trim().split("=");
      return (
        key.trim().toLowerCase() !== "validationmethods" ||
        setting?.split(",").some((method) => method.trim() === "http-01")
      );
    })
  );
}

async function caaError(hostname: string, lookup: (name: string) => Promise<CaaRecord[]>) {
  const labels = hostname.split(".");
  for (let index = 0; index < labels.length; index++) {
    const name = labels.slice(index).join(".");
    const records = await emptyIfNoDnsData(lookup(name)).catch(() => null);
    if (!records)
      return `CAA lookup at ${name} failed. Check its authoritative DNS and DNSSEC, then recheck DNS.`;
    if (!records.length) continue;
    const unsupported = records.some(
      (record) => record.critical & 128 && !["issue", "issuewild", "iodef"].some((tag) => tag in record),
    );
    const issues = records.flatMap((record) => (typeof record.issue === "string" ? [record.issue] : []));
    if (unsupported || (issues.length && !issues.some(permitsHttp01))) {
      return `CAA at ${name} blocks Let's Encrypt HTTP-01. Allow letsencrypt.org in its CAA issue records, then recheck DNS.`;
    }
    // issuewild alone does not restrict non-wildcard certificates. The nearest RRset wins.
    return null;
  }
  return null;
}

export async function dnsBlockingError(input: {
  hostname: string;
  records: StoredDnsRecord[];
  addresses: (type: string, name: string) => Promise<string[]>;
  caa: (name: string) => Promise<CaaRecord[]>;
}) {
  const { hostname, records, addresses, caa } = input;
  const [ipv4, ipv6] = await Promise.all([
    addresses("A", hostname).catch(() => null),
    addresses("AAAA", hostname).catch(() => null),
  ]);
  const proxied = [...(ipv4 ?? []), ...(ipv6 ?? [])].find(isCloudflareProxyAddress);
  if (proxied)
    return `${hostname} resolves to Cloudflare proxy address ${proxied}. Switch its record to DNS only and recheck DNS.`;
  if (!ipv4 || !ipv6)
    return `Address lookup failed for ${hostname}. Check public DNS and recheck before requesting a certificate.`;
  const unexpectedIpv6 = ipv6.find(
    (ip) =>
      !records.some(
        (record) => record.type === "AAAA" && dnsRecordVerified("AAAA", record.expectedValue, ip),
      ),
  );
  if (unexpectedIpv6)
    return `Unexpected AAAA ${hostname} → ${unexpectedIpv6}. Remove or correct it at the DNS provider, then recheck DNS.`;
  return caaError(hostname, caa);
}
