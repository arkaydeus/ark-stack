import { normalizeHostname } from "./hostnames.ts";

export type DnsProvider = "manual" | "cloudflare" | "other";
export type AdminMode = "public" | "tailnet";

export type DnsRecordPlan = {
  type: "A" | "AAAA" | "TXT" | "MX" | "CNAME";
  name: string;
  relativeName: string;
  value: string;
  priority?: number;
  ttl: number;
  purpose: string;
  required: boolean;
};

export type DomainPlanInput = {
  baseDomain: string;
  publicIpv4: string;
  publicIpv6?: string;
  adminMode: AdminMode;
  adminHostname?: string;
  databaseHostname?: string;
  mailHostname?: string;
  ownershipToken: string;
  includeDatabase: boolean;
  includeMail: boolean;
  existingMx?: string[];
  existingSpf?: string | null;
};

export function relativeDnsName(name: string, zone: string) {
  if (name === zone) return "@";
  if (name.endsWith(`.${zone}`)) return name.slice(0, -(zone.length + 1));
  return name;
}

export function buildDomainPlan(input: DomainPlanInput) {
  const zone = normalizeHostname(input.baseDomain);
  const records: DnsRecordPlan[] = [
    {
      type: "TXT",
      name: `_ark-stack.${zone}`,
      relativeName: `_ark-stack`,
      value: input.ownershipToken,
      ttl: 60,
      purpose: "Installation-bound domain ownership proof",
      required: true,
    },
  ];

  if (input.includeDatabase) {
    const hostname = normalizeHostname(input.databaseHostname ?? `db.${zone}`);
    records.push(
      ...addressRecords(hostname, zone, input.publicIpv4, input.publicIpv6, "Public database endpoint"),
    );
  }
  if (input.includeMail) {
    const hostname = normalizeHostname(input.mailHostname ?? `mail.${zone}`);
    records.push(
      ...addressRecords(
        hostname,
        zone,
        input.publicIpv4,
        input.publicIpv6,
        "Incoming and client mail endpoint",
      ),
    );
    if (input.existingMx?.length) {
      records.push({
        type: "MX",
        name: zone,
        relativeName: "@",
        value: `${hostname} (review existing MX: ${input.existingMx.join(", ")})`,
        priority: 10,
        ttl: 300,
        purpose: "Incoming mail — existing MX set must be reviewed before cutover",
        required: false,
      });
    } else {
      records.push({
        type: "MX",
        name: zone,
        relativeName: "@",
        value: hostname,
        priority: 10,
        ttl: 300,
        purpose: "Incoming mail for the domain",
        required: true,
      });
    }
    records.push({
      type: "TXT",
      name: zone,
      relativeName: "@",
      value: mergeSpf(input.existingSpf, "v=spf1 include:amazonses.com -all"),
      ttl: 300,
      purpose: "Outbound sender policy — merged with existing SPF, never a second SPF record",
      required: true,
    });
    records.push({
      type: "TXT",
      name: `_dmarc.${zone}`,
      relativeName: "_dmarc",
      value: `v=DMARC1; p=none; rua=mailto:dmarc@${zone}`,
      ttl: 300,
      purpose: "DMARC reporting policy",
      required: true,
    });
  }
  if (input.adminMode === "public") {
    const hostname = normalizeHostname(input.adminHostname ?? `admin.${zone}`);
    records.push(
      ...addressRecords(hostname, zone, input.publicIpv4, input.publicIpv6, "Public administration hostname"),
    );
  }

  return { zone, records };
}

function addressRecords(
  hostname: string,
  zone: string,
  ipv4: string,
  ipv6: string | undefined,
  purpose: string,
): DnsRecordPlan[] {
  const records: DnsRecordPlan[] = [
    {
      type: "A",
      name: hostname,
      relativeName: relativeDnsName(hostname, zone),
      value: ipv4,
      ttl: 300,
      purpose,
      required: true,
    },
  ];
  if (ipv6) {
    records.push({
      type: "AAAA",
      name: hostname,
      relativeName: relativeDnsName(hostname, zone),
      value: ipv6,
      ttl: 300,
      purpose: `${purpose} (IPv6)`,
      required: false,
    });
  }
  return records;
}

export function mergeSpf(existing: string | null | undefined, proposed: string) {
  if (!existing) return proposed;
  const mechanisms = new Set(
    [existing, proposed].flatMap((value) =>
      value
        .replace(/^v=spf1\s+/i, "")
        .split(/\s+/)
        .filter(Boolean)
        .filter((part) => !/^v=spf1$/i.test(part) && !/^([~+\-?]?)all$/i.test(part)),
    ),
  );
  return `v=spf1 ${[...mechanisms].join(" ")} -all`;
}

export const endpointStates = [
  "draft",
  "awaiting_dns",
  "verified",
  "issuing_certificate",
  "provisioning",
  "testing",
  "ready",
  "error",
] as const;

export type EndpointState = (typeof endpointStates)[number];

function stripDnsQuotes(value: string) {
  return value
    .trim()
    .replace(/^"+|"+$/g, "")
    .replace(/\\"/g, '"');
}

function normalizeDnsToken(type: string, value: string) {
  const trimmed = stripDnsQuotes(value).replace(/\.$/, "").trim();
  if (type === "TXT") {
    if (/^v=spf1\b/i.test(trimmed)) {
      const mechanisms = trimmed
        .replace(/^v=spf1\s+/i, "")
        .split(/\s+/)
        .filter(Boolean)
        .filter((part) => !/^([~+\-?]?)all$/i.test(part))
        .toSorted();
      return `v=spf1 ${mechanisms.join(" ")} -all`.toLowerCase();
    }
    return trimmed;
  }
  if (type === "MX") {
    const match = /^(\d+)\s+(\S+)$/.exec(trimmed);
    if (match) return `${match[1]} ${match[2].toLowerCase()}`;
    return `10 ${trimmed.toLowerCase()}`;
  }
  return trimmed.toLowerCase();
}

export function expectedDnsValue(type: string, value: string, priority?: number) {
  if (type === "MX") {
    const match = /^(\d+)\s+(\S+)$/.exec(value.trim());
    if (match) return normalizeDnsToken("MX", value);
    return normalizeDnsToken("MX", `${priority ?? 10} ${value}`);
  }
  return normalizeDnsToken(type, value);
}

export function observedDnsValue(type: string, values: string[]) {
  const normalized = values
    .map((item) => normalizeDnsToken(type, item))
    .filter(Boolean)
    .toSorted();
  return normalized.join(",");
}

export function dnsRecordVerified(type: string, expected: string, observed: string, priority?: number) {
  const want = expectedDnsValue(type, expected, priority);
  const got = observed
    .split(/[\n,]/)
    .map((item) => normalizeDnsToken(type, item))
    .filter(Boolean)
    .toSorted();
  return got.includes(want) || got.join(",") === want;
}
