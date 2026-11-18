import type { DomainDnsReview } from "./dns-review.ts";
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
  ipv6Status?: Ipv6Status;
  aaaaEnabled?: boolean;
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
  const ipv6 = aaaaAllowed({
    publicIpv6: input.publicIpv6,
    ipv6Status: input.ipv6Status ?? "unchecked",
    aaaaEnabled: input.aaaaEnabled ?? true,
  })
    ? input.publicIpv6
    : undefined;
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
    records.push(...addressRecords(hostname, zone, input.publicIpv4, ipv6, "Public database endpoint"));
  }
  if (input.includeMail) {
    const hostname = normalizeHostname(input.mailHostname ?? `mail.${zone}`);
    records.push(
      ...addressRecords(hostname, zone, input.publicIpv4, ipv6, "Incoming and client mail endpoint"),
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
    records.push(...addressRecords(hostname, zone, input.publicIpv4, ipv6, "Public administration hostname"));
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

export type Ipv6Status = "unchecked" | "passed" | "failed" | "not_present";

/** Effective AAAA for a domain (R9): the IPv6 preflight passed and the domain's switch is on. */
export function aaaaAllowed(input: {
  publicIpv6?: string | null;
  ipv6Status: Ipv6Status | string;
  aaaaEnabled: boolean;
}) {
  return Boolean(input.publicIpv6) && input.ipv6Status === "passed" && input.aaaaEnabled;
}

/**
 * Address records for a front-door route hostname (§3.13.1): an A record for the public IPv4,
 * always, and an AAAA record only when `aaaaAllowed`. A published AAAA is required, because a
 * broken one breaks IPv6 clients and Let's Encrypt (which prefers IPv6). Apex and `www` need no
 * special casing: Ark only writes A/AAAA, never a CNAME at the apex.
 */
export function routeAddressRecords(input: {
  hostname: string;
  zone: string;
  publicIpv4: string;
  publicIpv6?: string | null;
  ipv6Status: Ipv6Status | string;
  aaaaEnabled: boolean;
  purpose: string;
}): DnsRecordPlan[] {
  const hostname = normalizeHostname(input.hostname);
  const zone = normalizeHostname(input.zone);
  if (hostname !== zone && !hostname.endsWith(`.${zone}`)) {
    throw new Error(`${hostname} is not inside the domain ${zone}.`);
  }
  const relativeName = relativeDnsName(hostname, zone);
  const records: DnsRecordPlan[] = [
    {
      type: "A",
      name: hostname,
      relativeName,
      value: input.publicIpv4,
      ttl: 300,
      purpose: input.purpose,
      required: true,
    },
  ];
  if (aaaaAllowed(input)) {
    records.push({
      type: "AAAA",
      name: hostname,
      relativeName,
      value: input.publicIpv6!,
      ttl: 300,
      purpose: `${input.purpose} (IPv6)`,
      required: true,
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
  if (type === "AAAA" && trimmed.includes(":")) {
    try {
      return new URL("http://[" + trimmed + "]/").hostname.slice(1, -1);
    } catch {
      return trimmed.toLowerCase();
    }
  }
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

export function manualDnsGuides(
  zone: string,
  names: string[],
  includeAaaa: boolean,
): DomainDnsReview["guides"] {
  return [
    {
      title: "Namecheap",
      url: "https://www.namecheap.com/support/knowledgebase/article.aspx/434/2237/how-do-i-set-up-host-records-for-a-domain/",
      steps: [
        "Open Domain List → Manage → Advanced DNS → Host Records. Use this panel for BasicDNS, PremiumDNS or FreeDNS.",
        "Choose Add New Record and select A Record for IPv4 or AAAA Record for IPv6. Enter @ for the apex or www for the www hostname, and copy the value shown below.",
        "Use Automatic TTL. For a removal, delete the row that matches the listed type, host and prior value.",
      ],
    },
    {
      title: "Other DNS providers",
      steps: [
        `Find the authoritative DNS provider with dig NS ${zone} +short and open its DNS editor.`,
        "Enter the type, relative host, value and TTL shown below. If the provider asks for a full hostname, use the full name shown.",
        "Resolve conflicting records and turn off any DNS proxy or forwarding. Where CAA restricts issuance, allow letsencrypt.org.",
        "Remove the exact rows marked for removal, wait for the TTL, then recheck DNS.",
        ...names.flatMap((name) => [
          `Check IPv4 with dig A ${name} @1.1.1.1 +short.`,
          ...(includeAaaa ? [`Check IPv6 with dig AAAA ${name} @1.1.1.1 +short.`] : []),
        ]),
      ],
    },
  ];
}
