const V4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/(?:3[0-2]|[12]?\d)$/;
const V6 = /^[0-9a-f:]+\/(?:12[0-8]|1[01]\d|\d?\d)$/i;

export function parseCidr(value: string) {
  const cidr = value.trim();
  if (V4.test(cidr)) return { ok: true as const, version: 4 as const, cidr };
  if (V6.test(cidr)) return { ok: true as const, version: 6 as const, cidr };
  return { ok: false as const, cidr };
}

export function assertCidrs(values: string[]) {
  const invalid = values.filter((item) => !parseCidr(item).ok);
  if (invalid.length) throw new Error(`Invalid CIDR allowlist: ${invalid.join(", ")}`);
  return values.map((item) => item.trim());
}

export function ipv4ToInt(ip: string) {
  return ip.split(".").reduce((sum, part) => (sum << 8) + Number(part), 0) >>> 0;
}

export function clientAllowed(cidrs: string[], ip: string) {
  if (!cidrs.length) return { allowed: true, reason: "any-authenticated" as const };
  const trimmed = ip.replace(/^::ffff:/, "");
  for (const item of cidrs) {
    const parsed = parseCidr(item);
    if (!parsed.ok) continue;
    if (parsed.version === 4 && /^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) {
      const [network, bits] = item.split("/");
      const mask = bits === "0" ? 0 : (~0 << (32 - Number(bits))) >>> 0;
      if ((ipv4ToInt(trimmed) & mask) === (ipv4ToInt(network) & mask)) {
        return { allowed: true, reason: item };
      }
    }
    if (parsed.version === 6 && trimmed.includes(":")) {
      if (trimmed === item.split("/")[0] || item.endsWith("/0")) return { allowed: true, reason: item };
    }
  }
  return { allowed: false, reason: "source-not-allowlisted" as const };
}

export function nftAllowlist(cidrs: string[], port = 5432) {
  const rules = cidrs.map((cidr) => `tcp dport ${port} ip saddr ${cidr} accept`);
  return `# Generated public database source policy. Empty means any authenticated client.\n${rules.join("\n")}\n`;
}
