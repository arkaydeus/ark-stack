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

export function parseIpv6(ip: string) {
  const trimmed = ip
    .trim()
    .replace(/^\[|\]$/g, "")
    .split("%")[0];
  if (!trimmed.includes(":")) return null;
  if (trimmed.includes(".")) {
    const lastColon = trimmed.lastIndexOf(":");
    const v4 = trimmed.slice(lastColon + 1);
    const v6 = `${trimmed.slice(0, lastColon)}:0:0`;
    const mapped = parseIpv6(v6.replace(/:0:0$/, ""));
    if (!mapped) return null;
    const bytes = new Uint8Array(16);
    bytes.set(mapped.slice(0, 12), 0);
    const parts = v4.split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
      return null;
    }
    bytes[12] = parts[0];
    bytes[13] = parts[1];
    bytes[14] = parts[2];
    bytes[15] = parts[3];
    return bytes;
  }
  const halves = trimmed.split("::");
  if (halves.length > 2) return null;
  const head = ipv6Parts(halves[0] ?? "");
  const tail = halves.length === 2 ? ipv6Parts(halves[1] ?? "") : [];
  if (head.some((item) => !item) || tail.some((item) => !item)) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 0 : head.length !== 8) return null;
  const parts = halves.length === 2 ? [...head, ...Array(missing).fill("0"), ...tail] : head;
  if (parts.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/i.test(parts[i] ?? "")) return null;
    const value = Number.parseInt(parts[i] ?? "0", 16);
    bytes[i * 2] = (value >> 8) & 0xff;
    bytes[i * 2 + 1] = value & 0xff;
  }
  return bytes;
}

function ipv6Parts(part: string) {
  return part ? part.split(":") : [];
}

function prefixMatch(value: Uint8Array, network: Uint8Array, bits: number) {
  const full = Math.floor(bits / 8);
  const rem = bits % 8;
  for (let i = 0; i < full; i++) {
    if (value[i] !== network[i]) return false;
  }
  if (rem === 0) return true;
  const mask = (0xff << (8 - rem)) & 0xff;
  return (value[full] & mask) === (network[full] & mask);
}

export function clientAllowed(cidrs: string[], ip: string) {
  if (!cidrs.length) return { allowed: true, reason: "any-authenticated" as const };
  const trimmed = ip.replace(/^\[|\]$/g, "").replace(/^::ffff:/, "");
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
    if (parsed.version === 6) {
      const client = parseIpv6(trimmed);
      const [network, bits] = item.split("/");
      const net = parseIpv6(network);
      if (client && net && prefixMatch(client, net, Number(bits))) {
        return { allowed: true, reason: item };
      }
    }
  }
  return { allowed: false, reason: "source-not-allowlisted" as const };
}

export function nftAllowlist(cidrs: string[], port = 5432) {
  const valid = cidrs.map((item) => parseCidr(item)).filter((item) => item.ok);
  if (!valid.length) {
    return `# Generated public database source policy. Empty means any authenticated client.\ntable inet ark_db_ingress\ndelete table inet ark_db_ingress\n`;
  }
  const v4 = valid.filter((item) => item.version === 4).map((item) => `    ip saddr ${item.cidr} accept`);
  const v6 = valid.filter((item) => item.version === 6).map((item) => `    ip6 saddr ${item.cidr} accept`);
  return `#!/usr/sbin/nft -f
# Generated public database source policy. Default deny applies only to tcp/${port}.
# input covers a host-namespace listener; forward covers Docker DNAT to a published port.
table inet ark_db_ingress
delete table inet ark_db_ingress
table inet ark_db_ingress {
  chain input {
    type filter hook input priority -1; policy accept;
    tcp dport ${port} jump ark_db_allow
  }
  chain forward {
    type filter hook forward priority -1; policy accept;
    ct status dnat tcp dport ${port} jump ark_db_allow
  }
  chain ark_db_allow {
${[...v4, ...v6].join("\n")}
    drop
  }
}
`;
}
