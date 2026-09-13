const HOSTNAME =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".invalid", ".example", ".test"];

export function normalizeHostname(value: string) {
  const trimmed = value.trim().replace(/\.$/, "").toLowerCase();
  if (
    !trimmed ||
    [...trimmed].some((char) => {
      const code = char.charCodeAt(0);
      return code < 32 || code === 127;
    })
  ) {
    throw new Error("Hostname contains control characters or is empty.");
  }
  let ascii = trimmed;
  try {
    ascii = trimmed
      .split(".")
      .map((label) => (label.startsWith("xn--") ? label : punycodeLabel(label)))
      .join(".");
  } catch {
    throw new Error("Hostname is not a valid domain name.");
  }
  if (ascii.includes("..") || ascii.startsWith(".") || ascii.endsWith(".")) {
    throw new Error("Hostname is malformed.");
  }
  if (!HOSTNAME.test(ascii)) throw new Error("Enter a fully-qualified hostname, such as db.example.com.");
  if (ascii === "localhost" || BLOCKED_SUFFIXES.some((suffix) => ascii.endsWith(suffix))) {
    throw new Error("Reserved or special-use names cannot be claimed as public service hostnames.");
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ascii)) throw new Error("Use a hostname, not an IP address.");
  return ascii;
}

function punycodeLabel(label: string) {
  if (/^[a-z0-9-]+$/.test(label)) return label;
  return `xn--${label}`;
}

export function localPart(value: string) {
  const trimmed = value.trim();
  if (!/^[A-Za-z0-9.!#$%&'*+=?^_`{|}~-]+$/.test(trimmed)) {
    throw new Error("Mailbox local part contains unsupported characters.");
  }
  if (trimmed.includes("/") || trimmed.startsWith(".") || trimmed.endsWith(".") || trimmed.includes("..")) {
    throw new Error("Mailbox local part cannot include path separators or adjacent dots.");
  }
  return trimmed.toLowerCase();
}

export function postgresIdent(value: string, suffix = "") {
  const ident = `${value}${suffix}`.toLowerCase();
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(ident)) {
    throw new Error(`PostgreSQL identifier ${ident} exceeds limits or uses unsupported characters.`);
  }
  return ident;
}

export function quoteIdent(value: string) {
  return `"${value.replaceAll('"', '""')}"`;
}
