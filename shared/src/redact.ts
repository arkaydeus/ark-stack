const SECRET_KEYS = new Set([
  "password",
  "secret",
  "token",
  "authorization",
  "credential",
  "privatekey",
  "private_key",
  "accesstoken",
  "access_token",
  "refreshtoken",
  "refresh_token",
  "smtppassword",
  "databaseurl",
]);

const CANARY = /(password|secret|token|authorization)=([^\s&]+)/gi;

export function redactValue(value: unknown): unknown {
  if (typeof value === "string") return value.replace(CANARY, "$1=<redacted>");
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        SECRET_KEYS.has(key.toLowerCase().replaceAll("-", "")) ? "<redacted>" : redactValue(item),
      ]),
    );
  }
  return value;
}

export function redactLogLine(line: string, canaries: string[] = []) {
  let next = line.replace(CANARY, "$1=<redacted>");
  for (const canary of canaries) {
    if (canary) next = next.split(canary).join("<redacted>");
  }
  return [...next]
    .filter((char) => {
      const code = char.charCodeAt(0);
      return code > 31 || code === 9 || code === 10 || code === 13;
    })
    .join("");
}

export function omitSensitiveLabels(labels: Record<string, string>) {
  return Object.fromEntries(
    Object.entries(labels).filter(([key]) => !/(secret|password|token|credential)/i.test(key)),
  );
}
