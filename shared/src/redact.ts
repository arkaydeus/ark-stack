/**
 * Matched against the key with separators removed, so `AWS_SECRET_ACCESS_KEY`, `smtp-password`
 * and `clientSecret` all normalise to something these substrings catch.
 */
const SECRET_KEY_PATTERN =
  /(password|secret|token|authorization|credential|privatekey|apikey|database[a-z]*url|connectionstring|dsn)/;

const CANARY = /(password|secret|token|authorization)=([^\s&]+)/gi;
/** Credentials embedded in a connection string, e.g. `postgres://user:pw@host/db`. */
const URL_CREDENTIAL = /(\/\/[^/\s:@]+:)([^@\s/]+)(@)/g;

function redactString(value: string) {
  return value.replace(CANARY, "$1=<redacted>").replace(URL_CREDENTIAL, "$1<redacted>$3");
}

export function isSecretKey(key: string) {
  return SECRET_KEY_PATTERN.test(key.toLowerCase().replaceAll("-", "").replaceAll("_", ""));
}

export function redactValue(value: unknown): unknown {
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        isSecretKey(key) ? "<redacted>" : redactValue(item),
      ]),
    );
  }
  return value;
}

export function redactLogLine(line: string, canaries: string[] = []) {
  let next = redactString(line);
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
