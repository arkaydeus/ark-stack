// Minimal S3 client with AWS Signature Version 4 for the append-only canary (front door §3.18.2,
// FD-21). The canary needs versioned reads and deletes, object retention and the governance bypass
// header, which Bun's built-in S3 client does not expose. Path-style and virtual-host addressing are
// both supported, so the same code runs against MinIO, AWS S3, Backblaze B2 and Cloudflare R2.
import { createHash, createHmac } from "node:crypto";

export type S3Credentials = { accessKeyId: string; secretAccessKey: string; sessionToken?: string };

export type S3Location = {
  /** `https://host[:port]` (or `http://` for a local MinIO). */
  endpoint: string;
  region: string;
  bucket: string;
  pathStyle: boolean;
};

export type S3Response = {
  status: number;
  headers: Headers;
  body: Uint8Array;
  text: string;
  /** S3 error `<Code>` when the response is an error document. */
  code: string | null;
};

const sha256Hex = (data: Uint8Array | string) => createHash("sha256").update(data).digest("hex");
const hmac = (key: Uint8Array | string, data: string) => createHmac("sha256", key).update(data).digest();

/** RFC 3986 encoding as SigV4 requires; `/` is kept in paths. */
export function encodeRfc3986(value: string, keepSlash = false) {
  const encoded = encodeURIComponent(value).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
  return keepSlash ? encoded.replace(/%2F/g, "/") : encoded;
}

export function normalizeEndpoint(endpoint: string) {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(endpoint) ? endpoint : `https://${endpoint}`;
  const url = new URL(withScheme);
  if (url.protocol !== "https:" && url.protocol !== "http:")
    throw new Error("S3 endpoints use http or https.");
  if (url.username || url.password) throw new Error("S3 endpoints must not embed credentials.");
  if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
    throw new Error("S3 endpoints are a scheme, host and optional port only.");
  }
  return url;
}

export type SignInput = {
  method: string;
  url: URL;
  headers: Record<string, string>;
  body: Uint8Array;
  credentials: S3Credentials;
  region: string;
  service?: string;
  now?: Date;
};

/** Signs a request in place (SigV4, header auth) and returns the headers to send. */
export function signV4(input: SignInput) {
  const now = input.now ?? new Date();
  const amzDate = now
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "");
  const date = amzDate.slice(0, 8);
  const service = input.service ?? "s3";
  const payloadHash = sha256Hex(input.body);
  const headers: Record<string, string> = {
    ...Object.fromEntries(
      Object.entries(input.headers).map(([key, value]) => [key.toLowerCase(), value.trim()]),
    ),
    host: input.url.host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
  };
  if (input.credentials.sessionToken) headers["x-amz-security-token"] = input.credentials.sessionToken;
  const signedHeaderNames = Object.keys(headers).toSorted();
  const canonicalHeaders = signedHeaderNames.map((name) => `${name}:${headers[name]}\n`).join("");
  const query = [...input.url.searchParams.entries()]
    .map(([key, value]) => [encodeRfc3986(key), encodeRfc3986(value)] as const)
    .toSorted(([a, av], [b, bv]) => (a === b ? (av < bv ? -1 : 1) : a < b ? -1 : 1))
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
  const canonicalRequest = [
    input.method,
    input.url.pathname,
    query,
    canonicalHeaders,
    signedHeaderNames.join(";"),
    payloadHash,
  ].join("\n");
  const scope = `${date}/${input.region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${input.credentials.secretAccessKey}`, date), input.region), service),
    "aws4_request",
  );
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");
  headers.authorization = `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaderNames.join(";")}, Signature=${signature}`;
  delete headers.host;
  return headers;
}

export class S3Client {
  readonly endpoint: URL;

  constructor(
    readonly location: S3Location,
    private readonly credentials: S3Credentials,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.endpoint = normalizeEndpoint(location.endpoint);
  }

  /** URL for a bucket-level (`key` undefined) or object request. */
  url(key?: string, query: Record<string, string> = {}) {
    const base = new URL(this.endpoint.href);
    const encodedKey = key === undefined ? "" : encodeRfc3986(key, true);
    if (this.location.pathStyle) {
      base.pathname = `/${encodeRfc3986(this.location.bucket)}/${encodedKey}`;
    } else {
      base.hostname = `${this.location.bucket}.${base.hostname}`;
      base.pathname = `/${encodedKey}`;
    }
    for (const [name, value] of Object.entries(query)) base.searchParams.set(name, value);
    return base;
  }

  async request(
    method: string,
    key: string | undefined,
    options: {
      query?: Record<string, string>;
      headers?: Record<string, string>;
      body?: Uint8Array | string;
    } = {},
  ): Promise<S3Response> {
    const url = this.url(key, options.query);
    const body =
      typeof options.body === "string"
        ? new TextEncoder().encode(options.body)
        : (options.body ?? new Uint8Array());
    const headers = signV4({
      method,
      url,
      headers: options.headers ?? {},
      body,
      credentials: this.credentials,
      region: this.location.region || "us-east-1",
    });
    const response = await this.fetchImpl(url, {
      method,
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : Buffer.from(body),
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    });
    const bytes = new Uint8Array(await response.arrayBuffer());
    const text = new TextDecoder().decode(bytes);
    const code = response.status >= 300 ? (/<Code>([^<]+)<\/Code>/.exec(text)?.[1] ?? null) : null;
    return { status: response.status, headers: response.headers, body: bytes, text, code };
  }
}

export function contentMd5(body: string | Uint8Array) {
  return createHash("md5").update(body).digest("base64");
}

export function xmlValue(text: string, tag: string) {
  return new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(text)?.[1] ?? null;
}
