import { createHash, createHmac } from "node:crypto";

const DATE = "11111111";
const SERVICE = "ses";
const MESSAGE = "SendRawEmail";
const TERMINAL = "aws4_request";

function sign(key: Buffer | string, message: string) {
  return createHmac("sha256", key).update(message).digest();
}

export function deriveSesSmtpPassword(secretAccessKey: string, region: string) {
  let signature = sign(`AWS4${secretAccessKey}`, DATE);
  signature = sign(signature, region);
  signature = sign(signature, SERVICE);
  signature = sign(signature, TERMINAL);
  signature = sign(signature, MESSAGE);
  return Buffer.concat([Buffer.from([0x04]), signature]).toString("base64");
}

export function sesIdentityPlan(input: { domain: string; mailFrom: string; region: string }) {
  return {
    identity: input.domain,
    mailFrom: input.mailFrom,
    dkim: "easy",
    region: input.region,
    recordsNeeded: [
      { type: "CNAME", purpose: "DKIM" },
      { type: "MX", purpose: "MAIL FROM" },
      { type: "TXT", purpose: "MAIL FROM SPF" },
    ],
  };
}

export function hashPayload(body: string) {
  return createHash("sha256").update(body).digest("hex");
}

export function awsSigningKey(secret: string, date: string, region: string, service: string) {
  const kDate = sign(`AWS4${secret}`, date);
  const kRegion = sign(kDate, region);
  const kService = sign(kRegion, service);
  return sign(kService, "aws4_request");
}

export function signAwsRequest(input: {
  method: string;
  path: string;
  query?: string;
  region: string;
  service: string;
  accessKey: string;
  secretKey: string;
  body?: string;
  now?: Date;
}) {
  const now = input.now ?? new Date();
  const date = now.toISOString().slice(0, 10).replaceAll("-", "");
  const dateTime = `${date}T${now.toISOString().slice(11, 19).replaceAll(":", "")}Z`;
  const payload = input.body ?? "";
  const payloadHash = hashPayload(payload);
  const host =
    input.service === "ses"
      ? `email.${input.region}.amazonaws.com`
      : `${input.service}.${input.region}.amazonaws.com`;
  const headerMap: Record<string, string> = {
    host,
    "x-amz-date": dateTime,
    "x-amz-content-sha256": payloadHash,
  };
  const names = Object.keys(headerMap).toSorted();
  const canonicalHeaders = `${names.map((name) => `${name}:${headerMap[name]}`).join("\n")}\n`;
  const canonical = [
    input.method,
    input.path,
    input.query ?? "",
    canonicalHeaders,
    names.join(";"),
    payloadHash,
  ].join("\n");
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", dateTime, scope, hashPayload(canonical)].join("\n");
  const signature = createHmac("sha256", awsSigningKey(input.secretKey, date, input.region, input.service))
    .update(stringToSign)
    .digest("hex");
  return {
    url: `https://${host}${input.path}${input.query ? `?${input.query}` : ""}`,
    headers: {
      ...headerMap,
      authorization: `AWS4-HMAC-SHA256 Credential=${input.accessKey}/${scope}, SignedHeaders=${names.join(";")}, Signature=${signature}`,
    },
    body: payload,
  };
}
