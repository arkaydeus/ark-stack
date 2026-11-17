import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";

import { r2RetentionUntil, runAppendOnlyCanary } from "./backup-canary.ts";
import { S3Client, signV4 } from "./s3-client.ts";

describe("SigV4 (FD-21 canary client)", () => {
  test("matches the AWS documentation example (GET Object with Range)", () => {
    // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html, "GET Object".
    const headers = signV4({
      method: "GET",
      url: new URL("https://examplebucket.s3.amazonaws.com/test.txt"),
      headers: { range: "bytes=0-9" },
      body: new Uint8Array(),
      credentials: {
        accessKeyId: "AKIAIOSFODNN7EXAMPLE",
        secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      },
      region: "us-east-1",
      now: new Date("2013-05-24T00:00:00Z"),
    });
    expect(headers.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
    );
  });

  test("path-style and virtual-host addressing", () => {
    const credentials = { accessKeyId: "a", secretAccessKey: "b" };
    const path = new S3Client(
      { endpoint: "http://127.0.0.1:9000", region: "us-east-1", bucket: "bkt", pathStyle: true },
      credentials,
    );
    expect(path.url("ark/restic/data/x y").href).toBe("http://127.0.0.1:9000/bkt/ark/restic/data/x%20y");
    const dns = new S3Client(
      { endpoint: "https://s3.amazonaws.com", region: "us-east-1", bucket: "bkt", pathStyle: false },
      credentials,
    );
    expect(dns.url(undefined, { versioning: "" }).href).toBe("https://bkt.s3.amazonaws.com/?versioning=");
  });
});

const xmlError = (status: number, code: string) =>
  new Response(`<Error><Code>${code}</Code></Error>`, {
    status,
    headers: { "content-type": "application/xml" },
  });

type Store = Map<string, Array<{ versionId: string; body: Uint8Array }>>;

/**
 * A tiny versioned S3 stand-in. `unsupported` lists subresources answered with 501 NotImplemented,
 * like a provider that cannot report or enforce retention.
 */
function fakeS3(unsupported: string[]) {
  const store: Store = new Map();
  let counter = 0;
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const url = new URL(request.url);
      const [, , ...keyParts] = url.pathname.split("/");
      const key = decodeURIComponent(keyParts.join("/"));
      const sub = [...url.searchParams.keys()].find((name) => name !== "versionId") ?? "";
      if (sub && unsupported.includes(sub)) return xmlError(501, "NotImplemented");
      if (!key) {
        if (sub === "versioning" && request.method === "GET") {
          return new Response("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>");
        }
        return xmlError(403, "AccessDenied");
      }
      const versions = store.get(key) ?? [];
      const versionId = url.searchParams.get("versionId");
      if (request.method === "PUT" && !sub) {
        const entry = { versionId: `v${++counter}`, body: new Uint8Array(await request.arrayBuffer()) };
        store.set(key, [...versions, entry]);
        return new Response("", { headers: { "x-amz-version-id": entry.versionId } });
      }
      if (request.method === "GET" && !sub) {
        const found = versionId ? versions.find((item) => item.versionId === versionId) : versions.at(-1);
        return found ? new Response(Buffer.from(found.body)) : xmlError(404, "NoSuchKey");
      }
      if (request.method === "DELETE") {
        if (key.includes("/locks/") && !versionId) {
          store.delete(key);
          return new Response(null, { status: 204 });
        }
        return xmlError(403, "AccessDenied");
      }
      if (sub === "retention") return xmlError(403, "AccessDenied");
      return xmlError(400, "InvalidRequest");
    },
  });
  return { server, endpoint: `http://127.0.0.1:${server.port}` };
}

describe("append-only canary verdicts", () => {
  test("unsupported retention and policy checks are unknown, never healthy", async () => {
    const { server, endpoint } = fakeS3(["retention", "object-lock", "lifecycle", "policy"]);
    try {
      const client = new S3Client(
        { endpoint, region: "us-east-1", bucket: "bkt", pathStyle: true },
        { accessKeyId: "a", secretAccessKey: "b" },
      );
      const evidence = await runAppendOnlyCanary({
        client,
        provider: "other",
        prefix: "ark",
        recoveryWindowDays: 7,
      });
      expect(evidence.status).toBe("unknown");
      expect(evidence.findings.some((item) => /could not be evaluated/.test(item.message))).toBe(true);
      expect(evidence.findings.some((item) => /retention could not be read/.test(item.message))).toBe(true);
      // Deletions were refused and history kept, yet that alone is not "append-only: yes".
      expect(evidence.classes.every((item) => item.readback === "match")).toBe(true);
      expect(JSON.stringify(evidence)).not.toContain('"b"');
    } finally {
      server.stop(true);
    }
  });

  test("R2 without the read-only verifier stays unknown", async () => {
    const { server, endpoint } = fakeS3(["retention", "object-lock", "lifecycle", "policy", "versioning"]);
    try {
      const client = new S3Client(
        { endpoint, region: "auto", bucket: "bkt", pathStyle: true },
        { accessKeyId: "a", secretAccessKey: "b" },
      );
      const evidence = await runAppendOnlyCanary({
        client,
        provider: "r2",
        prefix: "ark",
        recoveryWindowDays: 7,
      });
      expect(evidence.status).toBe("unknown");
      expect(evidence.findings.map((item) => item.message)).toContain(
        "R2 bucket lock rules need the read-only Cloudflare verifier token to be proven",
      );
    } finally {
      server.stop(true);
    }
  });

  test("B2 key capabilities: deleteFiles makes the target deletable", async () => {
    const { server, endpoint } = fakeS3(["object-lock", "lifecycle", "policy"]);
    const b2Fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).includes("b2_authorize_account")) {
        return Response.json({
          apiInfo: { storageApi: { capabilities: ["listFiles", "readFiles", "writeFiles", "deleteFiles"] } },
        });
      }
      return fetch(input, init);
    }) as typeof fetch;
    try {
      const client = new S3Client(
        { endpoint, region: "us-east-005", bucket: "bkt", pathStyle: true },
        { accessKeyId: "a", secretAccessKey: "b" },
      );
      const evidence = await runAppendOnlyCanary({
        client,
        provider: "b2",
        prefix: "ark",
        recoveryWindowDays: 7,
        writer: { accessKeyId: "a", secretAccessKey: "b" },
        fetchImpl: b2Fetch,
      });
      expect(evidence.status).toBe("deletable");
      expect(evidence.findings.map((item) => item.message)).toContain(
        "the B2 application key holds deleteFiles",
      );
    } finally {
      server.stop(true);
    }
  });

  test("R2 lock rules must cover every protected prefix and must not lock locks/", () => {
    const now = new Date("2026-11-17T00:00:00Z");
    const covering = {
      rules: ["data/", "index/", "snapshots/", "keys/", "config"]
        .map((item) => ({
          enabled: true,
          prefix: `ark/restic/${item}`,
          condition: { type: "Age", maxAgeSeconds: 40 * 86_400 },
        }))
        .concat([
          {
            enabled: true,
            prefix: "ark/ark-canary/",
            condition: { type: "Age", maxAgeSeconds: 35 * 86_400 },
          },
        ]),
    };
    expect(r2RetentionUntil(covering, "ark", now)?.toISOString()).toBe("2026-12-22T00:00:00.000Z");
    expect(r2RetentionUntil({ rules: covering.rules.slice(1) }, "ark", now)).toBeNull();
    // A bucket-wide rule would also lock restic's locks/: not counted.
    expect(
      r2RetentionUntil(
        { rules: [{ enabled: true, prefix: "", condition: { type: "Indefinite" } }] },
        "ark",
        now,
      ),
    ).toBeNull();
  });
});

// Keeps the hash helper honest for the fake store above.
test("sha256 helper sanity", () => {
  expect(createHash("sha256").update("").digest("hex")).toBe(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
});
