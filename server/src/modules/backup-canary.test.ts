import { fakeS3 } from "./test-backup-s3.ts";
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { repositoryProtectionPolicy } from "@ark-stack/shared";

import { protectsRepositoryPolicy, r2RetentionUntil, runAppendOnlyCanary } from "./backup-canary.ts";
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

  for (const failure of ["501", "500", "timeout"] as const) {
    test(`destructive ${failure} stays unknown with successful original and retention readbacks`, async () => {
      const { server, endpoint } = fakeS3([], failure);
      try {
        const evidence = await runAppendOnlyCanary({
          client: new S3Client(
            { endpoint, region: "auto", bucket: "bkt", pathStyle: true },
            { accessKeyId: "a", secretAccessKey: "b" },
          ),
          provider: "minio",
          prefix: "ark",
          recoveryWindowDays: 7,
        });
        expect(evidence.status).toBe("unknown");
        expect(evidence.classes.every((item) => item.readback === "match")).toBe(true);
        expect(evidence.classes.every((item) => item.attempts.permanentDelete?.outcome !== "refused")).toBe(
          true,
        );
      } finally {
        server.stop(true);
      }
    });
  }

  test("an IAM exception on exact config is not covered by sibling canaries", async () => {
    const policy = repositoryProtectionPolicy("bkt", "ark");
    policy.Statement[0]!.Resource = ["arn:aws:s3:::bkt/ark/restic/config.ark-canary-*"];
    const { server, endpoint } = fakeS3([], undefined, policy);
    try {
      const evidence = await runAppendOnlyCanary({
        client: new S3Client(
          { endpoint, region: "auto", bucket: "bkt", pathStyle: true },
          { accessKeyId: "a", secretAccessKey: "b" },
        ),
        provider: "minio",
        prefix: "ark",
        recoveryWindowDays: 7,
      });
      expect(evidence.status).toBe("unknown");
      expect(evidence.findings.some((item) => item.message.includes("exact restic config"))).toBe(true);
    } finally {
      server.stop(true);
    }
    expect(protectsRepositoryPolicy(repositoryProtectionPolicy("bkt", "ark"), "bkt", "ark")).toBe(true);
    expect(protectsRepositoryPolicy(policy, "bkt", "ark")).toBe(false);
  });

  test("R2 bucket errors remain unknown despite valid indefinite verifier rules", async () => {
    const { server, endpoint } = fakeS3(["versioning", "object-lock"], "bucket500");
    const rules = [
      "restic/data/",
      "restic/index/",
      "restic/snapshots/",
      "restic/keys/",
      "restic/config",
      "ark-canary/",
    ].map((part) => ({ enabled: true, prefix: `ark/${part}`, condition: { type: "Indefinite" } }));
    try {
      const evidence = await runAppendOnlyCanary({
        client: new S3Client(
          { endpoint, region: "auto", bucket: "bkt", pathStyle: true },
          { accessKeyId: "a", secretAccessKey: "b" },
        ),
        provider: "r2",
        prefix: "ark",
        recoveryWindowDays: 7,
        verifier: { accountId: "fixture", token: "read-only" },
        fetchImpl: (async () => Response.json({ result: { rules } })) as unknown as typeof fetch,
      });
      expect(evidence.status).toBe("unknown");
      expect(evidence.findings.some((item) => item.message.includes("bucket-level"))).toBe(true);
    } finally {
      server.stop(true);
    }
    for (const condition of [
      { type: "Age", maxAgeSeconds: 3650 * 86400 },
      { type: "Date", date: "2099-01-01" },
    ]) {
      expect(
        r2RetentionUntil({ rules: rules.map((rule) => ({ ...rule, condition })) }, "ark", new Date()),
      ).toBeNull();
    }
  });

  test("unversioned R2 requires indefinite protection even for aged repository dependencies", async () => {
    const { server, endpoint } = fakeS3(
      ["versioning", "object-lock", "retention", "lifecycle", "policy"],
      undefined,
      undefined,
      undefined,
      true,
    );
    const rules = [
      "restic/data/",
      "restic/index/",
      "restic/snapshots/",
      "restic/keys/",
      "restic/config",
      "ark-canary/",
    ].map((part) => ({ enabled: true, prefix: `ark/${part}`, condition: { type: "Indefinite" } }));
    try {
      for (const finite of [true, false]) {
        const evidence = await runAppendOnlyCanary({
          client: new S3Client(
            { endpoint, region: "auto", bucket: "bkt", pathStyle: true },
            { accessKeyId: "a", secretAccessKey: "b" },
          ),
          provider: "r2",
          prefix: "ark",
          recoveryWindowDays: 7,
          verifier: { accountId: "fixture", token: "read-only" },
          fetchImpl: (async () =>
            Response.json({
              result: {
                rules: finite
                  ? rules.map((rule) => ({ ...rule, condition: { type: "Age", maxAgeSeconds: 30 * 86400 } }))
                  : rules,
              },
            })) as unknown as typeof fetch,
        });
        expect(evidence.classes.every((item) => item.readback === "match")).toBe(true);
        expect(evidence.status).toBe(finite ? "unknown" : "append_only");
      }
    } finally {
      server.stop(true);
    }
  });

  test("a destructive transport timeout is not a denial", async () => {
    const { server, endpoint } = fakeS3([]);
    try {
      const client = new S3Client(
        { endpoint, region: "auto", bucket: "bkt", pathStyle: true },
        { accessKeyId: "a", secretAccessKey: "b" },
      );
      const request = client.request.bind(client);
      client.request = async (...args) => {
        if (args[0] === "DELETE" && args[2]?.query?.versionId) throw new Error("operation timed out");
        return request(...args);
      };
      const evidence = await runAppendOnlyCanary({
        client,
        provider: "minio",
        prefix: "ark",
        recoveryWindowDays: 7,
      });
      expect(evidence.status).toBe("unknown");
      expect(evidence.classes.every((item) => item.attempts.permanentDelete?.outcome === "error")).toBe(true);
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
          condition: { type: "Indefinite" },
        }))
        .concat([
          {
            enabled: true,
            prefix: "ark/ark-canary/",
            condition: { type: "Indefinite" },
          },
        ]),
    };
    expect(r2RetentionUntil(covering, "ark", now)?.toISOString()).toBe("9999-12-31T00:00:00.000Z");
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
