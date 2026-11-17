import { afterAll, beforeAll, expect, test } from "bun:test";
import { repositoryProtectionPolicy, writerPolicy } from "@ark-stack/shared";
import { runAppendOnlyCanary } from "../../server/src/modules/backup-canary.ts";
import { S3Client } from "../../server/src/modules/s3-client.ts";
import { startMinio, type MinioFixture } from "./minio.ts";

let m: MinioFixture;
beforeAll(async () => {
  m = await startMinio("config-policy");
}, 60000);
afterAll(async () => {
  await m?.stop();
});

test("MinIO exact-config permission exception stays unhealthy until a bucket denial closes it", async () => {
  const bucket = "config-exception";
  await m.mc(["mb", "--with-lock", `ark/${bucket}`]);
  await m.mc(["retention", "set", "--default", "GOVERNANCE", "2d", `ark/${bucket}`]);
  const policy = writerPolicy(bucket, "ark");
  policy.Statement.find((statement) => statement.Effect === "Deny")!.Resource = [`arn:aws:s3:::${bucket}`];
  policy.Statement.push({
    Sid: "ExactConfigException",
    Effect: "Allow",
    Action: [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:BypassGovernanceRetention",
      "s3:PutObjectRetention",
    ],
    Resource: [`arn:aws:s3:::${bucket}/ark/restic/config`],
  });
  const writer = await m.createUser("config-writer", "config-writer", policy);
  const location = { endpoint: m.endpoint, region: "us-east-1", bucket, pathStyle: true };
  const client = new S3Client(location, writer);
  const run = () => runAppendOnlyCanary({ client, provider: "minio", prefix: "ark", recoveryWindowDays: 1 });
  const unsafe = await run();
  expect(unsafe.status).toBe("unknown");
  expect(unsafe.classes.every((item) => item.readback === "match")).toBe(true);
  expect(unsafe.classes.every((item) => item.attempts.permanentDelete?.outcome === "refused")).toBe(true);
  expect(unsafe.findings.some((item) => item.message.includes("exact restic config"))).toBe(true);
  const config = await client.request("PUT", "ark/restic/config", {
    body: "disposable exact config fixture",
  });
  expect(config.status).toBe(200);
  const query = { versionId: config.headers.get("x-amz-version-id")! };
  expect(
    (
      await client.request("DELETE", "ark/restic/config", {
        query,
        headers: { "x-amz-bypass-governance-retention": "true" },
      })
    ).status,
  ).toBe(204);
  expect((await client.request("GET", "ark/restic/config", { query })).status).toBe(404);

  const root = new S3Client(location, { accessKeyId: m.rootUser, secretAccessKey: m.rootPassword });
  expect(
    (
      await root.request("PUT", undefined, {
        query: { policy: "" },
        body: JSON.stringify(repositoryProtectionPolicy(bucket, "ark")),
      })
    ).status,
  ).toBe(204);
  const protectedVerdict = await run();
  expect(protectedVerdict.findings).toEqual([]);
  expect(protectedVerdict.status).toBe("append_only");
}, 60000);
