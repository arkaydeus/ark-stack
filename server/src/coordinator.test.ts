import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";

import { isInFlight, parseEnvFile } from "@ark-stack/shared";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { claimQueued, enqueue, processQueued, setDnsResolver } = await import("./coordinator.ts");
const { db } = await import("./db.ts");
const { backups, dnsRecords, domainClaims, operations } = await import("./schema.ts");
const { createId } = await import("@ark-stack/shared");
const { eq } = await import("drizzle-orm");

describe("coordinator enqueue and claims", () => {
  test("agent claims only fully prepared immutable jobs", async () => {
    const targetId = createId("tgt");
    const raw = await enqueue({ kind: "service.deploy", targetIds: [targetId], payload: {} });
    const prepared = await enqueue({
      kind: "service.logs",
      targetIds: [createId("tgt")],
      payload: { name: "web" },
    });
    const claimed = await claimQueued({ limit: 20, agentOwned: true });
    expect(claimed.rows.some((item) => item.id === raw.id)).toBe(false);
    expect(claimed.rows.some((item) => item.id === prepared.id)).toBe(true);
    await db
      .update(operations)
      .set({ status: "failed", claimToken: null })
      .where(eq(operations.id, prepared.id));
    await db.update(operations).set({ status: "failed" }).where(eq(operations.id, raw.id));
  });

  test("repeats backup.create after a succeeded operation", async () => {
    const target = createId("tgt");
    const first = await enqueue({
      kind: "backup.create",
      targetIds: [target],
      payload: { kind: "volume", targetId: target },
    });
    await db.update(operations).set({ status: "succeeded" }).where(eq(operations.id, first.id));
    const second = await enqueue({
      kind: "backup.create",
      targetIds: [target],
      payload: { kind: "volume", targetId: target },
    });
    expect(second.id).not.toBe(first.id);
    expect(isInFlight(second.status)).toBe(true);
  });

  test("concurrent processQueued claims a queued row once and refuses plan-only backup success", async () => {
    const targetId = createId("tgt");
    const first = await enqueue({
      kind: "backup.create",
      targetIds: [targetId],
      payload: { kind: "volume", targetId },
    });
    await Promise.all([processQueued(8), processQueued(8)]);
    const [row] = await db.select().from(operations).where(eq(operations.id, first.id));
    expect(row?.status).toBe("failed");
    expect(row?.error).toMatch(/plan cannot satisfy/);
  });

  test("restore tests mark the newest backup for a target", async () => {
    const target = createId("tgt");
    const older = createId("bak");
    const newer = createId("bak");
    await db.insert(backups).values([
      {
        id: older,
        kind: "volume",
        targetId: target,
        status: "uploaded",
        restoreVerified: false,
        createdAt: new Date(Date.now() - 60_000),
      },
      {
        id: newer,
        kind: "volume",
        targetId: target,
        status: "uploaded",
        restoreVerified: false,
        createdAt: new Date(),
      },
    ]);
    const operation = await enqueue({
      kind: "backup.restore_test",
      targetIds: [target],
      payload: { kind: "volume", targetId: target, backupId: newer },
    });
    await processQueued(8);
    const [oldRow] = await db.select().from(backups).where(eq(backups.id, older));
    const [newRow] = await db.select().from(backups).where(eq(backups.id, newer));
    const [op] = await db.select().from(operations).where(eq(operations.id, operation.id));
    expect(op?.status).toBe("failed");
    expect(oldRow?.restoreVerified).toBe(false);
    expect(newRow?.status).toBe("uploaded");
    expect(newRow?.restoreVerified).toBe(false);
  });

  test("verifies a mail-enabled DNS plan including MX", async () => {
    const domainId = createId("dom");
    const domainName = `verify-${domainId.slice(-8)}.example`;
    await db.insert(domainClaims).values({
      id: domainId,
      name: domainName,
      ownershipToken: "ark-own-test",
      status: "awaiting_dns",
    });
    await db.insert(dnsRecords).values([
      {
        id: createId("dns"),
        domainId,
        type: "TXT",
        name: `_ark-stack.${domainName}`,
        relativeName: "_ark-stack",
        expectedValue: "ark-own-test",
        purpose: "ownership",
        required: true,
      },
      {
        id: createId("dns"),
        domainId,
        type: "A",
        name: "mail.verify.example",
        relativeName: "mail",
        expectedValue: "203.0.113.10",
        purpose: "mail",
        required: true,
      },
      {
        id: createId("dns"),
        domainId,
        type: "MX",
        name: "verify.example",
        relativeName: "@",
        expectedValue: "mail.verify.example",
        purpose: "mail",
        required: true,
      },
    ]);
    const previousStub = process.env.ARK_DNS_STUB;
    process.env.ARK_DNS_STUB = "0";
    setDnsResolver({
      txt: async () => [["ark-own-test"]],
      a: async () => ["203.0.113.10"],
      aaaa: async () => [],
      mx: async () => [{ priority: 10, exchange: "mail.verify.example" }],
      cname: async () => [],
    });
    try {
      const operation = await enqueue({
        kind: "domain.verify",
        targetIds: [domainId],
        payload: { domainId },
      });
      await processQueued(8);
      const [op] = await db.select().from(operations).where(eq(operations.id, operation.id));
      const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, domainId));
      expect(op?.status).toBe("succeeded");
      expect(domain?.status).toBe("verified");
    } finally {
      setDnsResolver();
      if (previousStub === undefined) delete process.env.ARK_DNS_STUB;
      else process.env.ARK_DNS_STUB = previousStub;
    }
  });

  test("does not verify a domain with no ownership records", async () => {
    const domainId = createId("dom");
    await db.insert(domainClaims).values({
      id: domainId,
      name: `empty-${domainId.slice(-8)}.example`,
      ownershipToken: "ark-own-unpublished",
      status: "awaiting_dns",
    });
    const operation = await enqueue({ kind: "domain.verify", targetIds: [domainId] });
    await processQueued(8);
    const [op] = await db.select().from(operations).where(eq(operations.id, operation.id));
    const [domain] = await db.select().from(domainClaims).where(eq(domainClaims.id, domainId));
    expect(op?.status).toBe("failed");
    expect(domain?.status).not.toBe("verified");
  });
});
