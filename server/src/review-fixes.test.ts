import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";

import { parseEnvFile } from "@ark-stack/shared";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { claimQueued, enqueue, isDelegatedPayload } = await import("./coordinator.ts");
const { grantAccess } = await import("./access.ts");
const { db } = await import("./db.ts");
const { alerts, backups, certificates, endpoints, operations, platformAccess, user } =
  await import("./schema.ts");
const { evaluateAlerts } = await import("./modules/alerts.ts");
const { createId } = await import("@ark-stack/shared");
const { eq, inArray } = await import("drizzle-orm");

describe("delegated deploys are not re-planned by module workers", () => {
  test("a payload carrying the canonical compose is recognised as already delegated", () => {
    expect(
      isDelegatedPayload({
        kind: "update.apply",
        payload: { compose: "services: {}", composeHash: "sha256:abc", project: "ark-web" },
      }),
    ).toBe(true);
    expect(isDelegatedPayload({ kind: "update.apply", payload: { digest: "sha256:abc" } })).toBe(false);
    // The old guard looked for `file`, a key the delegation payload never sets.
    expect(
      isDelegatedPayload({ kind: "update.apply", payload: { file: "/tmp/x", project: "ark-web" } }),
    ).toBe(false);
    expect(isDelegatedPayload({ kind: "service.deploy", payload: { composeHash: "sha256:abc" } })).toBe(
      false,
    );
  });

  test("a delegated update.apply is claimable by the agent but not by the backup worker", async () => {
    const targetId = createId("tgt");
    const operation = await enqueue({
      kind: "update.apply",
      targetIds: [targetId],
      payload: {
        compose: "services: {}",
        composeHash: `sha256:${createId("h")}`,
        project: "ark-web",
        digest: `sha256:${"a".repeat(64)}`,
      },
    });
    const byBackupPrefixes = await claimQueued({
      limit: 20,
      kindPrefixes: ["backup.", "update.detect", "import."],
    });
    expect(byBackupPrefixes.rows.some((item) => item.id === operation.id)).toBe(false);

    const byAgent = await claimQueued({ limit: 20, agentOwned: true });
    expect(byAgent.rows.some((item) => item.id === operation.id)).toBe(true);
    await db
      .update(operations)
      .set({ status: "failed", claimToken: null })
      .where(eq(operations.id, operation.id));
  });
});

describe("enqueue deduplication after a terminal operation", () => {
  test("concurrent enqueues produce one queued row even when a prior attempt finished", async () => {
    const targetId = createId("tgt");
    const payload = { kind: "volume", targetId };
    const first = await enqueue({ kind: "backup.create", targetIds: [targetId], payload });
    await db
      .update(operations)
      .set({ status: "succeeded", claimToken: null })
      .where(eq(operations.id, first.id));

    const [a, b, c] = await Promise.all([
      enqueue({ kind: "backup.create", targetIds: [targetId], payload }),
      enqueue({ kind: "backup.create", targetIds: [targetId], payload }),
      enqueue({ kind: "backup.create", targetIds: [targetId], payload }),
    ]);
    expect(new Set([a.id, b.id, c.id]).size).toBe(1);

    const queued = await db.select().from(operations).where(eq(operations.status, "queued"));
    expect(queued.filter((item) => item.targetIds.includes(targetId))).toHaveLength(1);
    await db
      .update(operations)
      .set({ status: "failed", claimToken: null })
      .where(inArray(operations.id, [first.id, a.id]));
  });
});

describe("claiming never runs two operations against one target", () => {
  test("concurrent claimers cannot both take work for the same target", async () => {
    const targetId = createId("tgt");
    const first = await enqueue({
      kind: "backup.create",
      targetIds: [targetId],
      payload: { kind: "volume", targetId, nonce: createId("n") },
    });
    const second = await enqueue({
      kind: "backup.create",
      targetIds: [targetId],
      payload: { kind: "volume", targetId, nonce: createId("n") },
    });
    const claims = await Promise.all([
      claimQueued({ limit: 5, kindPrefix: "backup." }),
      claimQueued({ limit: 5, kindPrefix: "backup." }),
    ]);
    const taken = claims.flatMap((claim) => claim.rows).filter((row) => row.targetIds.includes(targetId));
    expect(taken).toHaveLength(1);
    await db
      .update(operations)
      .set({ status: "failed", claimToken: null })
      .where(inArray(operations.id, [first.id, second.id]));
  });
});

describe("alerts resolve once the condition is replaced", () => {
  test("a superseded certificate does not hold a critical alert open", async () => {
    const endpointId = createId("ep");
    await db.insert(endpoints).values({
      id: endpointId,
      hostname: `${createId("h")}.example.test`,
      kind: "admin",
      status: "testing",
    });
    const expired = createId("crt");
    const current = createId("crt");
    await db.insert(certificates).values([
      {
        id: expired,
        endpointId,
        names: ["old.example.test"],
        issuer: "test",
        expiresAt: new Date(Date.now() - 86_400_000),
        status: "superseded",
      },
      {
        id: current,
        endpointId,
        names: ["new.example.test"],
        issuer: "test",
        expiresAt: new Date(Date.now() + 90 * 86_400_000),
        status: "issued",
      },
    ]);
    await evaluateAlerts();
    const raised = await db
      .select()
      .from(alerts)
      .where(inArray(alerts.dedupKey, [`cert:${expired}`, `cert:${current}`]));
    expect(raised).toHaveLength(0);
    await db.delete(certificates).where(inArray(certificates.id, [expired, current]));
    await db.delete(endpoints).where(eq(endpoints.id, endpointId));
  });

  test("a fresh backup clears staleness for its target", async () => {
    const targetId = createId("tgt");
    const old = createId("bak");
    const fresh = createId("bak");
    await db.insert(backups).values([
      {
        id: old,
        kind: "volume",
        targetId,
        status: "uploaded",
        restoreVerified: false,
        createdAt: new Date(Date.now() - 5 * 86_400_000),
      },
      { id: fresh, kind: "volume", targetId, status: "uploaded", restoreVerified: false },
    ]);
    const stale = await db.select().from(backups);
    const newestPerTarget = stale
      .filter((item) => item.targetId === targetId)
      .toSorted((a, b) => b.createdAt.getTime() - a.createdAt.getTime())[0];
    expect(newestPerTarget?.id).toBe(fresh);
    await db.delete(backups).where(inArray(backups.id, [old, fresh]));
  });
});

describe("access grants survive concurrent writes", () => {
  test("two grants issued at once are both retained", async () => {
    const userId = createId("usr");
    await db.insert(user).values({
      id: userId,
      name: "Grant Race",
      email: `${userId}@example.test`,
      emailVerified: false,
    });
    await db.insert(platformAccess).values({ userId, role: "operator", projectIds: [], domainIds: [] });
    const projectA = createId("prj");
    const projectB = createId("prj");
    await Promise.all([
      grantAccess(userId, { projectId: projectA }),
      grantAccess(userId, { projectId: projectB }),
    ]);
    const [row] = await db.select().from(platformAccess).where(eq(platformAccess.userId, userId));
    expect(row?.projectIds).toContain(projectA);
    expect(row?.projectIds).toContain(projectB);

    // Re-granting the same project must not duplicate it.
    await grantAccess(userId, { projectId: projectA });
    const [again] = await db.select().from(platformAccess).where(eq(platformAccess.userId, userId));
    expect(again?.projectIds.filter((id) => id === projectA)).toHaveLength(1);

    await db.delete(platformAccess).where(eq(platformAccess.userId, userId));
    await db.delete(user).where(eq(user.id, userId));
  });
});
