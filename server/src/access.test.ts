import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

import { createId, parseEnvFile, privilegedRequestHash, type Access, type Role } from "@ark-stack/shared";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { consumePrivilegedGrant, requireDomainMailbox, requireOperator, requireOwner, requirePrivileged } =
  await import("./access.ts");
const { db } = await import("./db.ts");
const { domainClaims, mailboxes, stepUpGrants, user } = await import("./schema.ts");

async function seedOperator() {
  const userId = createId("usr");
  const sessionId = createId("ses");
  await db.insert(user).values({
    id: userId,
    name: "Step-up operator",
    email: `${userId}@example.test`,
    twoFactorEnabled: true,
    mfaEnrolledAt: new Date(Date.now() - 60_000),
  });
  return {
    access: { userId, role: "owner" as const, projectIds: [], domainIds: [] },
    session: {
      user: {
        id: userId,
        name: "Step-up operator",
        email: `${userId}@example.test`,
        twoFactorEnabled: true,
        mfaEnrolledAt: new Date(Date.now() - 60_000),
      },
      session: { id: sessionId, createdAt: new Date() },
    },
  };
}

describe("privileged step-up consumption", () => {
  test("consumes a grant once and rejects replay, mismatch, expiry, and a losing concurrent call", async () => {
    const { access, session } = await seedOperator();
    const plan = privilegedRequestHash("secret.reveal", { secretId: "sec_bound" });
    const other = privilegedRequestHash("secret.reveal", { secretId: "sec_other" });
    const grantId = createId("sup");
    await db.insert(stepUpGrants).values({
      id: grantId,
      userId: access.userId,
      sessionId: session.session.id,
      action: "secret.reveal",
      planHash: plan,
      expiresAt: new Date(Date.now() + 10 * 60_000),
    });

    await expect(requirePrivileged(access, session, "secret.reveal", other)).rejects.toThrow(
      /Verify your password/,
    );

    const [first, second] = await Promise.allSettled([
      requirePrivileged(access, session, "secret.reveal", plan),
      requirePrivileged(access, session, "secret.reveal", plan),
    ]);
    const outcomes = [first.status, second.status].toSorted();
    expect(outcomes).toEqual(["fulfilled", "rejected"]);
    await expect(requirePrivileged(access, session, "secret.reveal", plan)).rejects.toThrow(
      /Verify your password/,
    );

    const [consumed] = await db.select().from(stepUpGrants).where(eq(stepUpGrants.id, grantId));
    expect(consumed?.consumedAt).toBeInstanceOf(Date);

    await db.insert(stepUpGrants).values({
      id: createId("sup"),
      userId: access.userId,
      sessionId: session.session.id,
      action: "secret.reveal",
      planHash: plan,
      expiresAt: new Date(Date.now() - 1000),
    });
    expect(
      await consumePrivilegedGrant({
        userId: access.userId,
        sessionId: session.session.id,
        action: "secret.reveal",
        expectedPlanHash: plan,
      }),
    ).toBeNull();
  });

  test("alias reconciliation requires a mailbox on the same domain", async () => {
    const domainA = createId("dom");
    const domainB = createId("dom");
    await db.insert(domainClaims).values([
      { id: domainA, name: `${domainA}.example`, ownershipToken: "own-a" },
      { id: domainB, name: `${domainB}.example`, ownershipToken: "own-b" },
    ]);
    await db.insert(mailboxes).values({
      id: createId("mbx"),
      domainId: domainA,
      localPart: "owner",
      displayName: "Owner",
    });
    const mailbox = await requireDomainMailbox(domainA);
    expect(mailbox.domainId).toBe(domainA);
    await expect(requireDomainMailbox(domainB)).rejects.toThrow(/mailbox on this domain/);
  });
});

function accessFor(role: Role): Access {
  return { userId: `usr_${role}`, role, projectIds: [], domainIds: [] };
}

describe("owner-only route management", () => {
  test("requireOwner admits owners and refuses operators and viewers with 403", () => {
    expect(() => requireOwner(accessFor("owner"))).not.toThrow();
    for (const role of ["operator", "viewer"] as const) {
      let status = 0;
      try {
        requireOwner(accessFor(role));
      } catch (error) {
        status = (error as { status?: number }).status ?? 0;
      }
      expect(status).toBe(403);
    }
    // Operators still pass the operator gate, so requireOwner is the stricter check.
    expect(() => requireOperator(accessFor("operator"))).not.toThrow();
  });

  test("a route-management handler guarded by requireOwner answers 403 to operators and viewers", async () => {
    const app = new Hono<{ Variables: { access: Access } }>();
    app.use("*", async (c, next) => {
      c.set("access", accessFor((c.req.header("x-test-role") ?? "viewer") as Role));
      await next();
    });
    app.post("/api/front/routes", (c) => {
      requireOwner(c.get("access"));
      return c.json({ ok: true }, 201);
    });
    const call = (role: Role) =>
      app.request("/api/front/routes", { method: "POST", headers: { "x-test-role": role } });
    expect((await call("owner")).status).toBe(201);
    const operator = await call("operator");
    expect(operator.status).toBe(403);
    expect(await operator.text()).toContain("Owner access is required.");
    expect((await call("viewer")).status).toBe(403);
  });
});
