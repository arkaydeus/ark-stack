import { afterAll, beforeAll, expect, test } from "bun:test";
import { createId, privilegedRequestHash, type Role } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";
import { eq, inArray, like } from "drizzle-orm";

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { db, sql } = await import("./db.ts");
const { backupTargets, secrets, user, operations, stepUpGrants } = await import("./schema.ts");
const origin = new URL(process.env.BETTER_AUTH_URL ?? "http://localhost:3000").origin;
const prefix = createId("backup-route");
type Actor = { id: string; cookie: string; sessionId: string };
const actors: Actor[] = [];
let owner: Actor, operator: Actor, noMfa: Actor;
const input = {
  name: prefix,
  provider: "minio",
  endpoint: "http://127.0.0.1:9",
  region: "us-east-1",
  bucket: "bkt",
  prefix: "ark",
  pathStyle: true,
  recoveryWindowDays: 7,
  accessKeyId: "route-writer",
  secretAccessKey: "route-secret-value-0123456789",
  repositoryPassword: "route-repository-password-0123456789",
};
async function actor(role: Role, mfa: boolean) {
  const ctx = await auth.$context;
  const u = await ctx.internalAdapter.createUser(
    { name: prefix, email: `${createId("usr")}@example.test`, emailVerified: true },
    { method: "email-password" },
  );
  await sql`INSERT INTO platform_access (user_id, role) VALUES (${u.id}, ${role})`;
  if (mfa)
    await sql`UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${u.id}`;
  const session = await ctx.internalAdapter.createSession(u.id, false, { origin: "admin" });
  const signed = `${session.token}.${await makeSignature(session.token, ctx.secret)}`;
  const result = {
    id: u.id,
    sessionId: session.id,
    cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(signed)}`,
  };
  actors.push(result);
  return result;
}
const call = (a: Actor | null, method: string, path = "/api/backups/targets", body?: unknown) =>
  app.request(path, {
    method,
    headers: { origin, "content-type": "application/json", ...(a ? { cookie: a.cookie } : {}) },
    ...(method === "GET" ? {} : { body: JSON.stringify(body ?? {}) }),
  });
async function grant(body: unknown) {
  await db.insert(stepUpGrants).values({
    id: createId("sup"),
    userId: owner.id,
    sessionId: owner.sessionId,
    action: "credential.rotate",
    planHash: privilegedRequestHash("credential.rotate", {
      backupTarget: "s3",
      ...(body as Record<string, unknown>),
    }),
    expiresAt: new Date(Date.now() + 60000),
  });
}
beforeAll(async () => {
  owner = await actor("owner", true);
  operator = await actor("operator", true);
  noMfa = await actor("owner", false);
});
afterAll(async () => {
  await db.delete(operations).where(eq(operations.actorId, owner.id));
  const targets = await db
    .select({ id: backupTargets.id })
    .from(backupTargets)
    .where(like(backupTargets.name, `${prefix}%`));
  await db.delete(backupTargets).where(like(backupTargets.name, `${prefix}%`));
  if (targets.length)
    await db.delete(secrets).where(
      inArray(
        secrets.resourceId,
        targets.map((target) => target.id),
      ),
    );
  for (const a of actors) await db.delete(user).where(eq(user.id, a.id));
});

test("backup target routes require owner access, MFA and a request-bound credential.rotate grant", async () => {
  for (const path of ["/api/backups/targets", "/api/backups/targets/s3"])
    expect((await call(null, path.endsWith("s3") ? "PUT" : "GET", path, input)).status).toBe(401);
  expect((await call(operator, "GET")).status).toBe(403);
  expect((await call(operator, "PUT", "/api/backups/targets/s3", input)).status).toBe(403);
  expect((await call(noMfa, "PUT", "/api/backups/targets/s3", input)).status).toBe(403);
  expect((await call(owner, "PUT", "/api/backups/targets/s3", input)).status).toBe(403);
  await grant(input);
  const saved = await call(owner, "PUT", "/api/backups/targets/s3", input);
  expect(saved.status).toBe(200);
  const body = await saved.json();
  const targetId = body.target.id;
  expect(body.target.configRevision).toBeTruthy();
  const [queued] = await db.select().from(operations).where(eq(operations.id, body.verifyOperationId));
  expect(queued!.payload.revision).toBe(body.target.configRevision);
  const listed = await call(owner, "GET");
  expect(listed.status).toBe(200);
  const listedBody = await listed.json();
  expect(listedBody.bucketProtectionPolicy[targetId].Statement[0].Effect).toBe("Deny");
  for (const response of [JSON.stringify(body), JSON.stringify(listedBody)]) {
    expect(response).not.toContain(input.secretAccessKey);
    expect(response).not.toContain(input.repositoryPassword);
  }
  expect((await call(operator, "POST", `/api/backups/targets/${targetId}/verify`)).status).toBe(403);
  expect((await call(owner, "POST", `/api/backups/targets/${targetId}/verify`)).status).toBe(200);
  expect((await call(owner, "POST", "/api/backups/targets/missing/verify")).status).toBe(404);
  const wrong = { ...input, id: targetId, repositoryPassword: "replacement-password-0123456789" };
  await grant(wrong);
  expect((await call(owner, "PUT", "/api/backups/targets/s3", wrong)).status).toBe(422);
});
