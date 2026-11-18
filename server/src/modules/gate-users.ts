// Gate users (docs/design/front-door.md §3.9.6, FD-12): the people the owner lets through "Ark login"
// (SSO) routes. They sign in only on the login origin and have no `platform_access` row, so the
// admin API refuses them (FD-10) and admin-origin sign-in is refused for them (auth.ts).
//
// - Creation calls Better Auth's `signUpEmail` server-side with an explicit `gate` session origin and
//   a generated temporary password, then deletes the session sign-up minted (nobody holds it). The
//   password is sealed as a one-time secret (`secrets.once`) and leaves only through its own reveal,
//   at most once.
// - First login: until TOTP is enrolled a gate session can only enrol it on the login origin
//   (`/gate/enroll`); the gate check and authorize require MFA assurance, so no route is reachable.
// - Deletion removes the `user` row in one transaction: sessions, gate sessions, handoffs and route
//   access cascade, and the FD-11 triggers write the revocation journal and queue the forced-reload
//   drain atomically, so the affected HAProxy backends are fenced and their sessions close (§3.9.3).

import {
  GATE_USER_PASSWORD_SECRET_KIND,
  createId,
  decryptSecret,
  encryptSecret,
  generatePassword,
  type GateUserInput,
} from "@ark-stack/shared";
import { sql as statement } from "drizzle-orm";
import { HTTPException } from "hono/http-exception";

import { auth } from "../auth.ts";
import { db, sql, type DbTransaction } from "../db.ts";
import { loadEnv } from "../env.ts";
import { withSessionOrigin } from "../session-origin.ts";

/** Generated temporary passwords: 24 symbols from a 64-symbol alphabet (144 bits). */
const TEMPORARY_PASSWORD_LENGTH = 24;

export type GateUser = {
  id: string;
  email: string;
  name: string;
  createdAt: string;
  createdBy: string | null;
  mfaEnrolled: boolean;
  temporaryPassword: "unrevealed" | "revealed" | "none";
  routes: Array<{ routeId: string; hostname: string | null }>;
  activeSessions: number;
};

export async function listGateUsers(userId?: string): Promise<GateUser[]> {
  const rows = await sql`
    SELECT g.user_id, u.email, u.name, g.created_at, g.created_by, u.two_factor_enabled,
      s.id AS secret_id, s.revealed_at,
      coalesce((
        SELECT jsonb_agg(jsonb_build_object('routeId', a.route_id, 'hostname', e.hostname) ORDER BY e.hostname)
        FROM front_route_access a
        JOIN front_routes r ON r.id = a.route_id
        LEFT JOIN endpoints e ON e.id = r.endpoint_id
        WHERE a.user_id = g.user_id
      ), '[]'::jsonb) AS routes,
      (SELECT count(*)::int FROM session x WHERE x.user_id = g.user_id AND x.expires_at > now()) AS sessions
    FROM gate_users g
    JOIN "user" u ON u.id = g.user_id
    LEFT JOIN secrets s ON s.id = g.temporary_password_secret_id
    WHERE ${userId ?? null}::text IS NULL OR g.user_id = ${userId ?? null}
    ORDER BY u.email
  `;
  return rows.map((row) => ({
    id: String(row.user_id),
    email: String(row.email),
    name: String(row.name),
    createdAt: new Date(row.created_at as string).toISOString(),
    createdBy: row.created_by ? String(row.created_by) : null,
    mfaEnrolled: Boolean(row.two_factor_enabled),
    temporaryPassword: !row.secret_id ? "none" : row.revealed_at ? "revealed" : "unrevealed",
    routes: row.routes as GateUser["routes"],
    activeSessions: Number(row.sessions),
  }));
}

type Actor = { userId: string; role: string };

async function insertAudit(
  executor: Pick<DbTransaction, "execute">,
  actor: Actor,
  action: string,
  userId: string,
  detail: Record<string, unknown>,
) {
  await executor.execute(statement`
    INSERT INTO audit_events (id, actor_id, role, action, resource_type, resource_id, detail)
    VALUES (${createId("aud")}, ${actor.userId}, ${actor.role}, ${action}, 'gate-user', ${userId},
      ${JSON.stringify(detail)}::jsonb)
  `);
}

/**
 * Creates a gate user. `authorize` consumes the owner's `role.grant` step-up; it runs only after the
 * input is known good (the address is free), so a conflict does not burn the grant.
 */
export async function createGateUser(
  input: GateUserInput,
  actor: Actor,
  authorize: () => Promise<unknown>,
  /** The registered host serving this request; Better Auth derives its dynamic base URL from it. */
  baseHost: string,
): Promise<GateUser> {
  const [existing] = await sql`SELECT 1 FROM "user" WHERE lower(email) = ${input.email}`;
  if (existing)
    throw new HTTPException(409, { message: "An account with this email address already exists." });
  await authorize();

  const password = generatePassword(TEMPORARY_PASSWORD_LENGTH);
  const name = input.name ?? input.email.split("@")[0]!;
  // No request: the session sign-up mints gets its origin from this explicit scope, never a guess.
  const created = await withSessionOrigin("gate", () =>
    auth.api.signUpEmail({
      body: { name, email: input.email, password },
      // Only the canonical Host, never the owner's cookies: no request exists, so the session
      // origin comes from the explicit scope above.
      headers: new Headers({ host: baseHost }),
    }),
  );
  const userId = created.user.id;
  const env = loadEnv();
  try {
    await db.transaction(async (tx) => {
      // Sign-up signs the new account in; nobody holds that session, so it is removed at once.
      await tx.execute(statement`DELETE FROM session WHERE user_id = ${userId}`);
      const secretId = createId("sec");
      const sealed = encryptSecret(env.rootKey, password, env.rootKeyId);
      await tx.execute(statement`
        INSERT INTO secrets (id, kind, resource_type, resource_id, purpose, sensitivity, key_id, ciphertext, iv, auth_tag, once)
        VALUES (${secretId}, ${GATE_USER_PASSWORD_SECRET_KIND}, 'gate-user', ${userId}, 'gate-user', 'credential',
          ${sealed.keyId}, ${sealed.ciphertext}, ${sealed.iv}, ${sealed.authTag}, true)
      `);
      await tx.execute(statement`
        INSERT INTO gate_users (user_id, created_by, temporary_password_secret_id)
        VALUES (${userId}, ${actor.userId}, ${secretId})
      `);
      await insertAudit(tx, actor, "gate_user.create", userId, { email: input.email });
    });
  } catch (error) {
    // Never leave a half-created account (a password nobody can reveal, or no gate marker).
    await sql`DELETE FROM "user" WHERE id = ${userId}`;
    throw error;
  }
  const [user] = await listGateUsers(userId);
  return user!;
}

/**
 * Reveals a gate user's temporary password exactly once. `authorize` consumes the owner's
 * `secret.reveal` step-up after the target is known to have an unrevealed password.
 */
export async function revealGateUserPassword(
  userId: string,
  actor: Actor,
  authorize: (tx: DbTransaction) => Promise<unknown>,
) {
  const env = loadEnv();
  return db.transaction(async (tx) => {
    const [row] = await tx.execute(statement`
      SELECT g.user_id, s.id AS secret_id, s.revealed_at
      FROM gate_users g LEFT JOIN secrets s ON s.id = g.temporary_password_secret_id
      WHERE g.user_id = ${userId}
      FOR UPDATE OF g
    `);
    if (!row) throw new HTTPException(404, { message: "Gate user not found." });
    if (!row.secret_id || row.revealed_at)
      throw new HTTPException(409, {
        message: "This temporary password was already revealed. Delete the user and create it again.",
      });
    await authorize(tx);
    const [secret] = await tx.execute(statement`
      UPDATE secrets SET revealed_at = now()
      WHERE id = ${row.secret_id as string} AND revealed_at IS NULL AND once
      RETURNING ciphertext, iv, auth_tag
    `);
    if (!secret)
      throw new HTTPException(409, {
        message: "This temporary password was already revealed. Delete the user and create it again.",
      });
    await insertAudit(tx, actor, "secret.reveal", userId, { kind: GATE_USER_PASSWORD_SECRET_KIND });
    return decryptSecret(env.rootKey, {
      ciphertext: String(secret.ciphertext),
      iv: String(secret.iv),
      authTag: String(secret.auth_tag),
    });
  });
}

/**
 * Deletes a gate user and everything that authorizes them. Only gate users can be deleted here;
 * administrators are never matched. `authorize` consumes the owner's `role.grant` step-up inside the
 * same transaction, so a refused step-up deletes nothing.
 */
export async function deleteGateUser(
  userId: string,
  actor: Actor,
  authorize: (tx: DbTransaction) => Promise<unknown>,
) {
  return db.transaction(async (tx) => {
    const [row] = await tx.execute(statement`
      SELECT g.user_id, g.temporary_password_secret_id, u.email
      FROM gate_users g JOIN "user" u ON u.id = g.user_id
      WHERE g.user_id = ${userId}
      FOR UPDATE OF g, u
    `);
    if (!row) throw new HTTPException(404, { message: "Gate user not found." });
    await authorize(tx);
    const [counts] = await tx.execute(statement`
      SELECT
        (SELECT count(*)::int FROM session WHERE user_id = ${userId}) AS sessions,
        (SELECT count(*)::int FROM front_route_access WHERE user_id = ${userId}) AS route_access
    `);
    const revoked = await tx.execute(statement`
      SELECT DISTINCT route_id FROM gate_sessions WHERE user_id = ${userId} AND revoked_at IS NULL ORDER BY route_id
    `);
    // The cascade's gate-session triggers journal each affected route and queue the forced reload
    // in this transaction (migrations 0026/0028); this names the cause in the journal.
    await tx.execute(statement`SELECT set_config('ark.gate_revocation_reason', 'gate_user_deleted', true)`);
    await tx.execute(statement`DELETE FROM "user" WHERE id = ${userId}`);
    if (row.temporary_password_secret_id)
      await tx.execute(
        statement`DELETE FROM secrets WHERE id = ${row.temporary_password_secret_id as string}`,
      );
    const result = {
      id: userId,
      sessionsRemoved: Number(counts!.sessions),
      routeAccessRemoved: Number(counts!.route_access),
      revokedRouteIds: revoked.map((item) => String(item.route_id)),
    };
    await insertAudit(tx, actor, "gate_user.delete", userId, { email: row.email, ...result });
    return result;
  });
}
