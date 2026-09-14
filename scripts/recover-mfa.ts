import { randomBytes, timingSafeEqual } from "node:crypto";

import { sql } from "../server/src/db.ts";

const email = (process.argv[2] ?? "").trim().toLowerCase();
const confirmation = process.argv[3] ?? "";
const suppliedToken = process.argv[4] ?? "";
const recoveryToken = process.env.ARK_MFA_RECOVERY_TOKEN ?? "";

function equal(left: string, right: string) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

if (!email || confirmation !== `RESET:${email}` || !recoveryToken || !equal(suppliedToken, recoveryToken)) {
  console.error(
    "Usage: bun scripts/recover-mfa.ts <owner-email> RESET:<owner-email> <ARK_MFA_RECOVERY_TOKEN>",
  );
  process.exit(1);
}

await sql.begin(async (tx) => {
  await tx`SELECT pg_advisory_xact_lock(8042103)`;
  const [owner] = await tx`
    SELECT u.id
    FROM "user" u
    JOIN platform_access a ON a.user_id = u.id
    WHERE lower(u.email) = ${email} AND a.role = 'owner'
    FOR UPDATE
  `;
  if (!owner) throw new Error("The requested account is not an owner.");
  await tx`DELETE FROM two_factor WHERE user_id = ${owner.id}`;
  await tx`DELETE FROM step_up_grants WHERE user_id = ${owner.id}`;
  await tx`DELETE FROM session WHERE user_id = ${owner.id}`;
  await tx`
    UPDATE "user"
    SET two_factor_enabled = false, mfa_enrolled_at = NULL, updated_at = now()
    WHERE id = ${owner.id}
  `;
  await tx`
    INSERT INTO audit_events(id, actor_id, action, resource_type, resource_id, role, detail)
    VALUES (${`aud_${randomBytes(16).toString("hex")}`}, ${owner.id}, 'mfa.recovery_reset',
            'user', ${owner.id}, 'owner', '{"source":"host-recovery"}'::jsonb)
  `;
});

await sql.end();
console.log("MFA enrollment was reset. All sessions were revoked; sign in and enroll again immediately.");
