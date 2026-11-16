import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { generateInstallSecrets } from "@ark-stack/shared";
import postgres from "postgres";

const sourceUrl = process.env.DATABASE_URL;
if (!sourceUrl) throw new Error("DATABASE_URL is required for the upgrade migration test.");
const parsed = new URL(sourceUrl);
if (!["127.0.0.1", "localhost", "::1"].includes(parsed.hostname)) {
  throw new Error("Upgrade migration tests refuse a non-loopback PostgreSQL endpoint.");
}
const root = join(import.meta.dir, "..");
const databaseName = `ark_upgrade_${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
if (!/^ark_upgrade_[a-f0-9]{12}$/.test(databaseName)) throw new Error("Unsafe disposable database name.");
const databaseUrl = new URL(sourceUrl);
databaseUrl.pathname = `/${databaseName}`;
const admin = postgres(sourceUrl, { max: 1 });
const legacyUser = {
  id: "legacy-upgrade-user",
  name: "Legacy Owner",
  email: "legacy-owner@example.com",
};
const legacyPassword = "Legacy-Upgrade-Password-123!";
// Fixed scrypt fixture (N=16384, r=16, p=1, 64-byte key), independent of the
// upgraded library's hash function so sign-in must accept an existing hash.
const legacyAccount = {
  id: "legacy-upgrade-account",
  account_id: legacyUser.id,
  provider_id: "credential",
  user_id: legacyUser.id,
  password:
    "0123456789abcdef0123456789abcdef:be37d324a8b88b115aa8f3e16c8ae13c575bcd3f3846e66dddfdd7559af107edac38b954feb0bd0065b0702ac6f5a958534ae850b367ec28c45fe6fce02eff7f",
};
const createdAt = new Date("2025-01-02T03:04:05.000Z");
// A signed-in session from before the front door existed (0013 adds a required session.origin).
const legacySession = {
  id: "legacy-upgrade-session",
  token: "legacy-upgrade-session-token",
  user_id: legacyUser.id,
  expires_at: new Date("2099-01-01T00:00:00.000Z"),
};

function runMigration() {
  return new Promise<void>((resolve, reject) => {
    const child = spawn("bun", ["server/src/migrate.ts"], {
      cwd: root,
      env: { ...process.env, DATABASE_URL: databaseUrl.toString() },
      stdio: "inherit",
    });
    child.once("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`upgrade migration process exited ${code}`)),
    );
  });
}

try {
  await admin.unsafe(`CREATE DATABASE "${databaseName}"`);
  const target = postgres(databaseUrl.toString(), { max: 1 });
  try {
    await target.unsafe(`
      CREATE TABLE ark_migrations (
        id text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);
    const files = (await readdir(join(root, "server", "drizzle")))
      .filter((file) => /^000[0-3]_.*\.sql$/.test(file))
      .toSorted();
    for (const file of files) {
      await target.unsafe(await Bun.file(join(root, "server", "drizzle", file)).text());
      await target`INSERT INTO ark_migrations (id) VALUES (${file})`;
    }
    // Insert through the legacy schema, including its required issuer column.
    await target`
      INSERT INTO "user" (id, name, email, email_verified, created_at, updated_at)
      VALUES (${legacyUser.id}, ${legacyUser.name}, ${legacyUser.email}, true, ${createdAt}, ${createdAt})
    `;
    await target`
      INSERT INTO account (id, issuer, account_id, provider_id, user_id, password, created_at, updated_at)
      VALUES (${legacyAccount.id}, 'http://localhost:3000', ${legacyAccount.account_id},
        ${legacyAccount.provider_id}, ${legacyAccount.user_id}, ${legacyAccount.password}, ${createdAt}, ${createdAt})
    `;
    await target`
      INSERT INTO session (id, expires_at, token, user_id, created_at, updated_at)
      VALUES (${legacySession.id}, ${legacySession.expires_at}, ${legacySession.token},
        ${legacySession.user_id}, ${createdAt}, ${createdAt})
    `;
    await target`INSERT INTO platform_settings (id) VALUES ('default') ON CONFLICT DO NOTHING`;
  } finally {
    await target.end();
  }
  await runMigration();
  const verified = postgres(databaseUrl.toString(), { max: 1 });
  try {
    const migration = await verified`SELECT 1 FROM ark_migrations WHERE id = '0010_worker_heartbeats.sql'`;
    const stateful = await verified`
      SELECT 1 FROM information_schema.columns
      WHERE table_name = 'services' AND column_name = 'stateful'
    `;
    if (!migration.length || !stateful.length)
      throw new Error("Representative upgrade did not reach the current schema.");
    const accountIssuer = await verified`
      SELECT 1 FROM information_schema.columns
      WHERE table_name = 'account' AND column_name = 'issuer'
    `;
    const accountIssuerIndex = await verified`
      SELECT 1 FROM pg_indexes WHERE indexname = 'account_issuer_account_id_idx'
    `;
    if (accountIssuer.length || accountIssuerIndex.length)
      throw new Error("Upgrade left the legacy Better Auth account.issuer column or index behind.");
    const [retainedUser] = await verified`SELECT * FROM "user" WHERE id = ${legacyUser.id}`;
    assert.deepEqual(
      retainedUser,
      {
        ...legacyUser,
        email_verified: true,
        image: null,
        two_factor_enabled: false,
        mfa_enrolled_at: null,
        created_at: createdAt,
        updated_at: createdAt,
      },
      "Upgrade must preserve the existing user.",
    );
    const [retainedAccount] = await verified`
      SELECT id, account_id, provider_id, user_id, password, created_at, updated_at
      FROM account WHERE id = ${legacyAccount.id}
    `;
    assert.deepEqual(
      retainedAccount,
      {
        ...legacyAccount,
        created_at: createdAt,
        updated_at: createdAt,
      },
      "Upgrade must preserve the existing credential account and password hash.",
    );

    // 0013_front_door.sql must run after 0012_drop_account_issuer.sql over the same install.
    const applied = await verified`SELECT id FROM ark_migrations ORDER BY id`;
    const order = applied.map((row) => row.id as string);
    assert.ok(order.includes("0013_front_door.sql"), "The front-door migration must be applied.");
    assert.equal(
      order.indexOf("0013_front_door.sql"),
      order.indexOf("0012_drop_account_issuer.sql") + 1,
      "0013 must follow 0012 directly.",
    );
    const [origin] = await verified`
      SELECT is_nullable, column_default FROM information_schema.columns
      WHERE table_name = 'session' AND column_name = 'origin'
    `;
    assert.deepEqual(origin, { is_nullable: "NO", column_default: null }, "session.origin has no default.");
    const [retainedSession] = await verified`
      SELECT id, token, user_id, origin FROM session WHERE id = ${legacySession.id}
    `;
    assert.deepEqual(
      retainedSession,
      { id: legacySession.id, token: legacySession.token, user_id: legacySession.user_id, origin: "admin" },
      "Existing sessions must be backfilled to origin = admin.",
    );
    await assert.rejects(
      verified`
        INSERT INTO session (id, expires_at, token, user_id)
        VALUES ('missing-origin', now() + interval '1 day', 'missing-origin-token', ${legacyUser.id})
      `,
      /null value in column "origin"/,
      "A session insert that omits origin must fail.",
    );
    const [frontDoorSettings] = await verified`
      SELECT pooler_source_cidrs, pooler_allow_internet, gate_login_mode
      FROM platform_settings WHERE id = 'default'
    `;
    assert.deepEqual(
      frontDoorSettings,
      { pooler_source_cidrs: [], pooler_allow_internet: false, gate_login_mode: "disabled" },
      "Front-door exposure must default closed on upgrade.",
    );
    const frontDoorTables = await verified`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name IN ('tailnet_snapshots', 'tailnet_nodes',
        'private_cas', 'front_routes', 'front_route_access', 'gate_handoffs', 'gate_sessions',
        'client_certificates', 'database_clients', 'vercel_integrations', 'backup_targets')
    `;
    assert.equal(frontDoorTables.length, 11, "Every front-door table must exist after the upgrade.");

    // Import the production auth configuration only after selecting the disposable
    // database, so its singleton connection cannot touch the source database.
    const authUrl = "http://127.0.0.1:3000";
    Object.assign(process.env, generateInstallSecrets(), {
      DATABASE_URL: databaseUrl.toString(),
      BETTER_AUTH_URL: authUrl,
      BETTER_AUTH_TRUSTED_ORIGINS: authUrl,
    });
    const { sql } = await import("../server/src/db.ts");
    try {
      const { auth } = await import("../server/src/auth.ts");
      const signIn = (password: string) =>
        auth.handler(
          new Request(`${authUrl}/api/auth/sign-in/email`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Origin: authUrl },
            body: JSON.stringify({ email: legacyUser.email, password }),
          }),
        );
      const rejected = await signIn(`${legacyPassword}-wrong`);
      assert.equal(rejected.status, 401, "An incorrect legacy password must be rejected.");
      assert.equal((await rejected.json()).code, "INVALID_EMAIL_OR_PASSWORD");
      const sessions = await verified`
        SELECT id FROM session WHERE user_id = ${legacyUser.id} AND id <> ${legacySession.id}
      `;
      assert.equal(sessions.length, 0, "A rejected password must not create a session.");

      const accepted = await signIn(legacyPassword);
      assert.equal(accepted.status, 200, "The existing password must still sign in after upgrade.");
      const signedIn = await accepted.json();
      assert.equal(signedIn.user.id, legacyUser.id);
      assert.equal(signedIn.user.email, legacyUser.email);
      assert.ok(signedIn.token, "Successful sign-in must return a session token.");
      const [session] = await verified`
        SELECT user_id, origin FROM session WHERE token = ${signedIn.token}
      `;
      assert.equal(session?.user_id, legacyUser.id, "The token must belong to the migrated user.");
      assert.equal(session?.origin, "admin", "A sign-in on the admin origin must record origin = admin.");
    } finally {
      await sql.end();
    }
    console.log(
      "Legacy credential data preserved; incorrect password rejected and correct password signed in.\n" +
        "0013_front_door.sql applied after 0012; legacy session backfilled to origin = admin; " +
        "an insert omitting origin was refused; new sign-in recorded origin = admin.",
    );
  } finally {
    await verified.end();
  }
} finally {
  await admin`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ${databaseName} AND pid <> pg_backend_pid()`;
  const exists = await admin`SELECT 1 FROM pg_database WHERE datname = ${databaseName}`;
  if (exists.length) await admin.unsafe(`DROP DATABASE "${databaseName}"`);
  await admin.end();
}
