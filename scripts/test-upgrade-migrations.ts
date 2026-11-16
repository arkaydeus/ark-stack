import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
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
const policyState = await mkdtemp(join(tmpdir(), "ark-ingress-upgrade-"));
const ingressContainer = `ark-upgrade-ingress-${databaseName}`;
const ingressVolume = `${ingressContainer}-state`;
const ingressImage = "ark-db-ingress-test:local";

async function docker(args: string[], stdin?: string) {
  const child = Bun.spawn(["docker", ...args], {
    stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) throw new Error(`upgrade docker ${args[0]} failed: ${(stderr || stdout).slice(-2000)}`);
  return args[0] === "logs" ? stdout + stderr : stdout;
}

async function startIngress() {
  // Same pinned Bun base and packages as scripts/test-db-ingress.ts; Docker shares the
  // build cache. A separate netns keeps this upgrade from touching the host firewall.
  await docker(
    ["build", "--quiet", "-t", ingressImage, "-"],
    `FROM oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61
RUN apt-get update \
  && apt-get install -y --no-install-recommends nftables iproute2 \
  && rm -rf /var/lib/apt/lists/*
`,
  );
  const workerEntry = join(policyState, "startup-worker.ts");
  await writeFile(
    workerEntry,
    `import { processQueued } from ${JSON.stringify(join(root, "server/src/coordinator.ts"))};
import { sql } from ${JSON.stringify(join(root, "server/src/db.ts"))};
try { await processQueued(1, "pgbouncer."); } finally { await sql.end(); }
`,
  );
  const bundleDir = join(policyState, "bundle");
  // Build separately so entries from different filesystem roots keep flat output names.
  for (const entry of [join(root, "scripts", "database-ingress.ts"), workerEntry]) {
    const bundle = await Bun.build({ entrypoints: [entry], outdir: bundleDir, target: "bun" });
    if (!bundle.success) throw new Error(`Cannot bundle upgrade runtime: ${bundle.logs.join(" ")}`);
  }
  await writeFile(join(policyState, "pgbouncer", "expose"), "0\n");
  // Both processes use the installer's Linux ownership. Avoid macOS bind-mount inode
  // replacement semantics when the worker atomically publishes its next policy.
  await docker(["volume", "create", ingressVolume]);
  await docker([
    "run",
    "--rm",
    "-v",
    `${policyState}:/fixtures:ro`,
    "-v",
    `${ingressVolume}:/state`,
    ingressImage,
    "sh",
    "-ec",
    "cp -R /fixtures/pgbouncer /state/; chown -R 1000:1000 /state; chmod 700 /state/pgbouncer; chmod 600 /state/pgbouncer/*",
  ]);
  await docker([
    "run",
    "--detach",
    "--name",
    ingressContainer,
    "--add-host",
    "host.docker.internal:host-gateway",
    "--user",
    "0:0",
    "--cap-drop",
    "ALL",
    "--cap-add",
    "NET_ADMIN",
    "--cap-add",
    "DAC_OVERRIDE",
    "--security-opt",
    "no-new-privileges:true",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=64m",
    "-v",
    `${ingressVolume}:/state`,
    "-v",
    `${bundleDir}:/bundle:ro`,
    "-e",
    "ARK_PGBOUNCER_DIR=/state/pgbouncer",
    "-e",
    "ARK_DB_INGRESS_METRICS_DIR=/state/metrics",
    "-e",
    "ARK_EMBEDDED_WORKERS=0",
    "-e",
    "ARK_RUNTIME_ROLE=worker",
    "-e",
    "NODE_ENV=production",
    ingressImage,
    "bun",
    "/bundle/database-ingress.js",
  ]);
  for (let attempt = 0; attempt < 100; attempt++) {
    const status = await ingressFile("pgbouncer/allowlist.status").catch(() => "");
    if (status.includes("applied=true\n")) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const status = await ingressFile("pgbouncer/allowlist.status").catch(() => "missing status");
  const logs = await docker(["logs", ingressContainer]).catch((error) => String(error));
  throw new Error(`Upgrade ingress reconciler did not load the legacy policy: ${status} ${logs}`);
}

function ingressFile(file: string) {
  return docker(["exec", ingressContainer, "cat", `/state/${file}`]);
}

async function runIngressWorker(fail = false) {
  const workerUrl = new URL(databaseUrl);
  workerUrl.hostname = "host.docker.internal";
  await docker([
    "exec",
    "--user",
    "1000:1000",
    "-e",
    `DATABASE_URL=${workerUrl}`,
    "-e",
    `ARK_ROOT_KEY=${process.env.ARK_ROOT_KEY}`,
    ...(fail ? ["-e", "ARK_ALLOWLIST_HELPER=/state/apply-helper"] : []),
    ingressContainer,
    "bun",
    "/bundle/startup-worker.js",
  ]);
}

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
    await target`INSERT INTO database_clusters (id, name) VALUES ('legacy-cluster', 'legacy')`;
    await target`INSERT INTO managed_databases (id, cluster_id, name, exposure)
      VALUES ('legacy-public-db', 'legacy-cluster', 'legacy_public', 'public')`;
    await mkdir(join(policyState, "pgbouncer"));
    await writeFile(
      join(policyState, "pgbouncer", "allowlist.nft"),
      `table inet ark_db_ingress
delete table inet ark_db_ingress
table inet ark_db_ingress {
  chain input {
    type filter hook input priority -1; policy accept;
    tcp dport 5432 accept
  }
  chain forward {
    type filter hook forward priority -1; policy accept;
    ct status dnat tcp dport 5432 accept
  }
}
`,
    );
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
    // 0014_region.sql (FD-03) must follow 0013 and default the existing install to us-east.
    assert.equal(
      order.indexOf("0014_region.sql"),
      order.indexOf("0013_front_door.sql") + 1,
      "0014 must follow 0013 directly.",
    );
    const [regionSettings] = await verified`
      SELECT region, vps_region_label FROM platform_settings WHERE id = 'default'
    `;
    assert.deepEqual(
      regionSettings,
      { region: "us-east", vps_region_label: null },
      "An upgraded install must report region = us-east with no VPS region label.",
    );
    await assert.rejects(
      verified`UPDATE platform_settings SET region = 'mars-1' WHERE id = 'default'`,
      /platform_settings_region_check/,
      "Only the shared/src/region.ts presets may be stored.",
    );
    // 0017 stores the defaults; the startup reconciliation below upgrades the persisted policy.
    const [ingressLimits] = await verified`
      SELECT db_ingress_max_connections, db_ingress_rate_per_second, db_ingress_rate_burst
      FROM platform_settings WHERE id = 'default'
    `;
    assert.deepEqual(
      ingressLimits,
      { db_ingress_max_connections: 128, db_ingress_rate_per_second: 30, db_ingress_rate_burst: 60 },
      "An upgraded install must default to 128 concurrent and 30/s (burst 60) per source on tcp/5432.",
    );
    await assert.rejects(
      verified`UPDATE platform_settings SET db_ingress_max_connections = 0 WHERE id = 'default'`,
      /platform_settings_db_ingress_limits_check/,
      "A zero connection cap would lock every client out.",
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
    // Start the actual API with external workers, as on a host upgrade. It must queue a
    // reload without any owner action. The worker path below executes that same operation.
    Object.assign(process.env, {
      ARK_PGBOUNCER_DIR: join(policyState, "pgbouncer"),
      ARK_EMBEDDED_WORKERS: "0",
      ARK_LISTEN_PORT: "0",
      NODE_ENV: "production",
    });
    await startIngress();
    assert.ok(
      !(await docker(["exec", ingressContainer, "nft", "list", "table", "inet", "ark_db_ingress"])).includes(
        "ark_db_limits",
      ),
      "The pre-upgrade kernel table must lack FD-18 limits.",
    );
    delete process.env.ARK_ALLOWLIST_HELPER;
    delete process.env.ARK_APPLY_NFT;
    const api = spawn("bun", ["server/src/index.ts"], { cwd: root, env: process.env, stdio: "inherit" });
    try {
      for (let attempt = 0; attempt < 100; attempt++) {
        const [queued] = await verified`SELECT id FROM operations WHERE kind = 'pgbouncer.reload'
          AND payload->>'reason' = 'startup-db-ingress-policy'`;
        if (queued) break;
        if (api.exitCode !== null || attempt === 99)
          throw new Error("API startup did not enqueue policy reconciliation.");
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    } finally {
      api.kill("SIGTERM");
      await new Promise((resolve) => api.once("exit", resolve));
    }
    const { sql } = await import("../server/src/db.ts");
    try {
      const { reconcileDatabaseIngressOnStartup } = await import("../server/src/coordinator.ts");
      const first = await reconcileDatabaseIngressOnStartup();
      const repeated = await reconcileDatabaseIngressOnStartup();
      assert.equal(
        first?.id,
        repeated?.id,
        "Repeated startup reconciliation must reuse the in-flight operation.",
      );
      // Execute as the external worker: it waits for the real host reconciler's exact
      // policy acknowledgement, with no privileged helper in the worker process.
      await runIngressWorker();
      const [appliedPolicy] = await verified`SELECT status, error FROM operations WHERE id = ${first!.id}`;
      if (appliedPolicy?.status !== "succeeded") {
        const status = await ingressFile("pgbouncer/allowlist.status").catch(() => "missing status");
        const logs = await docker(["logs", ingressContainer]);
        throw new Error(`Startup policy operation failed: ${appliedPolicy?.error}\n${status}\n${logs}`);
      }
      const upgradedPolicy = await ingressFile("pgbouncer/allowlist.nft");
      assert.ok(upgradedPolicy.includes("chain ark_db_limits"));
      assert.ok(upgradedPolicy.includes("ct count over 128"));
      assert.ok(upgradedPolicy.includes("limit rate over 30/second burst 60 packets"));
      assert.ok(upgradedPolicy.includes("counter drop_conn4"));
      assert.ok(!upgradedPolicy.includes("delete table"));
      const installed = await docker([
        "exec",
        ingressContainer,
        "nft",
        "list",
        "table",
        "inet",
        "ark_db_ingress",
      ]);
      for (const expected of [
        "ark_db_limits",
        "ct count over 128",
        "limit rate over 30/second burst 60 packets",
        "drop_conn4",
        "drop_conn6",
        "drop_rate4",
        "drop_rate6",
      ]) {
        assert.ok(installed.includes(expected), `Startup must install ${expected} in the kernel.`);
      }
      assert.equal(await ingressFile("pgbouncer/expose"), "1\n");
      assert.equal(
        await ingressFile("pgbouncer/pgbouncer.ini").catch(() => "missing"),
        "missing",
        "Startup must reconcile the policy without rewriting PgBouncer config.",
      );
      // An apply failure on the next startup is observable as a failed operation.
      await docker([
        "exec",
        ingressContainer,
        "sh",
        "-ec",
        "printf '#!/bin/sh\necho simulated-apply-failure >&2\nexit 1\n' > /state/apply-helper; chmod 755 /state/apply-helper",
      ]);
      const retry = await reconcileDatabaseIngressOnStartup();
      await runIngressWorker(true);
      const [failure] = await verified`SELECT status, error FROM operations WHERE id = ${retry!.id}`;
      assert.equal(failure?.status, "failed");
      assert.match(failure!.error, /simulated-apply-failure/);
      delete process.env.ARK_ALLOWLIST_HELPER;
      console.log(
        "Startup upgraded the legacy public database policy without user action; duplicate startup was idempotent; apply failure was surfaced.",
      );
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
        "an insert omitting origin was refused; new sign-in recorded origin = admin.\n" +
        "0014_region.sql applied after 0013; the upgraded install reports region = us-east.",
    );
  } finally {
    await verified.end();
  }
} finally {
  await admin`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ${databaseName} AND pid <> pg_backend_pid()`;
  const exists = await admin`SELECT 1 FROM pg_database WHERE datname = ${databaseName}`;
  if (exists.length) await admin.unsafe(`DROP DATABASE "${databaseName}"`);
  await admin.end();
  await docker(["rm", "--force", ingressContainer]).catch(() => undefined);
  await docker(["volume", "rm", "--force", ingressVolume]).catch(() => undefined);
  await rm(policyState, { recursive: true, force: true });
}
