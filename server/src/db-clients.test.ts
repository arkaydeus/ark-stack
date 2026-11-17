// Database clients through the real app, Better Auth sessions, step-up grants, the database
// worker's operations and the application cluster (front door §3.10.3, §3.12, FD-17).
//
// PgBouncer itself is not running here (no admin socket, ARK_PGBOUNCER_RELOAD unset): the worker
// still renders and writes the files it would RELOAD, and this suite checks them. The live
// PgBouncer behaviour (connect, read-only preview, revoke with KILL_CLIENT) is covered by
// scripts/test-pgbouncer-public.ts against the pinned containers.

import { afterAll, beforeAll, beforeEach, describe, expect, test, spyOn } from "bun:test";
import { createPublicKey, generateKeyPairSync, X509Certificate } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createId, parseEnvFile, PGBOUNCER_FILES, type Role } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";
import postgres from "postgres";

import { buildCsr, extensionRequest } from "./modules/csr-test-kit.ts";

if (!process.env.DATABASE_URL && existsSync(".env")) {
  Object.assign(process.env, parseEnvFile(await Bun.file(".env").text()));
}

const { app } = await import("./app.ts");
const { auth } = await import("./auth.ts");
const { sql, db } = await import("./db.ts");
const clientModule = await import("./modules/db-clients.ts");
const { runOperation } = await import("./coordinator.ts");
const x509 = await import("./modules/x509.ts");

const authUrl = process.env.BETTER_AUTH_URL ?? "http://localhost:3000";
const origin = new URL(authUrl).origin;
const password = "Db-Clients-Test-Password-123!";
const appUrl = process.env.DATABASE_APP_URL ?? "";

type Actor = { userId: string; cookie: string };
const actors = {} as Record<
  Role | "ownerWithoutMfa" | "rateOwner" | "recoveryOwner" | "raceOwner" | "crossOwner",
  Actor
>;
const suffix = createId("x")
  .slice(-8)
  .toLowerCase()
  .replace(/[^a-z0-9]/g, "0");
const dbName = `fd17_${suffix}`;
const databaseId = createId("mdb");
const clusterId = createId("dcl");
const endpointId = createId("end");
const hostname = `db-${suffix}.example.com`;
const saved: Record<string, string | undefined> = {};
let work = "";
let originalRegion: string | undefined;
const revealedSecrets: string[] = [];

async function signUp(role: Role, mfa: boolean): Promise<Actor> {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser(
    { name: `Clients ${role}`, email: `${createId("usr")}@example.com`, emailVerified: true },
    { method: "email-password" },
  );
  await ctx.internalAdapter.linkAccount({
    userId: created.id,
    providerId: "credential",
    accountId: created.id,
    password: await ctx.password.hash(password),
  });
  await sql`INSERT INTO platform_access (user_id, role) VALUES (${created.id}, ${role})`;
  if (mfa) {
    await sql`
      UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute'
      WHERE id = ${created.id}
    `;
  }
  const session = await ctx.internalAdapter.createSession(created.id, false, { origin: "admin" });
  const signed = `${session.token}.${await makeSignature(session.token, ctx.secret)}`;
  return { userId: created.id, cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(signed)}` };
}

function call(actor: Actor, path: string, init: { method?: string; body?: unknown } = {}) {
  return app.request(`${origin}${path}`, {
    method: init.method ?? "GET",
    headers: {
      cookie: actor.cookie,
      origin,
      ...(init.method && init.method !== "GET" ? { "content-type": "application/json" } : {}),
    },
    body:
      init.body === undefined
        ? init.method && init.method !== "GET"
          ? "{}"
          : undefined
        : JSON.stringify(init.body),
  });
}

async function stepUp(actor: Actor, action: string, request: Record<string, unknown>) {
  const response = await call(actor, "/api/step-up", { method: "POST", body: { password, action, request } });
  expect(response.status).toBe(200);
}

const clientsPath = `/api/databases/${databaseId}/clients`;

/** Claim and execute exactly this operation, as the database worker does. */
async function runQueued(operationId: string, runtime?: Parameters<typeof runOperation>[2]) {
  const [row] = await sql`
    UPDATE operations SET status = 'running', claim_token = ${createId("claim")}, heartbeat_at = now()
    WHERE id = ${operationId} AND status = 'queued' RETURNING *
  `;
  expect(row).toBeDefined();
  const operation = {
    id: String(row!.id),
    kind: String(row!.kind),
    status: "running",
    actorId: (row!.actor_id as string | null) ?? null,
    idempotencyKey: String(row!.idempotency_key),
    planHash: String(row!.plan_hash),
    targetIds: row!.target_ids as string[],
    payload: row!.payload as Record<string, unknown>,
    claimToken: String(row!.claim_token),
    heartbeatAt: new Date(),
    error: null,
    createdAt: row!.created_at as Date,
    updatedAt: row!.updated_at as Date,
  };
  try {
    await runOperation(operation.kind as never, operation, runtime);
    await sql`UPDATE operations SET status = 'succeeded' WHERE id = ${operationId}`;
  } catch (error) {
    await sql`UPDATE operations SET status = 'failed', error = ${String(error)} WHERE id = ${operationId}`;
    throw error;
  }
}

async function issue(actor: Actor, body: Record<string, unknown>) {
  await stepUp(actor, "credential.rotate", { databaseId, ...body });
  const response = await call(actor, clientsPath, { method: "POST", body });
  expect(response.status).toBe(202);
  const result = (await response.json()) as {
    clientId: string;
    operationId: string;
    role: string;
    roleKind: string;
  };
  await runQueued(result.operationId);
  return result;
}

type Bundle = {
  clientId: string;
  role: string;
  roleKind: string;
  readOnly: boolean;
  password: string;
  privateKey: string | null;
  clientCaPem: string;
  certificate: {
    pem: string;
    serial: string;
    fingerprintSha256: string;
    notBefore: string;
    notAfter: string;
  };
  server: Record<string, unknown>;
  vercel: {
    env: Array<{ name: string; value: string; sensitive: boolean }>;
    nodePostgres: string;
    vercelJson: { regions: string[] };
    commands: string;
  };
};

async function reveal(actor: Actor, clientId: string) {
  await stepUp(actor, "secret.reveal", { databaseId, clientId });
  return call(actor, `${clientsPath}/${clientId}/reveal`, { method: "POST" });
}

async function revoke(actor: Actor, clientId: string) {
  await stepUp(actor, "credential.rotate", { databaseId, clientId });
  const response = await call(actor, `${clientsPath}/${clientId}/revoke`, { method: "POST" });
  expect(response.status).toBe(202);
  const result = (await response.json()) as { operationId: string };
  await runQueued(result.operationId);
}

const cluster = () => postgres(appUrl, { max: 1, onnotice: () => undefined });

async function roleState(role: string) {
  const admin = cluster();
  try {
    const [row] = await admin`
      SELECT a.rolcanlogin, a.rolconnlimit, a.rolpassword,
        pg_has_role(a.rolname, ${`${dbName}_runtime`}, 'MEMBER') AS runtime,
        pg_has_role(a.rolname, ${`${dbName}_readonly`}, 'MEMBER') AS readonly
      FROM pg_authid a WHERE a.rolname = ${role}
    `;
    return row as
      | {
          rolcanlogin: boolean;
          rolconnlimit: number;
          rolpassword: string;
          runtime: boolean;
          readonly: boolean;
        }
      | undefined;
  } finally {
    await admin.end();
  }
}

const pgbouncerFile = (name: string) => readFile(join(work, "pgbouncer", name), "utf8");

beforeAll(async () => {
  work = await mkdtemp(join(tmpdir(), "ark-db-clients-"));
  const overrides: Record<string, string> = {
    ARK_PGBOUNCER_DIR: join(work, "pgbouncer"),
    ARK_CERT_DIR: join(work, "certs"),
    ARK_APPLY_NFT: "0",
    ARK_EMBEDDED_WORKERS: "1",
    ARK_PGBOUNCER_RELOAD: "0",
  };
  for (const [name, value] of Object.entries(overrides)) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  [{ region: originalRegion } = { region: undefined }] =
    await sql`SELECT region FROM platform_settings WHERE id = 'default'`;
  await sql`
    INSERT INTO platform_settings (id, region) VALUES ('default', 'us-east')
    ON CONFLICT (id) DO UPDATE SET region = 'us-east'
  `;
  await sql`INSERT INTO endpoints (id, kind, hostname, exposure, status) VALUES (${endpointId}, 'database', ${hostname}, 'public', 'verified')`;
  await sql`INSERT INTO database_clusters (id, name, endpoint_id, status) VALUES (${clusterId}, ${`fd17-${suffix}`}, ${endpointId}, 'ready')`;
  await sql`INSERT INTO managed_databases (id, cluster_id, name, exposure, status) VALUES (${databaseId}, ${clusterId}, ${dbName}, 'public', 'ready')`;
  const admin = cluster();
  try {
    await admin.unsafe(`CREATE ROLE "${dbName}_runtime" NOLOGIN`);
    await admin.unsafe(`CREATE ROLE "${dbName}_readonly" NOLOGIN`);
  } finally {
    await admin.end();
  }
  actors.owner = await signUp("owner", true);
  actors.operator = await signUp("operator", true);
  actors.viewer = await signUp("viewer", true);
  actors.ownerWithoutMfa = await signUp("owner", false);
  actors.rateOwner = await signUp("owner", true);
  actors.recoveryOwner = await signUp("owner", true);
  actors.raceOwner = await signUp("owner", true);
  actors.crossOwner = await signUp("owner", true);
});

afterAll(async () => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  const roles = await sql`SELECT id, name, secret_id FROM database_roles WHERE database_id = ${databaseId}`;
  const cas = await sql`
    SELECT DISTINCT ca_id AS id FROM client_certificates WHERE subject_cn LIKE ${`${dbName}_%`}
    UNION SELECT ca_id AS id FROM database_clients WHERE database_id = ${databaseId}
  `;
  const caIds = cas.map((row) => row.id as string);
  await sql`DELETE FROM operations WHERE target_ids ? ${databaseId}`;
  await sql`DELETE FROM database_clients WHERE database_id = ${databaseId}`;
  await sql`DELETE FROM database_roles WHERE database_id = ${databaseId}`;
  if (caIds.length) {
    await sql`DELETE FROM client_certificates WHERE ca_id IN ${sql(caIds)}`;
    await sql`DELETE FROM private_cas WHERE id IN ${sql(caIds)}`;
    await sql`DELETE FROM secrets WHERE resource_id IN ${sql(caIds)}`;
  }
  await sql`DELETE FROM secrets WHERE resource_id = ${databaseId}`;
  await sql`DELETE FROM managed_databases WHERE id = ${databaseId}`;
  await sql`DELETE FROM database_clusters WHERE id = ${clusterId}`;
  await sql`DELETE FROM endpoints WHERE id = ${endpointId}`;
  const admin = cluster();
  try {
    for (const role of [
      ...roles.map((row) => row.name as string),
      `${dbName}_runtime`,
      `${dbName}_readonly`,
    ]) {
      await admin.unsafe(`DROP ROLE IF EXISTS "${role}"`);
    }
  } finally {
    await admin.end();
  }
  const ids = Object.values(actors).map((actor) => actor.userId);
  if (ids.length) {
    await sql`DELETE FROM audit_events WHERE actor_id IN ${sql(ids)}`;
    await sql`DELETE FROM step_up_grants WHERE user_id IN ${sql(ids)}`;
    await sql`UPDATE operations SET actor_id = NULL WHERE actor_id IN ${sql(ids)}`;
    await sql`DELETE FROM "user" WHERE id IN ${sql(ids)}`;
  }
  await sql`DELETE FROM audit_events WHERE resource_id = ${databaseId}`;
  await sql`DELETE FROM alerts WHERE dedup_key LIKE ${`pgbouncer-revoke:${dbName}_%`}`;
  if (originalRegion) await sql`UPDATE platform_settings SET region = ${originalRegion} WHERE id = 'default'`;
  if (work) await rm(work, { recursive: true, force: true });
});

describe("database client access control", () => {
  test("operators and viewers get 403 on every client endpoint, even with a matching grant", async () => {
    const body = { name: "denied", environment: "production" };
    for (const role of ["operator", "viewer"] as const) {
      if (role === "operator") await stepUp(actors.operator, "credential.rotate", { databaseId, ...body });
      for (const [method, path, payload] of [
        ["GET", clientsPath, undefined],
        ["POST", clientsPath, body],
        ["POST", `${clientsPath}/dbc_missing/reveal`, undefined],
        ["POST", `${clientsPath}/dbc_missing/revoke`, undefined],
        ["GET", `${clientsPath}/dbc_missing/vercel`, undefined],
      ] as const) {
        const response = await call(actors[role], path, { method, body: payload });
        expect(response.status, `${role} ${method} ${path}`).toBe(403);
        expect(((await response.json()) as { error: string }).error).toBe("Owner access is required.");
      }
    }
    const [queued] =
      await sql`SELECT count(*)::int AS n FROM operations WHERE kind = 'database.client_issue' AND target_ids ? ${databaseId}`;
    expect(queued!.n).toBe(0);
  });

  test("issue and revoke need MFA and a single-use credential.rotate grant; reveal needs secret.reveal", async () => {
    const body = { name: "gated", environment: "production" };
    const noMfa = await call(actors.ownerWithoutMfa, clientsPath, { method: "POST", body });
    expect(noMfa.status).toBe(403);
    expect(((await noMfa.json()) as { error: string }).error).toMatch(/MFA/);
    const noGrant = await call(actors.owner, clientsPath, { method: "POST", body });
    expect(noGrant.status).toBe(403);
    expect(((await noGrant.json()) as { error: string }).error).toMatch(
      /Verify your password and MFA for credential.rotate/,
    );
    // A grant bound to another body does not authorise this one.
    await stepUp(actors.owner, "credential.rotate", { databaseId, name: "other", environment: "production" });
    const wrongGrant = await call(actors.owner, clientsPath, { method: "POST", body });
    expect(wrongGrant.status).toBe(403);
    for (const path of [`${clientsPath}/dbc_missing/reveal`, `${clientsPath}/dbc_missing/revoke`]) {
      const response = await call(actors.ownerWithoutMfa, path, { method: "POST" });
      expect(response.status).toBe(403);
    }
  });
});

describe("issuance, one-time reveal and revocation", () => {
  const state: Record<
    string,
    { clientId: string; role: string; bundle?: Bundle; verifier?: string; secretId?: string }
  > = {};

  test("issuing returns a client; the worker creates the CA, certificate, role and PgBouncer files", async () => {
    const production = await issue(actors.owner, { name: "storefront", environment: "production" });
    expect(production.role).toBe(`${dbName}_storefront_production`);
    expect(production.roleKind).toBe("runtime");
    const preview = await issue(actors.owner, { name: "storefront", environment: "preview" });
    expect(preview.roleKind).toBe("readonly");
    state.a = { clientId: production.clientId, role: production.role };
    state.b = { clientId: preview.clientId, role: preview.role };

    const productionRole = await roleState(production.role);
    expect(productionRole).toMatchObject({
      rolcanlogin: true,
      rolconnlimit: 20,
      runtime: true,
      readonly: false,
    });
    const previewRole = await roleState(preview.role);
    expect(previewRole).toMatchObject({ rolcanlogin: true, rolconnlimit: 5, runtime: false, readonly: true });

    const list = await call(actors.owner, clientsPath);
    expect(list.status).toBe(200);
    const { clients } = (await list.json()) as { clients: Array<Record<string, unknown>> };
    expect(clients.map((item) => item.role)).toEqual([production.role, preview.role]);
    expect(clients[1]).toMatchObject({
      environment: "preview",
      roleKind: "readonly",
      readOnly: true,
      revealed: false,
      status: "active",
    });
    const listing = JSON.stringify(clients);
    expect(listing).not.toContain("BEGIN");
    expect(listing).not.toMatch(/sec_|keySecretId|password/i);
    const certificate = (clients[0]!.certificates as Array<{ notBefore: string; notAfter: string }>)[0]!;
    expect(new Date(certificate.notAfter).getTime() - new Date(certificate.notBefore).getTime()).toBe(
      90 * 86_400_000,
    );

    const ini = await pgbouncerFile(PGBOUNCER_FILES.config);
    expect(ini).toContain(`${dbName} = host=`);
    expect(ini).toContain(
      `${production.role} = pool_mode=transaction max_user_connections=20 max_user_client_connections=300`,
    );
    expect(ini).toContain(
      `${preview.role} = pool_mode=transaction max_user_connections=5 max_user_client_connections=100`,
    );
    const userlist = await pgbouncerFile(PGBOUNCER_FILES.userlist);
    expect(userlist).toContain(`"${production.role}"`);
    expect(userlist).toContain(`"${preview.role}"`);
  });

  test("the one-time reveal returns the bundle once; a second reveal fails", async () => {
    // The generic endpoint refuses the client's sealed key, even for the owner.
    const [keyRow] = await sql`
      SELECT cc.key_secret_id FROM client_certificates cc JOIN database_clients dc ON dc.ca_id = cc.ca_id
      WHERE dc.id = ${state.a!.clientId}
    `;
    expect(keyRow!.key_secret_id).toBeTruthy();
    await stepUp(actors.owner, "secret.reveal", { secretId: keyRow!.key_secret_id });
    const generic = await call(actors.owner, `/api/secrets/${keyRow!.key_secret_id}/reveal`, {
      method: "POST",
    });
    expect(generic.status).toBe(403);

    const first = await reveal(actors.owner, state.a!.clientId);
    expect(first.status).toBe(200);
    expect(first.headers.get("cache-control")).toBe("no-store");
    const bundle = (await first.json()) as Bundle;
    state.a!.bundle = bundle;
    revealedSecrets.push(bundle.password, bundle.privateKey!, bundle.certificate.pem);

    const certificate = new X509Certificate(bundle.certificate.pem);
    expect(certificate.verify(new X509Certificate(bundle.clientCaPem).publicKey)).toBe(true);
    expect(certificate.subject).toBe(`CN=${state.a!.role}`);
    expect(createPublicKey(bundle.privateKey!).export({ type: "spki", format: "der" })).toEqual(
      certificate.publicKey.export({ type: "spki", format: "der" }),
    );
    expect(bundle.password.length).toBeGreaterThanOrEqual(24);
    expect(bundle.server).toMatchObject({
      host: hostname,
      port: 5432,
      database: dbName,
      user: state.a!.role,
      sslmode: "verify-full",
      tlsMinVersion: "TLSv1.3",
    });
    const env = Object.fromEntries(bundle.vercel.env.map((item) => [item.name, item.value]));
    expect(env).toMatchObject({
      ARK_DB_HOST: hostname,
      ARK_DB_NAME: dbName,
      ARK_DB_USER: state.a!.role,
      ARK_DB_PASSWORD: bundle.password,
    });
    expect(Buffer.from(env.ARK_DB_CLIENT_CERT_B64!, "base64").toString("utf8")).toBe(bundle.certificate.pem);
    expect(Buffer.from(env.ARK_DB_CLIENT_KEY_B64!, "base64").toString("utf8")).toBe(bundle.privateKey!);
    expect(bundle.vercel.nodePostgres).toContain('import { attachDatabasePool } from "@vercel/functions";');
    expect(bundle.vercel.nodePostgres).toContain("attachDatabasePool(pool);");
    expect(bundle.vercel.vercelJson).toEqual({ regions: ["iad1"] });
    expect(bundle.vercel.commands).toContain("vercel env add ARK_DB_CLIENT_CERT_B64 production --sensitive");

    // The key is gone from storage; the reveal cannot be repeated, even with a fresh grant.
    const [after] =
      await sql`SELECT key_secret_id FROM client_certificates WHERE id = (SELECT cc.id FROM client_certificates cc JOIN database_clients dc ON dc.ca_id = cc.ca_id WHERE dc.id = ${state.a!.clientId})`;
    expect(after!.key_secret_id).toBeNull();
    const [gone] = await sql`SELECT count(*)::int AS n FROM secrets WHERE id = ${keyRow!.key_secret_id}`;
    expect(gone!.n).toBe(0);
    const second = await reveal(actors.owner, state.a!.clientId);
    expect(second.status).toBe(409);
    expect(((await second.json()) as { error: string }).error).toMatch(/already revealed/);

    const previewReveal = await reveal(actors.owner, state.b!.clientId);
    expect(previewReveal.status).toBe(200);
    state.b!.bundle = (await previewReveal.json()) as Bundle;
    expect(state.b!.bundle.readOnly).toBe(true);
    revealedSecrets.push(
      state.b!.bundle.password,
      state.b!.bundle.privateKey!,
      state.b!.bundle.certificate.pem,
    );
  });

  test("the Vercel guide endpoint has placeholders only and follows the platform region", async () => {
    await sql`UPDATE platform_settings SET region = 'eu-west' WHERE id = 'default'`;
    try {
      const response = await call(actors.owner, `${clientsPath}/${state.b!.clientId}/vercel`);
      expect(response.status).toBe(200);
      const guide = (await response.json()) as Bundle["vercel"] & { vercelRegion: string };
      expect(guide.vercelJson).toEqual({ regions: ["dub1"] });
      expect(guide.commands).toContain("vercel env add ARK_DB_USER preview");
      const text = JSON.stringify(guide);
      expect(text).not.toContain(state.b!.bundle!.password);
      expect(text).not.toContain("BEGIN");
    } finally {
      await sql`UPDATE platform_settings SET region = 'us-east' WHERE id = 'default'`;
    }
  });

  test("revoking B revokes its certificates and CA, rotates its password and drops it from PgBouncer; A is untouched", async () => {
    const before = {
      a: await roleState(state.a!.role),
      b: await roleState(state.b!.role),
      aSecret: (await sql`SELECT secret_id FROM database_roles WHERE name = ${state.a!.role}`)[0]!.secret_id,
      bSecret: (await sql`SELECT secret_id FROM database_roles WHERE name = ${state.b!.role}`)[0]!.secret_id,
    };
    const bundleBefore = await pgbouncerFile(PGBOUNCER_FILES.caBundle);
    expect(bundleBefore).toContain(state.b!.bundle!.clientCaPem.trim());
    expect(bundleBefore).toContain(state.a!.bundle!.clientCaPem.trim());

    await revoke(actors.owner, state.b!.clientId);

    const [client] =
      await sql`SELECT status, revoked_at, revoked_by FROM database_clients WHERE id = ${state.b!.clientId}`;
    expect(client).toMatchObject({ status: "revoked", revoked_by: actors.owner.userId });
    const certs =
      await sql`SELECT cc.status, pc.status AS ca_status FROM client_certificates cc JOIN private_cas pc ON pc.id = cc.ca_id JOIN database_clients dc ON dc.ca_id = cc.ca_id WHERE dc.id = ${state.b!.clientId}`;
    expect(certs.map((row) => [row.status, row.ca_status])).toEqual([["revoked", "revoked"]]);

    const after = { a: await roleState(state.a!.role), b: await roleState(state.b!.role) };
    expect(after.b!.rolpassword).not.toBe(before.b!.rolpassword);
    expect(after.b!.rolcanlogin).toBe(false);
    expect(after.a).toEqual(before.a);
    const [bRole] = await sql`SELECT secret_id FROM database_roles WHERE name = ${state.b!.role}`;
    expect(bRole!.secret_id).not.toBe(before.bSecret);
    const [old] = await sql`SELECT count(*)::int AS n FROM secrets WHERE id = ${before.bSecret}`;
    expect(old!.n).toBe(0);
    const [aRole] = await sql`SELECT secret_id FROM database_roles WHERE name = ${state.a!.role}`;
    expect(aRole!.secret_id).toBe(before.aSecret);

    const bundleAfter = await pgbouncerFile(PGBOUNCER_FILES.caBundle);
    expect(bundleAfter).not.toContain(state.b!.bundle!.clientCaPem.trim());
    expect(bundleAfter).toContain(state.a!.bundle!.clientCaPem.trim());
    const userlist = await pgbouncerFile(PGBOUNCER_FILES.userlist);
    expect(userlist).not.toContain(`"${state.b!.role}"`);
    expect(userlist).toContain(`"${state.a!.role}"`);
    expect(await pgbouncerFile(PGBOUNCER_FILES.config)).not.toContain(`${state.b!.role} =`);

    const steps =
      await sql`SELECT name FROM operation_steps WHERE operation_id IN (SELECT id FROM operations WHERE kind = 'database.client_revoke' AND target_ids ? ${state.b!.clientId}) ORDER BY created_at`;
    expect(steps.map((row) => row.name)).toEqual([
      "database-client-revoked",
      "pgbouncer-reload",
      "pgbouncer-kill-client-skipped",
    ]);

    const again = await reveal(actors.owner, state.b!.clientId);
    expect(again.status).toBe(409);
    const twice = await call(actors.owner, `${clientsPath}/${state.b!.clientId}/revoke`, { method: "POST" });
    expect(twice.status).toBe(409);
  });

  test("a CSR client gets a certificate for the submitted key and no stored key", async () => {
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const csrPem = buildCsr({
      key: pair.privateKey,
      attributes: [
        extensionRequest([
          x509.extension(x509.OID.extendedKeyUsage, false, x509.extendedKeyUsageValue([x509.OID.clientAuth])),
        ]),
      ],
    }).pem;
    const issued = await issue(actors.owner, { name: "worker", environment: "staging", csrPem });
    expect(issued.roleKind).toBe("readonly");
    const response = await reveal(actors.owner, issued.clientId);
    expect(response.status).toBe(200);
    const bundle = (await response.json()) as Bundle & { keySource: string };
    revealedSecrets.push(bundle.password, bundle.certificate.pem);
    expect(bundle.keySource).toBe("csr");
    expect(bundle.privateKey).toBeNull();
    expect(
      new X509Certificate(bundle.certificate.pem).publicKey.export({ type: "spki", format: "der" }),
    ).toEqual(pair.publicKey.export({ type: "spki", format: "der" }));
    const [keyRow] =
      await sql`SELECT cc.key_secret_id FROM client_certificates cc JOIN database_clients dc ON dc.ca_id = cc.ca_id WHERE dc.id = ${issued.clientId}`;
    expect(keyRow!.key_secret_id).toBeNull();
  });

  test("every issue, reveal and revoke is audited without PEM, key or password material", async () => {
    const rows =
      await sql`SELECT action, detail FROM audit_events WHERE resource_id = ${databaseId} ORDER BY created_at`;
    const actions = rows.map((row) => row.action as string);
    for (const action of [
      "database.client_issue",
      "database.client_issued",
      "database.client_reveal",
      "database.client_revoke",
      "database.client_revoked",
    ]) {
      expect(actions).toContain(action);
    }
    expect(actions.filter((action) => action === "database.client_reveal")).toHaveLength(3);
    const steps =
      await sql`SELECT evidence FROM operation_steps WHERE operation_id IN (SELECT id FROM operations WHERE target_ids ? ${databaseId})`;
    const text = JSON.stringify([...rows, ...steps]);
    expect(text).not.toMatch(/-----BEGIN|PRIVATE KEY|CERTIFICATE-----/);
    for (const secret of revealedSecrets) {
      expect(text).not.toContain(secret);
      // Base64 bodies of PEM material, line by line.
      for (const line of secret
        .split("\n")
        .filter((item) => item.length >= 40 && !item.startsWith("-----"))) {
        expect(text).not.toContain(line);
      }
    }
    // Revealed passwords also never appear in the generated PgBouncer HBA or INI.
    expect(await pgbouncerFile(PGBOUNCER_FILES.config)).not.toContain(revealedSecrets[0]!);
  });
});

describe("CSR submission hardening", () => {
  test("CSRs must be PEM, at most 16 KiB and well formed; refusals enqueue nothing", async () => {
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const valid = buildCsr({ key: pair.privateKey }).der;
    const cases: Array<[string, string, RegExp]> = [
      ["DER as base64", valid.toString("base64"), /PEM/],
      ["oversized", `${x509.toPem("CERTIFICATE REQUEST", valid)}${" ".repeat(17 * 1024)}`, /16 KiB/],
      ["truncated", x509.toPem("CERTIFICATE REQUEST", valid.subarray(0, 40)), /The CSR is malformed/],
      [
        "bad signature",
        x509.toPem(
          "CERTIFICATE REQUEST",
          Buffer.concat([valid.subarray(0, -1), Buffer.from([valid[valid.length - 1]! ^ 1])]),
        ),
        /does not verify|malformed/,
      ],
    ];
    for (const [label, csrPem, message] of cases) {
      const response = await call(actors.owner, clientsPath, {
        method: "POST",
        body: { name: "csrcase", environment: "preview", csrPem },
      });
      expect(response.status, label).toBe(422);
      expect(((await response.json()) as { error: string }).error, label).toMatch(message);
    }
    const [queued] =
      await sql`SELECT count(*)::int AS n FROM operations WHERE kind = 'database.client_issue' AND payload ->> 'name' = 'csrcase'`;
    expect(queued!.n).toBe(0);
  });

  test("submissions are rate limited per owner", async () => {
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 11; attempt++) {
      const response = await call(actors.rateOwner, clientsPath, {
        method: "POST",
        body: {
          name: "rate",
          environment: "preview",
          csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n",
        },
      });
      statuses.push(response.status);
    }
    expect(statuses.slice(0, 10).every((status) => status === 422)).toBe(true);
    expect(statuses[10]).toBe(429);
  });
});

async function queueIssue(body: Record<string, unknown>) {
  await stepUp(actors.recoveryOwner, "credential.rotate", { databaseId, ...body });
  const response = await call(actors.recoveryOwner, clientsPath, { method: "POST", body });
  expect(response.status, await response.clone().text()).toBe(202);
  return response.json() as Promise<{ clientId: string; operationId: string; role: string }>;
}
async function queueRevoke(clientId: string, actor = actors.recoveryOwner) {
  await stepUp(actor, "credential.rotate", { databaseId, clientId });
  return call(actor, `${clientsPath}/${clientId}/revoke`, { method: "POST" });
}

// The coordinator uses real persistence/role changes and injected admin I/O. This exercises
// its ordering and completion gates without global module mocks that affect other suites.
describe("database client failure recovery and races", () => {
  beforeEach(async () => {
    await sql`DELETE FROM client_issue_limits WHERE user_id = ${actors.recoveryOwner.userId}`;
  });
  test("failed role creation and RELOAD stay non-revealable; API retries reuse every credential", async () => {
    const body = { name: "recoverissue", environment: "production" };
    const first = await queueIssue(body);
    await expect(
      runQueued(first.operationId, {
        issue: (input) =>
          clientModule.issueDatabaseClient(input, async () => {
            throw new Error("role unavailable");
          }),
      }),
    ).rejects.toThrow("role unavailable");
    const [before] = await sql`SELECT dc.ca_id, dr.secret_id, cc.id AS cert_id, cc.key_secret_id
      FROM database_clients dc JOIN database_roles dr ON dr.id = dc.role_id
      JOIN client_certificates cc ON cc.ca_id = dc.ca_id WHERE dc.id = ${first.clientId}`;
    expect((await reveal(actors.recoveryOwner, first.clientId)).status).toBe(409);
    expect(
      (await clientModule.listDatabaseClients(databaseId)).find((c) => c.id === first.clientId)?.status,
    ).toBe("provisioning");
    const second = await queueIssue(body);
    expect(second.clientId).toBe(first.clientId);
    await expect(
      runQueued(second.operationId, {
        reload: async () => {
          throw new Error("reload unavailable");
        },
      }),
    ).rejects.toThrow("reload unavailable");
    expect((await reveal(actors.recoveryOwner, first.clientId)).status).toBe(409);
    const third = await queueIssue(body);
    await runQueued(third.operationId);
    const [after] = await sql`SELECT dc.ca_id, dr.secret_id, cc.id AS cert_id, cc.key_secret_id
      FROM database_clients dc JOIN database_roles dr ON dr.id = dc.role_id
      JOIN client_certificates cc ON cc.ca_id = dc.ca_id WHERE dc.id = ${first.clientId}`;
    expect(after).toEqual(before);
    const bundle = (await (await reveal(actors.recoveryOwner, first.clientId)).json()) as Bundle;
    const admin = cluster();
    const [role] = await admin`SELECT rolcanlogin FROM pg_roles WHERE rolname = ${bundle.role}`;
    await admin.end();
    expect(role!.rolcanlogin).toBe(true);
    // Authentication with the exact retained password (the runtime matrix covers public TLS).
    const url = new URL(appUrl);
    url.username = bundle.role;
    url.password = encodeURIComponent(bundle.password);
    const connection = postgres(url.toString(), { max: 1 });
    try {
      expect((await connection`SELECT current_user AS name`)[0]!.name).toBe(bundle.role);
    } finally {
      await connection.end();
    }
  });

  test("a missing real group role fails safely and can be retried after provisioning", async () => {
    const body = { name: "missinggroup", environment: "preview" };
    const request = await queueIssue(body);
    const admin = cluster();
    try {
      await admin.unsafe(`ALTER ROLE "${dbName}_readonly" RENAME TO "${dbName}_waiting"`);
      await expect(runQueued(request.operationId)).rejects.toThrow(/Group role .* is missing/);
      expect((await reveal(actors.recoveryOwner, request.clientId)).status).toBe(409);
    } finally {
      await admin.unsafe(`ALTER ROLE "${dbName}_waiting" RENAME TO "${dbName}_readonly"`);
      await admin.end();
    }
    const retry = await queueIssue(body);
    expect(retry.clientId).toBe(request.clientId);
    await runQueued(retry.operationId);
  });

  test("a failed client insert retires the orphan CA and key, and the API can retry", async () => {
    const body = { name: "orphan", environment: "production" };
    const request = await queueIssue(body);
    // Fail after certificate/secret creation but before linking the generation to a client.
    const trigger = `fd17_${suffix}`;
    await sql.unsafe(`CREATE FUNCTION ${trigger}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
      IF NEW.id = '${request.clientId}' THEN RAISE EXCEPTION 'injected client insert'; END IF; RETURN NEW; END $$`);
    await sql.unsafe(
      `CREATE TRIGGER ${trigger} BEFORE INSERT ON database_clients FOR EACH ROW EXECUTE FUNCTION ${trigger}()`,
    );
    try {
      await expect(runQueued(request.operationId)).rejects.toMatchObject({
        cause: { message: "injected client insert" },
      });
    } finally {
      await sql.unsafe(`DROP TRIGGER ${trigger} ON database_clients`);
      await sql.unsafe(`DROP FUNCTION ${trigger}()`);
    }
    const orphan =
      await sql`SELECT cc.status, cc.key_secret_id, ca.status AS ca_status FROM client_certificates cc
      JOIN private_cas ca ON ca.id = cc.ca_id WHERE cc.subject_cn = ${request.role}`;
    expect(orphan).toHaveLength(1);
    expect(orphan[0]).toMatchObject({ status: "revoked", ca_status: "revoked", key_secret_id: null });
    const retry = await queueIssue(body);
    expect(retry.clientId).toBe(request.clientId);
    await runQueued(retry.operationId);
  });

  test("role rotation, RELOAD and KILL_CLIENT failures all resume, with isolated alerts", async () => {
    const unaffected = await issue(actors.recoveryOwner, { name: "unaffected", environment: "production" });
    const unaffectedBefore = await roleState(unaffected.role);
    const keys: string[] = [];
    for (const point of ["rotation", "reload", "kill"] as const) {
      const target = await issue(actors.recoveryOwner, { name: `fail${point}`, environment: "preview" });
      const response = await queueRevoke(target.clientId);
      const queued = (await response.json()) as { operationId: string };
      const order: string[] = [];
      const runtime = {
        reloadRequired: () => true,
        reload: async () => {
          order.push("reload");
          if (point === "reload") throw new Error("injected reload");
        },
        kill: async (role: string) => {
          order.push(`kill:${role}`);
          throw new Error("injected kill");
        },
        ...(point === "rotation"
          ? {
              revoke: (input: Parameters<typeof clientModule.revokeDatabaseClient>[0]) =>
                clientModule.revokeDatabaseClient(input, async () => {
                  throw new Error("injected rotation");
                }),
            }
          : {}),
      };
      await expect(runQueued(queued.operationId, runtime)).rejects.toThrow(`injected ${point}`);
      expect(order).toEqual(
        point === "rotation" ? [] : point === "reload" ? ["reload"] : ["reload", `kill:${target.role}`],
      );
      const [pending] =
        await sql`SELECT revocation_completed_at FROM database_clients WHERE id = ${target.clientId}`;
      expect(pending!.revocation_completed_at).toBeNull();
      expect((await reveal(actors.recoveryOwner, target.clientId)).status).toBe(409);
      if (point === "kill") {
        keys.push(`pgbouncer-revoke:${target.role}`);
        const [alert] = await sql`SELECT resolved_at FROM alerts WHERE dedup_key = ${keys[0]!}`;
        expect(alert!.resolved_at).toBeNull();
      }
      const retry = await queueRevoke(target.clientId);
      expect(retry.status).toBe(202);
      const retried = (await retry.json()) as { operationId: string };
      order.length = 0;
      await runQueued(retried.operationId, {
        reloadRequired: () => true,
        reload: async (op) => {
          order.push("reload");
          await runOperation("pgbouncer.reload", op);
        },
        kill: async (role) => {
          order.push(`kill:${role}`);
          return { killed: 1, attempts: 1, remaining: 0 };
        },
      });
      expect(order).toEqual(["reload", `kill:${target.role}`]);
      const [done] =
        await sql`SELECT revocation_completed_at FROM database_clients WHERE id = ${target.clientId}`;
      expect(done!.revocation_completed_at).not.toBeNull();
      expect((await roleState(target.role))!.rolcanlogin).toBe(false);
      expect(await pgbouncerFile(PGBOUNCER_FILES.userlist)).not.toContain(`"${target.role}"`);
      expect(await roleState(unaffected.role)).toEqual(unaffectedBefore);
    }
    const other = await issue(actors.recoveryOwner, { name: "otheralert", environment: "preview" });
    const queued = (await (await queueRevoke(other.clientId)).json()) as { operationId: string };
    await expect(
      runQueued(queued.operationId, {
        reloadRequired: () => true,
        reload: async () => {},
        kill: async () => {
          throw new Error("other kill");
        },
      }),
    ).rejects.toThrow("other kill");
    const alerts =
      await sql`SELECT dedup_key, resolved_at FROM alerts WHERE dedup_key IN ${sql([...keys, `pgbouncer-revoke:${other.role}`] as [...string[], string])}`;
    expect(alerts).toHaveLength(2);
    expect(alerts.find((a) => a.dedup_key === keys[0])!.resolved_at).not.toBeNull();
    expect(alerts.find((a) => a.dedup_key !== keys[0])!.resolved_at).toBeNull();
    const retry = (await (await queueRevoke(other.clientId)).json()) as { operationId: string };
    await runQueued(retry.operationId, {
      reloadRequired: () => true,
      reload: async () => {},
      kill: async () => ({ killed: 0, remaining: 0, attempts: 1 }),
    });
  });

  test("concurrent issuance requests reserve one client identity before metadata exists", async () => {
    const body = { name: "duplicateissue", environment: "preview" };
    await Promise.all(
      [actors.recoveryOwner, actors.raceOwner].map((actor) =>
        stepUp(actor, "credential.rotate", { databaseId, ...body }),
      ),
    );
    const responses = await Promise.all(
      [actors.recoveryOwner, actors.raceOwner].map((actor) =>
        call(actor, clientsPath, { method: "POST", body }),
      ),
    );
    expect(responses.map((r) => r.status).toSorted()).toEqual([202, 409]);
    const operations = await sql`SELECT id FROM operations WHERE kind = 'database.client_issue'
      AND target_ids ? ${databaseId} AND payload->>'name' = 'duplicateissue'`;
    expect(operations).toHaveLength(1);
    await runQueued(String(operations[0]!.id));
  });

  test("queue serialization works with more callers than database pool connections", async () => {
    const outcomes = await Promise.allSettled(
      Array.from({ length: 12 }, () =>
        clientModule.queueClientIssue({
          databaseId,
          name: "poolpressure",
          environment: "preview",
          roleKind: "readonly",
          actorId: actors.recoveryOwner.userId,
        }),
      ),
    );
    const successes = outcomes.filter((o) => o.status === "fulfilled");
    expect(successes).toHaveLength(1);
    for (const outcome of outcomes)
      if (outcome.status === "rejected")
        expect(outcome.reason).toBeInstanceOf(clientModule.DatabaseClientError);
    if (successes[0]?.status === "fulfilled") await runQueued(successes[0].value.operation.id);
  });

  test("duplicate concurrent revoke POSTs create one operation and one audit entry", async () => {
    const target = await issue(actors.recoveryOwner, { name: "duplicate", environment: "preview" });
    await Promise.all(
      [actors.recoveryOwner, actors.raceOwner].map((actor) =>
        stepUp(actor, "credential.rotate", { databaseId, clientId: target.clientId }),
      ),
    );
    const responses = await Promise.all(
      [actors.recoveryOwner, actors.raceOwner].map((actor) =>
        call(actor, `${clientsPath}/${target.clientId}/revoke`, { method: "POST" }),
      ),
    );
    expect(responses.map((r) => r.status).toSorted()).toEqual([202, 409]);
    const operations =
      await sql`SELECT id FROM operations WHERE kind = 'database.client_revoke' AND payload->>'clientId' = ${target.clientId}`;
    const events =
      await sql`SELECT id FROM audit_events WHERE action = 'database.client_revoke' AND detail->>'clientId' = ${target.clientId}`;
    expect(operations).toHaveLength(1);
    expect(events).toHaveLength(1);
    await runQueued(String(operations[0]!.id));
  });

  test("queued owner-only jobs reject a demoted owner before touching lifecycle state", async () => {
    const target = await issue(actors.recoveryOwner, { name: "demoterevoke", environment: "preview" });
    const queuedRevoke = (await (await queueRevoke(target.clientId)).json()) as { operationId: string };
    const queuedIssue = await queueIssue({ name: "demoteissue", environment: "preview" });
    const before =
      await sql`SELECT status, ca_id, revoked_at FROM database_clients WHERE id = ${target.clientId}`;
    const roleBefore = await roleState(target.role);
    await sql`UPDATE platform_access SET role = 'operator' WHERE user_id = ${actors.recoveryOwner.userId}`;
    try {
      await expect(runQueued(queuedIssue.operationId)).rejects.toThrow("Only owners");
      await expect(runQueued(queuedRevoke.operationId)).rejects.toThrow("Only owners");
      expect(await sql`SELECT id FROM database_clients WHERE id = ${queuedIssue.clientId}`).toHaveLength(0);
      const after =
        await sql`SELECT status, ca_id, revoked_at FROM database_clients WHERE id = ${target.clientId}`;
      expect([...after]).toEqual([...before]);
      expect(await roleState(target.role)).toEqual(roleBefore);
    } finally {
      await sql`UPDATE platform_access SET role = 'owner' WHERE user_id = ${actors.recoveryOwner.userId}`;
    }
  });

  test("separately authorized concurrent reveals return one bundle and one audit event", async () => {
    const target = await issue(actors.raceOwner, { name: "racereveal", environment: "preview" });
    const responses = await Promise.all([
      reveal(actors.raceOwner, target.clientId),
      reveal(actors.recoveryOwner, target.clientId),
    ]);
    expect(responses.map((r) => r.status).toSorted()).toEqual([200, 409]);
    const events =
      await sql`SELECT id FROM audit_events WHERE action = 'database.client_reveal' AND detail->>'clientId' = ${target.clientId}`;
    expect(events).toHaveLength(1);
    const [key] =
      await sql`SELECT cc.key_secret_id FROM client_certificates cc JOIN database_clients dc ON dc.ca_id = cc.ca_id WHERE dc.id = ${target.clientId}`;
    expect(key!.key_secret_id).toBeNull();
  });

  test("reveal racing a revoke request preserves a single consistent claim and key state", async () => {
    const target = await issue(actors.raceOwner, { name: "racerevoke", environment: "preview" });
    const [shown, requested] = await Promise.all([
      reveal(actors.raceOwner, target.clientId),
      queueRevoke(target.clientId),
    ]);
    expect([200, 409]).toContain(shown.status);
    expect(requested.status).toBe(202);
    const [row] = await sql`SELECT dc.revealed_at, dc.revoked_at, cc.key_secret_id FROM database_clients dc
      JOIN client_certificates cc ON cc.ca_id = dc.ca_id WHERE dc.id = ${target.clientId}`;
    expect(row!.revoked_at).not.toBeNull();
    expect(row!.revealed_at !== null).toBe(shown.status === 200);
    expect(row!.key_secret_id === null).toBe(shown.status === 200);
    const events =
      await sql`SELECT id FROM audit_events WHERE action = 'database.client_reveal' AND detail->>'clientId' = ${target.clientId}`;
    expect(events).toHaveLength(shown.status === 200 ? 1 : 0);
    expect((await reveal(actors.raceOwner, target.clientId)).status).toBe(409);
    await runQueued(((await requested.json()) as { operationId: string }).operationId);
    const [after] =
      await sql`SELECT cc.key_secret_id FROM client_certificates cc JOIN database_clients dc ON dc.ca_id = cc.ca_id WHERE dc.id = ${target.clientId}`;
    expect(after!.key_secret_id).toBeNull();
  });

  test("inventory query count is three for many clients and linked CA generations", async () => {
    const existing = (await clientModule.listDatabaseClients(databaseId))[0]!;
    const [base] = await sql`SELECT ca_id FROM database_clients WHERE id = ${existing.id}`;
    for (let i = 0; i < 25; i++) {
      const roleId = createId("role");
      await sql`INSERT INTO database_roles (id, database_id, name, kind) VALUES (${roleId}, ${databaseId}, ${`${dbName}_inventory${i}_preview`}, 'client')`;
      await sql`INSERT INTO database_clients (id, database_id, name, environment, role_kind, role_id, ca_id)
        VALUES (${createId("dbc")}, ${databaseId}, ${`inventory${i}`}, 'preview', 'readonly', ${roleId}, ${base!.ca_id})`;
    }
    // A 70-generation cross-CA chain must not be truncated at the old 64-query bound.
    let previous = existing.certificates[0]!.id;
    const generated: string[] = [];
    for (let generation = 0; generation < 70; generation++) {
      const caId = createId("pca");
      const certId = createId("cc");
      await sql`INSERT INTO private_cas (id, purpose, name, cert_pem, key_secret_id, not_after)
        SELECT ${caId}, purpose, name, cert_pem, key_secret_id, not_after FROM private_cas WHERE id = ${base!.ca_id}`;
      await sql`INSERT INTO client_certificates (id, ca_id, subject_cn, serial, fingerprint_sha256, not_before, not_after)
        SELECT ${certId}, ${caId}, subject_cn, ${String(generation)}, ${`inventory-${generation}`}, not_before, not_after
        FROM client_certificates WHERE id = ${previous}`;
      await sql`UPDATE client_certificates SET superseded_by = ${certId} WHERE id = ${previous}`;
      previous = certId;
      generated.push(certId);
    }
    // Spy at the actual database boundary; this counts queries rather than mirroring traversal.
    const select = spyOn(db, "select");
    try {
      const list = await clientModule.listDatabaseClients(databaseId);
      expect(list.length).toBeGreaterThan(25);
      expect(select.mock.calls).toHaveLength(3);
      const certificates = list.find((c) => c.id === existing.id)!.certificates;
      expect(certificates).toHaveLength(existing.certificates.length + 70);
      expect(certificates.map((c) => c.id)).toEqual(expect.arrayContaining(generated));
    } finally {
      select.mockRestore();
    }
  });

  test("the recovery migration preserves completed legacy clients and gates failed issuance", async () => {
    const migration = await Bun.file(
      new URL("../drizzle/0019_database_client_recovery.sql", import.meta.url),
    ).text();
    await sql.begin(async (tx) => {
      const schema = `fd17_migration_${suffix}`;
      await tx.unsafe(`CREATE SCHEMA "${schema}"`);
      try {
        await tx.unsafe(`SET LOCAL search_path TO "${schema}"`);
        await tx.unsafe('CREATE TABLE "user" (id text PRIMARY KEY)');
        await tx.unsafe("CREATE TABLE database_clients (id text PRIMARY KEY)");
        await tx.unsafe("CREATE TABLE operations (kind text, payload jsonb, status text)");
        await tx`INSERT INTO database_clients (id) VALUES ('done'), ('failed'), ('legacy')`;
        await tx`INSERT INTO operations (kind, payload, status) VALUES
          ('database.client_issue', '{"clientId":"done"}', 'succeeded'),
          ('database.client_issue', '{"clientId":"failed"}', 'failed')`;
        await tx.unsafe(migration);
        const rows =
          await tx`SELECT id, issued_at, revocation_completed_at FROM database_clients ORDER BY id`;
        expect(rows.find((r) => r.id === "done")!.issued_at).not.toBeNull();
        expect(rows.find((r) => r.id === "failed")!.issued_at).toBeNull();
        expect(rows.find((r) => r.id === "legacy")!.issued_at).not.toBeNull();
        expect(rows.every((r) => r.revocation_completed_at === null)).toBe(true);
        const [counter] = await tx`SELECT count(*)::int AS n FROM client_issue_limits`;
        expect(counter!.n).toBe(0);
      } finally {
        await tx.unsafe(`DROP SCHEMA "${schema}" CASCADE`);
      }
    });
  });

  test("the sliding-window limit survives independent API processes and expires idle owners", async () => {
    const child = () =>
      Bun.spawn(
        [
          process.execPath,
          "--eval",
          `
      const { consumeClientIssueAttempt } = await import('./server/src/modules/db-clients.ts');
      const { sql } = await import('./server/src/db.ts');
      const outcomes = await Promise.all(Array.from({length: 7}, () => consumeClientIssueAttempt(${JSON.stringify(actors.crossOwner.userId)})));
      console.log(JSON.stringify(outcomes)); await sql.end();
    `,
        ],
        { env: process.env, stdout: "pipe", stderr: "pipe" },
      );
    const processes = [child(), child()];
    const results = await Promise.all(
      processes.map(async (p) => {
        const [code, stdout, stderr] = await Promise.all([
          p.exited,
          new Response(p.stdout).text(),
          new Response(p.stderr).text(),
        ]);
        expect(code, stderr).toBe(0);
        return JSON.parse(stdout) as boolean[];
      }),
    );
    expect(results.flat().filter(Boolean)).toHaveLength(10);
    expect(await clientModule.consumeClientIssueAttempt(actors.crossOwner.userId)).toBe(false);
    expect(
      await clientModule.consumeClientIssueAttempt(actors.crossOwner.userId, new Date(Date.now() + 600_001)),
    ).toBe(true);
    const rows = await sql`SELECT user_id FROM client_issue_limits`;
    expect(rows.map((row) => String(row.user_id))).toEqual([actors.crossOwner.userId]);
  });
});
