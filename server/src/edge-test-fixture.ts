import { testOpenSsl } from "./modules/test-openssl.ts";
import { dirname } from "node:path";
process.env.PATH = `${dirname(testOpenSsl())}:${process.env.PATH}`;
// Isolated database/process: mode changes revoke all sessions and must not affect other suites.
// The fake lego writes real certificate files; no public CA or DNS request is made.
import assert from "node:assert/strict";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { parseEnvFile, type OperationKind } from "@ark-stack/shared";
import postgres from "postgres";

const root = resolve(import.meta.dir, "../..");
const sourceUrl = process.env.DATABASE_URL!;
assert(["localhost", "127.0.0.1", "::1"].includes(new URL(sourceUrl).hostname));
const admin = postgres(sourceUrl, { max: 1 });
const name = `ark_edge_${crypto.randomUUID().replaceAll("-", "")}`;
const targetUrl = new URL(sourceUrl);
targetUrl.pathname = `/${name}`;
const directory = await mkdtemp(join(tmpdir(), "ark-coordinator-edge-"));
process.env.DATABASE_URL = targetUrl.toString();
process.env.BETTER_AUTH_URL = "https://admin.edge.example.com";
process.env.ARK_EDGE_DIR = join(directory, "edge");
process.env.ARK_CERT_DIR = join(directory, "certs");
process.env.ARK_ACME_EMAIL = "fixture@example.test";
process.env.ARK_LEGO_BIN = join(directory, "lego");
process.env.ARK_LEGO_ARGS_FILE = join(directory, "lego-args");

async function command(args: string[], env = process.env) {
  const child = Bun.spawn(args, { cwd: root, env, stdout: "pipe", stderr: "pipe" });
  const [exit, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  assert.equal(exit, 0, `${args.join(" ")}: ${stderr}`);
  return stdout;
}

// Resolve the actual shipped manifest with production, staging and omitted selections.
// `docker compose config` only interpolates; the installer-generated PgBouncer admin password is
// required by Compose but never used here, so a validation-only placeholder satisfies it.
const composeEnv: Record<string, string | undefined> = {
  ARK_PGBOUNCER_ADMIN_PASSWORD: "config-validation-only",
  ...process.env,
  ...parseEnvFile(await Bun.file(join(root, ".env.example")).text()),
};
async function stagingSetting(value?: string) {
  const env = { ...composeEnv };
  delete env.ARK_ACME_STAGING;
  if (value !== undefined) env.ARK_ACME_STAGING = value;
  const config = JSON.parse(
    await command(
      [
        "docker",
        "compose",
        "--env-file",
        "/dev/null",
        "-f",
        "infra/platform/docker-compose.yml",
        "config",
        "--format",
        "json",
      ],
      env,
    ),
  );
  return config.services["domain-worker"].environment.ARK_ACME_STAGING;
}
assert.equal(await stagingSetting(), "1");
assert.equal(await stagingSetting("1"), "1");
process.env.ARK_ACME_STAGING = await stagingSetting("0");
assert.equal(process.env.ARK_ACME_STAGING, "0");
console.log("Compose forwards production=0, staging=1 and safe omitted default=1");

await Bun.write(
  process.env.ARK_LEGO_BIN,
  `#!/bin/sh
set -eu
printf '%s\\n' "$@" > "$ARK_LEGO_ARGS_FILE"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --path) output="$2"; shift 2 ;;
    --domains) hostname="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$output/certificates"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=$hostname" -addext "subjectAltName=DNS:$hostname" -keyout "$output/certificates/$hostname.key" -out "$output/certificates/$hostname.crt" 2>/dev/null
`,
);
await chmod(process.env.ARK_LEGO_BIN, 0o755);
await admin.unsafe(`CREATE DATABASE "${name}"`);
let close: (() => Promise<unknown>) | undefined;
let caddy: ReturnType<typeof Bun.serve> | undefined;
try {
  await command(["bun", "server/src/migrate.ts"]);
  const { db, sql } = await import("./db.ts");
  close = () => sql.end();
  const { enqueue, runOperation } = await import("./coordinator.ts");
  const { certificates, endpoints, platformSettings, session, user, operationSteps } =
    await import("./schema.ts");
  const { eq } = await import("drizzle-orm");
  const calls: string[] = [];
  let candidate = "";
  caddy = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      calls.push(new URL(request.url).pathname);
      if (new URL(request.url).pathname === "/adapt") {
        candidate = await request.text();
        return Response.json({ result: { apps: {} } });
      }
      // edge.apply reads the running config first (routes it removes may hold WebSockets, FD-09).
      if (new URL(request.url).pathname === "/config/") return Response.json({ apps: {} });
      assert.equal(request.headers.get("cache-control"), "must-revalidate");
      return new Response("");
    },
  });
  process.env.ARK_EDGE_RELOAD_URL = `http://127.0.0.1:${caddy.port}`;
  await db
    .insert(platformSettings)
    .values({
      id: "default",
      adminMode: "tailnet",
      adminHostname: "admin.edge.example.com",
      authOrigin: "https://private.example.test",
    })
    .onConflictDoUpdate({
      target: platformSettings.id,
      set: {
        adminMode: "tailnet",
        adminHostname: "admin.edge.example.com",
        authOrigin: "https://private.example.test",
      },
    });
  await db.insert(endpoints).values([
    { id: "admin", kind: "admin", hostname: "admin.edge.example.com" },
    { id: "app", kind: "http", hostname: "app.edge.example.com" },
    { id: "waiting", kind: "http", hostname: "waiting.edge.example.com" },
  ]);
  await db.insert(user).values({ id: "owner", name: "Owner", email: "owner@example.test" });
  await db.insert(session).values({
    id: "session",
    token: "fixture",
    userId: "owner",
    origin: "admin",
    expiresAt: new Date(Date.now() + 60_000),
  });
  await Bun.write(join(process.env.ARK_EDGE_DIR!, "Caddyfile"), "original routing");
  await Bun.write(join(process.env.ARK_EDGE_DIR!, "serve.json"), "original serve routing");
  const [originalSettings] = await db.select().from(platformSettings);
  const originalSessions = await db.select().from(session);
  async function operation(kind: OperationKind, targetIds: string[] = [], payload = {}) {
    return enqueue({ kind, targetIds, payload: { ...payload, nonce: crypto.randomUUID() } });
  }
  // An older issued row must not override a newer pending/failed/untrusted deployment.
  for (const status of ["missing", "pending", "failed", "untrusted"]) {
    await db.delete(certificates);
    if (status !== "missing") {
      await db.insert(certificates).values([
        {
          id: "older",
          endpointId: "admin",
          names: ["admin.edge.example.com"],
          status: "issued",
          lastDeployedAt: new Date(1000),
        },
        {
          id: "current",
          endpointId: "admin",
          names: ["admin.edge.example.com"],
          status,
          lastDeployedAt: new Date(2000),
        },
      ]);
    }
    const op = await operation("admin.mode_change", [], { adminMode: "public" });
    await assert.rejects(runOperation("admin.mode_change", op), /admin certificate .* is not issued yet/);
    assert.deepEqual(await db.select().from(platformSettings), [originalSettings]);
    assert.deepEqual(await db.select().from(session), originalSessions);
    assert.equal(await Bun.file(join(process.env.ARK_EDGE_DIR!, "Caddyfile")).text(), "original routing");
    assert.equal(
      await Bun.file(join(process.env.ARK_EDGE_DIR!, "serve.json")).text(),
      "original serve routing",
    );
    assert.equal(calls.length, 0);
    assert.deepEqual(await db.select().from(operationSteps).where(eq(operationSteps.operationId, op.id)), []);
    console.log(`${status}: public mode rejected; routing, settings, sessions and Caddy untouched`);
  }
  await db.delete(certificates);
  // The Compose-resolved selection drives real issuance metadata and coordinator persistence.
  for (const endpoint of ["admin", "app"]) {
    const op = await operation("certificate.issue", [endpoint]);
    await runOperation("certificate.issue", op);
    const [cert] = await db.select().from(certificates).where(eq(certificates.endpointId, endpoint));
    assert.equal(cert!.issuer, "letsencrypt");
    assert.equal(cert!.status, "issued");
    assert(cert!.fingerprint);
    assert(!/acme-staging/.test(await Bun.file(process.env.ARK_LEGO_ARGS_FILE!).text()));
  }
  const mode = await operation("admin.mode_change", [], { adminMode: "public" });
  await runOperation("admin.mode_change", mode);
  const [settings] = await db.select().from(platformSettings);
  assert.equal(settings!.adminMode, "public");
  assert.equal(settings!.authOrigin, "https://admin.edge.example.com");
  assert.deepEqual(await db.select().from(session), []);
  assert(candidate.includes("admin.edge.example.com {"));
  assert(candidate.includes("app.edge.example.com {"));
  assert(!candidate.includes("waiting.edge.example.com {"));
  assert.deepEqual(calls, ["/config/", "/adapt", "/load"]);
  const apply = await operation("edge.apply");
  await runOperation("edge.apply", apply);
  const [step] = await db.select().from(operationSteps).where(eq(operationSteps.operationId, apply.id));
  assert.deepEqual(step!.evidence.awaitingCertificate, ["waiting.edge.example.com"]);
  assert.deepEqual((step!.evidence.unrouted as string[]).toSorted(), [
    "app.edge.example.com",
    "waiting.edge.example.com",
  ]);
  assert.equal(step!.evidence.applied, true);
  console.log(
    "Production issuance -> issued rows -> public admin and app rendered; sessions revoked on success; edge evidence recorded",
  );
  // Staging metadata stays untrusted and is omitted by the same database-backed plan.
  process.env.ARK_ACME_STAGING = await stagingSetting("1");
  const staged = await operation("certificate.renew", ["admin"]);
  await runOperation("certificate.renew", staged);
  const certs = await db.select().from(certificates).where(eq(certificates.endpointId, "admin"));
  assert(certs.some((cert) => cert.issuer === "letsencrypt-staging" && cert.status === "untrusted"));
  assert(/acme-staging/.test(await Bun.file(process.env.ARK_LEGO_ARGS_FILE!).text()));
  const stagedApply = await operation("edge.apply");
  await runOperation("edge.apply", stagedApply);
  assert(!candidate.includes("admin.edge.example.com {"));
  const [stagedStep] = await db
    .select()
    .from(operationSteps)
    .where(eq(operationSteps.operationId, stagedApply.id));
  assert.deepEqual(stagedStep!.evidence.awaitingCertificate, [
    "admin.edge.example.com",
    "waiting.edge.example.com",
  ]);
  console.log("Staging issuance -> untrusted row -> admin omitted and awaitingCertificate recorded");
} finally {
  caddy?.stop(true);
  await close?.();
  await admin`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ${name} AND pid <> pg_backend_pid()`;
  await admin.unsafe(`DROP DATABASE "${name}"`);
  await admin.end();
  await rm(directory, { recursive: true, force: true });
}
