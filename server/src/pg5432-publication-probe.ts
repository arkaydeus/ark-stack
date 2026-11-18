// FD-26 full publication path in the domain worker's identity and mounts. The caller supplies a
// disposable control database and the real edge/validator sockets; no Docker access or NET_ADMIN.
import { createId } from "@ark-stack/shared";
import { makeSignature } from "better-auth/crypto";
import { app } from "./app.ts";
import { auth } from "./auth.ts";
import { sql } from "./db.ts";
import {
  enqueue,
  processQueued,
  fencePoolerListener,
  queuePoolerEdgeApply,
  runOperation,
} from "./coordinator.ts";
import { edgePolicy } from "./modules/edge-observe.ts";
import { PgbouncerReloadError } from "./modules/pgbouncer.ts";
import { MockLocalApi } from "./mock-localapi.ts";

const testDatabase = new URL(process.env.DATABASE_URL!);
if (
  !/^ark-edge-pg-control-[0-9]+-[a-f0-9]{8}$/.test(testDatabase.hostname) ||
  testDatabase.pathname !== "/ark_platform"
)
  throw new Error("Publication probes require the runtime suite's disposable control database.");

const [command, raw = "{}"] = process.argv.slice(2);
const input = JSON.parse(raw);
const origin = "http://localhost:3000";
const password = "Publication-Test-Password-123!";
const mock = new MockLocalApi({
  backendState: "Running",
  suffix: ".tail1234.ts.net",
  self: { id: "nPublicationEdge", name: "ark-edge", ips: ["100.64.0.1"], tags: ["tag:ark-edge"] },
  peers: [{ id: "nPublicationPG", name: "pg-home", ips: [input.ip] }],
  reachable: new Set([`${input.ip}:5432`]),
});
process.env.ARK_EDGE_TS_SOCKET = "/tmp/publication-localapi.sock";
let cookie = "";
async function call(method: string, path: string, body?: unknown) {
  const response = await app.request(origin + path, {
    method,
    headers: { cookie, origin, "content-type": "application/json" },
    body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
  });
  const value = await response.json();
  if (response.status >= 400)
    throw new Error(`${method} ${path}: ${response.status} ${JSON.stringify(value)}`);
  return value;
}
async function session(create = false) {
  const ctx = await auth.$context;
  let id = "";
  if (create) {
    const user = await ctx.internalAdapter.createUser(
      { name: "Publication Owner", email: "publication@example.com", emailVerified: true },
      { method: "email-password" },
    );
    id = user.id;
    await ctx.internalAdapter.linkAccount({
      userId: id,
      providerId: "credential",
      accountId: id,
      password: await ctx.password.hash(password),
    });
    await sql`INSERT INTO platform_access (user_id, role) VALUES (${id}, 'owner')`;
    await sql`UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${id}`;
  } else {
    const [user] = await sql`SELECT id FROM "user" WHERE email = 'publication@example.com'`;
    id = user!.id;
  }
  const row = await ctx.internalAdapter.createSession(id, false, { origin: "admin" });
  cookie = `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${row.token}.${await makeSignature(row.token, ctx.secret)}`)}`;
}
async function workerUntil<T>(promise: Promise<T>) {
  let done = false;
  const settled = promise.finally(() => {
    done = true;
  });
  const handled = settled.catch((error: unknown) => error);
  for (let i = 0; i < 150; i++) {
    if (done) break;
    await processQueued(1, "edge.l4_apply");
    await Bun.sleep(20);
  }
  await handled;
  return settled;
}
try {
  await mock.listen(process.env.ARK_EDGE_TS_SOCKET);
  if (command === "prepare") {
    await session(true);
    await sql`INSERT INTO platform_settings (id, public_ipv4) VALUES ('default','203.0.113.10') ON CONFLICT (id) DO UPDATE SET public_ipv4 = '203.0.113.10'`;
    await sql`INSERT INTO domain_claims (id,name,ownership_token,status) VALUES ('dom_publication','example.com','publication-token','verified')`;
    await runOperation(
      "edge.observe",
      await enqueue({
        kind: "edge.observe",
        targetIds: ["tailnet:edge"],
        payload: { fixture: createId("t") },
      }),
    );
    const request = {
      kind: "postgres",
      hostname: "pg17.example.com",
      target: "pg-home.tail1234.ts.net",
      targetPort: 5432,
      tlsMode: "passthrough",
      compatPort: 20007,
      sourceCidrs: [input.source + "/32"],
    };
    await call("POST", "/api/step-up", { password, action: "exposure.public", request });
    const created = await call("POST", "/api/front/routes", request);
    const id = created.route.id;
    await sql`UPDATE front_routes SET status = 'ready' WHERE id = ${id}`;
    // Stand in for the completed DNS/certificate lifecycle. Passthrough uses the target's actual
    // TLS certificate; the observer still requires the endpoint's issued lifecycle marker.
    await sql`INSERT INTO certificates (id,endpoint_id,names,status)
      SELECT ${createId("crt")}, endpoint_id, '["pg17.example.com"]'::jsonb, 'issued' FROM front_routes WHERE id = ${id}`;
    await call("POST", "/api/step-up", { password, action: "exposure.public", request: { routeId: id } });
    await call("POST", `/api/front/routes/${id}/enable`, {});
  } else if (command === "remove-compat") {
    await session();
    const [route] = await sql`SELECT id FROM front_routes WHERE kind = 'postgres'`;
    await call("PATCH", `/api/front/routes/${route!.id}`, { compatPort: null });
  } else if (command === "apply") {
    await processQueued(20, "edge.");
    const jobs =
      await sql`SELECT status,error FROM operations WHERE kind = 'edge.l4_apply' ORDER BY created_at DESC`;
    if (!jobs.length || jobs.some((job) => job.status !== "succeeded"))
      throw new Error(`Publication did not finish: ${JSON.stringify(jobs)}`);
  } else if (command === "open-pooler") {
    await sql`INSERT INTO database_clusters (id,name) VALUES ('dcl_publication','publication')`;
    await sql`INSERT INTO managed_databases (id,cluster_id,name,exposure,source_cidrs) VALUES ('mdb_publication','dcl_publication','shop','public',jsonb_build_array(${input.source + "/32"}::text))`;
    await sql`UPDATE platform_settings SET pooler_source_cidrs = jsonb_build_array(${input.source + "/32"}::text), pooler_allow_internet = false WHERE id = 'default'`;
    await queuePoolerEdgeApply();
    await processQueued(1, "edge.l4_apply");
  } else if (command === "fence") {
    await workerUntil(fencePoolerListener("publication-watchdog", { timeoutMs: 15_000 }));
  } else if (command === "failed-reload") {
    const operation = await enqueue({
      kind: "pgbouncer.reload",
      targetIds: [],
      payload: { fixture: "last-client" },
    });
    let failed = false;
    try {
      await workerUntil(runOperation("pgbouncer.reload", operation));
    } catch (error) {
      if (!(error instanceof PgbouncerReloadError)) throw error;
      failed = true;
    }
    if (!failed) throw new Error("The unavailable PgBouncer admin socket unexpectedly reloaded");
    const [step] =
      await sql`SELECT evidence FROM operation_steps WHERE name = 'edge-l4-apply' AND evidence->'poolerPolicy'->'fence'->>'reason' = 'no-admitted-client' ORDER BY created_at DESC LIMIT 1`;
    if (!step?.evidence?.applied)
      throw new Error("Failed PgBouncer reload was not preceded by an applied edge fence");
  } else throw new Error(`Unknown command ${command}`);
  const policy = await edgePolicy();
  if ((command === "prepare" || command === "apply") && !policy.routes.length) {
    const routes =
      await sql`SELECT r.id,r.enabled,r.status,r.target_ip,r.target_node_stable_id,e.hostname FROM front_routes r JOIN endpoints e ON e.id = r.endpoint_id`;
    throw new Error(`No publishable API route: ${JSON.stringify({ policy, routes })}`);
  }
  if (command === "apply") {
    const jobs = await sql`SELECT kind,status,error FROM operations WHERE kind LIKE 'edge.%'`;
    const steps =
      await sql`SELECT evidence FROM operation_steps WHERE name = 'edge-l4-apply' ORDER BY created_at DESC LIMIT 1`;
    if (jobs.some((job) => job.status === "failed") || !steps[0]?.evidence?.postgresRoutes?.length)
      throw new Error(`API route not rendered: ${JSON.stringify({ jobs, steps })}`);
  }
  console.log(JSON.stringify({ ok: true, routes: policy.routes }));
} finally {
  mock.stop();
  await sql.end();
}
