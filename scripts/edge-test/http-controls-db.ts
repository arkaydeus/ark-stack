// Disposable PostgreSQL and real API state for the FD-23 HAProxy runtime suite.
import { createHmac, generateKeyPairSync } from "node:crypto";
import { resolve } from "node:path";

import type { EdgeHttpRoute } from "@ark-stack/shared";

import type { GateEdge } from "./gate-edge.ts";
import type { EdgeTestRuntime } from "./runtime.ts";
import { buildCsr } from "../../server/src/modules/csr-test-kit.ts";

export async function startHttpControlsDb(runtime: EdgeTestRuntime) {
  const root = resolve(import.meta.dir, "../..");
  const child = Bun.spawn([process.execPath, "--no-env-file", "scripts/test-db.ts", "up"], {
    cwd: root,
    stdout: "pipe",
    stderr: "inherit",
  });
  const [code, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  const container = /^# Started and migrated (ark-test-db-[a-f0-9]{12})\./m.exec(stdout)?.[1];
  if (container) runtime.containers.push(container);
  const env = Object.fromEntries(
    [...stdout.matchAll(/^export ([A-Z_]+)='([^']*)'$/gm)].map(([, key, value]) => [key!, value!]),
  );
  if (code !== 0 || !container || !env.DATABASE_URL) throw new Error("Could not start the FD-23 database.");
  Object.assign(process.env, env);
  const { sql } = await import("../../server/src/db.ts");
  const { auth } = await import("../../server/src/auth.ts");
  const { app } = await import("../../server/src/app.ts");
  const { edgePlan, enqueue } = await import("../../server/src/coordinator.ts");
  const { edgeLeaseDocument } = await import("../../server/src/modules/gate-revocations.ts");
  const { createPrivateCa, generateCaCrl, issueClientCertificate } =
    await import("../../server/src/modules/pki.ts");
  const origin = new URL(env.BETTER_AUTH_URL!).origin;
  const ctx = await auth.$context;
  const owner = await ctx.internalAdapter.createUser(
    {
      name: "FD-23 owner",
      email: "owner@example.test",
      emailVerified: true,
    },
    { method: "email-password" },
  );
  await sql`INSERT INTO platform_access (user_id, role) VALUES (${owner.id}, 'owner')`;
  await sql`UPDATE "user" SET two_factor_enabled = true, mfa_enrolled_at = now() - interval '1 minute' WHERE id = ${owner.id}`;
  const session = await ctx.internalAdapter.createSession(owner.id, false, { origin: "admin" });
  const signed = createHmac("sha256", ctx.secret).update(session.token).digest("base64");
  const cookie = `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${session.token}.${signed}`)}`;
  const workerUrl = new URL(env.DATABASE_URL);
  workerUrl.hostname = container;
  workerUrl.port = "5432";
  const workerEnv = {
    DATABASE_URL: workerUrl.toString(),
    ARK_RUNTIME_ROLE: "worker",
    ARK_ROOT_KEY: env.ARK_ROOT_KEY!,
    BETTER_AUTH_SECRET: env.BETTER_AUTH_SECRET!,
    ARK_FRONT_INGRESS_DIR: "/edge/fixture-ingress",
  };

  return {
    close: () => sql.end(),
    lease: edgeLeaseDocument,
    plan: () => edgePlan("tailnet", null),
    async clientCa(name: string) {
      const ca = await createPrivateCa({ purpose: "http-client", name });
      await generateCaCrl({ caId: ca.id });
      return ca;
    },
    async issue(caId: string, subjectCn: string) {
      const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const csrPem = buildCsr({ key: pair.privateKey }).pem;
      const { certificate } = await issueClientCertificate({ caId, subjectCn, csrPem });
      return {
        id: certificate.id,
        serial: certificate.serial,
        cert: certificate.certPem!,
        key: pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      };
    },
    async seed(edge: GateEdge, routes: EdgeHttpRoute[], caIds: Record<string, string>) {
      await runtime.docker("network", "connect", edge.stack.networks.edgeControl, container);
      await sql`INSERT INTO platform_settings (id, admin_mode, public_ipv4)
        VALUES ('default', 'tailnet', '203.0.113.10')
        ON CONFLICT (id) DO UPDATE SET admin_mode = 'tailnet', public_ipv4 = '203.0.113.10'`;
      await sql`INSERT INTO tailnet_snapshots (source, generation, completed_at, valid_until)
        VALUES ('edge', 'fd23', now(), now() + interval '6 minutes')`;
      const [peer] = routes;
      await sql`INSERT INTO tailnet_nodes (source, generation, stable_id, dns_name, host_name, ipv4, is_self, online, observed_at)
        VALUES ('edge', 'fd23', 'nEDGE', 'edge.test.ts.net', 'edge', '100.64.0.1', true, true, now()),
               ('edge', 'fd23', ${peer!.stableId}, 'home.test.ts.net', 'home', ${peer!.ip}, false, true, now())`;
      for (const route of routes) {
        const endpointId = `end_${route.id}`;
        await sql`INSERT INTO endpoints (id, kind, hostname, exposure)
          VALUES (${endpointId}, 'route', ${route.hostname}, 'public')`;
        await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at)
          VALUES (${`crt_${route.id}`}, ${endpointId}, ${JSON.stringify([route.hostname])}::jsonb, 'issued', now())`;
        await sql`INSERT INTO front_routes (id, kind, endpoint_id, listen_port, target_input,
          target_node_stable_id, target_ip, target_port, access_mode, rate_limit, client_ca_id, status, enabled)
          VALUES (${route.id}, 'http', ${endpointId}, 443, 'home.test.ts.net', ${route.stableId}, ${route.ip},
            ${route.port}, ${route.access}, ${route.rateLimit ? JSON.stringify(route.rateLimit) : null}::jsonb,
            ${caIds[route.id] ?? null}, 'ready', true)`;
      }
    },
    async revoke(routeId: string, certificateId: string) {
      const result = await app.request(
        `${origin}/api/front/routes/${routeId}/client-certificates/${certificateId}/revoke`,
        {
          method: "POST",
          headers: { origin, cookie, "content-type": "application/json" },
          body: "{}",
        },
      );
      if (!result.ok) throw new Error(`HTTP revoke failed (${result.status}): ${await result.text()}`);
      const [row] = await sql`SELECT id, created_at FROM gate_revocations
        WHERE route_id = ${routeId} AND reason = 'client_certificate_revoked' AND applied_at IS NULL`;
      if (!row) throw new Error("HTTP revoke did not write a pending journal row");
      return { id: String(row.id), at: new Date(row.created_at).getTime() };
    },
    async applied(id: string, operationId: string) {
      const [row] = await sql`SELECT applied_at, applied_by FROM gate_revocations WHERE id = ${id}`;
      return !!row?.applied_at && row.applied_by === operationId;
    },
    async corruptCrl(caId: string, value: string | null) {
      await sql`UPDATE private_cas SET crl_pem = ${value} WHERE id = ${caId}`;
    },
    async corruptCertificate(caId: string, certificateId: string, value: string) {
      await sql`UPDATE private_cas SET cert_pem = ${value} WHERE id = ${caId}`;
      await sql`UPDATE client_certificates SET cert_pem = ${value} WHERE id = ${certificateId}`;
    },
    async recoverCrls() {
      const { refreshHttpRouteCrls } = await import("../../server/src/modules/route-pki.ts");
      return refreshHttpRouteCrls((tx) => enqueue({ kind: "edge.apply", targetIds: ["platform"] }, tx));
    },
    async queueApply() {
      await enqueue({ kind: "edge.apply", targetIds: ["platform"] });
    },
    async run(edge: GateEdge, kind: "edge.apply" | "edge.drain" | "edge.l4_apply", queue = false) {
      const result = await edge.runCoordinator(kind, workerEnv, {
        acknowledgeIngress: kind === "edge.l4_apply",
        enqueue: queue,
      });
      if (result.status !== "succeeded") throw new Error(`${kind} failed: ${result.error}`);
      return result.id;
    },
  };
}
