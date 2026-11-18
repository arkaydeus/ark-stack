// Mandatory local FD-27 acceptance. The disposable DB is supplied by mise run test:db.
import { test } from "bun:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, X509Certificate } from "node:crypto";
import { mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  CADDY_GLOBAL_BLOCK,
  EDGE_L4_GENERATION_ENV,
  IPV6_PREFLIGHT_RETRY_MS,
  dockerIpv6Ready,
  ipv6ProbeRequest,
  l4Limits,
  l4PolicyFingerprint,
  normalizeHostname,
  publicIpv6,
  renderEdgeL4Generation,
  signIpv6Report,
  type EdgeL4Input,
  type Ipv6ProbeReport,
  type Ipv6ProbeRequest,
  type OperationKind,
} from "@ark-stack/shared";

import { app } from "../../server/src/app.ts";
import {
  enqueue,
  revealSecret,
  runDnsMaintenance,
  runOperation,
  setDnsResolver,
} from "../../server/src/coordinator.ts";
import { db, sql } from "../../server/src/db.ts";
import { loadEnv } from "../../server/src/env.ts";
import { MockLocalApi } from "../../server/src/mock-localapi.ts";
import { observeEdgeTailnet } from "../../server/src/modules/edge-observe.ts";
import { edgeLocalApi } from "../../server/src/modules/tailnet-localapi.ts";
import {
  ipv6PreflightChallenge,
  ipv6PreflightDue,
  ipv6PreflightKind,
  ipv6PreflightTarget,
  ipv6Settings,
} from "../../server/src/modules/ipv6-preflight.ts";
import {
  createCaMaterial,
  createPrivateCa,
  generateCaCrl,
  issueClientCertificate,
  signClientCertificate,
} from "../../server/src/modules/pki.ts";
import { planPgbouncer, renderPgbouncerFiles } from "../../server/src/modules/pgbouncer.ts";
import { EdgeTestRuntime } from "../edge-test/runtime.ts";
import type { Subprocess } from "bun";
import type { ProbeCredential } from "../ipv6-preflight-probe.ts";

const root = resolve(import.meta.dir, "../..");
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
const pgImage = "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929";
const pebbleImage =
  "ghcr.io/letsencrypt/pebble:2.10.3@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef";
const dnsImage =
  "ghcr.io/letsencrypt/pebble-challtestsrv:2.10.3@sha256:0152c8cb506e2ecba2900ed47d23932e27e3e6575a7d2c8ef93c7719ee3dea4c";
const legoImage =
  "goacme/lego:v4.26.0@sha256:39e65153badce8c67fa16caed2f89ebb15db5747ffbbd502603ce0bbaf2ed218";
const platform = Bun.YAML.parse(await Bun.file(join(root, "infra/platform/docker-compose.yml")).text()) as {
  services: Record<string, { image: string }>;
  networks: { admin: { enable_ipv6: boolean } };
};
const appHost = "app.fd27.example.com";
const dbHost = "db.fd27.example.com";
const pgHost = "pg.fd27.example.com";
const domainId = "dom_fd27";
const targetIp = "100.76.27.17";
const tlsHost = "tls.fd27.example.com";
const mtlsHost = "mtls.fd27.example.com";
const role = "ipv6_probe";
const password = crypto.randomUUID();
const database = "probe_db";

async function retry<T>(attempt: () => Promise<T>, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      return await attempt();
    } catch (error) {
      if (Date.now() >= deadline) throw error;
      await Bun.sleep(250);
    }
  }
}

async function executeFixtureOperation(operation: Awaited<ReturnType<typeof enqueue>>) {
  try {
    await runOperation(operation.kind as OperationKind, operation);
    await sql`UPDATE operations SET status='succeeded' WHERE id=${operation.id}`;
  } catch (error) {
    await sql`UPDATE operations SET status='failed' WHERE id=${operation.id}`;
    throw error;
  }
}

async function preflight() {
  const operation = await enqueue({
    kind: ipv6PreflightKind,
    targetIds: [ipv6PreflightTarget],
    idempotencyKey: crypto.randomUUID(),
  });
  await executeFixtureOperation(operation);
  return operation;
}

async function submit(
  request: Ipv6ProbeRequest,
  token: string,
  report: Ipv6ProbeReport,
  pattern?: RegExp,
  consumed = true,
) {
  const signature = signIpv6Report(report, token);
  const call = (mac: string) =>
    app.request("http://127.0.0.1:3000/api/settings/ipv6/preflight/result", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signature: mac, report }),
    });
  assert.equal(request.id, report.id);
  assert.equal((await call("A".repeat(43))).status, 403);
  const response = await call(signature);
  assert.equal(response.status, 202, await response.clone().text());
  const { operationId } = await response.json();
  // Exercise the same coordinator operation with the submitted payload and get its terminal error.
  const queued = await db.query.operations.findFirst({
    where: (operations, { eq }) => eq(operations.id, operationId),
  });
  assert.ok(queued);
  const completion = executeFixtureOperation(queued);
  if (pattern) await assert.rejects(completion, pattern);
  else await completion;
  if (consumed) assert.equal((await call(signature)).status, 403);
  return queued.id;
}

async function enqueueManaged() {
  return enqueue({
    kind: ipv6PreflightKind,
    targetIds: [ipv6PreflightTarget],
    idempotencyKey: crypto.randomUUID(),
  });
}

async function scheduleManaged() {
  await runDnsMaintenance();
  const row = await db.query.operations.findFirst({
    where: (operations, { eq, like, or }) =>
      or(
        eq(operations.idempotencyKey, "ipv6.preflight"),
        like(operations.idempotencyKey, "ipv6.preflight:%"),
      ),
    orderBy: (operations, { desc }) => desc(operations.createdAt),
  });
  assert.ok(row);
  return row;
}
async function observe() {
  const operation = await enqueue({
    kind: "edge.observe",
    targetIds: ["tailnet:edge"],
    idempotencyKey: crypto.randomUUID(),
  });
  await executeFixtureOperation(operation);
}

test("native IPv6, separate PostgreSQL probes, AAAA withdrawal and Pebble HTTP-01", async () => {
  const testDb = new URL(process.env.DATABASE_URL ?? "");
  assert.ok(
    testDb.username === "ark_migration" &&
      testDb.hostname === "127.0.0.1" &&
      process.env.BETTER_AUTH_SECRET?.startsWith("test-db-"),
    "Use the disposable test database via mise run test:ipv6-preflight.",
  );
  const suffix = crypto.randomUUID().slice(0, 8);
  const name = `ark-fd27-${suffix}`;
  const dir = await mkdtemp(join(tmpdir(), name + "-"));
  const runtime = new EdgeTestRuntime(dir, name + "-v6");
  const stopSignals = runtime.installSignalHandlers();
  const v4Network = name + "-v4";
  const image = name + ":vps";
  const imageTags: string[] = [];
  const vps = name + "-vps";
  const runner = name + "-runner";
  const denied = name + "-denied";
  const dns = name + "-dns";
  const pebble = name + "-pebble";
  // Use global-unicast addresses only on this internal Docker network. Nothing is routed externally.
  const prefix = `2001:db9:${suffix.slice(0, 4)}:${suffix.slice(4, 8)}`;
  const address = publicIpv6(`${prefix}::10`)!;
  const source = publicIpv6(`${prefix}::20`)!;
  const docker = runtime.docker.bind(runtime);
  const host = (...args: string[]) => docker("exec", vps, ...args);
  const nested = (...args: string[]) => host("docker", ...args);
  const compose = (...args: string[]) => nested("compose", "-f", "/work/compose.yml", ...args);
  const staged = (operation: string) => host("bun", "/work/inside.js", operation);
  const files = {
    host: join(dir, "ipv6-host.json"),
    docker: join(dir, "snapshot.json"),
    edge: join(dir, "l4"),
  };
  const savedEnv = {
    ARK_OFFHOST_HEARTBEAT_URL: process.env.ARK_OFFHOST_HEARTBEAT_URL,
    ARK_IPV6_HOST_SNAPSHOT: process.env.ARK_IPV6_HOST_SNAPSHOT,
    ARK_IPV6_DOCKER_SNAPSHOT: process.env.ARK_IPV6_DOCKER_SNAPSHOT,
    ARK_EDGE_L4_DIR: process.env.ARK_EDGE_L4_DIR,
    ARK_EDGE_TS_SOCKET: process.env.ARK_EDGE_TS_SOCKET,
  };
  Object.assign(process.env, {
    ARK_IPV6_HOST_SNAPSHOT: files.host,
    ARK_IPV6_DOCKER_SNAPSHOT: files.docker,
    ARK_EDGE_L4_DIR: files.edge,
  });

  async function put(path: string, content: string) {
    const file = join(dir, path);
    await Bun.write(file, content);
    await host("mkdir", "-p", "/work/" + (path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : ""));
    await docker("cp", file, `${vps}:/work/${path}`);
  }

  async function snapshot(dockerState = true) {
    await Bun.write(files.host, await staged("host"));
    if (dockerState) {
      await staged("observe");
      await Bun.write(files.docker, await host("cat", "/work/snapshot.json"));
    }
  }

  const credentials: Record<string, ProbeCredential> = {};
  let worker: Subprocess | undefined;
  let localApi: MockLocalApi | undefined;
  let releaseRunner: (() => void) | undefined;
  let tlsReceiver: ReturnType<typeof Bun.serve> | undefined;
  let api: ReturnType<typeof Bun.serve> | undefined;
  let respond: (request: Ipv6ProbeRequest) => Promise<Response>;
  async function stopWorker() {
    if (!worker) return;
    worker.kill();
    await worker.exited;
    worker = undefined;
    delete process.env.ARK_OFFHOST_HEARTBEAT_URL;
  }
  async function startWorker() {
    if (!tlsReceiver) {
      const crt = join(dir, "receiver.crt");
      const key = join(dir, "receiver.key");
      const openssl = Bun.spawn(
        [
          "openssl",
          "req",
          "-x509",
          "-newkey",
          "ec",
          "-pkeyopt",
          "ec_paramgen_curve:P-256",
          "-nodes",
          "-days",
          "2",
          "-subj",
          "/CN=127.0.0.1",
          "-addext",
          "subjectAltName=IP:127.0.0.1",
          "-keyout",
          key,
          "-out",
          crt,
        ],
        { stdout: "ignore", stderr: "ignore" },
      );
      assert.equal(await openssl.exited, 0);
      tlsReceiver = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        tls: { cert: Bun.file(crt), key: Bun.file(key) },
        async fetch(request) {
          assert.equal(new URL(request.url).pathname, "/preflight");
          assert.equal(
            request.headers.get("authorization"),
            `Bearer ${process.env.ARK_OFFHOST_HEARTBEAT_TOKEN}`,
          );
          return respond(ipv6ProbeRequest.parse(await request.json()));
        },
      });
      api = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: app.fetch });
    }
    process.env.ARK_OFFHOST_HEARTBEAT_URL = tlsReceiver.url.toString();
    worker = Bun.spawn(
      [
        process.execPath,
        "--no-env-file",
        "-e",
        `
      import { runDomainJobs } from "./workers/src/domains.ts";
      import { executeClaimedJob } from "./server/src/coordinator.ts";
      // The fixture controls public DNS explicitly after the withdrawal check.
      await runDomainJobs((job) => job.kind === "domain.verify" ? Promise.resolve() : executeClaimedJob(job), { pollMs: 50 });
    `,
      ],
      {
        cwd: root,
        env: {
          ...process.env,
          ARK_API_URL: api!.url.toString().replace(/\/$/, ""),
          ARK_EDGE_DIR: join(dir, "caddy"),
          ARK_WORKER_TOKEN: process.env.ARK_DOMAIN_WORKER_TOKEN,
          NODE_EXTRA_CA_CERTS: join(dir, "receiver.crt"),
        },
        stdout: "ignore",
        stderr: "inherit",
      },
    );
  }

  async function completed(id: string, status: "succeeded" | "failed") {
    return retry(async () => {
      const row = await db.query.operations.findFirst({
        where: (operations, { eq }) => eq(operations.id, id),
      });
      assert.ok(row);
      assert.equal(row.status, status, row.error ?? `${row.kind} is ${row.status}`);
      return row;
    }, 35_000);
  }

  async function probe(request: Ipv6ProbeRequest, client = runner, auth = credentials) {
    return JSON.parse(
      await docker(
        "exec",
        client,
        "bun",
        "/tmp/inside.js",
        "probe",
        JSON.stringify({ request, credentials: auth }),
      ),
    ) as Ipv6ProbeReport;
  }
  const secret = loadEnv().authSecret;
  async function challenge() {
    await snapshot();
    const operation = await preflight();
    const signed = await ipv6PreflightChallenge(operation.id, secret);
    assert.ok(signed, "The ready host must issue a signed request for its active listeners.");
    return signed;
  }

  async function generation(input: EdgeL4Input) {
    const gen = renderEdgeL4Generation(input);
    for (const [path, content] of Object.entries(gen.files))
      await put(`l4/generations/${gen.id}/${path}`, content);
    await rm(join(files.edge, "current"), { force: true });
    await symlink(`generations/${gen.id}`, join(files.edge, "current"));
    await nested("rm", "-f", "edge-l4").catch(() => undefined);
    await nested(
      "run",
      "-d",
      "--name",
      "edge-l4",
      "--label",
      "com.docker.compose.project=ark-platform",
      "--label",
      "com.docker.compose.service=edge-l4",
      "--network",
      "container:edge-ts",
      "--user",
      "0",
      "-v",
      "/work/l4:/l4:ro",
      "-v",
      "/work/run:/var/run/haproxy",
      "-e",
      `${EDGE_L4_GENERATION_ENV}=/l4/generations/${gen.id}`,
      haproxy,
      "haproxy",
      "-W",
      "-db",
      "-S",
      "/var/run/haproxy/master.sock,gid,4400,mode,660",
      "-f",
      `/l4/generations/${gen.id}/haproxy.cfg`,
    );
    await retry(async () =>
      assert.match(
        await nested(
          "exec",
          "edge-l4",
          "sh",
          "-c",
          "test -S /var/run/haproxy/admin.sock && test -S /var/run/haproxy/master.sock && echo ready",
        ),
        /ready/,
      ),
    );
  }

  let haproxy = "";
  let v4Created = false;
  let guestBuilt = false;
  try {
    await sql`INSERT INTO platform_settings (id, public_ipv4, public_ipv6) VALUES ('default', '203.0.113.27', ${address})
      ON CONFLICT (id) DO UPDATE SET public_ipv4 = EXCLUDED.public_ipv4, public_ipv6 = EXCLUDED.public_ipv6`;
    await sql`INSERT INTO domain_claims (id, name, ownership_token, status) VALUES (${domainId}, 'fd27.example.com', 'fd27-token', 'verified')`;
    await sql`INSERT INTO endpoints (id,domain_id,kind,hostname,exposure,status)
      VALUES ('ep_fd27app',${domainId},'route',${appHost},'public','awaiting_dns')`;
    await sql`INSERT INTO dns_records (id,domain_id,type,name,relative_name,expected_value,purpose,required)
      VALUES ('dns_fd27app',${domainId},'A',${appHost},'app','203.0.113.27','Fixture HTTP endpoint',true)`;
    await docker(
      "build",
      "--target",
      "vps",
      "-f",
      join(root, "scripts/host-hardening-test/Dockerfile"),
      "-t",
      image,
      root,
    );
    guestBuilt = true;
    await docker("network", "create", "--internal", v4Network);
    v4Created = true;
    runtime.containers.push(vps);
    await mkdir(join(dir, "acme"), { mode: 0o755 });
    await docker(
      "run",
      "-d",
      "--name",
      vps,
      "--network",
      v4Network,
      "--privileged",
      "--cgroupns",
      "private",
      "--tmpfs",
      "/run",
      "--tmpfs",
      "/run/lock",
      "-v",
      `${dir}/acme:/work/acme`,
      "-v",
      "/var/lib/docker",
      "-v",
      "/var/lib/containerd",
      image,
      "/sbin/init",
    );
    await host("mkdir", "-p", "/work/run", "/work/acme", "/etc/docker");
    const builds = await Promise.all(
      [join(import.meta.dir, "inside.ts"), join(root, "scripts/observe-docker-ipv6.ts")].map((entrypoint) =>
        Bun.build({ entrypoints: [entrypoint], target: "bun", outdir: dir }),
      ),
    );
    for (const build of builds) assert.ok(build.success, build.logs.join("\n"));
    await docker("cp", join(dir, "inside.js"), `${vps}:/work/inside.js`);
    await host("mkdir", "-p", "/work/scripts");
    await docker("cp", join(dir, "observe-docker-ipv6.js"), `${vps}:/work/scripts/observe-docker-ipv6.ts`);
    await snapshot(false);
    await preflight();
    assert.equal((await ipv6Settings())?.ipv6Status, "not_present");
    assert.equal((await sql`SELECT count(*)::int AS n FROM dns_records WHERE type='AAAA'`)[0]?.n, 0);
    console.log("IPv4-only guest reports not_present and plans no AAAA.");

    await docker("network", "create", "--internal", "--ipv6", "--subnet", prefix + "::/64", runtime.network);
    runtime.networkCreated = true;
    await docker("network", "connect", "--ip6", address, runtime.network, vps);
    for (const [client, ip] of [
      [runner, source],
      [denied, prefix + "::21"],
    ] as const) {
      runtime.containers.push(client);
      await docker(
        "run",
        "-d",
        "--name",
        client,
        "--network",
        runtime.network,
        "--ip6",
        ip,
        image,
        "sleep",
        "infinity",
      );
      await docker("cp", join(dir, "inside.js"), `${client}:/tmp/inside.js`);
    }

    await host("sh", "-ec", "systemctl unmask docker.service docker.socket; systemctl start docker");
    const images = [
      bunImage,
      pgImage,
      platform.services.edge!.image,
      platform.services["edge-l4"]!.image,
      platform.services["pgbouncer-public"]!.image,
    ];
    await Promise.all(
      images.map(async (ref, index) => {
        const tag = name + ":nested-" + index;
        await docker("image", "inspect", ref).catch(() => docker("pull", ref));
        await docker("image", "tag", ref, tag);
        imageTags[index] = tag;
      }),
    );
    // Keep tags across Docker Desktop's containerd store and the guest's classic image store.
    const save = Bun.spawn(["docker", "image", "save", ...imageTags], { stdout: "pipe", stderr: "inherit" });
    const load = Bun.spawn(["docker", "exec", "-i", vps, "docker", "load"], {
      stdin: save.stdout,
      stdout: "ignore",
      stderr: "inherit",
    });
    assert.deepEqual(await Promise.all([save.exited, load.exited]), [0, 0]);
    const [bun, postgres, caddy, proxy, pgbouncer] = imageTags as [string, string, string, string, string];
    haproxy = proxy;
    async function composeFile(ipv6: boolean) {
      await put(
        "compose.yml",
        `name: ark-platform
services:
  edge-ts:
    container_name: edge-ts
    image: ${bun}
    pull_policy: never
    command: [sleep, infinity]
    stop_grace_period: 1s
    ports: ["80:80", "443:443", "5432:5432", "8883:8883", "20007:20007", "20008:20008"]
    networks: [admin, pgbouncer-ingress]
  tailscale:
    container_name: tailscale
    image: ${bun}
    pull_policy: never
    command: [sleep, infinity]
    stop_grace_period: 1s
    profiles: [tailnet]
    networks: [admin]
  tailnet-gateway:
    container_name: tailnet-gateway
    image: ${bun}
    pull_policy: never
    command: [sleep, infinity]
    stop_grace_period: 1s
    profiles: [tailnet]
    network_mode: "service:tailscale"
networks:
  admin:
    enable_ipv6: ${ipv6}
    ipam:
      config: [{subnet: "100.76.27.0/24"}]
  pgbouncer-ingress: { internal: true }
`,
      );
      await put(
        "mail.yml",
        `name: ark-mail
services:
  stalwart:
    container_name: stalwart
    image: ${bun}
    pull_policy: never
    command: [sleep, infinity]
    stop_grace_period: 1s
    ports: ["25:25"]
    networks: [mail-public]
networks:
  mail-public: { enable_ipv6: ${ipv6} }
`,
      );
    }
    await composeFile(false);
    await compose("--profile", "tailnet", "up", "-d");
    await nested("compose", "-f", "/work/mail.yml", "up", "-d");
    await staged("prepare");
    await compose("--profile", "tailnet", "up", "-d");
    await nested("compose", "-f", "/work/mail.yml", "up", "-d");
    await assert.rejects(staged("proxy-off"), /before disabling Docker's proxy/);
    assert.equal(platform.networks.admin.enable_ipv6, true);
    await composeFile(true);
    await staged("upgrade-networks");
    const tailnet = await nested("ps", "--format", "{{.Names}}");
    assert.match(tailnet, /tailscale/);
    assert.match(tailnet, /tailnet-gateway/);
    const mailBefore = await nested("inspect", "--format", "{{.Id}}", "stalwart");
    const current = await nested("inspect", "--format", "{{.Id}}", "edge-ts");
    const baseline = (await Bun.file(join(root, "infra/platform/Caddyfile")).text())
      .split(":80 {")[1]!
      .split("# Public admin")[0]!
      .replace("/var/lib/ark/acme", "/work/acme");

    async function cert(hostname: string) {
      await host("mkdir", "-p", "/work/tls/" + hostname);
      await host(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=" + hostname,
        "-addext",
        "subjectAltName=DNS:" + hostname,
        "-keyout",
        `/work/tls/${hostname}/key.pem`,
        "-out",
        `/work/tls/${hostname}/cert.pem`,
      );
      return host("cat", `/work/tls/${hostname}/cert.pem`);
    }
    credentials.https = { ca: await cert(appHost) };
    credentials.rt_fd27pg = { ca: await cert(pgHost), username: role, database, password };
    await put(
      "Caddyfile",
      `${CADDY_GLOBAL_BLOCK.replace("admin edge-admin:2019", "admin off")}
:80 {${baseline}
${appHost} {
  bind 127.0.0.1
  tls /work/tls/${appHost}/cert.pem /work/tls/${appHost}/key.pem
  respond "ipv6"
}
`,
    );
    async function startCaddy() {
      await nested("rm", "-f", "edge").catch(() => undefined);
      await nested(
        "run",
        "-d",
        "--name",
        "edge",
        "--label",
        "com.docker.compose.project=ark-platform",
        "--label",
        "com.docker.compose.service=edge",
        "--network",
        "container:edge-ts",
        "-v",
        "/work:/work:ro",
        caddy,
        "caddy",
        "run",
        "--config",
        "/work/Caddyfile",
        "--adapter",
        "caddyfile",
      );
    }
    await startCaddy();
    await generation({ httpHostnames: [appHost] });
    await snapshot();
    await assert.rejects(preflight(), /proxy disabled/);
    await nested("rm", "-f", "edge", "edge-l4");
    await staged("proxy-off");
    assert.notEqual(await nested("inspect", "--format", "{{.Id}}", "stalwart"), mailBefore);
    assert.notEqual(await nested("inspect", "--format", "{{.Id}}", "edge-ts"), current);
    await startCaddy();
    await generation({ httpHostnames: [appHost] });
    await staged("install-observer");
    assert.equal(await host("systemctl", "is-enabled", "ark-docker-ipv6.timer"), "enabled");
    assert.ok(dockerIpv6Ready(JSON.parse(await host("cat", "/var/lib/ark/ipv6/snapshot.json")).docker));
    const manual = await challenge();
    const manualReport = await probe(manual.request);
    await snapshot();
    await submit(manual.request, manual.token, manualReport);
    assert.equal((await ipv6Settings())?.ipv6Status, "passed");

    await nested(
      "run",
      "-d",
      "--name",
      "app-postgres",
      "--network",
      "ark-platform_admin",
      "--ip",
      targetIp,
      "--tmpfs",
      "/var/lib/postgresql/data",
      "-e",
      "POSTGRES_PASSWORD=" + password,
      "-v",
      "/work/tls:/tls:ro",
      "--entrypoint",
      "sh",
      postgres,
      "-ec",
      `cp /tls/${pgHost}/cert.pem /tmp/server.crt; cp /tls/${pgHost}/key.pem /tmp/server.key;
chown postgres /tmp/server.*; chmod 600 /tmp/server.key;
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key`,
    );
    // The image starts a temporary Unix-socket-only server during init. Wait for the final listener.
    await retry(() =>
      nested(
        "exec",
        "-e",
        "PGPASSWORD=" + password,
        "app-postgres",
        "psql",
        "-h",
        "127.0.0.1",
        "-U",
        "postgres",
        "-tAc",
        "SELECT 1",
      ),
    );
    await nested(
      "exec",
      "app-postgres",
      "psql",
      "-U",
      "postgres",
      "-v",
      "ON_ERROR_STOP=1",
      "-c",
      `CREATE ROLE ${role} LOGIN PASSWORD '${password}'`,
      "-c",
      `CREATE DATABASE ${database} OWNER ${role}`,
    );
    const clientCa = createCaMaterial({ id: "pca_fd27", purpose: "db-client", name: "FD-27 probe" });
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const clientCert = signClientCertificate({
      ca: { certPem: clientCa.certPem, privateKey: clientCa.privateKey },
      subjectCn: role,
      publicKey: pair.publicKey,
    });
    credentials.pgbouncer = {
      ca: await cert(dbHost),
      cert: clientCert.certPem,
      key: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
      username: role,
      password,
      database,
    };
    const plan = planPgbouncer({
      databases: [{ id: "mdb_fd27", name: database, exposure: "public" }],
      clients: [
        {
          id: "dbc_fd27",
          databaseId: "mdb_fd27",
          environment: "production",
          status: "active",
          caId: "pca_fd27",
          role: { name: role, connectionLimit: 20, password },
        },
      ],
      certificates: [
        {
          id: "ccert_fd27",
          caId: "pca_fd27",
          status: "issued",
          rolloverState: "current",
          supersededBy: null,
          notAfter: clientCert.notAfter,
        },
      ],
      cas: [
        {
          id: "pca_fd27",
          purpose: "db-client",
          status: "active",
          certPem: clientCa.certPem,
          notAfter: clientCa.notAfter,
        },
      ],
      now: new Date(),
      host: "app-postgres",
    });
    const poolerFiles = renderPgbouncerFiles({
      plan,
      adminPassword: crypto.randomUUID(),
      certificateDir: "/var/lib/ark/pgbouncer/certs",
    });
    for (const [path, content] of Object.entries(poolerFiles)) await put("pgbouncer/" + path, content);
    await host("mkdir", "-p", "/work/pgbouncer/certs");
    await host("cp", `/work/tls/${dbHost}/cert.pem`, "/work/pgbouncer/certs/fullchain.pem");
    await host("cp", `/work/tls/${dbHost}/key.pem`, "/work/pgbouncer/certs/privkey.pem");
    await host("chown", "-R", "1000:1000", "/work/pgbouncer");
    await nested("network", "create", "--internal", "database-management");
    await nested("network", "connect", "database-management", "app-postgres");
    await nested(
      "run",
      "-d",
      "--name",
      "pgbouncer-public",
      "--network",
      "ark-platform_pgbouncer-ingress",
      "--user",
      "1000:1000",
      "-v",
      "/work/pgbouncer:/var/lib/ark/pgbouncer:ro",
      "--tmpfs",
      "/var/run/pgbouncer:uid=1000,gid=1000,mode=0700",
      "--entrypoint",
      "/usr/bin/pgbouncer",
      pgbouncer,
      "/var/lib/ark/pgbouncer/pgbouncer.ini",
    );
    await nested("network", "connect", "database-management", "pgbouncer-public");

    const cidrs = [source + "/128"];
    const policy = (
      kind: "postgres" | "tcp" | "tls",
      listenPort: number,
      tlsMode: "passthrough" | "plain" | "terminate" | "terminate_mtls",
      options: { compatPort?: number; clientCaId?: string } = {},
    ) =>
      l4PolicyFingerprint({
        kind,
        listenPort,
        tlsMode,
        sourceCidrs: cidrs,
        allowInternet: false,
        limits: l4Limits(kind),
        ...options,
      });
    const pgRoute = {
      id: "rt_fd27pg",
      hostname: pgHost,
      stableId: "nFd27",
      ip: targetIp,
      port: 5432,
      sourceCidrs: cidrs,
      compatPort: 20007,
      policy: policy("postgres", 5432, "passthrough", { compatPort: 20007 }),
    };
    const rawRoute = {
      ...pgRoute,
      id: "rt_fd27raw",
      hostname: "tcp.fd27.example.com",
      listenPort: 20008,
      policy: policy("tcp", 20008, "plain"),
    };
    const pooler = { hostname: dbHost, sourceCidrs: cidrs };
    await sql`INSERT INTO endpoints (id,domain_id,kind,hostname,exposure,status) VALUES
      ('ep_fd27pg',${domainId},'route',${pgHost},'public','awaiting_dns'),
      ('ep_fd27raw',${domainId},'route',${rawRoute.hostname},'public','awaiting_dns'),
      ('ep_fd27db',${domainId},'database',${dbHost},'public','awaiting_dns')`;
    await sql`INSERT INTO front_routes (id,kind,endpoint_id,listen_port,compat_port,target_input,target_node_stable_id,
      target_ip,target_port,access_mode,tls_mode,enabled,status,source_cidrs) VALUES
      (${pgRoute.id},'postgres','ep_fd27pg',5432,20007,${targetIp},'nFd27',${targetIp},5432,'public','passthrough',false,'ready',${JSON.stringify(cidrs)}::jsonb),
      (${rawRoute.id},'tcp','ep_fd27raw',20008,null,${targetIp},'nFd27',${targetIp},5432,'public','plain',false,'ready',${JSON.stringify(cidrs)}::jsonb)`;
    await sql`INSERT INTO database_clusters (id,name,endpoint_id) VALUES ('dcl_fd27','fd27','ep_fd27db')`;
    await sql`INSERT INTO managed_databases (id,cluster_id,name,exposure,source_cidrs)
      VALUES ('mdb_fd27','dcl_fd27',${database},'private',${JSON.stringify(cidrs)}::jsonb)`;
    await sql`UPDATE platform_settings SET pooler_source_cidrs=${JSON.stringify(cidrs)}::jsonb WHERE id='default'`;
    for (const mode of ["route", "pooler", "both"] as const) {
      await sql`UPDATE front_routes SET enabled=${mode !== "pooler"} WHERE id IN (${pgRoute.id},${rawRoute.id})`;
      await sql`UPDATE managed_databases SET exposure=${mode === "route" ? "private" : "public"} WHERE id='mdb_fd27'`;
      await generation({
        httpHostnames: [appHost],
        postgresRoutes: mode === "pooler" ? [] : [pgRoute],
        tcpRoutes: mode === "pooler" ? [] : [rawRoute],
        pooler: mode === "route" ? null : pooler,
      });
      await snapshot();
      if (mode === "route") {
        const obsolete = await challenge();
        const report = await probe(obsolete.request);
        await snapshot();
        await sql`UPDATE front_routes SET source_cidrs='["2001:db9::99/128"]', updated_at=now() WHERE id=${pgRoute.id}`;
        await submit(obsolete.request, obsolete.token, report, /older configuration/, false);
        await assert.rejects(preflight(), /does not match the active HAProxy configuration/);
        await sql`UPDATE front_routes SET source_cidrs=${JSON.stringify(cidrs)}::jsonb WHERE id=${pgRoute.id}`;

        const delegated = await challenge();
        const classic = await probe({
          ...delegated.request,
          checks: [
            { id: "pgbouncer", protocol: "postgres-classic", port: 5432, hostname: dbHost },
            delegated.request.checks[0]!,
          ],
        });
        assert.equal(classic.checks[0]?.outcome, "failed");
        // An admitted TCP connection to the real PostgreSQL backend corroborates the address and
        // source port, but a signer without database credentials cannot attest to a query.
        const claimed = {
          id: pgRoute.id,
          ...JSON.parse(
            await docker(
              "exec",
              runner,
              "bun",
              "/tmp/inside.js",
              "postgres-handshake",
              JSON.stringify({
                address,
                hostname: pgHost,
                ca: credentials[pgRoute.id]!.ca,
              }),
            ),
          ),
        };
        const genuine = await probe(delegated.request);
        await snapshot();
        const { logs } = await Bun.file(files.docker).json();
        assert.ok(
          logs.some(
            (log: { source: string; sourcePort: number; frontend?: string; connected?: boolean }) =>
              log.source === claimed.source &&
              log.sourcePort === claimed.sourcePort &&
              log.frontend === "fe_pg5432" &&
              log.connected,
          ),
          "The handshake without SQL login must have independent HAProxy backend-connect evidence.",
        );
        await submit(
          delegated.request,
          delegated.token,
          {
            ...genuine,
            checks: genuine.checks.map((check) => (check.id === pgRoute.id ? claimed : check)),
          },
          /5432\/postgres-direct/,
        );
        const checks = (await ipv6Settings())?.ipv6Evidence?.checks as {
          id: string;
          outcome: string;
          reason?: string;
        }[];
        assert.deepEqual(checks.find(({ id }) => id === pgRoute.id)?.outcome, "unverified");
        assert.match(checks.find(({ id }) => id === pgRoute.id)?.reason ?? "", /requires the managed runner/);

        const started = Promise.withResolvers<void>();
        const release = Promise.withResolvers<void>();
        releaseRunner = () => release.resolve();
        respond = async () => {
          const body = new ReadableStream<Uint8Array>({
            async start(controller) {
              controller.enqueue(new TextEncoder().encode('{"checks":'));
              started.resolve();
              await release.promise;
              controller.error(new Error("The fixture runner disconnected mid-report."));
            },
          });
          return new Response(body, { headers: { "content-type": "application/json" } });
        };
        await startWorker();
        await sql`UPDATE platform_settings SET ipv6_checked_at=${new Date(Date.now() - IPV6_PREFLIGHT_RETRY_MS - 1).toISOString()}::timestamptz`;
        const outage = await scheduleManaged();
        await Promise.race([
          started.promise,
          Bun.sleep(10_000).then(() => {
            throw new Error("The HTTPS runner did not receive the scheduled check.");
          }),
        ]);
        // The edge job must complete while the preflight is still awaiting the HTTPS response.
        const drain = await enqueue({
          kind: "edge.drain",
          targetIds: ["platform"],
          payload: { reason: "fixture" },
        });
        await completed(drain.id, "succeeded");
        releaseRunner();
        releaseRunner = undefined;
        await completed(outage.id, "failed");
        const failed = await ipv6Settings();
        assert.equal(failed?.ipv6Status, "failed");
        assert.equal(await ipv6PreflightDue(), false);
        await sql`UPDATE platform_settings SET ipv6_checked_at=${new Date(Date.now() - IPV6_PREFLIGHT_RETRY_MS - 1).toISOString()}::timestamptz`;
        assert.equal(await ipv6PreflightDue(), true);
        respond = async (request) => {
          const result = await probe(request);
          await snapshot();
          return Response.json(result);
        };
        const retried = await scheduleManaged();
        assert.notEqual(retried.id, outage.id);
        await completed(retried.id, "succeeded");
        assert.equal((await ipv6Settings())?.ipv6Evidence?.fingerprint, failed?.ipv6Evidence?.fingerprint);
      } else {
        if (mode === "both") {
          respond = async (request) => {
            const forbidden = await probe(request, denied);
            assert.ok(
              forbidden.checks
                .filter(({ id }) => ["pgbouncer", pgRoute.id].includes(id))
                .every(({ outcome }) => outcome !== "passed"),
            );
            const bad = await probe(request, runner, {
              ...credentials,
              pgbouncer: { ...credentials.pgbouncer, cert: undefined, key: undefined },
              [pgRoute.id]: { ...credentials[pgRoute.id], password: "wrong-password" },
            });
            assert.equal(bad.checks.find(({ id }) => id === "pgbouncer")?.outcome, "unverified");
            assert.equal(bad.checks.find(({ id }) => id === pgRoute.id)?.outcome, "failed");
            const result = await probe(request);
            await snapshot();
            return Response.json(result);
          };
        }
        await completed((await enqueueManaged()).id, "succeeded");
      }

      const settings = await ipv6Settings();
      assert.equal(settings?.ipv6Status, "passed");
      const checks = settings?.ipv6Evidence?.checks as { source: string; protocol: string }[];
      assert.equal(
        checks.some(({ protocol }) => protocol === "postgres-classic"),
        mode !== "route",
      );
      assert.equal(
        checks.some(({ protocol }) => protocol === "postgres-direct"),
        mode !== "pooler",
      );
      for (const evidence of checks) assert.equal(evidence.source, source);
      console.log(`${mode} passed with ${source} confirmed by the edge logs.`);
    }

    await stopWorker();
    const observationSocket = join(dir, "edge.sock");
    localApi = new MockLocalApi({
      backendState: "Running",
      suffix: ".tail27.ts.net",
      self: { id: "nEdge27", name: "ark-edge", ips: ["100.76.27.1"], tags: ["tag:ark-edge"] },
      peers: [{ id: pgRoute.stableId, name: "target", ips: [targetIp] }],
      reachable: new Set([`${targetIp}:5432`]),
    });
    process.env.ARK_EDGE_TS_SOCKET = await localApi.listen(observationSocket);
    await sql`INSERT INTO certificates (id, endpoint_id, names, status, last_deployed_at) VALUES
      ('crt_fd27pg', 'ep_fd27pg', ${JSON.stringify([pgHost])}::jsonb, 'issued', now()),
      ('crt_fd27raw', 'ep_fd27raw', ${JSON.stringify([rawRoute.hostname])}::jsonb, 'issued', now())`;
    await observeEdgeTailnet({
      api: edgeLocalApi(observationSocket),
      enqueue: async () => undefined,
    });
    const policyFingerprint = (await ipv6Settings())?.ipv6Evidence?.fingerprint;
    const [before] = await sql`SELECT updated_at FROM front_routes WHERE id=${pgRoute.id}`;
    await Bun.sleep(5);
    await observe();
    const [after] = await sql`SELECT updated_at FROM front_routes WHERE id=${pgRoute.id}`;
    assert.notDeepEqual(before?.updated_at, after?.updated_at);
    await snapshot();
    assert.equal(await ipv6PreflightDue(), false);
    assert.equal((await ipv6Settings())?.ipv6Evidence?.fingerprint, policyFingerprint);

    const deadTls = {
      ...pgRoute,
      id: "rt_fd27tls",
      hostname: tlsHost,
      listenPort: 8883,
      port: 6543,
      tlsMode: "terminate" as const,
      policy: policy("tls", 8883, "terminate"),
      certificatePem: (await cert(tlsHost)) + "\n" + (await host("cat", `/work/tls/${tlsHost}/key.pem`)),
    };
    credentials[deadTls.id] = { ca: await host("cat", `/work/tls/${tlsHost}/cert.pem`) };
    const mtlsCa = await createPrivateCa({ purpose: "tcp-client", name: "FD-27 mTLS" });
    const mtlsClient = await issueClientCertificate({
      caId: mtlsCa.id,
      subjectCn: "fd27-mtls",
      keyOwner: { resourceType: "platform", resourceId: "platform" },
    });
    const mtlsKey = await db.query.secrets.findFirst({
      where: (secrets, { eq }) => eq(secrets.id, mtlsClient.certificate.keySecretId!),
    });
    assert.ok(mtlsKey);
    assert.ok(mtlsClient.certificate.certPem);
    const mtls = {
      ...deadTls,
      id: "rt_fd27mtls",
      hostname: mtlsHost,
      port: 5432,
      tlsMode: "terminate_mtls" as const,
      policy: policy("tls", 8883, "terminate_mtls", { clientCaId: mtlsCa.id }),
      certificatePem: (await cert(mtlsHost)) + "\n" + (await host("cat", `/work/tls/${mtlsHost}/key.pem`)),
      clientCaPem: mtlsClient.caCertPem,
      clientCrlPem: (await generateCaCrl({ caId: mtlsCa.id })).crlPem,
    };
    credentials[mtls.id] = {
      ca: await host("cat", `/work/tls/${mtlsHost}/cert.pem`),
      cert: mtlsClient.certificate.certPem,
      key: revealSecret(mtlsKey),
    };
    await sql`INSERT INTO endpoints (id,domain_id,kind,hostname,exposure,status) VALUES
      ('ep_fd27tls',${domainId},'route',${tlsHost},'public','awaiting_dns'),
      ('ep_fd27mtls',${domainId},'route',${mtlsHost},'public','awaiting_dns')`;
    await sql`INSERT INTO front_routes (id,kind,endpoint_id,listen_port,target_input,target_node_stable_id,
      target_ip,target_port,access_mode,tls_mode,enabled,status,source_cidrs,client_ca_id) VALUES
      (${deadTls.id},'tls','ep_fd27tls',8883,${targetIp},'nFd27',${targetIp},6543,'public','terminate',true,'ready',${JSON.stringify(cidrs)}::jsonb,null),
      (${mtls.id},'tls','ep_fd27mtls',8883,${targetIp},'nFd27',${targetIp},5432,'public','terminate_mtls',true,'ready',${JSON.stringify(cidrs)}::jsonb,${mtlsCa.id})`;
    const dataRoutes = { httpHostnames: [appHost], postgresRoutes: [pgRoute], tcpRoutes: [rawRoute], pooler };
    await generation({ ...dataRoutes, tlsRoutes: [deadTls, mtls], sniPorts: [8883] });
    await snapshot();
    const invalidClient = {
      ...credentials,
      [mtls.id]: { ca: credentials[mtls.id]!.ca, cert: clientCert.certPem, key: credentials.pgbouncer!.key },
    };
    respond = async (request) => {
      const report = await probe(request, runner, invalidClient);
      assert.equal(
        report.checks.find(({ id }) => id === deadTls.id)?.outcome,
        "passed",
        "Public TLS completed even though the backend is offline.",
      );
      await snapshot();
      return Response.json(report);
    };
    await startWorker();
    const failedTls = await completed((await enqueueManaged()).id, "failed");
    assert.match(
      failedTls.error ?? "",
      /8883\/tls/,
      "The managed operation must record the listener failures.",
    );
    const tlsEvidence = (await ipv6Settings())?.ipv6Evidence?.checks as {
      id: string;
      outcome: string;
      reason?: string;
    }[];
    assert.match(tlsEvidence.find(({ id }) => id === deadTls.id)?.reason ?? "", /edge did not log/);
    assert.notEqual(tlsEvidence.find(({ id }) => id === mtls.id)?.outcome, "passed");

    await sql`UPDATE front_routes SET enabled=false WHERE id=${deadTls.id}`;
    await generation({ ...dataRoutes, tlsRoutes: [mtls], sniPorts: [8883] });
    await snapshot();
    respond = async (request) => {
      const result = await probe(request);
      await snapshot();
      return Response.json(result);
    };
    await completed((await enqueueManaged()).id, "succeeded");
    const mtlsEvidence = (await ipv6Settings())?.ipv6Evidence?.checks as { id: string; outcome: string }[];
    assert.equal(mtlsEvidence.find(({ id }) => id === mtls.id)?.outcome, "passed");

    const [planned] = await sql`SELECT expected_value FROM dns_records WHERE domain_id=${domainId}
      AND name=${appHost} AND type='AAAA' AND withdrawal_reason IS NULL`;
    assert.equal(planned?.expected_value, address);

    // Pebble lives on the simulated WAN, has an AAAA answer only, and requests the actual Caddy webroot.
    await docker(
      "run",
      "-d",
      "--name",
      dns,
      "--network",
      runtime.network,
      dnsImage,
      "-defaultIPv4",
      "",
      "-defaultIPv6",
      "",
      "-http01",
      "",
      "-https01",
      "",
      "-tlsalpn01",
      "",
    );
    runtime.containers.push(dns);
    const resolverIp = await docker(
      "inspect",
      "--format",
      `{{(index .NetworkSettings.Networks "${runtime.network}").IPAddress}}`,
      dns,
    );
    const dnsAction = (action: string, payload: Record<string, unknown>) =>
      docker(
        "exec",
        runner,
        "bun",
        "-e",
        `
        const response = await fetch("http://${resolverIp}:8055/${action}", {
          method: "POST", body: ${JSON.stringify(JSON.stringify(payload))},
        });
        if (!response.ok) throw new Error(await response.text());
      `,
      );
    const resolveAaaa = async (hostname: string): Promise<string[]> =>
      JSON.parse(
        await docker(
          "exec",
          runner,
          "bun",
          "-e",
          `
        import { Resolver } from "node:dns/promises";
        const resolver = new Resolver();
        resolver.setServers(["${resolverIp}:8053"]);
        const records = await resolver.resolve6(${JSON.stringify(hostname)}).catch((error) => {
          if (["ENODATA", "ENOTFOUND"].includes(error.code)) return [];
          throw error;
        });
        console.log(JSON.stringify(records));
      `,
        ),
      );
    await retry(() => dnsAction("add-aaaa", { host: appHost, addresses: [planned?.expected_value] }));
    assert.deepEqual(await resolveAaaa(appHost), [address]);
    await docker(
      "create",
      "--name",
      pebble,
      "--network",
      runtime.network,
      "-e",
      "PEBBLE_VA_NOSLEEP=1",
      pebbleImage,
      "-config",
      "/config.json",
      "-dnsserver",
      resolverIp + ":8053",
    );
    runtime.containers.push(pebble);
    const pem = `/work/tls/${appHost}`;
    await docker("cp", `${vps}:${pem}/cert.pem`, join(dir, "pebble-cert.pem"));
    await docker("cp", `${vps}:${pem}/key.pem`, join(dir, "pebble-key.pem"));
    await Bun.write(
      join(dir, "pebble.json"),
      JSON.stringify({
        pebble: {
          listenAddress: ":14000",
          managementListenAddress: ":15000",
          certificate: "/cert.pem",
          privateKey: "/key.pem",
          httpPort: 80,
          tlsPort: 443,
        },
      }),
    );
    for (const [from, to] of [
      ["pebble-cert.pem", "cert.pem"],
      ["pebble-key.pem", "key.pem"],
      ["pebble.json", "config.json"],
    ]) {
      await docker("cp", join(dir, from), `${pebble}:/${to}`);
    }
    await docker("start", pebble);
    const pebbleIp = await docker(
      "inspect",
      "--format",
      `{{(index .NetworkSettings.Networks "${runtime.network}").IPAddress}}`,
      pebble,
    );
    const acme = `https://${appHost}:14000/dir`;
    // The ACME client reaches the API by IPv4. Validation DNS gives Pebble only the published AAAA.
    await retry(() =>
      docker(
        "exec",
        runner,
        "bun",
        "-e",
        `const r=await fetch("https://${pebbleIp}:14000/dir", { tls: { rejectUnauthorized: false } }); if (!r.ok) process.exit(1);`,
      ),
    );
    const output = await docker(
      "run",
      "--rm",
      "--network",
      runtime.network,
      "--add-host",
      `${appHost}:${pebbleIp}`,
      "-e",
      "LEGO_CA_CERTIFICATES=/fixture/pebble-cert.pem",
      "-v",
      `${dir}/pebble-cert.pem:/fixture/pebble-cert.pem:ro`,
      "-v",
      `${dir}/acme:/webroot`,
      "--entrypoint",
      "/bin/sh",
      legoImage,
      "-ec",
      '/lego --server "$1" --email test@fd27.example.com --accept-tos --domains "$2" --http --http.webroot /webroot --path /lego-state run; cat "/lego-state/certificates/$2.crt"',
      "lego",
      acme,
      appHost,
    );
    const issued = new X509Certificate(output);
    assert.equal(issued.checkHost(normalizeHostname(appHost)), appHost);
    console.log("Pebble issued through the native IPv6 port-80 publication with an AAAA-only answer.");

    await host("nft", "add", "table", "inet", "fd27_test");
    await host(
      "nft",
      "add",
      "chain",
      "inet",
      "fd27_test",
      "provider",
      "{ type filter hook prerouting priority -110; policy accept; }",
    );
    await host(
      "nft",
      "add",
      "rule",
      "inet",
      "fd27_test",
      "provider",
      "ip6",
      "daddr",
      address,
      "tcp",
      "dport",
      "443",
      "drop",
    );
    await snapshot();
    const closed = await enqueueManaged();
    await completed(closed.id, "failed");
    const failedOperation = closed.id;
    await stopWorker();
    assert.equal((await ipv6Settings())?.ipv6Status, "failed");
    const [old] = await sql`SELECT withdrawal_reason, withdrawal_confirmed_at FROM dns_records
      WHERE domain_id=${domainId} AND name=${appHost} AND type='AAAA'`;
    assert.equal(old?.withdrawal_reason, "ipv6");
    assert.equal(old?.withdrawal_confirmed_at, null);
    await dnsAction("clear-aaaa", { host: appHost });
    setDnsResolver({
      a: async () => ["203.0.113.27"],
      aaaa: resolveAaaa,
      txt: async () => [["fd27-token"]],
      mx: async () => [],
      cname: async () => [],
      caa: async () => [],
    });
    const verify = await db.query.operations.findFirst({
      where: (operations, { eq }) => eq(operations.idempotencyKey, `dns.ipv6:${failedOperation}:${domainId}`),
    });
    assert.ok(verify, "Preflight should durably queue FD-19 DNS verification.");
    await runOperation("domain.verify", verify);
    assert.ok(
      (
        await sql`SELECT withdrawal_confirmed_at FROM dns_records
      WHERE domain_id=${domainId} AND name=${appHost} AND type='AAAA'`
      )[0]?.withdrawal_confirmed_at,
    );
    console.log("Closing IPv6 443 failed the operation and FD-19 confirmed withdrawal.");
  } catch (error) {
    for (const service of ["edge", "edge-l4", "app-postgres", "pgbouncer-public"]) {
      const result = await runtime
        .dockerOutput("exec", vps, "docker", "logs", "--tail", "12", service)
        .catch(() => null);
      if (result) console.error(service, result.stdout, result.stderr);
    }
    await runtime.dumpLogs();
    throw error;
  } finally {
    releaseRunner?.();
    await stopWorker();
    await api?.stop(true);
    await tlsReceiver?.stop(true);
    localApi?.stop();
    for (const [key, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    stopSignals();
    await runtime.cleanup();
    if (v4Created) await dockerCleanup("network", "rm", v4Network);
    if (guestBuilt) await dockerCleanup("image", "rm", image);
    if (imageTags.length) await dockerCleanup("image", "rm", ...imageTags.filter(Boolean));
  }
}, 600_000);

async function dockerCleanup(...args: string[]) {
  await Bun.spawn(["docker", ...args], { stdout: "ignore", stderr: "ignore" }).exited;
}
