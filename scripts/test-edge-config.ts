// `mise run test:edge`: validates every rendered and static Caddyfile on the pinned Caddy image against
// fixture certificates, then runs the edge behaviour tests from docs/design/front-door.md §3.5, §3.14,
// FD-24 and FD-02 in disposable containers: header stripping, Server/Via removal, WebSockets across
// reloads and idle, and the production edge serving Ark-issued certificates (TLS, the :80 block, and
// certificate reloads through the real `writeEdge`). The production edge is the shipped `edge-ts` and
// `edge` Compose services (FD-05): `edge` runs in the kernel-mode Tailscale node's namespace, its admin
// API is reachable only from edge-control, and a restarted or replaced `edge-ts` is recovered by the
// same rejoin step `mise run maintain` runs. No tailnet is needed; `mise run test:edge-tailnet` covers
// the checks that need one.
// The `edge` service runs the custom Caddy build (FD-23: the official image's binary rebuilt with the
// pinned caddy-ratelimit plugin), so validation and behaviour tests run on that image; the official
// pin remains the tailnet-gateway image and the base of the custom build.
// The bump procedure for the pinned images is in docs/operating.md ("Third-party image pins").
import { X509Certificate, randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { connect } from "node:tls";

import {
  EDGE_CERT_DIR,
  GATE_LOGIN_SITE_COMMENT,
  edgeCertificatePaths,
  planEdge,
  renderCaddyfile,
} from "@ark-stack/shared";

import { rejoinNamespaceDependents } from "./edge-namespace.ts";
import { checkEdgeCaddyBase, composeEdgeImage, prepareEdgeImage } from "./edge-test/edge-image.ts";
import { checkReleasePins } from "./edge-test/pins.ts";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";
import { type EdgeStack, startEdgeStack } from "./edge-test/stack.ts";
import { bunImage } from "./test-images.ts";

const caddyImage = "caddy:2.11.9@sha256:4e2425f6009577e7c651010f16679c28f7d12df3e7b1914f941a7a3370746b3c";
/** The shipped edge image (FD-23), set by `checkPins`: built from the edge-caddy stage or pinned. */
let edgeImage = "";
let edgePlatformArgs: string[] = [];
// The edge node (edge-ts) and the admin node (tailscale) share this pin.
const tailscaleImage =
  "tailscale/tailscale:v1.86.2@sha256:241d9518b7e0b6e533dbd0117fcea15acb4174249210837f52b71615949ce9d2";
// edge-ts never reaches Tailscale's control plane in this run: login fails fast and tailscaled keeps
// running, which is what a node without TS_EDGE_AUTHKEY does.
const offlineLoginServer = "--login-server=http://127.0.0.1:9";
const root = resolve(import.meta.dir, "..");
const fixtures = join(import.meta.dir, "edge-test");
const idleSeconds = 80;

const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-${suffix}-`));
// Match the production worker and edge identity, independent of the host uid.
const productionUser = "1000:1000";
const network = `ark-edge-${suffix}`;
const runtime = new EdgeTestRuntime(directory, network, bunImage);
const containers = runtime.containers;
const removeSignalHandlers = runtime.installSignalHandlers();

type Report = { name: string; lines: string[] };
type CaddyContainer = {
  name: string;
  url: (port: number, scheme?: string) => string;
  port: (port: number) => number;
};

async function docker(...args: string[]) {
  return runtime.docker(...args);
}

function expect(report: Report, condition: boolean, claim: string, observed: string) {
  if (!condition) throw new Error(`[${report.name}] FAILED: ${claim} (observed: ${observed})`);
  report.lines.push(`  ok  ${claim} [${observed}]`);
}

async function waitFor<T>(what: string, attempt: () => Promise<T | undefined>, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await attempt().catch(() => undefined);
    if (value !== undefined) return value;
    await Bun.sleep(200);
  }
  throw new Error(`Timed out after ${timeoutMs} ms waiting for ${what}.`);
}

function fixture(name: string) {
  return Bun.file(join(fixtures, name)).text();
}

// ---- Pins ------------------------------------------------------------------------------------------------

async function checkPins() {
  const compose = await Bun.file(join(root, "infra/platform/docker-compose.yml")).text();
  const caddyPins = [...compose.matchAll(/^\s*image:\s*(caddy:\S+)\s*$/gm)].map((match) => match[1]);
  if (caddyPins.length !== 1 || caddyPins.some((pin) => pin !== caddyImage)) {
    throw new Error(
      `infra/platform/docker-compose.yml must pin tailnet-gateway to the tested ${caddyImage}; found ${JSON.stringify(caddyPins)}.`,
    );
  }
  composeEdgeImage(compose);
  checkEdgeCaddyBase(await Bun.file(join(root, "Dockerfile")).text(), caddyImage);
  const tailscalePins = [...compose.matchAll(/^\s*image:\s*(tailscale\/tailscale:\S+)\s*$/gm)].map(
    (match) => match[1],
  );
  // edge-ts, tailscale and FD-30's backup-ts.
  if (tailscalePins.length !== 3 || tailscalePins.some((pin) => pin !== tailscaleImage)) {
    throw new Error(
      `infra/platform/docker-compose.yml must pin edge-ts, tailscale and backup-ts to the tested ${tailscaleImage}; found ${JSON.stringify(tailscalePins)}.`,
    );
  }
  const tailscaleVersion = await docker(
    "run",
    "--rm",
    "--entrypoint",
    "tailscale",
    tailscaleImage,
    "version",
  );
  if (!tailscaleVersion.startsWith("1.86.2\n")) {
    throw new Error(`${tailscaleImage} reports ${tailscaleVersion.split("\n")[0]}, expected 1.86.2.`);
  }
  checkReleasePins(await Bun.file(join(root, "infra/platform/release.json")).json(), caddyImage);
  const dockerfile = await Bun.file(join(root, "Dockerfile")).text();
  if (!dockerfile.includes(bunImage)) {
    throw new Error(`Dockerfile no longer pins ${bunImage}; update the edge-test fixture image to match.`);
  }
  const version = await docker("run", "--rm", caddyImage, "caddy", "version");
  if (!version.startsWith("v2.11.9 ")) throw new Error(`${caddyImage} reports ${version}, expected v2.11.9.`);
  console.log(
    `Compose and release.json pin the tested image ${caddyImage} (${version.split(" ")[0]}); release bundle digest matches.`,
  );
  const edge = await prepareEdgeImage(docker, { root, compose });
  edgeImage = edge.image;
  edgePlatformArgs = edge.platformArgs;
  console.log(
    `Compose ${edge.kind === "build" ? "builds" : "pins"} the edge image ${edgeImage} (${edge.version}, with http.handlers.rate_limit) on ${caddyImage.split("@")[0]}.`,
  );
  console.log(`Compose pins edge-ts, tailscale and backup-ts to the tested ${tailscaleImage}.`);
}

// ---- Fixture certificates -------------------------------------------------------------------------------

// Hostnames laid out like Ark's certificate directory (<dir>/<hostname>/{fullchain,privkey}.pem).
// `pending` and `failed` have files on disk too, so the tests prove the status gate, not file absence.
const issuedHostnames = ["admin.example.com", "example.com", "www.example.com"];
const unissued = { "pending.example.com": "pending", "failed.example.com": "failed" } as const;
const fixtureCerts = {
  served: join(directory, "certs"),
  renewed: join(directory, "renewed"),
};

async function generateFixtureCertificates() {
  await chmod(directory, 0o755);
  const hostnames = [...issuedHostnames, ...Object.keys(unissued)];
  const script = [
    "set -e",
    // login.example.com: the FD-10 login origin of the rendered §3.5 example (validation only).
    `for name in ${hostnames.map((name) => `certs/${name}`).join(" ")} certs/login.example.com renewed/www.example.com; do`,
    '  host="${name#*/}"; mkdir -p "/out/$name"',
    '  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=$host" -addext "subjectAltName=DNS:$host" -keyout "/out/$name/privkey.pem" -out "/out/$name/fullchain.pem" 2>/dev/null',
    '  chmod 600 "/out/$name/privkey.pem"',
    "done",
    "chown -R 1000:1000 /out/certs /out/renewed",
  ].join("\n");
  await docker(
    "run",
    "--rm",
    "--user",
    "0:0",
    "--env",
    "HOME=/tmp",
    "--volume",
    `${directory}:/out`,
    bunImage,
    "sh",
    "-c",
    script,
  );
}

async function fingerprintOf(path: string) {
  return new X509Certificate(await Bun.file(path).text()).fingerprint256;
}

// The rows the coordinator reads, turned into the writeEdge input by the production planner.
function fixturePlan() {
  const at = new Date();
  const hostnames = [...issuedHostnames, ...Object.keys(unissued)];
  const endpoints = hostnames.map((hostname) => ({
    id: `end_${hostname}`,
    kind: hostname === "admin.example.com" ? "admin" : "http",
    hostname,
    exposure: "public",
  }));
  const certificates = hostnames.map((hostname) => ({
    endpointId: `end_${hostname}`,
    status: unissued[hostname as keyof typeof unissued] ?? "issued",
    lastDeployedAt: at,
  }));
  return planEdge({ adminMode: "public", adminHostname: "admin.example.com", endpoints, certificates });
}

// ---- Static validation -----------------------------------------------------------------------------------

async function validate(name: string, source: string, image = edgeImage) {
  const file = join(directory, `validate-${name}.Caddyfile`);
  await Bun.write(file, source);
  await docker(
    "run",
    "--rm",
    "--name",
    `ark-edge-validate-${name}-${suffix}`,
    "--volume",
    `${file}:/etc/caddy/Caddyfile:ro`,
    "--volume",
    `${fixtureCerts.served}:${EDGE_CERT_DIR}:ro`,
    ...(image === edgeImage ? edgePlatformArgs : []),
    image,
    "caddy",
    "adapt",
    "--config",
    "/etc/caddy/Caddyfile",
    "--adapter",
    "caddyfile",
    "--validate",
  ).catch((error: Error) => {
    throw new Error(`${name} Caddy validation failed: ${error.message}`);
  });
  console.log(`  ok  ${name} adapts and validates on ${image.split("@")[0]}`);
}

async function validateConfigurations() {
  const certificates = issuedHostnames.map((hostname) => ({
    hostname,
    status: "issued",
    ...edgeCertificatePaths(hostname),
  }));
  const publicConfig = renderCaddyfile({
    adminMode: "public",
    adminHostname: "admin.example.com",
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
    certificates,
  });
  const internal = publicConfig.indexOf("respond @internal 404");
  const browser = publicConfig.indexOf("reverse_proxy @browserApi");
  const unknown = publicConfig.indexOf("respond @unknownApi 404");
  const fallback = publicConfig.lastIndexOf("reverse_proxy api:3000");
  if (!(internal >= 0 && internal < browser && browser < unknown && unknown < fallback)) {
    throw new Error("Generated public route ordering does not preserve the deny boundary.");
  }
  const appConfig = renderCaddyfile({
    adminMode: "public",
    adminHostname: "admin.example.com",
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
    certificates,
    appRoutes: [{ hostname: "example.com" }, { hostname: "www.example.com", upstream: "app:8080" }],
  });
  const tlsSites = appConfig.match(
    /^ {2}tls \/var\/lib\/ark\/certs\/\S+\/fullchain\.pem \S+\/privkey\.pem$/gm,
  );
  if (tlsSites?.length !== 3) {
    throw new Error(`Generated app-route config should load 3 Ark certificates, found ${tlsSites?.length}.`);
  }
  // FD-09: the §3.5 example, rendered by the production planner (www proxies to the tailnet target,
  // the apex redirects to www). FD-10 adds the login origin (login.example.com) and its path
  // allowlist. FD-11 makes www the §3.5 SSO route (forward_auth, the exact callback and logout
  // rewrites, the guarded /webhooks/* bypass); an SSO route whose bypass covers the whole site is
  // omitted.
  const route = {
    stableId: "nHOME",
    ip: "100.101.102.103",
    port: 3000,
    access: "public" as const,
    internalNames: ["home.tail1234.ts.net", "home"],
    internalIps: ["fd7a:115c:a1e0::6465:6667"],
  };
  const routePlan = planEdge({
    adminMode: "public",
    adminHostname: "admin.example.com",
    gateHostname: "login.example.com",
    endpoints: [...issuedHostnames, "login.example.com"].map((hostname) => ({
      id: `end_${hostname}`,
      kind: hostname === "admin.example.com" ? "admin" : hostname === "login.example.com" ? "gate" : "route",
      hostname,
      exposure: "public",
    })),
    certificates: [...issuedHostnames, "login.example.com"].map((hostname) => ({
      endpointId: `end_${hostname}`,
      status: "issued",
      lastDeployedAt: new Date(),
    })),
    httpRoutes: [
      { ...route, id: "rt_k3x9", hostname: "www.example.com", access: "sso", bypassPaths: ["/webhooks/*"] },
      { ...route, id: "rt_a1b2", hostname: "example.com", redirectTo: "www.example.com" },
      { ...route, id: "rt_sso1", hostname: "admin.example.com", access: "sso", bypassPaths: ["/*"] },
    ],
  });
  if (routePlan.omitted.map((item) => item.id).join() !== "rt_sso1") {
    throw new Error("The planner must omit the SSO route whose bypass covers the whole site.");
  }
  const routeConfig = renderCaddyfile({
    ...routePlan,
    gate: routePlan.gateHostname ? { hostname: routePlan.gateHostname } : undefined,
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
  });
  if (
    !routeConfig.includes("uri /api/gate/check?route=rt_k3x9") ||
    !routeConfig.includes("rewrite * /api/gate/callback") ||
    !routeConfig.includes("uri /api/gate/bypass-check?route=rt_k3x9")
  ) {
    throw new Error("The rendered §3.5 example must gate www.example.com (FD-11).");
  }
  if (!routeConfig.includes(`${GATE_LOGIN_SITE_COMMENT}\nlogin.example.com {`)) {
    throw new Error("The rendered §3.5 example must include the login-origin site block (FD-10).");
  }
  // FD-23: a rate-limited SSO route with client certificates, a rate-limited redirect and an mTLS route
  // that admits nobody, with fixture certificates standing in for the route CA and its leaves.
  const der = async (hostname: string) =>
    new X509Certificate(
      await Bun.file(join(fixtureCerts.served, hostname, "fullchain.pem")).text(),
    ).raw.toString("base64");
  const caCertificate = await der("admin.example.com");
  const controlsPlan = planEdge({
    adminMode: "tailnet",
    endpoints: issuedHostnames.map((hostname) => ({
      id: `end_${hostname}`,
      kind: "route",
      hostname,
      exposure: "public",
    })),
    certificates: issuedHostnames.map((hostname) => ({
      endpointId: `end_${hostname}`,
      status: "issued",
      lastDeployedAt: new Date(),
    })),
    httpRoutes: [
      {
        ...route,
        id: "rt_k3x9",
        hostname: "www.example.com",
        access: "sso",
        bypassPaths: ["/webhooks/*"],
        rateLimit: { requests: 100, window: "1m" },
        clientAuth: { caCertificate, certificates: [await der("www.example.com"), await der("example.com")] },
      },
      {
        ...route,
        id: "rt_a1b2",
        hostname: "example.com",
        redirectTo: "www.example.com",
        rateLimit: { requests: 5, window: "10s" },
      },
      {
        ...route,
        id: "rt_m0n0",
        hostname: "admin.example.com",
        clientAuth: { caCertificate, certificates: [] },
      },
    ],
  });
  if (controlsPlan.omitted.length)
    throw new Error(`FD-23 routes were omitted: ${JSON.stringify(controlsPlan.omitted)}`);
  const controlsConfig = renderCaddyfile({
    ...controlsPlan,
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
  });
  console.log("Validating rendered and static Caddyfiles (tls files from fixture certificates):");
  await validate("generated-public-with-http-routes", routeConfig);
  await validate("generated-public", publicConfig);
  await validate(
    "generated-tailnet-edge",
    renderCaddyfile({ adminMode: "tailnet", challengeDir: "/var/lib/ark/acme", apiUpstream: "api:3000" }),
  );
  await validate("generated-public-with-app-routes", appConfig);
  await validate("generated-rate-limit-and-mtls", controlsConfig);
  await validate("bootstrap-edge", await Bun.file(join(root, "infra/platform/Caddyfile")).text());
  // tailnet-gateway runs the official image.
  await validate(
    "tailnet-gateway",
    await Bun.file(join(root, "infra/platform/TailnetCaddyfile")).text(),
    caddyImage,
  );
  console.log("Generated and static Caddy configurations validate with deny-first route ordering.");
}

// ---- Containers ------------------------------------------------------------------------------------------

async function publishedPort(container: string, port: number) {
  return waitFor(`${container} to publish ${port}/tcp`, async () => {
    const match = (await docker("port", container, `${port}/tcp`)).match(/127\.0\.0\.1:(\d+)/);
    return match ? Number(match[1]) : undefined;
  });
}

async function startUpstream() {
  runtime.networkCreated = true;
  await docker("network", "create", network);
  const name = `ark-edge-upstream-${suffix}`;
  containers.push(name);
  await docker(
    "run",
    "--detach",
    "--name",
    name,
    "--network",
    network,
    "--network-alias",
    "upstream",
    // The production admin site proxies to api:3000.
    "--network-alias",
    "api",
    "--publish",
    "127.0.0.1::3000",
    "--volume",
    `${join(fixtures, "upstream.ts")}:/fixture/upstream.ts:ro`,
    bunImage,
    "bun",
    "/fixture/upstream.ts",
  );
  const port = await publishedPort(name, 3000);
  await waitFor("the fixture upstream", async () =>
    (await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(2_000) })).ok ? true : undefined,
  );
}

async function startCaddy(label: string, caddyfile: string, ports: number[], volumes: string[] = []) {
  const name = `ark-edge-${label}-${suffix}`;
  const file = join(directory, `${label}.Caddyfile`);
  await Bun.write(file, caddyfile);
  containers.push(name);
  await docker(
    "run",
    "--detach",
    "--name",
    name,
    "--network",
    network,
    ...ports.flatMap((port) => ["--publish", `127.0.0.1::${port}`]),
    "--volume",
    `${file}:/etc/caddy/Caddyfile:ro`,
    ...volumes.flatMap((volume) => ["--volume", volume]),
    ...edgePlatformArgs,
    edgeImage,
  );
  const mapped = new Map<number, number>();
  for (const port of ports) mapped.set(port, await publishedPort(name, port));
  const port = (inner: number) => {
    const outer = mapped.get(inner);
    if (outer === undefined) throw new Error(`${name} does not publish ${inner}`);
    return outer;
  };
  return {
    name,
    port,
    url: (inner, scheme = "http") => `${scheme}://127.0.0.1:${port(inner)}`,
  } as CaddyContainer;
}

async function waitForAdmin(caddy: CaddyContainer) {
  await waitFor(`${caddy.name} admin API`, async () =>
    (await fetch(`${caddy.url(2019)}/config/`, { signal: AbortSignal.timeout(2_000) })).ok ? true : undefined,
  );
}

// POST the Caddyfile text straight to /load (the WebSocket fixtures change the config on every load).
async function load(caddy: CaddyContainer, caddyfile: string) {
  const response = await fetch(`${caddy.url(2019)}/load`, {
    method: "POST",
    headers: { "content-type": "text/caddyfile" },
    body: caddyfile,
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok)
    throw new Error(`${caddy.name} /load returned ${response.status}: ${await response.text()}`);
  return response.status;
}

// ---- Header stripping and Server/Via removal -------------------------------------------------------------

const forged = {
  "X-Forwarded-For": "6.6.6.6",
  "X-Forwarded-Host": "evil.example",
  "X-Ark-User": "usr_forged_mallory",
  "X-Ark-Email": "mallory@evil.example",
  Cookie: "a=1; __Host-ark_gate=gate-secret; b=2",
};

async function upstreamSaw(url: string, headers: Record<string, string> = forged) {
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(10_000) });
  if (response.status !== 200) throw new Error(`${url} returned ${response.status}`);
  return (await response.json()) as Record<string, string | undefined>;
}

async function headerBehaviour(caddy: CaddyContainer, report: Report) {
  const seen = await upstreamSaw(`${caddy.url(8080)}/headers`);
  const forwardedFor = seen["x-forwarded-for"] ?? "";
  expect(
    report,
    forwardedFor !== "" && !forwardedFor.includes("6.6.6.6"),
    "forged X-Forwarded-For: 6.6.6.6 is replaced by the real client address",
    `upstream X-Forwarded-For: ${forwardedFor}`,
  );
  expect(
    report,
    seen["x-forwarded-host"] !== "evil.example",
    "forged X-Forwarded-Host is replaced",
    `upstream X-Forwarded-Host: ${seen["x-forwarded-host"]}`,
  );
  const arkHeaders = Object.keys(seen).filter((name) => name.startsWith("x-ark-"));
  expect(
    report,
    arkHeaders.length === 0,
    "forged X-Ark-User and X-Ark-Email never reach the upstream (public route)",
    `upstream X-Ark-* headers: ${JSON.stringify(arkHeaders)}`,
  );
  const cookie = seen.cookie ?? "";
  expect(
    report,
    cookie === "a=1; b=2",
    "gate cookie is stripped from the upstream Cookie, other cookies kept",
    `sent Cookie: ${forged.Cookie} -> upstream Cookie: ${cookie}`,
  );
  const leading = await upstreamSaw(`${caddy.url(8080)}/headers`, {
    Cookie: "__Host-ark_gate=gate-secret; c=3",
  });
  expect(
    report,
    leading.cookie === "c=3",
    "gate cookie is stripped when it is the first cookie",
    `upstream Cookie: ${leading.cookie}`,
  );
  for (const [sent, expected] of [
    ["a=1; __Host-ark_gate=gate-secret", "a=1"],
    ["__Host-ark_gate=gate-secret", ""],
    ["__Host-ark_gate_state=state-secret; __Host-ark_gate=gate-secret; c=3", "c=3"],
    ["a=1; c=3", "a=1; c=3"],
  ]) {
    const observed = await upstreamSaw(`${caddy.url(8080)}/headers`, { Cookie: sent });
    expect(
      report,
      (observed.cookie ?? "") === expected,
      "gate cookies are stripped at the end, alone or together; ordinary cookies stay intact",
      `sent Cookie: ${sent} -> upstream Cookie: ${JSON.stringify(observed.cookie ?? "")}`,
    );
  }

  const sso = await upstreamSaw(`${caddy.url(8081)}/headers`);
  expect(
    report,
    sso["x-ark-user"] === "usr_gate_alice" && sso["x-ark-email"] === "alice@example.com",
    "SSO route: forged X-Ark-User is replaced by the forward_auth identity",
    `upstream X-Ark-User: ${sso["x-ark-user"]}, X-Ark-Email: ${sso["x-ark-email"]}`,
  );
  expect(
    report,
    !(sso.cookie ?? "").includes("ark_gate") && !(sso["x-forwarded-for"] ?? "").includes("6.6.6.6"),
    "SSO route: gate cookie and forged X-Forwarded-For do not reach the upstream",
    `upstream Cookie: ${sso.cookie}, X-Forwarded-For: ${sso["x-forwarded-for"]}`,
  );

  const redirect = await fetch(`${caddy.url(8080)}/redirect`, { redirect: "manual" });
  expect(
    report,
    redirect.status === 302 && redirect.headers.get("location") === "https://www.example.com/next?x=1#frag",
    "Location pointing at the tailnet name is rewritten to the public origin",
    `http://home.tail1234.ts.net:3000/next?x=1#frag -> ${redirect.status} ${redirect.headers.get("location")}`,
  );
  const cookies = redirect.headers.getSetCookie();
  expect(
    report,
    cookies.length === 2 &&
      cookies.every((value) => !/domain=/i.test(value)) &&
      cookies.some((value) => value.startsWith("sid=1; Path=/;")),
    "Set-Cookie Domain attributes are removed (cookies become host-only)",
    cookies.join(" | "),
  );
  const ipRedirect = await fetch(`${caddy.url(8080)}/redirect-ip`, { redirect: "manual" });
  expect(
    report,
    ipRedirect.headers.get("location") === "https://www.example.com/ip-path",
    "scheme-relative Location pointing at the tailnet IP is rewritten",
    `//100.101.102.103:3000/ip-path -> ${ipRedirect.headers.get("location")}`,
  );
  const external = await fetch(`${caddy.url(8080)}/redirect-external`, { redirect: "manual" });
  expect(
    report,
    external.headers.get("location") === "https://other.example.net/keep",
    "Location pointing elsewhere is left unchanged",
    `${external.headers.get("location")}`,
  );
}

async function viaBehaviour(caddy: CaddyContainer, report: Report) {
  const cases: Array<[string, number, string, number]> = [
    ["2xx upstream response", 8080, "/headers", 200],
    ["2xx SSO route", 8081, "/headers", 200],
    ["3xx upstream redirect", 8080, "/redirect", 302],
    ["3xx Caddy redirect", 8082, "/path?q=1", 308],
    ["4xx upstream error", 8080, "/status/404", 404],
    ["4xx edge response", 8080, "/.ark/gate/unknown", 404],
    ["5xx upstream error", 8080, "/status/500", 500],
    ["5xx static error page (unreachable upstream)", 8083, "/", 502],
  ];
  for (const [label, port, path, status] of cases) {
    const response = await fetch(`${caddy.url(port)}${path}`, { redirect: "manual" });
    const body = await response.text();
    const server = response.headers.get("server");
    const via = response.headers.get("via");
    const poweredBy = response.headers.get("x-powered-by");
    expect(
      report,
      response.status === status && server === null && via === null && poweredBy === null,
      `${label}: no Server, Via or X-Powered-By`,
      `status ${response.status}, Server: ${server}, Via: ${via}, X-Powered-By: ${poweredBy}`,
    );
    if (status === 502) {
      expect(
        report,
        body.includes("ark-static-error-502") && !body.includes("upstream:3999"),
        "502 serves the static error page without the upstream address",
        body.match(/ark-static-error-\d+[^<]*/)?.[0] ?? body.slice(0, 80),
      );
    }
  }
  const control = await fetch(`${caddy.url(8084)}/headers`);
  await control.body?.cancel();
  const controlVia = control.headers.get("via");
  expect(
    report,
    controlVia !== null && /caddy/i.test(controlVia),
    "control: `header_down -Via` alone is insufficient, so the deferred site header is required",
    `Via: ${controlVia}`,
  );
}

let headerCaddy: Promise<CaddyContainer> | undefined;

// One Caddy container serves both the header-stripping and the Server/Via tests.
function headerFixture() {
  headerCaddy ??= (async () => {
    const caddy = await startCaddy(
      "headers",
      await fixture("headers.Caddyfile"),
      [8080, 8081, 8082, 8083, 8084],
      [`${join(root, "infra/platform/edge-errors")}:/etc/caddy/errors:ro`],
    );
    await waitFor(`${caddy.name} sites`, async () =>
      (await fetch(`${caddy.url(8080)}/`, { signal: AbortSignal.timeout(2_000) })).ok ? true : undefined,
    );
    return caddy;
  })();
  return headerCaddy;
}

// ---- WebSockets ------------------------------------------------------------------------------------------

type Socket = { socket: WebSocket; closed: Promise<CloseEvent>; closeEvent?: CloseEvent };

async function openSocket(url: string) {
  const socket = new WebSocket(url);
  const result: Socket = {
    socket,
    closed: new Promise((resolveClose) => {
      socket.addEventListener("close", (event) => {
        result.closeEvent = event;
        resolveClose(event);
      });
    }),
  };
  await new Promise<void>((resolveOpen, reject) => {
    const timer = setTimeout(() => reject(new Error(`WebSocket ${url} did not open`)), 10_000);
    socket.addEventListener("open", () => {
      clearTimeout(timer);
      resolveOpen();
    });
    socket.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error(`WebSocket ${url} failed to open`));
    });
  });
  return result;
}

async function echo(connection: Socket, message: string) {
  if (connection.closeEvent) return `closed with ${connection.closeEvent.code}`;
  return new Promise<string>((resolveEcho) => {
    const timer = setTimeout(() => resolveEcho("no echo within 5 s"), 5_000);
    connection.socket.addEventListener(
      "message",
      (event) => {
        clearTimeout(timer);
        resolveEcho(String(event.data));
      },
      { once: true },
    );
    connection.closed.then((event) => {
      clearTimeout(timer);
      resolveEcho(`closed with ${event.code}`);
    });
    connection.socket.send(message);
  });
}

async function generation(caddy: CaddyContainer) {
  const response = await fetch(`${caddy.url(8080)}/`);
  await response.body?.cancel();
  return response.headers.get("x-ark-test-generation");
}

function websocketConfig(template: string, streamCloseDelay: string, configGeneration: number) {
  return template
    .replaceAll("__STREAM_CLOSE_DELAY__", streamCloseDelay)
    .replaceAll("__GENERATION__", String(configGeneration));
}

async function websocketReloadTests(report: Report) {
  const template = await fixture("websocket.Caddyfile");
  const caddy = await startCaddy("ws-reload", websocketConfig(template, "5m", 1), [8080, 2019]);
  await waitForAdmin(caddy);
  const url = `${caddy.url(8080, "ws")}/ws`;

  const kept = await openSocket(url);
  const before = await echo(kept, "before-reload");
  await load(caddy, websocketConfig(template, "5m", 2));
  const loaded = await generation(caddy);
  const after = await echo(kept, "after-reload");
  expect(
    report,
    loaded === "2" && before === "before-reload" && after === "after-reload" && !kept.closeEvent,
    "stream_close_delay 5m: WebSocket survives a config /load",
    `live generation ${loaded}; echo before: ${before}; echo after: ${after}`,
  );
  kept.socket.close(1000);
  await kept.closed;

  await load(caddy, websocketConfig(template, "0s", 3));
  const zero = await openSocket(url);
  const zeroEcho = await echo(zero, "zero-delay");
  const started = Date.now();
  await load(caddy, websocketConfig(template, "0s", 4));
  const event = await Promise.race([zero.closed, Bun.sleep(10_000).then(() => undefined)]);
  expect(
    report,
    zeroEcho === "zero-delay" && event?.code === 1001,
    "stream_close_delay 0s: WebSocket closes with 1001 on a config /load",
    event ? `close code ${event.code} ${Date.now() - started} ms after /load` : "still open after 10 s",
  );
}

async function websocketIdleTest(report: Report) {
  const template = await fixture("websocket.Caddyfile");
  const caddy = await startCaddy("ws-idle", websocketConfig(template, "5m", 1), [8080]);
  await waitFor(`${caddy.name} site`, async () => ((await generation(caddy)) === "1" ? true : undefined));
  const connection = await openSocket(`${caddy.url(8080, "ws")}/ws`);
  const first = await echo(connection, "idle-start");
  await Bun.sleep(idleSeconds * 1_000);
  const last = await echo(connection, "idle-end");
  expect(
    report,
    first === "idle-start" && last === "idle-end" && !connection.closeEvent,
    `WebSocket stays open through ${idleSeconds} s with no frames`,
    `echo after ${idleSeconds} s idle: ${last}`,
  );
  connection.socket.close(1000);
}

// ---- Ark-issued certificates on the production edge (FD-02) ----------------------------------------------

type Edge = CaddyContainer & { edgeDir: string; stack: EdgeStack; refreshPorts: () => Promise<void> };

// The shipped `edge-ts`, `edge` and `edge-l4` Compose services in a disposable project (scripts/edge-test/stack.ts;
// HTTPS reaches Caddy through HAProxy on 443 since FD-25):
// pinned images, kernel-mode edge-ts with its capabilities and /dev/net/tun, `edge` in its namespace
// as uid/gid 1000 with every capability dropped, the bootstrap Caddyfile, the edge-admin alias, and the
// ACME webroot and certificate directory mounted read-only. Only host paths and ports differ.
async function startProductionEdge(): Promise<Edge> {
  const acme = join(directory, "acme");
  const edgeDir = join(directory, "edge");
  await mkdir(join(acme, ".well-known", "acme-challenge"), { recursive: true });
  await mkdir(edgeDir);
  await Bun.write(join(acme, ".well-known", "acme-challenge", "fixture-token"), "fixture-token.key-auth");
  // As the installer does: tmp/edge/Caddyfile starts as the bootstrap config, and writeEdge replaces it.
  await Bun.write(join(edgeDir, "Caddyfile"), await Bun.file(join(root, "infra/platform/Caddyfile")).text());
  // The worker writes this directory as uid 1000 in production too.
  await docker(
    "run",
    "--rm",
    "--user",
    "0:0",
    "--volume",
    `${edgeDir}:/edge`,
    bunImage,
    "chown",
    "-R",
    "1000:1000",
    "/edge",
  );
  const stack = await startEdgeStack({
    runtime,
    project: `ark-edge-${suffix}`,
    directory,
    acmeDir: acme,
    certDir: fixtureCerts.served,
    edgeDir,
    ports: ["127.0.0.1::80", "127.0.0.1::443", "127.0.0.1::41642/udp"],
    edgeTsEnvironment: { TS_EXTRA_ARGS: `--shields-up ${offlineLoginServer}` },
  });
  // The production admin site proxies to api:3000 on the admin network.
  await docker("network", "connect", "--alias", "api", stack.networks.admin, `ark-edge-upstream-${suffix}`);
  const ports = new Map<number, number>();
  const refreshPorts = async () => {
    ports.set(80, await stack.hostPort(80));
    ports.set(443, await stack.hostPort(443));
  };
  await refreshPorts();
  const port = (inner: number) => {
    const outer = ports.get(inner);
    if (outer === undefined) throw new Error(`${stack.edgeTs} does not publish ${inner}`);
    return outer;
  };
  return {
    name: stack.edge,
    port,
    url: (inner, scheme = "http") => `${scheme}://127.0.0.1:${port(inner)}`,
    edgeDir,
    stack,
    refreshPorts,
  };
}

// Bundles scripts/edge-test/write-edge.ts, including the production writeEdge and its dependencies,
// so the container needs nothing from the host's node_modules (which may link outside the repo).
let writeEdgeBundle: Promise<string> | undefined;
function bundleWriteEdge() {
  writeEdgeBundle ??= (async () => {
    const outdir = join(directory, "write-edge");
    const built = await Bun.build({
      entrypoints: [join(fixtures, "write-edge.ts")],
      target: "bun",
      outdir,
    });
    if (!built.success) throw new Error(`Bundling write-edge.ts failed: ${built.logs.join("\n")}`);
    return outdir;
  })();
  return writeEdgeBundle;
}

// Runs the bundled write-edge.ts on edge-control, as the domain worker does, so it reaches edge-admin:2019.
async function edgeApply(edge: Edge, mode: "write" | "load-without-revalidate", input?: unknown) {
  const bundle = await bundleWriteEdge();
  return docker(
    "run",
    "--rm",
    "--network",
    edge.stack.networks.edgeControl,
    "--user",
    productionUser,
    "--env",
    "HOME=/tmp",
    "--env",
    "ARK_EDGE_DIR=/edge",
    "--env",
    "ARK_EDGE_RELOAD_URL=http://edge-admin:2019",
    "--env",
    "ARK_ACME_WEBROOT=/var/lib/ark/acme",
    "--volume",
    `${bundle}:/harness:ro`,
    "--volume",
    `${edge.edgeDir}:/edge`,
    "--workdir",
    "/tmp",
    bunImage,
    "bun",
    "/harness/write-edge.js",
    mode,
    ...(input === undefined ? [] : [JSON.stringify(input)]),
  );
}

let productionEdge: Promise<Edge> | undefined;

// One production edge, configured once through writeEdge, serves the TLS, :80 and reload tests.
function productionEdgeFixture() {
  productionEdge ??= (async () => {
    const edge = await startProductionEdge();
    await waitFor(`${edge.name} bootstrap :80`, async () =>
      (await plainGet(edge, "unknown.example.net", "/")).status === 404 ? true : undefined,
    );
    const applied = JSON.parse(await edgeApply(edge, "write", fixturePlan())) as { applied: boolean };
    if (!applied.applied) throw new Error("writeEdge did not apply the configuration.");
    return edge;
  })();
  return productionEdge;
}

function servedFingerprint(port: number, servername: string) {
  return new Promise<string>((resolveFingerprint, reject) => {
    const socket = connect({ host: "127.0.0.1", port, servername, rejectUnauthorized: false }, () => {
      const fingerprint = socket.getPeerCertificate().fingerprint256;
      socket.end();
      resolveFingerprint(fingerprint);
    });
    socket.setTimeout(10_000, () => socket.destroy(new Error("TLS handshake timed out")));
    socket.on("error", reject);
  });
}

type Reply = { status: number; headers: Record<string, string | string[] | undefined>; body: string };

function collect(resolveReply: (reply: Reply) => void) {
  return (response: import("node:http").IncomingMessage) => {
    let body = "";
    response.setEncoding("utf8");
    response.on("data", (chunk: string) => (body += chunk));
    response.on("end", () =>
      resolveReply({ status: response.statusCode ?? 0, headers: response.headers, body }),
    );
  };
}

// Plain HTTP to the edge's :80 with an explicit Host header (fetch cannot override Host).
function plainGet(edge: Edge, host: string, path: string) {
  return new Promise<Reply>((resolveReply, reject) => {
    const request = httpRequest(
      { host: "127.0.0.1", port: edge.port(80), path, headers: { host }, timeout: 10_000 },
      collect(resolveReply),
    );
    request.on("timeout", () => request.destroy(new Error("HTTP request timed out")));
    request.on("error", reject);
    request.end();
  });
}

function secureGet(edge: Edge, host: string, path: string) {
  return new Promise<Reply>((resolveReply, reject) => {
    const request = httpsRequest(
      {
        host: "127.0.0.1",
        port: edge.port(443),
        servername: host,
        path,
        headers: { host },
        rejectUnauthorized: false,
        timeout: 10_000,
      },
      collect(resolveReply),
    );
    request.on("timeout", () => request.destroy(new Error("HTTPS request timed out")));
    request.on("error", reject);
    request.end();
  });
}

function short(fingerprint: string) {
  return `…${fingerprint.slice(-20)}`;
}

async function tlsTest(report: Report) {
  const edge = await productionEdgeFixture();
  const identity = await docker(
    "exec",
    edge.name,
    "sh",
    "-c",
    'id -u; id -g; stat -c "%u:%g %a" /var/lib/ark/certs/admin.example.com/privkey.pem',
  );
  expect(
    report,
    identity === "1000\n1000\n1000:1000 600",
    "production edge runs as 1000:1000 and reads uid-1000 0600 keys with all capabilities dropped",
    identity,
  );
  for (const hostname of issuedHostnames) {
    const expected = await fingerprintOf(edgeCertificatePaths(hostname, fixtureCerts.served).fullchain);
    const served = await servedFingerprint(edge.port(443), hostname);
    expect(
      report,
      served === expected,
      `TLS handshake for ${hostname} shows its Ark fixture certificate`,
      `served ${short(served)}, fixture ${short(expected)}`,
    );
  }
  for (const [hostname, status] of Object.entries(unissued)) {
    const outcome = await servedFingerprint(edge.port(443), hostname).then(
      (fingerprint) => `served ${short(fingerprint)}`,
      (error: Error) => `handshake refused (${error.message.split("\n")[0]})`,
    );
    expect(
      report,
      outcome.startsWith("handshake refused"),
      `${hostname} (certificate ${status}, files on disk) is not served`,
      outcome,
    );
  }
  const admin = await secureGet(edge, "admin.example.com", "/");
  const internal = await secureGet(edge, "admin.example.com", "/api/internal/anything");
  expect(
    report,
    admin.status === 200 && admin.body === "ok" && internal.status === 404,
    "admin site proxies to api:3000 over the Ark certificate and still denies /api/internal/*",
    `GET / -> ${admin.status} ${JSON.stringify(admin.body)}; GET /api/internal/anything -> ${internal.status}`,
  );
  const unrouted = await secureGet(edge, "example.com", "/anything");
  expect(
    report,
    unrouted.status === 503 &&
      unrouted.body === "This hostname is not routed yet." &&
      unrouted.headers.server === undefined &&
      !/api|upstream|edge-admin|app-edge|:\d+/.test(unrouted.body),
    "unrouted endpoint answers a fixed 503 naming no internal host",
    `${unrouted.status} ${JSON.stringify(unrouted.body)}, Server: ${unrouted.headers.server}`,
  );
}

async function redirectTest(report: Report) {
  const edge = await productionEdgeFixture();
  for (const hostname of issuedHostnames) {
    const reply = await plainGet(edge, hostname, "/path?x=1");
    expect(
      report,
      reply.status === 308 && reply.headers.location === `https://${hostname}/path?x=1`,
      `http://${hostname} redirects to HTTPS with 308`,
      `${reply.status} Location: ${reply.headers.location}`,
    );
  }
  for (const hostname of [...Object.keys(unissued), "unknown.example.net"]) {
    const reply = await plainGet(edge, hostname, "/path?x=1");
    expect(
      report,
      reply.status === 404 && reply.headers.location === undefined,
      `http://${hostname} (not served) returns 404`,
      `${reply.status} ${JSON.stringify(reply.body)}`,
    );
  }
  for (const hostname of ["example.com", "pending.example.com", "unknown.example.net"]) {
    const reply = await plainGet(edge, hostname, "/.well-known/acme-challenge/fixture-token");
    expect(
      report,
      reply.status === 200 && reply.body === "fixture-token.key-auth",
      `ACME HTTP-01 challenge is served for ${hostname} without a redirect`,
      `${reply.status} ${JSON.stringify(reply.body)}`,
    );
  }
}

async function certificateReloadTest(report: Report) {
  const edge = await productionEdgeFixture();
  const hostname = "www.example.com";
  const live = edgeCertificatePaths(hostname, fixtureCerts.served);
  const renewed = edgeCertificatePaths(hostname, fixtureCerts.renewed);
  const [oldFingerprint, newFingerprint] = [
    await fingerprintOf(live.fullchain),
    await fingerprintOf(renewed.fullchain),
  ];
  const initial = await servedFingerprint(edge.port(443), hostname);
  expect(
    report,
    initial === oldFingerprint,
    "writeEdge applied the issued certificate",
    `served ${short(initial)}`,
  );

  // A renewal replaces the files at the same paths, as issueCertificateFiles does.
  await docker(
    "run",
    "--rm",
    "--user",
    productionUser,
    "--volume",
    `${fixtureCerts.served}:/live`,
    "--volume",
    `${fixtureCerts.renewed}:/renewed:ro`,
    bunImage,
    "sh",
    "-c",
    `cp /renewed/${hostname}/fullchain.pem /live/${hostname}/fullchain.pem && cp /renewed/${hostname}/privkey.pem /live/${hostname}/privkey.pem`,
  );
  const plain = JSON.parse(await edgeApply(edge, "load-without-revalidate")) as { status: number };
  const afterPlain = await servedFingerprint(edge.port(443), hostname);
  expect(
    report,
    plain.status === 200 && afterPlain === oldFingerprint,
    "control: files swapped, identical /adapt + /load without Cache-Control: must-revalidate keeps the old certificate",
    `/load ${plain.status}; served ${short(afterPlain)} (old ${short(oldFingerprint)})`,
  );

  const applied = JSON.parse(await edgeApply(edge, "write", fixturePlan())) as { applied: boolean };
  const afterWrite = await servedFingerprint(edge.port(443), hostname);
  expect(
    report,
    applied.applied && afterWrite === newFingerprint,
    "identical config re-applied through writeEdge (must-revalidate) serves the renewed certificate",
    `applied ${applied.applied}; served ${short(afterWrite)} (new ${short(newFingerprint)})`,
  );
  const other = await servedFingerprint(edge.port(443), "example.com");
  expect(
    report,
    other === (await fingerprintOf(edgeCertificatePaths("example.com", fixtureCerts.served).fullchain)),
    "other hostnames keep their certificates across the reload",
    `example.com served ${short(other)}`,
  );
}

// ---- edge-ts namespace (FD-05) ---------------------------------------------------------------------------

type Inspected = {
  Id: string;
  Config: { User: string; Env: string[] };
  HostConfig: {
    NetworkMode: string;
    CapAdd: string[] | null;
    CapDrop: string[] | null;
    Devices: Array<{ PathOnHost: string; PathInContainer: string }> | null;
    SecurityOpt: string[] | null;
    PortBindings: Record<string, unknown> | null;
  };
  NetworkSettings: { Networks: Record<string, { IPAddress: string }> };
};

async function inspect(container: string) {
  return (JSON.parse(await docker("inspect", container)) as Inspected[])[0]!;
}

function interfaces(procNetDev: string) {
  return procNetDev
    .split("\n")
    .slice(2)
    .map((line) => line.split(":")[0]!.trim())
    .filter(Boolean)
    .toSorted();
}

function tailscale(container: string, ...args: string[]) {
  return docker("exec", container, "tailscale", "--socket=/var/run/tailscale/tailscaled.sock", ...args);
}

async function namespaceTest(report: Report) {
  const edge = await productionEdgeFixture();
  const { stack } = edge;
  const [owner, caddy] = [await inspect(stack.edgeTs), await inspect(stack.edge)];
  const env = Object.fromEntries(owner.Config.Env.map((entry) => entry.split(/=(.*)/s).slice(0, 2)));
  const caps = (owner.HostConfig.CapAdd ?? []).map((cap) => cap.replace(/^CAP_/, "")).toSorted();
  expect(
    report,
    JSON.stringify(caps) === '["NET_ADMIN","NET_RAW"]' &&
      JSON.stringify(owner.HostConfig.CapDrop) === '["ALL"]' &&
      (owner.HostConfig.Devices ?? []).some((device) => device.PathInContainer === "/dev/net/tun") &&
      (owner.HostConfig.SecurityOpt ?? []).includes("no-new-privileges:true"),
    "edge-ts: kernel-mode capabilities only (cap_drop ALL + NET_ADMIN, NET_RAW), /dev/net/tun, no-new-privileges",
    `CapAdd ${JSON.stringify(caps)}, CapDrop ${JSON.stringify(owner.HostConfig.CapDrop)}, devices ${JSON.stringify(owner.HostConfig.Devices?.map((device) => device.PathInContainer))}`,
  );
  expect(
    report,
    env.TS_USERSPACE === "false" &&
      env.TS_ACCEPT_DNS === "false" &&
      env.TS_TAILSCALED_EXTRA_ARGS === "--port=41642",
    "edge-ts: TS_USERSPACE=false, TS_ACCEPT_DNS=false, tailscaled on --port=41642",
    `TS_USERSPACE=${env.TS_USERSPACE} TS_ACCEPT_DNS=${env.TS_ACCEPT_DNS} TS_TAILSCALED_EXTRA_ARGS=${env.TS_TAILSCALED_EXTRA_ARGS}`,
  );
  expect(
    report,
    caddy.HostConfig.NetworkMode === `container:${owner.Id}` &&
      Object.keys(caddy.HostConfig.PortBindings ?? {}).length === 0 &&
      Object.keys(caddy.NetworkSettings.Networks ?? {}).length === 0 &&
      (caddy.HostConfig.CapAdd ?? []).length === 0 &&
      JSON.stringify(caddy.HostConfig.CapDrop) === '["ALL"]' &&
      caddy.Config.User === "1000:1000",
    "edge: in edge-ts's namespace with no ports or networks of its own, uid 1000, no capabilities",
    `NetworkMode ${caddy.HostConfig.NetworkMode.slice(0, 22)}…, ports ${JSON.stringify(Object.keys(caddy.HostConfig.PortBindings ?? {}))}, CapAdd ${JSON.stringify(caddy.HostConfig.CapAdd)}`,
  );
  const [ownerLinks, caddyLinks] = [
    interfaces(await docker("exec", stack.edgeTs, "cat", "/proc/net/dev")),
    interfaces(await docker("exec", stack.edge, "cat", "/proc/net/dev")),
  ];
  expect(
    report,
    caddyLinks.includes("tailscale0") && JSON.stringify(ownerLinks) === JSON.stringify(caddyLinks),
    "kernel mode: tailscale0 exists in the namespace Caddy runs in",
    `edge sees ${caddyLinks.filter((name) => /^(eth|tailscale)/.test(name)).join(", ")}`,
  );
  const prefs = JSON.parse(await tailscale(stack.edgeTs, "debug", "prefs")) as Record<string, unknown>;
  expect(
    report,
    prefs.ShieldsUp === true && prefs.CorpDNS === false,
    "--shields-up through TS_EXTRA_ARGS and TS_ACCEPT_DNS=false reach tailscaled's prefs on v1.86.2",
    `ShieldsUp ${prefs.ShieldsUp}, CorpDNS ${prefs.CorpDNS}`,
  );
  const udp = await docker("exec", stack.edgeTs, "ss", "-lunp");
  const published = await stack.hostPort(41642, "udp");
  expect(
    report,
    /:41642\s.*tailscaled/.test(udp) && published > 0,
    "tailscaled listens on UDP 41642 and edge-ts publishes it",
    `${udp
      .split("\n")
      .find((line) => line.includes(":41642"))
      ?.replace(/\s+/g, " ")}; published on 127.0.0.1:${published}/udp`,
  );
  // tailscaled clears and installs its netfilter rules with the image's iptables (legacy backend),
  // which needs CAP_NET_RAW in addition to CAP_NET_ADMIN.
  const tailscaledLog = async (container: string) => {
    const output = await runtime.dockerOutput("logs", container);
    return output.stdout + output.stderr;
  };
  const logs = await waitFor(`${stack.edgeTs} tailscaled startup`, async () => {
    const text = await tailscaledLog(stack.edgeTs);
    return /Switching ipn state|Received error/.test(text) ? text : undefined;
  });
  const deniedLines = logs.split("\n").filter((line) => /can't initialize ip6?tables table/.test(line));
  const denied = deniedLines.length > 0;
  const iptables = await docker("exec", stack.edgeTs, "iptables", "-S").then(
    (rules) => `ok (${rules.split("\n").length} rules)`,
    (error: Error) => `failed: ${error.message.split("\n")[0]}`,
  );
  expect(
    report,
    !denied && iptables.startsWith("ok"),
    "edge-ts can run iptables, and tailscaled logs no netfilter permission error",
    `iptables -S ${iptables}; permission errors in log: ${denied}${denied ? ` (${[...new Set(deniedLines.map((line) => line.replace(/^\S+ \S+ /, "")))].slice(0, 3).join(" | ")})` : ""}`,
  );
  const control = `ark-edge-ts-control-${suffix}`;
  containers.push(control);
  await docker(
    "run",
    "--detach",
    "--name",
    control,
    "--cap-drop",
    "ALL",
    "--cap-add",
    "NET_ADMIN",
    "--device",
    "/dev/net/tun:/dev/net/tun",
    "--env",
    "TS_USERSPACE=false",
    "--env",
    "TS_STATE_DIR=/tmp/tailscale",
    "--env",
    `TS_EXTRA_ARGS=${offlineLoginServer}`,
    tailscaleImage,
  );
  const withoutRaw = await waitFor(`${control} iptables error`, async () => {
    const match = (await tailscaledLog(control)).match(/can't initialize iptables table `\w+': [^\n(]+/);
    return match?.[0];
  });
  expect(
    report,
    withoutRaw.includes("Permission denied"),
    "control: with NET_ADMIN alone, tailscaled's iptables calls fail, so NET_RAW is required",
    withoutRaw.trim(),
  );
}

// Probes Caddy's admin API from a disposable container on the given network.
async function adminProbe(networkName: string, aliases: string[], targets: string[]) {
  const script = `
    const results = {};
    for (const target of process.argv.slice(1)) {
      try {
        const response = await fetch(target + "/config/", { signal: AbortSignal.timeout(3000) });
        results[target] = "HTTP " + response.status;
      } catch (error) {
        results[target] = "unreachable (" + (error.name === "TimeoutError" ? "timed out" : error.code ?? error.name) + ")";
      }
    }
    console.log(JSON.stringify(results));
  `;
  const output = await docker(
    "run",
    "--rm",
    "--network",
    networkName,
    ...aliases.flatMap((alias) => ["--network-alias", alias]),
    bunImage,
    "bun",
    "--eval",
    script,
    ...targets,
  );
  return JSON.parse(output.split("\n").at(-1)!) as Record<string, string>;
}

async function adminIsolationTest(report: Report) {
  const edge = await productionEdgeFixture();
  const { stack } = edge;
  const networks = (await inspect(stack.edgeTs)).NetworkSettings.Networks;
  const controlIp = networks[stack.networks.edgeControl]?.IPAddress;
  const adminIp = networks[stack.networks.admin]?.IPAddress;
  if (!controlIp || !adminIp) throw new Error(`edge-ts is not on both networks: ${JSON.stringify(networks)}`);

  const worker = await adminProbe(stack.networks.edgeControl, [], ["http://edge-admin:2019"]);
  expect(
    report,
    worker["http://edge-admin:2019"] === "HTTP 200",
    "a domain-worker stand-in on edge-control reaches edge-admin:2019",
    JSON.stringify(worker),
  );
  const targets = ["http://edge-admin:2019", `http://${controlIp}:2019`, `http://${adminIp}:2019`];
  const api = await adminProbe(stack.networks.admin, ["api"], targets);
  expect(
    report,
    targets.every((target) => api[target]?.startsWith("unreachable")),
    "a container on admin as `api` cannot reach the admin API by alias, edge-control address or admin address",
    targets.map((target) => `${target.replace("http://", "")} -> ${api[target]}`).join("; "),
  );
}

async function servingOutcome(edge: Edge) {
  await edge.refreshPorts();
  const challenge = await plainGet(edge, "example.com", "/.well-known/acme-challenge/fixture-token").catch(
    (error: Error) => ({ status: 0, body: error.message, headers: {} }) as Reply,
  );
  const redirect = await plainGet(edge, "www.example.com", "/path").catch(
    (error: Error) => ({ status: 0, body: error.message, headers: {} }) as Reply,
  );
  // HTTPS goes through edge-l4 (HAProxy on 443) to Caddy on 127.0.0.1:8443 (FD-25).
  const https = await secureGet(edge, "admin.example.com", "/").catch(
    (error: Error) => ({ status: 0, body: error.message, headers: {} }) as Reply,
  );
  return {
    serving:
      challenge.status === 200 &&
      challenge.body === "fixture-token.key-auth" &&
      redirect.status === 308 &&
      https.status === 200,
    observed: `challenge ${challenge.status || challenge.body}, redirect ${redirect.status || redirect.body}, https via edge-l4 ${https.status || https.body}`,
  };
}

async function waitUntilServing(edge: Edge) {
  return waitFor(`${edge.name} to serve`, async () => {
    const outcome = await servingOutcome(edge);
    return outcome.serving ? outcome : undefined;
  });
}

async function strandedOutcome(edge: Edge) {
  // Give the published port a moment to point at the new namespace.
  await Bun.sleep(1_000);
  return servingOutcome(edge);
}

async function recreationTest(report: Report) {
  const edge = await productionEdgeFixture();
  const { stack } = edge;
  const log = (line: string) => report.lines.push(`      ${line}`);
  const rejoin = () =>
    rejoinNamespaceDependents({ project: stack.project, composeArgs: stack.composeArgs, log });

  // 1. The maintain path: `docker compose up` after edge-ts's definition changed.
  const before = await inspect(stack.edge);
  const changed = join(directory, "edge-ts-generation.yml");
  await Bun.write(changed, 'services:\n  edge-ts:\n    environment:\n      ARK_TEST_GENERATION: "2"\n');
  await docker(
    "compose",
    ...stack.composeArgs,
    "-f",
    changed,
    "up",
    "--detach",
    "--no-deps",
    "--wait",
    "--wait-timeout",
    "120",
    "edge-ts",
    "edge",
    "edge-l4",
  );
  const [owner, caddy, haproxy] = [
    await inspect(stack.edgeTs),
    await inspect(stack.edge),
    await inspect(stack.edgeL4),
  ];
  const composed = await waitUntilServing(edge);
  expect(
    report,
    caddy.Id !== before.Id &&
      caddy.HostConfig.NetworkMode === `container:${owner.Id}` &&
      haproxy.HostConfig.NetworkMode === `container:${owner.Id}` &&
      (await rejoin()).length === 0,
    "compose up recreates edge and edge-l4 with a changed edge-ts and joins the new namespace; rejoin finds nothing to do",
    `edge ${before.Id.slice(0, 12)} -> ${caddy.Id.slice(0, 12)} in container:${owner.Id.slice(0, 12)}; ${composed.observed}`,
  );

  // 2. edge-ts restarted in place (a tailscaled crash, `docker restart`): Compose does not notice.
  await docker("restart", stack.edgeTs);
  const restarted = await strandedOutcome(edge);
  expect(
    report,
    !restarted.serving,
    "control: after edge-ts restarts in place, edge is stranded in the old namespace",
    restarted.observed,
  );
  const fixedRestart = await rejoin();
  const afterRestart = await waitUntilServing(edge);
  expect(
    report,
    fixedRestart.length === 2 && fixedRestart.every((item) => item.reason === "owner-restarted"),
    "rejoin (run by mise run maintain and mise run edge:rejoin) recreates edge and edge-l4; :80 and 443 serve again",
    `${JSON.stringify(fixedRestart)}; ${afterRestart.observed}`,
  );

  // 3. edge-ts replaced on its own (`up --force-recreate edge-ts`).
  await stack.compose("up", "--detach", "--no-deps", "--force-recreate", "--wait", "edge-ts");
  const replaced = await strandedOutcome(edge);
  expect(
    report,
    !replaced.serving,
    "control: after edge-ts alone is recreated, edge is stranded",
    replaced.observed,
  );
  const fixedReplace = await rejoin();
  const afterReplace = await waitUntilServing(edge);
  const worker = await adminProbe(stack.networks.edgeControl, [], ["http://edge-admin:2019"]);
  expect(
    report,
    fixedReplace.length === 2 &&
      fixedReplace.every((item) => item.reason === "owner-replaced") &&
      worker["http://edge-admin:2019"] === "HTTP 200",
    "rejoin recreates edge and edge-l4 in the new edge-ts: :80, 443 and edge-admin:2019 work again",
    `${JSON.stringify(fixedReplace)}; ${afterReplace.observed}; edge-admin ${worker["http://edge-admin:2019"]}`,
  );
}

// ---- Runner ----------------------------------------------------------------------------------------------

async function run(name: string, test: (report: Report) => Promise<unknown>) {
  const report: Report = { name, lines: [] };
  const started = Date.now();
  try {
    await test(report);
    console.log(
      `\n[${name}] passed in ${((Date.now() - started) / 1000).toFixed(1)} s\n${report.lines.join("\n")}`,
    );
    return true;
  } catch (error) {
    console.error(`\n[${name}] FAILED\n${report.lines.join("\n")}\n  ${(error as Error).message}`);
    return false;
  }
}

async function dumpLogs() {
  await runtime.dumpLogs();
}

let failed = false;
try {
  await checkPins();
  await generateFixtureCertificates();
  await validateConfigurations();
  console.log(`\nEdge behaviour tests on ${edgeImage} (the idle test takes ${idleSeconds} s):`);
  await startUpstream();
  const results = await Promise.all([
    run("websocket idle", websocketIdleTest),
    run("header stripping", async (report) => headerBehaviour(await headerFixture(), report)),
    run("server and via removal", async (report) => viaBehaviour(await headerFixture(), report)),
    run("websocket across reload", websocketReloadTests),
    // The reload test swaps certificate files, so it runs after the read-only TLS and :80 tests. The
    // recreation test restarts and replaces edge-ts, so it runs last.
    (async () => [
      await run("ark certificates: tls", tlsTest),
      await run("ark certificates: http redirect", redirectTest),
      await run("edge-ts namespace", namespaceTest),
      await run("edge admin API isolation", adminIsolationTest),
      await run("ark certificates: reload through writeEdge", certificateReloadTest),
      await run("edge-ts recreation", recreationTest),
    ])(),
  ]);
  failed = results.flat().includes(false);
  if (failed) await dumpLogs();
  else console.log("\nAll edge behaviour tests passed.");
} catch (error) {
  failed = true;
  console.error((error as Error).message);
  await dumpLogs();
} finally {
  await runtime.cleanup();
  removeSignalHandlers();
}
if (failed) process.exit(1);
