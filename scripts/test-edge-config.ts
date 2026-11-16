// `mise run test:edge`: validates every rendered and static Caddyfile on the pinned Caddy image, then
// runs the edge behaviour tests from docs/design/front-door.md §3.5 and FD-24 in disposable containers:
// header stripping, Server/Via removal, WebSockets across reloads and idle, and certificate reloads.
// The bump procedure for the pinned images is in docs/operating.md ("Third-party image pins").
import { X509Certificate, randomBytes } from "node:crypto";
import { copyFile, mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { connect } from "node:tls";

import { renderCaddyfile } from "@ark-stack/shared";

import { checkReleasePins } from "./edge-test/pins.ts";
import { EdgeTestRuntime } from "./edge-test/runtime.ts";

const caddyImage = "caddy:2.11.9@sha256:4e2425f6009577e7c651010f16679c28f7d12df3e7b1914f941a7a3370746b3c";
// Same pin as the Dockerfile runtime stage; hosts the fixture upstream and generates fixture certificates.
const bunImage =
  "oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61";
const root = resolve(import.meta.dir, "..");
const fixtures = join(import.meta.dir, "edge-test");
const idleSeconds = 80;

const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), `ark-edge-${suffix}-`));
const network = `ark-edge-${suffix}`;
const runtime = new EdgeTestRuntime(directory, network);
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
  if (caddyPins.length !== 2 || caddyPins.some((pin) => pin !== caddyImage)) {
    throw new Error(
      `infra/platform/docker-compose.yml must pin edge and tailnet-gateway to the tested ${caddyImage}; found ${JSON.stringify(caddyPins)}.`,
    );
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
}

// ---- Static validation -----------------------------------------------------------------------------------

async function validate(name: string, source: string) {
  const file = join(directory, `validate-${name}.Caddyfile`);
  await Bun.write(file, source);
  await docker(
    "run",
    "--rm",
    "--name",
    `ark-edge-validate-${name}-${suffix}`,
    "--volume",
    `${file}:/etc/caddy/Caddyfile:ro`,
    caddyImage,
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
  console.log(`  ok  ${name} adapts and validates on ${caddyImage.split("@")[0]}`);
}

async function validateConfigurations() {
  const publicConfig = renderCaddyfile({
    adminMode: "public",
    adminHostname: "admin.example.com",
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
  });
  const internal = publicConfig.indexOf("respond @internal 404");
  const browser = publicConfig.indexOf("reverse_proxy @browserApi");
  const unknown = publicConfig.indexOf("respond @unknownApi 404");
  const fallback = publicConfig.lastIndexOf("reverse_proxy api:3000");
  if (!(internal >= 0 && internal < browser && browser < unknown && unknown < fallback)) {
    throw new Error("Generated public route ordering does not preserve the deny boundary.");
  }
  console.log("Validating rendered and static Caddyfiles:");
  await validate("generated-public", publicConfig);
  await validate(
    "generated-tailnet-edge",
    renderCaddyfile({ adminMode: "tailnet", challengeDir: "/var/lib/ark/acme", apiUpstream: "api:3000" }),
  );
  await validate(
    "generated-public-with-app-routes",
    renderCaddyfile({
      adminMode: "public",
      adminHostname: "admin.example.com",
      challengeDir: "/var/lib/ark/acme",
      apiUpstream: "api:3000",
      appRoutes: [{ hostname: "app.example.com", upstream: "app:8080" }],
    }),
  );
  await validate("bootstrap-edge", await Bun.file(join(root, "infra/platform/Caddyfile")).text());
  await validate("tailnet-gateway", await Bun.file(join(root, "infra/platform/TailnetCaddyfile")).text());
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
    caddyImage,
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

// Same request shape as `writeEdge`: POST the Caddyfile text to /load.
async function load(caddy: CaddyContainer, caddyfile: string, mustRevalidate = false) {
  const response = await fetch(`${caddy.url(2019)}/load`, {
    method: "POST",
    headers: {
      "content-type": "text/caddyfile",
      ...(mustRevalidate ? { "cache-control": "must-revalidate" } : {}),
    },
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
      [`${join(fixtures, "errors")}:/etc/caddy/errors:ro`],
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

// ---- Certificate reload ----------------------------------------------------------------------------------

function servedFingerprint(port: number) {
  return new Promise<string>((resolveFingerprint, reject) => {
    const socket = connect(
      { host: "127.0.0.1", port, servername: "edge.test", rejectUnauthorized: false },
      () => {
        const fingerprint = socket.getPeerCertificate().fingerprint256;
        socket.end();
        resolveFingerprint(fingerprint);
      },
    );
    socket.setTimeout(10_000, () => socket.destroy(new Error("TLS handshake timed out")));
    socket.on("error", reject);
  });
}

function short(fingerprint: string) {
  return `…${fingerprint.slice(-20)}`;
}

async function certificateReloadTest(report: Report) {
  const certs = join(directory, "certs");
  await mkdir(certs);
  await docker(
    "run",
    "--rm",
    "--user",
    `${process.getuid?.() ?? 0}:${process.getgid?.() ?? 0}`,
    "--env",
    "HOME=/tmp",
    "--volume",
    `${certs}:/out`,
    bunImage,
    "sh",
    "-c",
    "set -e; for name in old new; do openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=edge.test -addext subjectAltName=DNS:edge.test -keyout /out/$name.key -out /out/$name.pem 2>/dev/null; done",
  );
  const fingerprint = async (name: string) =>
    new X509Certificate(await Bun.file(join(certs, `${name}.pem`)).text()).fingerprint256;
  const [oldFingerprint, newFingerprint] = [await fingerprint("old"), await fingerprint("new")];
  const install = async (name: string) => {
    await copyFile(join(certs, `${name}.pem`), join(certs, "fullchain.pem"));
    await copyFile(join(certs, `${name}.key`), join(certs, "privkey.pem"));
  };
  await install("old");

  const caddyfile = await fixture("certificate.Caddyfile");
  const caddy = await startCaddy("certificate", caddyfile, [8443, 2019], [`${certs}:/certs:ro`]);
  await waitForAdmin(caddy);
  await load(caddy, caddyfile, true);
  const initial = await waitFor("the fixture certificate", () => servedFingerprint(caddy.port(8443)));
  expect(
    report,
    initial === oldFingerprint,
    "initial certificate is served",
    `fingerprint ${short(initial)}`,
  );

  await install("new");
  const plain = await load(caddy, caddyfile);
  const afterPlain = await servedFingerprint(caddy.port(8443));
  expect(
    report,
    plain === 200 && afterPlain === oldFingerprint,
    "files swapped, identical /load without Cache-Control: must-revalidate keeps the old certificate",
    `/load ${plain}; served ${short(afterPlain)} (old ${short(oldFingerprint)})`,
  );

  const forced = await load(caddy, caddyfile, true);
  const afterForced = await servedFingerprint(caddy.port(8443));
  expect(
    report,
    forced === 200 && afterForced === newFingerprint,
    "identical /load with Cache-Control: must-revalidate serves the new certificate",
    `/load ${forced}; served ${short(afterForced)} (new ${short(newFingerprint)})`,
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
  await validateConfigurations();
  console.log(`\nEdge behaviour tests on ${caddyImage} (the idle test takes ${idleSeconds} s):`);
  await startUpstream();
  const results = await Promise.all([
    run("websocket idle", websocketIdleTest),
    run("header stripping", async (report) => headerBehaviour(await headerFixture(), report)),
    run("server and via removal", async (report) => viaBehaviour(await headerFixture(), report)),
    run("websocket across reload", websocketReloadTests),
    run("certificate reload", certificateReloadTest),
  ]);
  failed = results.includes(false);
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
