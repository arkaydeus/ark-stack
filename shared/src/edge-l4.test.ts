import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, readlink, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  allowedServerIndex,
  generationId,
  haproxyConfigServers,
  haproxyHttpServerName,
  haproxyLaunchDecision,
  haproxyLoopServerName,
  haproxyServerName,
  parseReload,
  parseServersState,
  parseShowProc,
  parseShowSess,
  parseShowStat,
  renderEdgeL4Generation,
  type EdgeL4TlsRoute,
} from "./edge-l4.ts";
import { routeIdentityKey } from "./edge-withdrawal.ts";
import {
  currentGeneration,
  hashGenerationDir,
  HaproxyMaster,
  HaproxyWithdrawalAdapter,
  installEdgeL4Generation,
  InvalidGenerationError,
  validateGeneration,
  type HaproxyCli,
} from "./haproxy-control.ts";

const route: EdgeL4TlsRoute = {
  id: "rt_p7q2",
  hostname: "mqtt.example.com",
  stableId: "nNAS1CNTRL",
  ip: "100.88.1.20",
  port: 1883,
  sourceCidrs: ["203.0.113.0/24"],
};

/** One `backend` section of a rendered configuration, up to the next blank line. */
function section(text: string, name: string) {
  const start = text.indexOf(`\nbackend ${name}\n`);
  const end = text.indexOf("\n\n", start + 1);
  return text.slice(start + 1, end < 0 ? undefined : end);
}

describe("edge-l4 rendering (§3.8.5 fe_tls443)", () => {
  const generation = renderEdgeL4Generation({
    httpHostnames: ["www.example.com", "example.com", "login.example.com", "example.com"],
  });
  const config = generation.files["haproxy.cfg"]!;

  test("443 accepts only a TLS ClientHello within 5 s and sends HTTP, login and unknown SNI to Caddy", () => {
    expect(config).toContain("frontend fe_tls443\n    bind :::443 v4v6\n");
    expect(config).toContain("    tcp-request inspect-delay 5s\n");
    expect(config).toContain(
      "    tcp-request content accept if { req.ssl_hello_type 1 }\n    tcp-request content reject\n",
    );
    expect(config).toContain(
      "    acl ark_http_sni req.ssl_sni -i example.com login.example.com www.example.com\n",
    );
    expect(config).toContain("    use_backend be_caddy if ark_http_sni\n");
    expect(config).toContain("    default_backend be_caddy\n");
    expect(config).toContain("backend be_caddy\n");
    expect(config).toContain("    server caddy 127.0.0.1:8443 send-proxy-v2\n");
  });

  test("the Caddy loopback hop fails fast: no retries, no redispatch and a short connect timeout", () => {
    const withRoute = renderEdgeL4Generation({ httpHostnames: ["www.example.com"], tlsRoutes: [route] });
    for (const text of [config, withRoute.files["haproxy.cfg"]!, withRoute.files["haproxy.closed.cfg"]!]) {
      const caddy = section(text, "be_caddy");
      expect(caddy).toContain("\n    retries 0\n");
      expect(caddy).toContain("\n    timeout connect 1s\n");
      expect(caddy.trimEnd()).toEndWith("    server caddy 127.0.0.1:8443 send-proxy-v2");
      // A single server: redispatch would have nowhere else to go and must not be enabled anywhere.
      expect(text).not.toMatch(/^\s+option redispatch/m);
      // The fast-fail settings are scoped to Caddy; defaults keep the 5 s connect timeout.
      expect(text.match(/^\s+retries /gm)).toHaveLength(1);
      expect(text).toContain(
        "defaults\n    mode tcp\n    log global\n    option tcplog\n    timeout connect 5s\n",
      );
    }
    expect(section(withRoute.files["haproxy.cfg"]!, "be_rt_p7q2_tls")).not.toContain("retries");
  });

  test("HTTP route hostnames have independent fail-fast backends in both configurations", () => {
    const a = { ...route, id: "rt_web1", hostname: "a.example.com", port: 3000 };
    const b = { ...a, id: "rt_web2", hostname: "b.example.com" };
    const scoped = renderEdgeL4Generation({
      httpHostnames: [a.hostname, b.hostname, "login.example.com"],
      httpRoutes: [b, a],
      tlsRoutes: [route],
    });
    expect(haproxyHttpServerName(a)).not.toBe(haproxyHttpServerName(b));
    for (const path of ["haproxy.cfg", "haproxy.closed.cfg"]) {
      const text = scoped.files[path]!;
      for (const host of [a, b]) {
        const backend = `be_http_${host.hostname}`;
        expect(text).toContain(`use_backend ${backend} if { req.ssl_sni -i ${host.hostname} }`);
        const stanza = section(text, backend);
        expect(stanza).toContain("    retries 0\n    timeout connect 1s\n");
        expect(stanza).toContain(`server ${haproxyHttpServerName(host)} 127.0.0.1:8443 send-proxy-v2`);
      }
      expect(text).toContain("acl ark_http_sni req.ssl_sni -i login.example.com\n");
      expect(text).toContain("default_backend be_reject\n");
    }
  });

  test("the global section shares the admin socket with group 4400 and bounds old workers", () => {
    expect(config).toContain("    stats socket /var/run/haproxy/admin.sock mode 660 gid 4400 level admin\n");
    expect(config).toContain("    hard-stop-after 30m\n");
    expect(config).toContain('    default-path origin "${ARK_EDGE_L4_GENERATION}"\n');
    expect(config).toContain("    timeout client 1h\n");
  });

  test("without tailnet routes the closed variant is the same router", () => {
    expect(generation.files["haproxy.closed.cfg"]).toBe(config);
    expect(haproxyLaunchDecision(config, new Set())).toMatchObject({ open: true, guarded: false });
  });

  test("the generation ID is the content hash and changes with any byte", () => {
    expect(generation.id).toBe(generationId(generation.files));
    expect(generation.id).toMatch(/^[a-f0-9]{64}$/);
    const other = renderEdgeL4Generation({ httpHostnames: ["www.example.com"] });
    expect(other.id).not.toBe(generation.id);
    expect(
      renderEdgeL4Generation({ httpHostnames: ["login.example.com", "www.example.com", "example.com"] }).id,
    ).toBe(generation.id);
    expect(() => generationId({ "../x": "" })).toThrow();
  });

  test("hostnames are validated before rendering (no directive injection)", () => {
    expect(() => renderEdgeL4Generation({ httpHostnames: ["a.example.com }\n    use_backend x"] })).toThrow();
    expect(() => renderEdgeL4Generation({ httpHostnames: ["Example.COM"] })).toThrow();
  });

  test("a tailnet TLS route is SNI-routed through allowlist and stick table to an identity-named server", () => {
    const withRoute = renderEdgeL4Generation({ httpHostnames: ["www.example.com"], tlsRoutes: [route] });
    const full = withRoute.files["haproxy.cfg"]!;
    const server = haproxyServerName(route);
    expect(server).toMatch(/^t_[a-f0-9]{32}$/);
    expect(full).toContain("    use_backend be_rt_p7q2_tls if { req.ssl_sni -i mqtt.example.com }\n");
    expect(full).toContain("# ark-tailnet-route rt_p7q2 100.88.1.20:1883\n");
    expect(full).toContain("    tcp-request content reject if !{ src -f allow/rt_p7q2.lst }\n");
    expect(full).toContain(`    server ${server} 100.88.1.20:1883 maxconn 50\n`);
    // Route rules precede the HTTP rule; nothing follows the terminal accept/reject.
    expect(full.indexOf("be_rt_p7q2_tls if")).toBeLessThan(
      full.indexOf("use_backend be_caddy if ark_http_sni"),
    );
    expect(withRoute.files["allow/rt_p7q2.lst"]).toBe("203.0.113.0/24\n");
    expect(withRoute.files["haproxy.closed.cfg"]).not.toContain("rt_p7q2");
    expect(withRoute.manifest.routes).toEqual([
      {
        id: "rt_p7q2",
        kind: "tls",
        hostname: "mqtt.example.com",
        stableId: "nNAS1CNTRL",
        target: "100.88.1.20:1883",
        listenPort: 443,
        mode: "passthrough",
        backend: "be_rt_p7q2_tls",
        server,
      },
    ]);
  });

  test("empty allowlists deny all; non-tailnet targets and hostname collisions are refused", () => {
    const denyAll = renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [{ ...route, sourceCidrs: [] }] });
    expect(denyAll.files["allow/rt_p7q2.lst"]).toBe("");
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [{ ...route, ip: "10.0.0.1" }] }),
    ).toThrow();
    expect(() => renderEdgeL4Generation({ httpHostnames: ["mqtt.example.com"], tlsRoutes: [route] })).toThrow(
      /collides/,
    );
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [{ ...route, sourceCidrs: ["nope"] }] }),
    ).toThrow();
  });
});

describe("HAProxy launch decision", () => {
  test("an HTTP pin must match the lease to open the full configuration", () => {
    const http = { ...route, id: "rt_web1", hostname: "www.example.com", port: 3000 };
    const full = renderEdgeL4Generation({ httpHostnames: [http.hostname], httpRoutes: [http] }).files[
      "haproxy.cfg"
    ]!;
    expect(haproxyLaunchDecision(full, new Set([routeIdentityKey(http)]))).toMatchObject({
      open: true,
      guarded: true,
      backends: [http.hostname],
      denied: [],
    });
    for (const allowed of [new Set<string>(), new Set([routeIdentityKey({ ...http, stableId: "nNEW" })])]) {
      expect(haproxyLaunchDecision(full, allowed)).toMatchObject({
        open: false,
        guarded: true,
        denied: [http.hostname],
      });
    }
  });

  const full = renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [route] }).files["haproxy.cfg"]!;
  const identity = routeIdentityKey(route);

  test("open only when every tailnet server is authorised by its exact identity and pin", () => {
    expect(haproxyLaunchDecision(full, new Set([identity]))).toMatchObject({ open: true, guarded: true });
    expect(haproxyLaunchDecision(full, new Set())).toMatchObject({
      open: false,
      denied: ["100.88.1.20:1883"],
    });
    // Same backend, different StableID (a replaced machine): denied.
    const replaced = routeIdentityKey({ ...route, stableId: "nIMPOSTOR" });
    expect(haproxyLaunchDecision(full, new Set([replaced])).open).toBe(false);
  });

  test("an unmarked or renamed tailnet server fails closed", () => {
    const tampered = full.replace(/server t_[a-f0-9]{32}/, "server legacy");
    expect(haproxyLaunchDecision(tampered, new Set([identity])).open).toBe(false);
    const moved = full.replace("100.88.1.20:1883 maxconn", "100.88.1.21:1883 maxconn");
    expect(haproxyLaunchDecision(moved, new Set([identity])).open).toBe(false);
  });

  test("servers are attributed to their backend", () => {
    expect(haproxyConfigServers(full).map((server) => [server.backend, server.key])).toEqual([
      ["be_caddy", null],
      ["be_rt_p7q2_tls", "100.88.1.20:1883"],
    ]);
    expect(allowedServerIndex(new Set([identity, "garbage"])).get(haproxyServerName(route))).toBe(
      "100.88.1.20:1883",
    );
  });
});

describe("HAProxy CLI parsers", () => {
  test("show proc distinguishes current and old workers", () => {
    const text = `#<PID>          <type>          <reloads>       <uptime>        <version>
1               master          1 [failed: 0]   0d00h00m03s     3.2.26
# workers
53              worker          0               0d00h00m00s     3.2.26
# old workers
8               worker          1               0d00h00m03s     3.2.26
# programs
`;
    expect(parseShowProc(text)).toEqual([
      { pid: 1, type: "master", reloads: 1, section: "master" },
      { pid: 53, type: "worker", reloads: 0, section: "current" },
      { pid: 8, type: "worker", reloads: 1, section: "old" },
    ]);
  });

  test("show servers state, show sess, show stat and reload", () => {
    const state = parseServersState(`1
# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port
3 be_caddy 1 caddy 127.0.0.1 2 0 1 1 3 1 0 2 0 0 0 0 - 8443 - 0 0 - - 0
4 be_x 1 t_abc 100.64.1.2 2 1 1 1 3 1 0 2 0 0 0 0 - 443 - 0 0 - - 0
`);
    expect(state).toEqual([
      {
        backend: "be_caddy",
        server: "caddy",
        addr: "127.0.0.1",
        port: 8443,
        adminState: 0,
        operState: 2,
        key: null,
      },
      {
        backend: "be_x",
        server: "t_abc",
        addr: "100.64.1.2",
        port: 443,
        adminState: 1,
        operState: 2,
        key: "100.64.1.2:443",
      },
    ]);
    expect(
      parseShowSess(
        "0xffff90c44280: proto=tcpv4 src=127.0.0.1:38249 fe=fe_raw be=be_raw srv=t_raw ts=00 epoch=0\n0xffff90c44670: proto=sockpair src=unix:1 fe=GLOBAL be=<NONE> srv=<none> ts=00\n",
      ),
    ).toEqual([
      { id: "0xffff90c44280", frontend: "fe_raw", backend: "be_raw", server: "t_raw" },
      { id: "0xffff90c44670", frontend: "GLOBAL", backend: "<NONE>", server: "<none>" },
    ]);
    expect(parseShowStat("# pxname,svname,qcur,qmax,scur\nfe_tls443,FRONTEND,,,3\n")).toEqual([
      { pxname: "fe_tls443", svname: "FRONTEND", qcur: "", qmax: "", scur: "3" },
    ]);
    expect(parseReload("Success=1\n--\n[NOTICE] Loading success.\n")).toEqual({
      success: true,
      answered: true,
      log: "[NOTICE] Loading success.",
    });
    expect(parseReload("Success=0\n--\n[ALERT] config : Fatal errors found\n").success).toBe(false);
  });
});

// ---- A fake master CLI with workers, servers and sessions ---------------------------------------------

type FakeServer = { backend: string; server: string; addr: string; port: number; admin: number };
type FakeWorker = {
  pid: number;
  section: "current" | "old";
  stopped: boolean;
  servers: FakeServer[];
  sessions: { id: string; backend: string; server: string }[];
};

function fakeMaster(workers: FakeWorker[], log: string[] = []): HaproxyCli {
  const header =
    "# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port";
  return async (_socket, command) => {
    log.push(command);
    if (command === "show proc") {
      const current = workers.filter((worker) => worker.section === "current");
      const old = workers.filter((worker) => worker.section === "old");
      return `#<PID>          <type>          <reloads>       <uptime>        <version>\n1               master          0 [failed: 0]   0d00h00m01s     3.2.26\n# workers\n${current.map((w) => `${w.pid}               worker          0               0d00h00m01s     3.2.26\n`).join("")}# old workers\n${old.map((w) => `${w.pid}               worker          1               0d00h00m01s     3.2.26\n`).join("")}`;
    }
    const match = /^@!(\d+) (.*)$/.exec(command);
    if (!match) return "Unknown command.\n";
    const worker = workers.find((item) => item.pid === Number(match[1]));
    if (!worker) return `Can't find the target PID matching the prefix '@!${match[1]}'\n`;
    const [verb, ...rest] = match[2]!.split(" ");
    const sub = rest.join(" ");
    if (match[2] === "show servers state") {
      return `1\n${header}\n${worker.servers.map((s, i) => `${i + 3} ${s.backend} 1 ${s.server} ${s.addr} 2 ${s.admin} 1 1 3 1 0 2 0 0 0 0 - ${s.port} - 0 0 - - 0`).join("\n")}\n\n`;
    }
    if (match[2] === "show sess") {
      return (
        "0xffff: proto=sockpair fe=GLOBAL be=<NONE> srv=<none>\n" +
        worker.sessions
          .map(
            (s) => `${s.id}: proto=tcpv4 src=1.2.3.4:5 fe=fe_tls443 be=${s.backend} srv=${s.server} ts=00\n`,
          )
          .join("")
      );
    }
    if (match[2] === "show stat") {
      return `# pxname,svname,scur\nfe_tls443,FRONTEND,${worker.sessions.length}\n`;
    }
    if (verb === "disable" && sub.startsWith("server ")) {
      if (worker.stopped) return "Proxy is disabled.\n";
      const [backend, server] = sub.slice(7).split("/");
      const target = worker.servers.find((s) => s.backend === backend && s.server === server);
      if (!target) return "No such server.\n";
      target.admin |= 1;
      return "\n";
    }
    if (verb === "shutdown" && sub.startsWith("sessions server ")) {
      if (worker.stopped) return "Proxy is disabled.\n";
      const [backend, server] = sub.slice(16).split("/");
      worker.sessions = worker.sessions.filter((s) => !(s.backend === backend && s.server === server));
      return "\n";
    }
    if (verb === "shutdown" && sub.startsWith("session ")) {
      worker.sessions = worker.sessions.filter((s) => s.id !== sub.slice(8));
      return "\n";
    }
    if (verb === "shutdown" && sub.startsWith("frontend ")) return "\n";
    return "Unknown command.\n";
  };
}

describe("HaproxyWithdrawalAdapter", () => {
  test("legacy admission is left alone until an accepting scoped worker is verified", async () => {
    const legacy = { backend: "be_caddy", server: "caddy", addr: "127.0.0.1", port: 8443, admin: 0 };
    const old: FakeWorker = {
      pid: 10,
      section: "current",
      stopped: false,
      servers: [legacy],
      sessions: [{ id: "0x10", backend: legacy.backend, server: legacy.server }],
    };
    const workers = [old];
    const log: string[] = [];
    const adapter = new HaproxyWithdrawalAdapter("/fake", fakeMaster(workers, log));
    expect(await adapter.hasLegacyHttp()).toBe(true);
    expect(await adapter.ensureHttpControl()).toBe(false);
    expect((await adapter.retireLegacyHttp()).error).toMatch(/accepting scoped generation/);

    old.section = "old";
    expect((await adapter.retireLegacyHttp()).error).toMatch(/accepting scoped generation/);
    expect(await adapter.ensureHttpControl()).toBe(false);
    expect(log.every((command) => !/disable server|shutdown session/.test(command))).toBe(true);

    old.stopped = true;
    workers.push({
      pid: 11,
      section: "current",
      stopped: false,
      servers: [{ ...legacy, server: "caddy_platform" }],
      sessions: [{ id: "0x11", backend: legacy.backend, server: "caddy_platform" }],
    });
    expect(await adapter.ensureHttpControl()).toBe(false);
    expect((await adapter.retireLegacyHttp()).error).toBeUndefined();
    expect(log).toContain("@!10 shutdown session 0x10");
    expect(old.sessions).toEqual([]);
    expect(workers[1]!.sessions).toHaveLength(1);
    expect(await adapter.hasLegacyHttp()).toBe(false);
    expect(await adapter.ensureHttpControl()).toBe(true);
  });

  const allowedRoute = { ...route, id: "rt_keep", hostname: "keep.example.com", ip: "100.88.1.30" };
  const keepServer = haproxyServerName(allowedRoute);
  const dropServer = haproxyServerName(route);
  const workers = (): FakeWorker[] => [
    {
      pid: 53,
      section: "current",
      stopped: false,
      servers: [
        { backend: "be_caddy", server: "caddy", addr: "127.0.0.1", port: 8443, admin: 0 },
        { backend: "be_rt_keep_tls", server: keepServer, addr: "100.88.1.30", port: 1883, admin: 0 },
        { backend: "be_rt_p7q2_tls", server: dropServer, addr: "100.88.1.20", port: 1883, admin: 0 },
      ],
      sessions: [
        { id: "0x1", backend: "be_rt_p7q2_tls", server: dropServer },
        { id: "0x2", backend: "be_rt_keep_tls", server: keepServer },
        { id: "0x3", backend: "be_caddy", server: "caddy" },
      ],
    },
    {
      pid: 8,
      section: "old",
      stopped: true,
      servers: [{ backend: "be_rt_p7q2_tls", server: dropServer, addr: "100.88.1.20", port: 1883, admin: 0 }],
      sessions: [{ id: "0x9", backend: "be_rt_p7q2_tls", server: dropServer }],
    },
  ];

  test("fences admission first, then drains sessions in current and leaving workers", async () => {
    const state = workers();
    const log: string[] = [];
    const adapter = new HaproxyWithdrawalAdapter("/fake", fakeMaster(state, log));
    const result = await adapter.enforce(new Set([routeIdentityKey(allowedRoute)]));
    expect(result.error).toBeUndefined();
    expect(result.active).toEqual(["100.88.1.20:1883", "100.88.1.30:1883"]);
    expect(result.withdrawn).toEqual(["100.88.1.20:1883"]);
    // Current worker: disabled before sessions were shut down; unrelated sessions remain.
    expect(log.indexOf(`@!53 disable server be_rt_p7q2_tls/${dropServer}`)).toBeLessThan(
      log.indexOf(`@!53 shutdown sessions server be_rt_p7q2_tls/${dropServer}`),
    );
    expect(state[0]!.servers.find((s) => s.server === dropServer)!.admin & 1).toBe(1);
    expect(state[0]!.servers.find((s) => s.server === keepServer)!.admin).toBe(0);
    expect(state[0]!.sessions.map((s) => s.id)).toEqual(["0x2", "0x3"]);
    // Leaving worker: server commands refused, so its session was shut down individually.
    expect(log).toContain("@!8 shutdown session 0x9");
    expect(state[1]!.sessions).toEqual([]);
    // A second pass finds nothing new to withdraw.
    const again = await adapter.enforce(new Set([routeIdentityKey(allowedRoute)]));
    expect(again).toMatchObject({ withdrawn: [] });
    expect(again.error).toBeUndefined();
  });

  test("withdraws old HTTP identities and pending connections without fencing the same hostname's replacement", async () => {
    const old = { ...route, hostname: "www.example.com" };
    const replacement = { ...old, stableId: "nNEW" };
    const backend = "be_http_www.example.com";
    const serverFor = (input: typeof old) => ({
      backend,
      server: haproxyHttpServerName(input),
      addr: "127.0.0.1",
      port: 8443,
      admin: 0,
    });
    const state = workers();
    state[0]!.servers.push(serverFor(replacement));
    state[0]!.sessions.push({ id: "0xb", backend, server: serverFor(replacement).server });
    state[1]!.servers.push(serverFor(old));
    state[1]!.sessions.push(
      { id: "0xa", backend, server: serverFor(old).server },
      { id: "0xc", backend, server: "<none>" },
    );
    const adapter = new HaproxyWithdrawalAdapter("/fake", fakeMaster(state));
    const result = await adapter.enforceHttp(new Set([routeIdentityKey(replacement)]));
    expect(result.error).toBeUndefined();
    expect(result.withdrawn).toEqual([old.hostname]);
    expect(state[0]!.sessions.some((session) => session.id === "0xb")).toBe(true);
    expect(state[1]!.sessions.map((session) => session.id)).toEqual(["0x9"]);
  });

  test("an empty allowlist (expired lease) withdraws every tailnet server but never Caddy", async () => {
    const state = workers();
    const result = await new HaproxyWithdrawalAdapter("/fake", fakeMaster(state)).enforce(new Set());
    expect(result.withdrawn).toEqual(["100.88.1.20:1883", "100.88.1.30:1883"]);
    expect(state[0]!.sessions.map((s) => s.id)).toEqual(["0x3"]);
    expect(state[0]!.servers[0]!.admin).toBe(0);
  });

  test("a session that cannot be closed is a withdrawal failure, not success", async () => {
    const state = workers();
    const cli = fakeMaster(state);
    const stubborn: HaproxyCli = async (socket, command, timeout) => {
      if (command.includes("shutdown session")) return "\n"; // pretends, closes nothing
      return cli(socket, command, timeout);
    };
    const result = await new HaproxyWithdrawalAdapter("/fake", stubborn).enforce(new Set());
    expect(result.error).toMatch(
      /withdrawal failed: worker \d+: \d+ session\(s\) to withdrawn backends remain/,
    );
  });

  test("an unreachable master socket reports unreachable", async () => {
    const result = await new HaproxyWithdrawalAdapter("/fake", async () => {
      throw new Error("ENOENT");
    }).enforce(new Set());
    expect(result).toMatchObject({ unreachable: true });
  });

  test("a brief master socket refusal during reload is retried before the watchdog reports failure", async () => {
    const cli = fakeMaster(workers());
    let refused = false;
    const reexec: HaproxyCli = async (socket, command, timeout) => {
      if (command === "show proc" && !refused) {
        refused = true;
        throw Object.assign(new Error("connection refused"), { code: "ECONNREFUSED" });
      }
      return cli(socket, command, timeout);
    };
    const result = await new HaproxyWithdrawalAdapter("/fake", reexec).enforce(new Set());
    expect(refused).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.withdrawn).toEqual(["100.88.1.20:1883", "100.88.1.30:1883"]);
  });

  test("stop fences tailnet servers and sessions without shutting down public HTTP", async () => {
    const state = workers();
    const log: string[] = [];
    const cli = fakeMaster(state, log);
    let fail = true;
    const failing: HaproxyCli = async (socket, command, timeout) =>
      fail && command.includes("disable server") ? "Unexpected failure.\n" : cli(socket, command, timeout);
    const adapter = new HaproxyWithdrawalAdapter("/fake", failing);
    expect((await adapter.enforce(new Set())).error).toMatch(/Unexpected failure/);
    // A worker that appears after the failed pass (a restart) is not touched by stop.
    state.push({
      pid: 99,
      section: "current",
      stopped: false,
      servers: [],
      sessions: [{ id: "0x77", backend: "be_caddy", server: "caddy" }],
    });
    // The disable operation recovers before the fallback is attempted.
    fail = false;
    await adapter.stop();
    expect(log.some((command) => command.includes("shutdown frontend"))).toBe(false);
    expect(log).not.toContain("@!99 shutdown frontend fe_tls443");
    expect(
      state
        .filter((worker) => worker.pid !== 99)
        .every((worker) => worker.sessions.every((session) => session.backend === "be_caddy")),
    ).toBe(true);
    expect(state.find((worker) => worker.pid === 99)!.sessions).toHaveLength(1);
  });

  test.each(["throw", "empty"])(
    "a transient mid-pass show proc %s retries without stopping public HTTP",
    async (failure) => {
      const state = workers().slice(0, 1);
      state[0]!.servers = state[0]!.servers.slice(0, 1);
      state[0]!.sessions = [{ id: "0x3", backend: "be_caddy", server: "caddy" }];
      const log: string[] = [];
      const cli = fakeMaster(state, log);
      let proc = 0;
      const adapter = new HaproxyWithdrawalAdapter("/fake", async (socket, command, timeout) => {
        if (command === "show proc" && ++proc === 2) {
          if (failure === "throw") throw new Error("reload disconnected CLI");
          return "";
        }
        return cli(socket, command, timeout);
      });
      expect((await adapter.enforce(new Set())).error).toBeUndefined();
      await adapter.stop();
      expect(log.some((command) => command.includes("shutdown"))).toBe(false);
      expect(state[0]!.sessions).toHaveLength(1);
    },
  );

  test("a departing worker is skipped and a newly appearing worker is drained", async () => {
    const state = workers();
    const cli = fakeMaster(state);
    let changed = false;
    const adapter = new HaproxyWithdrawalAdapter("/fake", async (socket, command, timeout) => {
      if (!changed && command === "@!53 show servers state") {
        changed = true;
        const next = { ...state.shift()!, pid: 99 };
        state.push(next);
        return "Can't find the target PID";
      }
      return cli(socket, command, timeout);
    });
    expect((await adapter.enforce(new Set())).error).toBeUndefined();
    expect(state.every((worker) => worker.sessions.every((session) => session.backend === "be_caddy"))).toBe(
      true,
    );
  });

  test("continuous worker churn exhausts the bounded passes without claiming success", async () => {
    const state = workers().slice(0, 1);
    const cli = fakeMaster(state);
    let count = 0;
    const adapter = new HaproxyWithdrawalAdapter("/fake", async (socket, command, timeout) => {
      if (command === "show proc" && ++count > 1) state[0]!.pid++;
      return cli(socket, command, timeout);
    });
    expect((await adapter.enforce(new Set())).error).toContain("worker set changed");
    expect(count).toBe(21);
  });

  test.each(["show servers state", "show sess"])(
    "dropped %s answers never verify withdrawal",
    async (verb) => {
      const cli = fakeMaster(workers());
      const adapter = new HaproxyWithdrawalAdapter("/fake", async (socket, command, timeout) =>
        command.endsWith(verb) ? "" : cli(socket, command, timeout),
      );
      expect((await adapter.enforce(new Set())).error).toContain(`incomplete ${verb}`);
    },
  );

  test.each(["garbage", "0xffff: proto=sockpair fe=GLOBAL be=<NONE> srv=<none>\n0x12: fe=truncated"])(
    "malformed session dumps fail closed (%s)",
    async (answer) => {
      const cli = fakeMaster(workers());
      const adapter = new HaproxyWithdrawalAdapter("/fake", async (socket, command, timeout) =>
        command.endsWith("show sess") ? answer : cli(socket, command, timeout),
      );
      expect((await adapter.enforce(new Set())).error).toContain("incomplete show sess");
    },
  );

  test("a server dump dropped after its header is not a verified empty router", async () => {
    const cli = fakeMaster(workers());
    const adapter = new HaproxyWithdrawalAdapter("/fake", async (socket, command, timeout) =>
      command.endsWith("show servers state")
        ? "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_port\n"
        : cli(socket, command, timeout),
    );
    expect((await adapter.enforce(new Set())).error).toContain("incomplete show servers state");
  });

  test("stop refuses to act without an inspected worker", async () => {
    await expect(new HaproxyWithdrawalAdapter("/fake", fakeMaster(workers())).stop()).rejects.toThrow(
      /could not be inspected/,
    );
  });
});

async function scratch() {
  return mkdtemp(join(tmpdir(), "ark-edge-l4-"));
}
const valid = async (_socket: string, generation: string) => ({
  ok: true,
  generation,
  hash: generation,
  diagnostics: "",
});
const refuse = async (_socket: string, generation: string) => ({
  ok: false,
  generation,
  hash: generation,
  diagnostics: "[ALERT] parse error",
});
const wrongHash = async (_socket: string, generation: string) => ({
  ok: true,
  generation,
  hash: "0".repeat(64),
  diagnostics: "",
});

describe("generation install (§3.8.6)", () => {
  test("a valid candidate is written immutably, swapped atomically and reloaded", async () => {
    const root = await scratch();
    const commands: string[] = [];
    const master = new HaproxyMaster("/fake", async (_s, command) => {
      commands.push(command);
      return command === "reload"
        ? "Success=1\n--\n[NOTICE] Loading success.\n"
        : "#<PID> <type>\n1 master 0\n# workers\n9 worker 0\n";
    });
    const first = renderEdgeL4Generation({ httpHostnames: ["www.example.com"] });
    const result = await installEdgeL4Generation({
      root,
      generation: first,
      validatorSocket: "/v",
      master,
      validate: valid,
    });
    expect(result).toMatchObject({ generation: first.id, previous: null, changed: true, reloaded: true });
    expect(await readlink(join(root, "current"))).toBe(`generations/${first.id}`);
    expect(await hashGenerationDir(join(root, "generations", first.id))).toBe(first.id);
    expect(await readFile(join(root, "current", "haproxy.cfg"), "utf8")).toBe(first.files["haproxy.cfg"]!);
    expect(commands).toEqual(["reload", "show proc"]);
    // Re-applying the same generation changes nothing and sends no reload.
    commands.length = 0;
    expect(
      await installEdgeL4Generation({
        root,
        generation: first,
        validatorSocket: "/v",
        master,
        validate: valid,
      }),
    ).toMatchObject({ changed: false });
    expect(commands).toEqual([]);
    // The next generation prunes only once no worker is draining, keeping the previous one.
    const second = renderEdgeL4Generation({ httpHostnames: ["example.com"] });
    const next = await installEdgeL4Generation({
      root,
      generation: second,
      validatorSocket: "/v",
      master,
      validate: valid,
    });
    expect(next).toMatchObject({ previous: first.id, generation: second.id });
    expect((await readdir(join(root, "generations"))).toSorted()).toEqual([first.id, second.id].toSorted());
    await rm(root, { recursive: true, force: true });
  });

  test("an invalid candidate is refused before `current` changes or a reload is sent", async () => {
    const root = await scratch();
    const commands: string[] = [];
    const master = new HaproxyMaster("/fake", async (_s, command) => {
      commands.push(command);
      return "Success=1\n--\n";
    });
    const good = renderEdgeL4Generation({ httpHostnames: ["www.example.com"] });
    await installEdgeL4Generation({ root, generation: good, validatorSocket: "/v", validate: valid });
    const bad = renderEdgeL4Generation({ httpHostnames: ["bad.example.com"] });
    await expect(
      installEdgeL4Generation({ root, generation: bad, validatorSocket: "/v", master, validate: refuse }),
    ).rejects.toBeInstanceOf(InvalidGenerationError);
    expect(await currentGeneration(root)).toBe(good.id);
    expect(commands).toEqual([]);
    expect(await readdir(join(root, "generations"))).toEqual([good.id]);
    // A validator answering a different hash is refused the same way.
    await expect(
      installEdgeL4Generation({ root, generation: bad, validatorSocket: "/v", master, validate: wrongHash }),
    ).rejects.toThrow();
    expect(await currentGeneration(root)).toBe(good.id);
    await rm(root, { recursive: true, force: true });
  });

  test("Success=0 restores the previous `current`", async () => {
    const root = await scratch();
    const good = renderEdgeL4Generation({ httpHostnames: ["www.example.com"] });
    await installEdgeL4Generation({ root, generation: good, validatorSocket: "/v", validate: valid });
    const master = new HaproxyMaster("/fake", async () => "Success=0\n--\n[ALERT] cannot bind\n");
    const next = renderEdgeL4Generation({ httpHostnames: ["example.com"] });
    await expect(
      installEdgeL4Generation({ root, generation: next, validatorSocket: "/v", master, validate: valid }),
    ).rejects.toThrow(/old workers keep serving/);
    expect(await currentGeneration(root)).toBe(good.id);
    await rm(root, { recursive: true, force: true });
  });

  test.each(["refused", "timeout", "empty", "Success=0"])(
    "unconfirmed reload (%s) restores and retries even on first install",
    async (failure) => {
      for (const initial of [false, true]) {
        const root = await scratch();
        try {
          const good = renderEdgeL4Generation({ httpHostnames: ["old.example.com"] });
          if (initial)
            await installEdgeL4Generation({ root, generation: good, validatorSocket: "/v", validate: valid });
          const candidate = renderEdgeL4Generation({ httpHostnames: ["new.example.com"] });
          let attempts = 0;
          const master = new HaproxyMaster("/fake", async (_socket, command) => {
            if (command !== "reload") return "#<PID> <type>\n1 master 0\n# workers\n9 worker 0\n";
            if (++attempts === 1) {
              if (failure === "empty") return "";
              if (failure === "Success=0") return "Success=0\n--\n";
              throw new Error(failure);
            }
            return "Success=1\n--\n";
          });
          const input = { root, generation: candidate, validatorSocket: "/v", validate: valid, master };
          await expect(installEdgeL4Generation(input)).rejects.toThrow();
          expect(await currentGeneration(root)).toBe(initial ? good.id : null);
          expect((await installEdgeL4Generation(input)).reloaded).toBe(true);
          expect(attempts).toBe(2);
          expect(await currentGeneration(root)).toBe(candidate.id);
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      }
    },
  );

  test("a failed forced reload of the current generation stays retryable", async () => {
    const root = await scratch();
    try {
      const generation = renderEdgeL4Generation({ httpHostnames: [] });
      await installEdgeL4Generation({ root, generation, validatorSocket: "/v", validate: valid });
      let attempts = 0;
      const master = new HaproxyMaster("/fake", async (_socket, command) => {
        if (command !== "reload") return "#<PID>\n1 master 0\n";
        if (++attempts === 1) throw new Error("ambiguous timeout");
        return "Success=1\n--\n";
      });
      const input = { root, generation, validatorSocket: "/v", validate: valid, master };
      await expect(installEdgeL4Generation({ ...input, force: true })).rejects.toThrow();
      expect((await installEdgeL4Generation(input)).reloaded).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("hashing refuses symlinks inside a generation", async () => {
    const root = await scratch();
    await writeFile(join(root, "haproxy.cfg"), "x");
    await symlink("/etc/passwd", join(root, "leak"));
    await expect(hashGenerationDir(root)).rejects.toThrow(/symlink/);
    await rm(root, { recursive: true, force: true });
  });
});

test("validator client allows both 10-second checks and aborts a hung validator", async () => {
  const root = await scratch();
  const socket = join(root, "validator.sock");
  let delay = 20_050;
  const server = Bun.serve({
    unix: socket,
    async fetch() {
      await Bun.sleep(delay);
      return Response.json({ ok: true, hash: "a".repeat(64) });
    },
  });
  try {
    expect((await validateGeneration(socket, "a".repeat(64))).ok).toBe(true);
    delay = 100;
    await expect(validateGeneration(socket, "a".repeat(64), 20)).rejects.toThrow();
  } finally {
    await server.stop(true);
    await rm(root, { recursive: true, force: true });
  }
}, 26_000);

describe("HaproxyWithdrawalAdapter with terminated routes (FD-14)", () => {
  const terminated = { ...route, policy: "0123456789abcdef" };
  const target = haproxyServerName(terminated);
  const loop = haproxyLoopServerName(terminated);
  const state = (): FakeWorker[] => [
    {
      pid: 70,
      section: "current",
      stopped: false,
      servers: [
        { backend: "be_caddy", server: "caddy", addr: "127.0.0.1", port: 8443, admin: 0 },
        { backend: "be_rt_p7q2_tls", server: loop, addr: "-", port: 0, admin: 0 },
        { backend: "be_rt_p7q2", server: target, addr: "100.88.1.20", port: 1883, admin: 0 },
      ],
      sessions: [
        { id: "0x1", backend: "be_rt_p7q2_tls", server: loop },
        { id: "0x2", backend: "be_rt_p7q2", server: target },
        { id: "0x3", backend: "be_caddy", server: "caddy" },
      ],
    },
  ];

  test("the loop server is authorised exactly when its target server is", async () => {
    const workers = state();
    const log: string[] = [];
    const adapter = new HaproxyWithdrawalAdapter("/fake", fakeMaster(workers, log));
    const kept = await adapter.enforce(new Set([routeIdentityKey(terminated)]));
    expect(kept.error).toBeUndefined();
    expect(kept.withdrawn).toEqual([]);
    expect(log.some((command) => command.includes("disable"))).toBe(false);
  });

  test("a revoked policy fences the loop and target servers, then drains both sessions", async () => {
    const workers = state();
    const log: string[] = [];
    const adapter = new HaproxyWithdrawalAdapter("/fake", fakeMaster(workers, log));
    // The same route with a new policy fingerprint (for example a narrowed allowlist).
    const result = await adapter.enforce(
      new Set([routeIdentityKey({ ...terminated, policy: "fedcba9876543210" })]),
    );
    expect(result.error).toBeUndefined();
    expect(result.withdrawn).toEqual(["100.88.1.20:1883"]);
    const disables = log.filter((command) => command.includes("disable server"));
    expect(disables).toEqual([
      `@!70 disable server be_rt_p7q2_tls/${loop}`,
      `@!70 disable server be_rt_p7q2/${target}`,
    ]);
    expect(log.indexOf(disables[1]!)).toBeLessThan(log.findIndex((command) => command.includes("shutdown")));
    expect(workers[0]!.sessions.map((session) => session.id)).toEqual(["0x3"]);
  });

  test("stop fences loop servers too, never Caddy", async () => {
    const workers = state();
    const log: string[] = [];
    const adapter = new HaproxyWithdrawalAdapter("/fake", fakeMaster(workers, log));
    await adapter.enforce(new Set([routeIdentityKey(terminated)]));
    await adapter.stop();
    expect(log).toContain(`@!70 disable server be_rt_p7q2_tls/${loop}`);
    expect(log).not.toContain("@!70 disable server be_caddy/caddy");
    expect(workers[0]!.sessions.map((session) => session.id)).toEqual(["0x3"]);
  });
});
