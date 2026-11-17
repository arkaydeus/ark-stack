import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, readlink, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  allowedServerIndex,
  generationId,
  haproxyConfigServers,
  haproxyLaunchDecision,
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

describe("edge-l4 rendering (§3.8.5 fe_tls443)", () => {
  const generation = renderEdgeL4Generation({
    httpHostnames: ["www.example.com", "example.com", "login.example.com", "example.com"],
  });
  const config = generation.files["haproxy.cfg"]!;

  test("443 accepts only a TLS ClientHello within 5 s and sends HTTP, login and unknown SNI to Caddy", () => {
    expect(config).toContain("frontend fe_tls443\n    bind :443\n");
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
        hostname: "mqtt.example.com",
        stableId: "nNAS1CNTRL",
        target: "100.88.1.20:1883",
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
      return worker.sessions
        .map((s) => `${s.id}: proto=tcpv4 src=1.2.3.4:5 fe=fe_tls443 be=${s.backend} srv=${s.server} ts=00\n`)
        .join("");
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

  test("stop shuts every frontend and proxied session down in the workers of the failed pass", async () => {
    const state = workers();
    const log: string[] = [];
    const cli = fakeMaster(state, log);
    const failing: HaproxyCli = async (socket, command, timeout) =>
      command.includes("disable server") ? "Unexpected failure.\n" : cli(socket, command, timeout);
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
    await adapter.stop();
    expect(log).toContain("@!53 shutdown frontend fe_tls443");
    expect(log).not.toContain("@!99 shutdown frontend fe_tls443");
    expect(state.filter((worker) => worker.pid !== 99).every((worker) => worker.sessions.length === 0)).toBe(
      true,
    );
    expect(state.find((worker) => worker.pid === 99)!.sessions).toHaveLength(1);
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

  test("hashing refuses symlinks inside a generation", async () => {
    const root = await scratch();
    await writeFile(join(root, "haproxy.cfg"), "x");
    await symlink("/etc/passwd", join(root, "leak"));
    await expect(hashGenerationDir(root)).rejects.toThrow(/symlink/);
    await rm(root, { recursive: true, force: true });
  });
});
