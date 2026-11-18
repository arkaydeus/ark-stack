// FD-14 (docs/design/front-door.md §3.8.2, §3.8.4-§3.8.6): TLS-TCP routes by SNI on 443 and shared
// SNI ports, raw-TCP routes on dedicated ports, their admission policy, the raw-port nftables table,
// the API's listener and settings rules and the installer's SNI port selection.
import { describe, expect, test } from "bun:test";

import {
  L4_LIMIT_DEFAULTS,
  allowedServerIndex,
  haproxyConfigServers,
  haproxyLaunchDecision,
  haproxyLoopServerName,
  haproxyServerDenied,
  haproxyServerName,
  l4PolicyFingerprint,
  parseSniPorts,
  renderEdgeL4Generation,
  routeAllowlist,
  type EdgeL4TcpRoute,
  type EdgeL4TlsRoute,
} from "./edge-l4.ts";
import { routeIdentityKey } from "./edge-withdrawal.ts";
import { frontRawPortPolicies, renderFrontRawPorts } from "./front-raw-nft.ts";
import {
  assertFieldsForKind,
  assertL4Enableable,
  assertSupportedRouteKind,
  checkL4RouteSettings,
  frontRouteCreateInput,
  l4LooseningChanges,
  routeListenPort,
} from "./front-routes.ts";
import { applyEdgeSniPorts } from "./install.ts";

const CERT =
  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----";
const CA = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----";
const CRL = "-----BEGIN X509 CRL-----\nMIIX\n-----END X509 CRL-----";

/** The literal §3.8.5 route: rt_p7q2 mqtt.example.com:443 -> 100.88.1.20:1883, terminate_mtls. */
const mqtt: EdgeL4TlsRoute = {
  id: "rt_p7q2",
  hostname: "mqtt.example.com",
  stableId: "nNAS1CNTRL",
  ip: "100.88.1.20",
  port: 1883,
  sourceCidrs: ["203.0.113.0/24"],
  tlsMode: "terminate_mtls",
  policy: "a1b2c3d4e5f60718",
  certificatePem: CERT,
  clientCaPem: CA,
  clientCrlPem: CRL,
};
/** The literal §3.8.5 raw route: rt_t001 ssh-box.example.com:20001 -> 100.77.9.3:22, plain. */
const ssh: EdgeL4TcpRoute = {
  id: "rt_t001",
  hostname: "ssh-box.example.com",
  stableId: "nBOX1",
  ip: "100.77.9.3",
  port: 22,
  listenPort: 20001,
  sourceCidrs: ["198.51.100.7/32"],
  policy: "0011223344556677",
};

function block(text: string, header: string) {
  const start = text.indexOf(`\n${header}\n`);
  if (start < 0) throw new Error(`no ${header}`);
  const end = text.indexOf("\n\n", start + 1);
  return text.slice(start + 1, end < 0 ? undefined : end);
}

describe("TLS-TCP routes (§3.8.5)", () => {
  const generation = renderEdgeL4Generation({ httpHostnames: ["www.example.com"], tlsRoutes: [mqtt] });
  const config = generation.files["haproxy.cfg"]!;
  const target = haproxyServerName(mqtt);
  const loop = haproxyLoopServerName(mqtt);

  test("terminate_mtls admits in the SNI backend, then loops through abns with PROXY v2", () => {
    expect(config).toContain("    use_backend be_rt_p7q2_tls if { req.ssl_sni -i mqtt.example.com }\n");
    const outer = block(config, "backend be_rt_p7q2_tls");
    expect(outer).toContain("tcp-request content track-sc1 src table ad_src_rt_p7q2");
    expect(outer).toContain("tcp-request content track-sc2 int(1) table ad_total_rt_p7q2");
    expect(outer).toContain("tcp-request content lua.ark-admit rt_p7q2 50 10 20");
    expect(outer).toContain("tcp-request content reject unless { var(txn.ark_admitted) -m bool }");
    expect(generation.files["admission.lua"]).toContain('command("show proc")');
    expect(block(config, "backend ad_total_rt_p7q2")).toContain("store conn_cur");
    const inner = block(config, "frontend fe_rt_p7q2_tls");
    expect(inner).toContain(
      `    bind abns@ark_${target.slice(2)} accept-proxy ssl crt certs/rt_p7q2.pem ca-file cas/rt_p7q2.pem verify required crl-file cas/rt_p7q2.crl\n`,
    );
    expect(inner).toContain("    default_backend be_rt_p7q2");
    expect(block(config, "backend be_rt_p7q2")).toContain(`    server ${target} 100.88.1.20:1883 maxconn 50`);
    expect(generation.files["certs/rt_p7q2.pem"]).toBe(`${CERT}\n`);
    expect(generation.files["cas/rt_p7q2.pem"]).toBe(`${CA}\n`);
    expect(generation.files["cas/rt_p7q2.crl"]).toBe(`${CRL}\n`);
    expect(generation.files["allow/rt_p7q2.lst"]).toBe("203.0.113.0/24\n");
    expect(generation.manifest.routes[0]).toMatchObject({
      mode: "terminate_mtls",
      backend: "be_rt_p7q2",
      server: target,
      loop: { backend: "be_rt_p7q2_tls", server: loop },
    });
  });

  test("terminate has no client CA; passthrough forwards the client's TLS untouched", () => {
    const terminate = renderEdgeL4Generation({
      httpHostnames: [],
      tlsRoutes: [{ ...mqtt, tlsMode: "terminate" }],
    }).files;
    expect(terminate["haproxy.cfg"]).toContain("accept-proxy ssl crt certs/rt_p7q2.pem\n");
    expect(terminate["cas/rt_p7q2.pem"]).toBeUndefined();
    const passthrough = renderEdgeL4Generation({
      httpHostnames: [],
      tlsRoutes: [{ ...mqtt, tlsMode: "passthrough", certificatePem: undefined }],
    }).files;
    expect(passthrough["haproxy.cfg"]).not.toContain("abns@");
    expect(passthrough["haproxy.cfg"]).not.toContain(" ssl ");
    expect(passthrough["certs/rt_p7q2.pem"]).toBeUndefined();
  });

  test("a terminated route needs its certificate, CA and CRL; terminate needs a restricted list", () => {
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [{ ...mqtt, clientCrlPem: undefined }] }),
    ).toThrow(/CRL/);
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [{ ...mqtt, certificatePem: "nope" }] }),
    ).toThrow(/certificate/);
    for (const variant of [{ sourceCidrs: [] }, { allowInternet: true }]) {
      expect(() =>
        renderEdgeL4Generation({
          httpHostnames: [],
          tlsRoutes: [{ ...mqtt, tlsMode: "terminate", ...variant }],
        }),
      ).toThrow(/restricted/);
    }
  });

  test("termination refuses a certificate chain without its private key before hashing", () => {
    for (const tlsMode of ["terminate", "terminate_mtls"] as const) {
      expect(() =>
        renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [{ ...mqtt, tlsMode, certificatePem: CA }] }),
      ).toThrow(/certificate and key/);
    }
  });

  test("per-route limits are rendered from the stored values", () => {
    const limited = renderEdgeL4Generation({
      httpHostnames: [],
      tlsRoutes: [{ ...mqtt, limits: { maxConn: 3, perSourceConn: 2, perSourceRate: 7 } }],
    }).files["haproxy.cfg"]!;
    expect(limited).toContain("lua.ark-admit rt_p7q2 3 2 7");
    expect(limited).toContain("    maxconn 4\n");
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [{ ...mqtt, limits: { maxConn: 0 } }] }),
    ).toThrow(/maxConn/);
  });

  test("a shared SNI port gets its own TLS-only frontend that rejects unknown SNI", () => {
    const shared = renderEdgeL4Generation({
      httpHostnames: ["mqtt.example.com"],
      sniPorts: [8883],
      tlsRoutes: [{ ...mqtt, listenPort: 8883 }],
    }).files["haproxy.cfg"]!;
    const frontend = block(shared, "frontend fe_tls8883");
    expect(frontend).toContain("    bind :8883\n");
    expect(frontend).toContain(
      "    tcp-request content accept if { req.ssl_hello_type 1 }\n    tcp-request content reject\n",
    );
    expect(frontend).toContain("    use_backend be_rt_p7q2_tls if { req.ssl_sni -i mqtt.example.com }\n");
    expect(frontend).toEndWith("    default_backend be_reject");
    expect(block(shared, "backend be_reject")).toContain("tcp-request content reject");
    // The same hostname may be an HTTP route on 443 and a TLS route on 8883.
    expect(block(shared, "frontend fe_tls443")).not.toContain("be_rt_p7q2_tls");
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [{ ...mqtt, listenPort: 8883 }] }),
    ).toThrow(/not 443 or an enabled shared SNI port/);
    expect(() => renderEdgeL4Generation({ httpHostnames: [], sniPorts: [8443], tlsRoutes: [] })).toThrow(
      /not supported/,
    );
  });

  test("the closed variant keeps HTTP but renders no route, frontend or key material", () => {
    const closed = generation.files["haproxy.closed.cfg"]!;
    expect(closed).toContain("frontend fe_tls443");
    expect(closed).not.toContain("rt_p7q2");
    expect(closed).not.toContain("abns@");
  });
});

describe("raw-TCP routes (§3.8.5)", () => {
  const config = renderEdgeL4Generation({ httpHostnames: [], tcpRoutes: [ssh] }).files["haproxy.cfg"]!;

  test("one frontend per dedicated port: allowlist, per-source and total limits, then the target", () => {
    const frontend = block(config, "frontend fe_rt_t001");
    expect(frontend).toContain("bind :20001");
    expect(frontend).toContain("track-sc1 src table ad_src_rt_t001");
    expect(frontend).toContain("track-sc2 int(1) table ad_total_rt_t001");
    expect(frontend).toContain("lua.ark-admit rt_t001 20 5 10");
    expect(block(config, "backend be_rt_t001")).toContain(
      `    server ${haproxyServerName(ssh)} 100.77.9.3:22 maxconn 20`,
    );
    expect(L4_LIMIT_DEFAULTS.tcp).toEqual({ maxConn: 20, perSourceConn: 5, perSourceRate: 10 });
  });

  test("ports outside 20000-20049 and duplicate ports are refused", () => {
    for (const listenPort of [19999, 20050, 443, 5432])
      expect(() =>
        renderEdgeL4Generation({ httpHostnames: [], tcpRoutes: [{ ...ssh, listenPort }] }),
      ).toThrow();
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], tcpRoutes: [ssh, { ...ssh, id: "rt_t002" }] }),
    ).toThrow(/already has a raw TCP route/);
  });
});

describe("allowlists: empty denies all, only allowInternet opens (§3.8.6)", () => {
  test("rendered lists", () => {
    const render = (route: Partial<EdgeL4TcpRoute>) =>
      renderEdgeL4Generation({ httpHostnames: [], tcpRoutes: [{ ...ssh, ...route }] }).files[
        "allow/rt_t001.lst"
      ];
    expect(render({ sourceCidrs: [] })).toBe("");
    expect(render({ sourceCidrs: [], allowInternet: true })).toBe("0.0.0.0/0\n::/0\n");
    expect(render({ sourceCidrs: ["2001:db8::/48", "198.51.100.7/32", "198.51.100.7/32"] })).toBe(
      "198.51.100.7/32\n2001:db8::/48\n",
    );
  });

  test("open or near-open prefixes never render without allowInternet", () => {
    for (const cidr of ["0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/7", "2000::/3"]) {
      expect(() => routeAllowlist({ sourceCidrs: [cidr] })).toThrow(/allowInternet/);
    }
    expect(routeAllowlist({ sourceCidrs: ["10.0.0.0/8", "2001:db8::/16"] })).toEqual([
      "10.0.0.0/8",
      "2001:db8::/16",
    ]);
    expect(() => routeAllowlist({ sourceCidrs: ["nope"] })).toThrow();
  });
});

describe("policy fingerprints in server names (§3.8.6 revocation)", () => {
  const base = {
    kind: "tls" as const,
    listenPort: 443,
    tlsMode: "terminate_mtls" as const,
    sourceCidrs: ["203.0.113.0/24"],
    allowInternet: false,
    limits: L4_LIMIT_DEFAULTS.tls,
    clientCaId: "pca_1",
    revokedSerials: ["01"],
  };

  test("every admission input changes the fingerprint; order and duplicates do not", () => {
    const fingerprint = l4PolicyFingerprint(base);
    expect(fingerprint).toMatch(/^[a-f0-9]{16}$/);
    expect(l4PolicyFingerprint({ ...base, sourceCidrs: ["203.0.113.0/24", "203.0.113.0/24"] })).toBe(
      fingerprint,
    );
    for (const change of [
      { sourceCidrs: ["203.0.113.0/25"] },
      { allowInternet: true },
      { tlsMode: "terminate" as const },
      { limits: { ...base.limits, perSourceConn: 9 } },
      { revokedSerials: ["01", "02"] },
      { clientCaId: "pca_2" },
      { listenPort: 8883 },
    ]) {
      expect(l4PolicyFingerprint({ ...base, ...change })).not.toBe(fingerprint);
    }
  });

  test("a policy change makes the old servers (target and loop) unauthorised", () => {
    const old = { ...mqtt, policy: "1111111111111111" };
    const next = { ...mqtt, policy: "2222222222222222" };
    const index = allowedServerIndex(new Set([routeIdentityKey(next)]));
    const targetOld = { server: haproxyServerName(old), key: "100.88.1.20:1883" };
    const loopOld = { server: haproxyLoopServerName(old), key: null };
    expect(haproxyServerDenied(targetOld, index)).toBe(true);
    expect(haproxyServerDenied(loopOld, index)).toBe(true);
    expect(haproxyServerDenied({ server: haproxyServerName(next), key: "100.88.1.20:1883" }, index)).toBe(
      false,
    );
    expect(haproxyServerDenied({ server: haproxyLoopServerName(next), key: null }, index)).toBe(false);
    expect(haproxyServerDenied({ server: "caddy", key: null }, index)).toBe(false);
    // HTTP identities are unchanged by the optional fifth element.
    const http = { id: "rt_web1", hostname: "www.example.com", stableId: "n1", ip: "100.88.1.21", port: 80 };
    expect(JSON.parse(decodeURIComponent(routeIdentityKey(http)))).toHaveLength(4);
  });

  test("the launch guard opens only for the exact policy", () => {
    const config = renderEdgeL4Generation({ httpHostnames: [], tlsRoutes: [mqtt], tcpRoutes: [ssh] }).files[
      "haproxy.cfg"
    ]!;
    expect(
      haproxyConfigServers(config)
        .filter((server) => server.key)
        .map((server) => server.key),
    ).toEqual(["100.88.1.20:1883", "100.77.9.3:22"]);
    const allowed = new Set([routeIdentityKey(mqtt), routeIdentityKey(ssh)]);
    expect(haproxyLaunchDecision(config, allowed).open).toBe(true);
    expect(
      haproxyLaunchDecision(
        config,
        new Set([routeIdentityKey({ ...mqtt, policy: "ffffffffffffffff" }), routeIdentityKey(ssh)]),
      ).denied,
    ).toEqual(["100.88.1.20:1883"]);
  });
});

describe("raw-port nftables (FD-14, the ark_db_ingress style)", () => {
  test("every range port is covered: closed, deny-all, allowlist or explicit internet", () => {
    const rules = renderFrontRawPorts([
      { id: "rt_t001", listenPort: 20001, sourceCidrs: ["198.51.100.7/32", "2001:db8::/48"] },
      { id: "rt_t002", listenPort: 20002, sourceCidrs: [] },
      { id: "rt_t003", listenPort: 20003, sourceCidrs: [], allowInternet: true },
    ]);
    const policies = frontRawPortPolicies(rules);
    expect(policies.size).toBe(50);
    expect(policies.get(20000)).toBe("closed");
    expect(policies.get(20001)).toBe("allowlist");
    expect(policies.get(20002)).toBe("deny-all");
    expect(policies.get(20003)).toBe("internet");
    expect(rules).toContain('tcp dport 20000-20049 counter name "drop_closed" drop');
    expect(rules).toContain("ip saddr 198.51.100.7/32 goto port_20001_limits");
    expect(rules).toContain("ip6 saddr 2001:db8::/48 goto port_20001_limits");
    const chain = (name: string) =>
      new RegExp(`\n  chain ${name} \\{\n([\\s\\S]*?)\n  \\}`).exec(rules)?.[1] ?? "";
    // The deny-all port: no saddr rule at all before its drop.
    expect(chain("port_20002")).toBe(
      '    # rt_t002: empty allowlist = deny all\n    counter name "drop_allowlist" drop',
    );
    expect(chain("port_20003")).toContain("goto port_20003_limits");
    expect(chain("port_20003")).not.toContain("drop_allowlist");
    expect(chain("port_20001_limits")).toEndWith("    accept");
    expect(rules).toContain("ct direction original ct status dnat tcp dport vmap {");
  });

  test("bad ports, duplicates and open prefixes are refused", () => {
    expect(() => renderFrontRawPorts([{ id: "rt_a", listenPort: 22, sourceCidrs: [] }])).toThrow();
    expect(() =>
      renderFrontRawPorts([
        { id: "rt_a", listenPort: 20001, sourceCidrs: [] },
        { id: "rt_b", listenPort: 20001, sourceCidrs: [] },
      ]),
    ).toThrow();
    expect(() =>
      renderFrontRawPorts([{ id: "rt_a", listenPort: 20001, sourceCidrs: ["0.0.0.0/0"] }]),
    ).toThrow();
  });
});

const tcp = (input: Partial<Parameters<typeof checkL4RouteSettings>[0]>) =>
  checkL4RouteSettings({
    kind: "tcp",
    listenPort: 20001,
    tlsMode: undefined,
    sourceCidrs: undefined,
    allowInternet: undefined,
    allowPlaintext: true,
    protocolAuthConfirmed: undefined,
    limits: undefined,
    ...input,
  });

const tls = (input: Partial<Parameters<typeof checkL4RouteSettings>[0]>) =>
  checkL4RouteSettings({
    kind: "tls",
    listenPort: 443,
    tlsMode: "passthrough",
    sourceCidrs: ["203.0.113.0/24"],
    allowInternet: undefined,
    protocolAuthConfirmed: undefined,
    limits: undefined,
    ...input,
  });

describe("route API rules (§3.8.2, §3.8.4)", () => {
  const reserved = [25, 80, 443, 465, 587, 993, 2019, 3000, 5432, 41641, 41642];

  test("tcp routes only on 20000-20049, never on platform or mail ports", () => {
    expect(routeListenPort("tcp", 20000, [])).toBe(20000);
    expect(routeListenPort("tcp", 20049, [])).toBe(20049);
    for (const port of [19999, 20050, 8883, 22])
      expect(() => routeListenPort("tcp", port, [])).toThrow(/outside/);
    for (const port of reserved)
      expect(() => routeListenPort("tcp", port, [])).toThrow(/platform or mail port/);
    expect(() => routeListenPort("tcp", undefined, [])).toThrow(/dedicated listenPort/);
  });

  test("tls routes on 443 or an enabled shared SNI port, never on a raw port", () => {
    expect(routeListenPort("tls", undefined, [])).toBe(443);
    expect(routeListenPort("tls", 8883, [8883])).toBe(8883);
    expect(() => routeListenPort("tls", 8883, [])).toThrow(/not enabled at install/);
    expect(() => routeListenPort("tls", 20001, [8883])).toThrow(/raw TCP port/);
    for (const port of reserved.filter((item) => item !== 443))
      expect(() => routeListenPort("tls", port, [])).toThrow(/platform or mail port/);
    expect(() => routeListenPort("tls", 9999, [])).toThrow(/neither/);
  });

  test("kinds: postgres waits for FD-26; HTTP and L4 fields do not mix", () => {
    expect(assertSupportedRouteKind(undefined)).toBe("http");
    expect(assertSupportedRouteKind("tcp")).toBe("tcp");
    expect(() => assertSupportedRouteKind("postgres")).toThrow(/FD-26/);
    expect(() => assertFieldsForKind("http", { sourceCidrs: [] })).toThrow(/sourceCidrs/);
    expect(() => assertFieldsForKind("tls", { accessMode: "public" })).toThrow(/accessMode/);
    expect(
      frontRouteCreateInput.parse({
        kind: "tcp",
        hostname: "ssh.example.com",
        target: "box",
        targetPort: 22,
        listenPort: 20001,
        allowPlaintext: true,
        sourceCidrs: ["198.51.100.7/32"],
      }),
    ).toMatchObject({ listenPort: 20001 });
  });

  test("plain needs allowPlaintext, and opens to the internet only with protocol authentication", () => {
    expect(tcp({ sourceCidrs: ["198.51.100.7/32"] })).toMatchObject({
      tlsMode: "plain",
      allowInternet: false,
    });
    expect(() => tcp({ allowPlaintext: undefined })).toThrow(/allowPlaintext/);
    expect(() => tcp({ tlsMode: "passthrough" })).toThrow(/plain/);
    expect(() => tcp({ allowInternet: true })).toThrow(/protocolAuthConfirmed/);
    expect(tcp({ allowInternet: true, protocolAuthConfirmed: true })).toMatchObject({ allowInternet: true });
    // An empty list is stored (deny all) but can never be enabled; see below.
    expect(tcp({}).sourceCidrs).toEqual([]);
    expect(() => tcp({ sourceCidrs: ["0.0.0.0/0"] })).toThrow(/allowInternet/);
  });

  test("tls modes; terminate keeps its restricted, non-empty list", () => {
    expect(tls({}).limits).toEqual(L4_LIMIT_DEFAULTS.tls);
    expect(() => tls({ tlsMode: undefined })).toThrow(/tlsMode/);
    expect(() => tls({ tlsMode: "plain" })).toThrow(/plain/);
    expect(() => tls({ tlsMode: "terminate", sourceCidrs: [] })).toThrow(/restricted/);
    expect(() => tls({ tlsMode: "terminate", allowInternet: true })).toThrow(/restricted/);
    expect(tls({ tlsMode: "terminate_mtls", sourceCidrs: [], allowInternet: true }).allowInternet).toBe(true);
    expect(() => tls({ allowPlaintext: true })).toThrow(/plain tcp routes only/);
  });

  test("enable: an empty list alone never opens a route; allowInternet needs its saved confirmation", () => {
    const route = {
      kind: "tcp",
      sourceCidrs: [] as string[],
      allowInternet: false,
      internetConfirmedAt: null as Date | null,
      protocolAuthConfirmed: false,
      tlsMode: "plain",
    };
    expect(() => assertL4Enableable(route)).toThrow(/denies every source/);
    expect(() => assertL4Enableable({ ...route, allowInternet: true })).toThrow(/exposure.public/);
    expect(() =>
      assertL4Enableable({ ...route, allowInternet: true, internetConfirmedAt: new Date() }),
    ).toThrow(/protocol authentication/);
    expect(() =>
      assertL4Enableable({
        ...route,
        allowInternet: true,
        internetConfirmedAt: new Date(),
        protocolAuthConfirmed: true,
      }),
    ).not.toThrow();
    expect(() => assertL4Enableable({ ...route, sourceCidrs: ["198.51.100.7/32"] })).not.toThrow();
    expect(() => assertL4Enableable({ ...route, kind: "http" })).not.toThrow();
  });

  test("loosening changes need a step-up; tightening ones do not", () => {
    const current = tcp({ sourceCidrs: ["198.51.100.0/24"] });
    expect(l4LooseningChanges(current, tcp({ sourceCidrs: [] }))).toEqual([]);
    expect(l4LooseningChanges(current, tcp({ sourceCidrs: ["198.51.100.0/24", "192.0.2.1/32"] }))).toEqual([
      "sourceCidrs",
    ]);
    expect(
      l4LooseningChanges(
        current,
        tcp({ sourceCidrs: ["198.51.100.0/24"], allowInternet: true, protocolAuthConfirmed: true }),
      ),
    ).toEqual(["allowInternet", "protocolAuthConfirmed"]);
    expect(
      l4LooseningChanges(current, tcp({ sourceCidrs: ["198.51.100.0/24"], limits: { maxConn: 30 } })),
    ).toEqual(["limits.maxConn"]);
  });
});

describe("install-time shared SNI ports", () => {
  test("parse refuses anything but 8883, 5671, 636 and 6380", () => {
    expect(parseSniPorts("")).toEqual([]);
    expect(parseSniPorts(" 6380,8883,8883 ")).toEqual([6380, 8883]);
    for (const value of ["25", "993", "443", "8883x", "20001"]) expect(() => parseSniPorts(value)).toThrow();
  });

  test("the installer writes the selection and exactly one publish entry per enabled port", () => {
    const first = applyEdgeSniPorts(
      "A=1\nARK_EDGE_SNI_PORTS=636\nARK_EDGE_SNI_PORT_636=636:636\n",
      "8883,6380",
    );
    expect(first.ports).toEqual([6380, 8883]);
    expect(first.env).toBe(
      "A=1\nARK_EDGE_SNI_PORTS=6380,8883\nARK_EDGE_SNI_PORT_6380=6380:6380\nARK_EDGE_SNI_PORT_8883=8883:8883\n",
    );
    // Without a supplied value the existing selection is kept.
    expect(applyEdgeSniPorts(first.env).env).toBe(first.env);
    expect(applyEdgeSniPorts(first.env, "").env).toBe("A=1\nARK_EDGE_SNI_PORTS=\n");
    expect(() => applyEdgeSniPorts("", "25")).toThrow();
  });
});
