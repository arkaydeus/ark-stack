// FD-26 (docs/design/front-door.md §3.8.3, §3.8.5): the 5432 PostgreSQL router `fe_pg5432`, PgBouncer
// behind one pooler-wide policy (`be_pgbouncer`), `postgres` routes by direct-TLS SNI and the opt-in
// compatibility port, and the API rules for the `postgres` route kind.
import { describe, expect, test } from "bun:test";

import {
  OPEN_CIDRS,
  POOLER_ALLOWLIST_FILE,
  haproxyConfigServers,
  haproxyLaunchDecision,
  haproxyServerName,
  l4PolicyFingerprint,
  renderEdgeL4Generation,
  type EdgeL4PostgresRoute,
  type EdgeL4TcpRoute,
} from "./edge-l4.ts";
import {
  assertL4Enableable,
  checkCompatPort,
  checkL4RouteSettings,
  frontRouteCreateInput,
  l4LooseningChanges,
  routeListenPort,
} from "./front-routes.ts";

const CERT =
  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----";
const CA = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----";
const CRL = "-----BEGIN X509 CRL-----\nMIIX\n-----END X509 CRL-----";

/** The literal §3.8.5 route: rt_pg01 pg-home.example.com:5432 -> 100.90.4.7:5432, passthrough (PG >= 17). */
const pgHome: EdgeL4PostgresRoute = {
  id: "rt_pg01",
  hostname: "pg-home.example.com",
  stableId: "nPGHOME1",
  ip: "100.90.4.7",
  port: 5432,
  sourceCidrs: ["198.51.100.0/24"],
  policy: "0a1b2c3d4e5f6071",
};
const pooler = { hostname: "db.example.com", sourceCidrs: ["203.0.113.0/24"] };

function section(config: string, header: string) {
  const start = config.indexOf(`\n${header}\n`);
  if (start < 0) throw new Error(`no section ${header}`);
  const rest = config.slice(start + 1);
  const end = rest.search(/\n\n/);
  return rest.slice(0, end < 0 ? undefined : end);
}

describe("fe_pg5432 (§3.8.5)", () => {
  const generation = renderEdgeL4Generation({ httpHostnames: [], pooler, postgresRoutes: [pgHome] });
  const config = generation.files["haproxy.cfg"]!;

  test("classic SSLRequest, GSSENC and Cancel go to PgBouncer; direct TLS by SNI; everything else rejected", () => {
    expect(section(config, "frontend fe_pg5432").split("\n")).toEqual([
      "frontend fe_pg5432",
      "    bind :5432",
      "    maxconn 2000",
      "    tcp-request inspect-delay 5s",
      "    acl pg_ssl_request req.payload(0,8) -m bin 0000000804d2162f",
      "    acl pg_gssenc_request req.payload(0,8) -m bin 0000000804d21630",
      "    acl pg_cancel_request req.payload(0,8) -m bin 0000001004d2162e",
      "    acl tls_client_hello req.ssl_hello_type 1",
      "    tcp-request content accept if pg_ssl_request || pg_gssenc_request || pg_cancel_request || tls_client_hello",
      "    tcp-request content reject",
      "    # Ark databases via PgBouncer: classic negotiation, or direct TLS for the DB hostname / no SNI.",
      "    use_backend be_pgbouncer if pg_ssl_request || pg_gssenc_request || pg_cancel_request",
      "    use_backend be_pgbouncer if tls_client_hello { req.ssl_sni -i db.example.com }",
      "    use_backend be_pgbouncer if tls_client_hello !{ req.ssl_sni -m found }",
      "    # Postgres routes by SNI (direct TLS).",
      "    use_backend be_rt_pg01_pg if tls_client_hello { req.ssl_sni -i pg-home.example.com }",
      "    default_backend be_reject",
    ]);
    expect(config).toContain("backend be_reject\n    tcp-request content reject\n");
  });

  test("be_pgbouncer enforces exactly the pooler-wide allowlist and reaches PgBouncer by name", () => {
    const backend = section(config, "backend be_pgbouncer");
    expect(backend).toContain(`    tcp-request content reject if !{ src -f ${POOLER_ALLOWLIST_FILE} }`);
    expect(backend).toContain(
      "    server pgbouncer pgbouncer-public:5432 maxconn 2000 init-addr last,none resolvers docker",
    );
    // Never the PROXY protocol to PgBouncer.
    expect(backend).not.toContain("send-proxy");
    expect(generation.files[POOLER_ALLOWLIST_FILE]).toBe("203.0.113.0/24\n");
    expect(config).toContain("resolvers docker\n    nameserver dns 127.0.0.11:53\n    hold valid 10s\n");
    expect(generation.manifest.pooler).toEqual({
      hostname: "db.example.com",
      server: "pgbouncer-public:5432",
      admits: "allowlist",
    });
  });

  test("the route backend applies its own allowlist and limits before forwarding (passthrough)", () => {
    const backend = section(config, "backend be_rt_pg01_pg");
    expect(backend).toContain("    tcp-request content reject if !{ src -f allow/rt_pg01.lst }");
    expect(backend).toContain("    tcp-request content lua.ark-admit rt_pg01 50 10 20");
    expect(backend).toContain(`    server ${haproxyServerName(pgHome)} 100.90.4.7:5432 maxconn 50`);
    expect(generation.files["allow/rt_pg01.lst"]).toBe("198.51.100.0/24\n");
    expect(config).toContain("# ark-tailnet-route rt_pg01 100.90.4.7:5432");
  });

  test("the closed configuration keeps PgBouncer (not a tailnet backend) but no route", () => {
    const closed = generation.files["haproxy.closed.cfg"]!;
    expect(closed).toContain("use_backend be_pgbouncer if pg_ssl_request");
    expect(closed).not.toContain("rt_pg01");
    // PgBouncer is never a guarded tailnet server, so it cannot hold the launch guard closed.
    expect(haproxyConfigServers(closed).find((server) => server.server === "pgbouncer")?.key).toBeNull();
    expect(haproxyLaunchDecision(closed, new Set())).toMatchObject({ open: true, guarded: false });
    expect(haproxyLaunchDecision(config, new Set()).open).toBe(false);
  });

  test("no published database: no PgBouncer rule, so SSLRequest connections are rejected", () => {
    const routesOnly = renderEdgeL4Generation({ httpHostnames: [], postgresRoutes: [pgHome] });
    const frontend = section(routesOnly.files["haproxy.cfg"]!, "frontend fe_pg5432");
    expect(frontend).not.toContain("be_pgbouncer");
    expect(frontend).toContain("default_backend be_reject");
    expect(routesOnly.files["haproxy.cfg"]).not.toContain("resolvers docker");
    expect(routesOnly.files[POOLER_ALLOWLIST_FILE]).toBeUndefined();
    expect(routesOnly.manifest.pooler).toBeNull();
    // Without a pooler or a postgres route there is no 5432 listener at all.
    expect(renderEdgeL4Generation({ httpHostnames: [] }).files["haproxy.cfg"]).not.toContain("fe_pg5432");
  });

  test("pooler allowlists: empty denies all, only allowInternet opens, near-open lists are refused", () => {
    const empty = renderEdgeL4Generation({ httpHostnames: [], pooler: { hostname: null, sourceCidrs: [] } });
    expect(empty.files[POOLER_ALLOWLIST_FILE]).toBe("");
    expect(empty.manifest.pooler?.admits).toBe("nobody");
    expect(section(empty.files["haproxy.cfg"]!, "frontend fe_pg5432")).not.toContain("req.ssl_sni -i");
    const open = renderEdgeL4Generation({
      httpHostnames: [],
      pooler: { hostname: "db.example.com", sourceCidrs: ["203.0.113.0/24"], allowInternet: true },
    });
    expect(open.files[POOLER_ALLOWLIST_FILE]).toBe(OPEN_CIDRS.map((cidr) => `${cidr}\n`).join(""));
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], pooler: { hostname: null, sourceCidrs: ["0.0.0.0/0"] } }),
    ).toThrow(/allowInternet/);
    expect(() =>
      renderEdgeL4Generation({
        httpHostnames: [],
        pooler: { hostname: null, sourceCidrs: [], server: "100.64.1.2:5432" },
      }),
    ).toThrow(/tailnet/);
    expect(() =>
      renderEdgeL4Generation({
        httpHostnames: [],
        pooler: { hostname: null, sourceCidrs: [], server: "pg bouncer:1" },
      }),
    ).toThrow(/hostname:port/);
  });

  test("terminated routes terminate with ALPN postgresql on the loop-back frontend", () => {
    const terminated = renderEdgeL4Generation({
      httpHostnames: [],
      postgresRoutes: [
        {
          ...pgHome,
          id: "rt_pg16",
          hostname: "pg16.example.com",
          tlsMode: "terminate",
          certificatePem: CERT,
        },
        {
          ...pgHome,
          id: "rt_pgm",
          hostname: "pgm.example.com",
          tlsMode: "terminate_mtls",
          certificatePem: CERT,
          clientCaPem: CA,
          clientCrlPem: CRL,
        },
      ],
    });
    const text = terminated.files["haproxy.cfg"]!;
    expect(text).toMatch(
      /bind abns@ark_[a-f0-9]{32} accept-proxy ssl crt certs\/rt_pg16\.pem alpn postgresql\n/,
    );
    expect(text).toMatch(
      /bind abns@ark_[a-f0-9]{32} accept-proxy ssl crt certs\/rt_pgm\.pem alpn postgresql ca-file cas\/rt_pgm\.pem verify required crl-file cas\/rt_pgm\.crl\n/,
    );
    expect(terminated.files["cas/rt_pgm.crl"]).toContain("X509 CRL");
    expect(terminated.manifest.routes.find((route) => route.id === "rt_pg16")?.loop?.backend).toBe(
      "be_rt_pg16_pg",
    );
    expect(() =>
      renderEdgeL4Generation({
        httpHostnames: [],
        postgresRoutes: [{ ...pgHome, tlsMode: "terminate", sourceCidrs: [], certificatePem: CERT }],
      }),
    ).toThrow(/restricted/);
  });

  test("the compatibility port relays raw TCP to the target behind the route's admission", () => {
    const compat = renderEdgeL4Generation({
      httpHostnames: [],
      postgresRoutes: [{ ...pgHome, compatPort: 20007 }],
    });
    const frontend = section(compat.files["haproxy.cfg"]!, "frontend fe_rt_pg01_compat");
    expect(frontend).toContain("    bind :20007");
    expect(frontend).toContain("    tcp-request content reject if !{ src -f allow/rt_pg01.lst }");
    expect(frontend).toContain("    default_backend be_rt_pg01_compat");
    expect(section(compat.files["haproxy.cfg"]!, "backend be_rt_pg01_compat")).toContain(
      `    server ${haproxyServerName(pgHome)} 100.90.4.7:5432 maxconn 50`,
    );
    expect(compat.manifest.routes[0]?.compat).toEqual({
      listenPort: 20007,
      backend: "be_rt_pg01_compat",
      server: haproxyServerName(pgHome),
    });
    expect(() =>
      renderEdgeL4Generation({
        httpHostnames: [],
        postgresRoutes: [{ ...pgHome, compatPort: 20007, tlsMode: "terminate", certificatePem: CERT }],
      }),
    ).toThrow(/passthrough/);
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], postgresRoutes: [{ ...pgHome, compatPort: 30000 }] }),
    ).toThrow(/outside/);
    const ssh: EdgeL4TcpRoute = {
      id: "rt_t001",
      hostname: "ssh-box.example.com",
      stableId: "nBOX1",
      ip: "100.77.9.3",
      port: 22,
      listenPort: 20007,
      sourceCidrs: ["203.0.113.7/32"],
    };
    expect(() =>
      renderEdgeL4Generation({
        httpHostnames: [],
        tcpRoutes: [ssh],
        postgresRoutes: [{ ...pgHome, compatPort: 20007 }],
      }),
    ).toThrow(/already has a raw TCP route/);
  });

  test("a route cannot take the database hostname or another route's SNI", () => {
    expect(() =>
      renderEdgeL4Generation({
        httpHostnames: [],
        pooler,
        postgresRoutes: [{ ...pgHome, hostname: "db.example.com" }],
      }),
    ).toThrow(/database hostname/);
    expect(() =>
      renderEdgeL4Generation({ httpHostnames: [], postgresRoutes: [pgHome, { ...pgHome, id: "rt_pg02" }] }),
    ).toThrow(/collides/);
  });

  test("the compat port is part of a postgres route's policy; tls/tcp fingerprints are unchanged", () => {
    const base = {
      listenPort: 5432,
      tlsMode: "passthrough" as const,
      sourceCidrs: ["198.51.100.0/24"],
      allowInternet: false,
      limits: { maxConn: 50, perSourceConn: 10, perSourceRate: 20 },
    };
    expect(l4PolicyFingerprint({ ...base, kind: "postgres", compatPort: 20007 })).not.toBe(
      l4PolicyFingerprint({ ...base, kind: "postgres", compatPort: null }),
    );
    expect(l4PolicyFingerprint({ ...base, kind: "tls", listenPort: 443, compatPort: 20007 })).toBe(
      l4PolicyFingerprint({ ...base, kind: "tls", listenPort: 443 }),
    );
  });
});

function settings(input: Record<string, unknown>) {
  return checkL4RouteSettings({
    kind: "postgres",
    listenPort: 5432,
    tlsMode: "passthrough",
    sourceCidrs: ["198.51.100.0/24"],
    allowInternet: undefined,
    protocolAuthConfirmed: undefined,
    limits: undefined,
    ...input,
  } as Parameters<typeof checkL4RouteSettings>[0]);
}

describe("postgres route API rules", () => {
  test("listen on 5432 only; TLS modes; the compatibility port is passthrough-only from the range", () => {
    expect(routeListenPort("postgres", undefined, [])).toBe(5432);
    expect(routeListenPort("postgres", 5432, [])).toBe(5432);
    expect(() => routeListenPort("postgres", 443, [])).toThrow(/5432/);
    expect(settings({ compatPort: 20007 })).toMatchObject({
      kind: "postgres",
      compatPort: 20007,
      limits: { maxConn: 50 },
    });
    expect(() => settings({ tlsMode: "plain" })).toThrow(/plain/);
    expect(() => settings({ tlsMode: "terminate", compatPort: 20007 })).toThrow(/passthrough/);
    expect(() => settings({ tlsMode: "terminate", sourceCidrs: [] })).toThrow(/restricted/);
    expect(() => settings({ allowPlaintext: true })).toThrow(/plain tcp/);
    expect(() => checkCompatPort(5432, "passthrough")).toThrow(/20000-20049/);
    expect(() => checkCompatPort(20050, "passthrough")).toThrow(/20000-20049/);
    expect(
      frontRouteCreateInput.parse({
        kind: "postgres",
        hostname: "pg-home.example.com",
        target: "pg-home",
        targetPort: 5432,
        tlsMode: "passthrough",
        compatPort: 20007,
        sourceCidrs: ["198.51.100.0/24"],
      }),
    ).toMatchObject({ compatPort: 20007 });
  });

  test("enable needs someone admitted; a new compatibility port is a loosening change", () => {
    expect(() =>
      assertL4Enableable({
        kind: "postgres",
        sourceCidrs: [],
        allowInternet: false,
        internetConfirmedAt: null,
        protocolAuthConfirmed: false,
        tlsMode: "passthrough",
      }),
    ).toThrow(/empty/);
    const current = checkL4RouteSettings({
      kind: "postgres",
      listenPort: 5432,
      tlsMode: "passthrough",
      sourceCidrs: ["198.51.100.0/24"],
      allowInternet: false,
      protocolAuthConfirmed: undefined,
      limits: undefined,
    });
    expect(l4LooseningChanges(current, { ...current, compatPort: 20007 })).toContain("compatPort");
    expect(l4LooseningChanges({ ...current, compatPort: 20007 }, current)).not.toContain("compatPort");
  });
});
