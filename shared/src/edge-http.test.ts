// FD-09 (docs/design/front-door.md §3.5): HTTP route options, input validation, the rendered site
// blocks, the Location policy and an injection fuzz test. The runtime behaviour of the same rendered
// config on Caddy 2.11.9 behind the HAProxy SNI router is in scripts/test-edge-routes.ts.
import { describe, expect, test } from "bun:test";

import { CADDY_GLOBAL_BLOCK, edgeCertificatePaths, planEdge, renderCaddyfile } from "./edge.ts";
import {
  EDGE_ERRORS_DIR,
  HTTP_ROUTE_DEFAULTS,
  checkedHttpRoute,
  evaluateLocation,
  httpRouteOptions,
  locationPolicy,
  type EdgeHttpRoute,
} from "./edge-http.ts";
import { launchDecision, routeIdentityKey } from "./edge-withdrawal.ts";
import { ValidationError } from "./errors.ts";

const base = { challengeDir: "/var/lib/ark/acme", apiUpstream: "api:3000" } as const;

/** The §3.5 example route: www.example.com -> home.tail1234.ts.net (100.101.102.103:3000). */
const www: EdgeHttpRoute = {
  id: "rt_k3x9",
  hostname: "www.example.com",
  stableId: "nHOME",
  ip: "100.101.102.103",
  port: 3000,
  access: "public",
  internalNames: ["home.tail1234.ts.net.", "home", "HOME.tail1234.ts.net"],
  internalIps: ["fd7a:115c:a1e0::6465:6667"],
};
/** The §3.5 apex: example.com -> canonical redirect to www. */
const apex: EdgeHttpRoute = {
  ...www,
  id: "rt_a1b2",
  hostname: "example.com",
  redirectTo: "www.example.com",
};

function issued(...hostnames: string[]) {
  return hostnames.map((hostname) => ({ hostname, status: "issued", ...edgeCertificatePaths(hostname) }));
}

function render(routes: EdgeHttpRoute[], hostnames = routes.map((route) => route.hostname)) {
  return renderCaddyfile({
    ...base,
    adminMode: "tailnet",
    certificates: issued(...hostnames),
    httpRoutes: routes,
  });
}

/** A site block of a rendered Caddyfile (address line through its closing brace). */
function site(caddyfile: string, address: string) {
  const start = caddyfile.indexOf(`\n${address} {\n`);
  if (start < 0) return undefined;
  const end = caddyfile.indexOf("\n}\n", start + 1);
  return caddyfile.slice(start + 1, end + 3);
}

describe("HTTP route options (§3.5 defaults)", () => {
  test("defaults", () => {
    expect(httpRouteOptions({})).toEqual(HTTP_ROUTE_DEFAULTS);
    expect(HTTP_ROUTE_DEFAULTS).toEqual({
      maxBodyMb: 25,
      hsts: true,
      upstreamHost: "public",
      rewriteLocation: true,
      responseHeaderTimeout: "60s",
      streamCloseDelay: "5m",
    });
    // redirectTo lives in the same JSON column but is read separately; unknown keys are ignored.
    expect(httpRouteOptions({ redirectTo: "www.example.com", future: 1 })).toEqual(HTTP_ROUTE_DEFAULTS);
  });

  test("accepts valid overrides", () => {
    expect(
      httpRouteOptions({
        maxBodyMb: 100,
        hsts: false,
        upstreamHost: "target",
        rewriteLocation: false,
        responseHeaderTimeout: "5m",
        streamCloseDelay: "0s",
        streamTimeout: "24h",
      }),
    ).toEqual({
      maxBodyMb: 100,
      hsts: false,
      upstreamHost: "target",
      rewriteLocation: false,
      responseHeaderTimeout: "5m",
      streamCloseDelay: "0s",
      streamTimeout: "24h",
    });
  });

  test.each([
    { maxBodyMb: 0 },
    { maxBodyMb: 2.5 },
    { maxBodyMb: "25" },
    { maxBodyMb: 1e9 },
    { hsts: "yes" },
    { rewriteLocation: 1 },
    { upstreamHost: "home.tail1234.ts.net" },
    { responseHeaderTimeout: "0s" },
    { responseHeaderTimeout: "60" },
    { responseHeaderTimeout: "1d" },
    { responseHeaderTimeout: "25h" },
    { streamCloseDelay: "-1s" },
    { streamCloseDelay: "5m\n}" },
    { streamTimeout: "1.5s" },
  ])("refuses %p", (options) => {
    expect(() => httpRouteOptions(options)).toThrow(ValidationError);
  });
});

describe("route validation (§3.5: every interpolated value)", () => {
  test.each<[string, Partial<EdgeHttpRoute>]>([
    ["SSO before FD-11", { access: "sso" }],
    ["an unknown access mode", { access: "open" as "public" }],
    ["an upper-case id", { id: "rt_K3X9" }],
    ["an id with a newline", { id: "rt_k3x9\nreverse_proxy 10.0.0.1:80" }],
    ["a tailnet hostname", { hostname: "home.tail1234.ts.net" }],
    ["an un-normalised hostname", { hostname: "WWW.example.com" }],
    ["a hostname with a brace", { hostname: "www.example.com{" }],
    ["an IP hostname", { hostname: "1.2.3.4" }],
    ["a non-tailnet target", { ip: "172.17.0.2" }],
    ["a reserved tailnet address", { ip: "100.100.100.100" }],
    ["a non-canonical IPv6 target", { ip: "fd7a:115c:a1e0:0::103" }],
    ["a target with a port", { ip: "100.101.102.103:3000" }],
    ["port 0", { port: 0 }],
    ["port 65536", { port: 65536 }],
    ["no StableID", { stableId: "" }],
    ["a bypass path with a space", { bypassPaths: ["/hooks x"] }],
    ["a relative bypass path", { bypassPaths: ["hooks/*"] }],
    ["a bypass path with ..", { bypassPaths: ["/a/../b"] }],
    ["a bypass path with a brace", { bypassPaths: ["/a{b}"] }],
    ["a redirect to itself", { redirectTo: "www.example.com" }],
    ["a redirect with a path", { redirectTo: "example.com/x" }],
    ["a non-tailnet internal address", { internalIps: ["10.0.0.1"] }],
    ["invalid options", { options: { maxBodyMb: -1 } }],
  ])("refuses %s", (_name, change) => {
    expect(() => checkedHttpRoute({ ...www, ...change })).toThrow(ValidationError);
    expect(() => render([{ ...www, ...change }], ["www.example.com"])).toThrow(ValidationError);
  });

  test("accepts §3.5 bypass paths and normalises internal names", () => {
    const checked = checkedHttpRoute({ ...www, bypassPaths: ["/webhooks/*", "/api/v1.2/~x-y_z"] });
    expect(checked.internalNames).toEqual(["home", "home.tail1234.ts.net"]);
    expect(checked.internalIps.map((ip) => ip.canonical)).toEqual([
      "100.101.102.103",
      "fd7a:115c:a1e0::6465:6667",
    ]);
    // Names that cannot form an authority are dropped, never rendered.
    expect(
      checkedHttpRoute({ ...www, internalNames: ["Bob's Mac", "x\ny", "100.1.2.3"] }).internalNames,
    ).toEqual([]);
  });
});

describe("rendered site blocks (§3.5 example)", () => {
  const caddyfile = render([www, apex]);
  const proxy = site(caddyfile, "www.example.com")!;
  const redirect = site(caddyfile, "example.com")!;

  test("the shared snippets follow the global block once", () => {
    expect(caddyfile.startsWith(`${CADDY_GLOBAL_BLOCK}\n\n(ark_route_base) {`)).toBe(true);
    expect(caddyfile.match(/^\(ark_route_base\) \{$/gm)).toHaveLength(1);
    expect(caddyfile.match(/^\(ark_upstream\) \{$/gm)).toHaveLength(1);
    const snippet = caddyfile.slice(caddyfile.indexOf("(ark_route_base)"), caddyfile.indexOf(":80 {"));
    for (const line of [
      "    -Server",
      "    -Via",
      "    -X-Powered-By",
      "    X-Content-Type-Options nosniff",
      "    Referrer-Policy strict-origin-when-cross-origin",
      "    defer",
      "  request_header -X-Ark-*",
      "  handle_errors 502 503 504 {",
      `    root * ${EDGE_ERRORS_DIR}`,
      "    rewrite * /{err.status_code}.html",
      '  header_up Cookie "(^|;\\s*)__Host-ark_gate[^;]*" ""',
      '  header_up Cookie "^;\\s*" ""',
      "  header_down -Server",
      '  header_down Set-Cookie "(?i);\\s*domain=[^;]*" ""',
      "  flush_interval -1",
    ]) {
      expect(snippet).toContain(`${line}\n`);
    }
    // No `header_up -X-Ark-*` upstream: on SSO routes it would strip the forward_auth identity.
    expect(snippet).not.toContain("header_up -X-Ark");
  });

  test("a proxying route: loopback bind, Ark certificate, no-leak headers, limits and timeouts", () => {
    expect(caddyfile).toContain(
      "# rt_k3x9 www.example.com: public access\n# ark-tailnet-route rt_k3x9 100.101.102.103:3000\nwww.example.com {\n",
    );
    expect(proxy).toStartWith(
      "www.example.com {\n  bind 127.0.0.1\n  tls /var/lib/ark/certs/www.example.com/fullchain.pem /var/lib/ark/certs/www.example.com/privkey.pem\n  import ark_route_base\n",
    );
    for (const line of [
      '  header Strict-Transport-Security "max-age=31536000"',
      "    max_size 25MB",
      "  handle /.ark/gate/* {",
      `    vars ark_tailnet_route ${routeIdentityKey(www)}`,
      "    reverse_proxy 100.101.102.103:3000 {",
      "      import ark_upstream",
      "      stream_close_delay 5m",
      "        dial_timeout 5s",
      "        response_header_timeout 60s",
      "        keepalive 90s",
      "      header_down -Location",
      "      @ark_location header Location *",
      "          header Location {rp.header.Location}",
      "          copy_response",
    ]) {
      expect(proxy).toContain(`${line}\n`);
    }
    expect(proxy).not.toContain("stream_timeout");
    expect(proxy).not.toContain("forward_auth");
    expect(proxy).not.toContain("header_up Host");
    // Rejects run before the value is copied, in the documented order.
    const order = ["malformed", "scheme", "internal", "suffix"].map((name) =>
      proxy.indexOf(`error @ark_location_${name} 502`),
    );
    expect(order.every((index, i) => index > 0 && (i === 0 || index > order[i - 1]!))).toBe(true);
    expect(order.at(-1)!).toBeLessThan(proxy.indexOf("header Location {rp.header.Location}"));
  });

  test("the apex route redirects to www with HSTS and nothing else", () => {
    expect(caddyfile).toContain(
      "# rt_a1b2 example.com: canonical redirect to www.example.com\nexample.com {\n",
    );
    expect(redirect).toBe(
      'example.com {\n  bind 127.0.0.1\n  tls /var/lib/ark/certs/example.com/fullchain.pem /var/lib/ark/certs/example.com/privkey.pem\n  import ark_route_base\n  header Strict-Transport-Security "max-age=31536000"\n  redir https://www.example.com{uri} 308\n}\n',
    );
    expect(caddyfile).not.toContain("# ark-tailnet-route rt_a1b2");
  });

  test(":80 redirects exactly the served route hostnames", () => {
    expect(site(caddyfile, ":80")).toContain("  @known host www.example.com example.com\n");
  });

  test("per-route options are rendered", () => {
    const tuned = render([
      {
        ...www,
        options: {
          maxBodyMb: 1,
          hsts: false,
          upstreamHost: "target",
          responseHeaderTimeout: "5s",
          streamCloseDelay: "30s",
          streamTimeout: "2h",
          rewriteLocation: false,
        },
      },
    ]);
    const body = site(tuned, "www.example.com")!;
    expect(body).not.toContain("Strict-Transport-Security");
    for (const line of [
      "    max_size 1MB",
      "      header_up Host {upstream_hostport}",
      "      stream_close_delay 30s",
      "      stream_timeout 2h",
      "        response_header_timeout 5s",
    ]) {
      expect(body).toContain(`${line}\n`);
    }
    // Without rewriting, internal authorities are not passed through: they get the 502.
    expect(body).not.toContain("https://www.example.com${1}");
    const plain = locationPolicy(checkedHttpRoute({ ...www, options: { rewriteLocation: false } }));
    expect(plain.rewrite).toBeNull();
    for (const location of ["//home.tail1234.ts.net/x", "http://100.101.102.103:3000/", "//home/x"])
      expect(evaluateLocation(plain, location)).toMatchObject({ status: 502 });
    expect(evaluateLocation(plain, "/x")).toEqual({ location: "/x" });
  });

  test("the launch guard opens for allowed routes and the closed variant renders no route", () => {
    expect(launchDecision(caddyfile, new Set([routeIdentityKey(www)])).open).toBe(true);
    expect(launchDecision(caddyfile, new Set()).open).toBe(false);
    // Only the pinned backend is a tailnet dial; the Location regexes never read as one.
    expect(launchDecision(caddyfile, new Set([routeIdentityKey(www)])).backends).toEqual([
      "100.101.102.103:3000",
    ]);
    const closed = renderCaddyfile({
      ...base,
      adminMode: "tailnet",
      certificates: issued("www.example.com"),
    });
    expect(closed).not.toContain("ark_route_base");
    expect(closed).not.toContain("100.101.102.103");
  });

  test("an IPv6 target dials its bracketed address", () => {
    const v6 = render([{ ...www, ip: "fd7a:115c:a1e0::6465:6667", internalIps: ["100.101.102.103"] }]);
    expect(v6).toContain("    reverse_proxy [fd7a:115c:a1e0::6465:6667]:3000 {\n");
    expect(
      launchDecision(v6, new Set([routeIdentityKey({ ...www, ip: "fd7a:115c:a1e0::6465:6667" })])).open,
    ).toBe(true);
  });

  test("duplicate route ids are refused", () => {
    expect(() => render([www, { ...www, hostname: "two.example.com" }])).toThrow(/more than once/);
  });
});

describe("fail closed on unimplemented access modes (FD-11 not shipped)", () => {
  const sso: EdgeHttpRoute = { ...www, id: "rt_sso1", hostname: "sso.example.com", access: "sso" };

  test("planEdge omits an enabled SSO route and never asks for its certificate", () => {
    const plan = planEdge({ adminMode: "tailnet", endpoints: [], certificates: [], httpRoutes: [www, sso] });
    expect(plan.httpRoutes.map((route) => route.id)).toEqual(["rt_k3x9"]);
    expect(plan.omitted).toEqual([
      { id: "rt_sso1", hostname: "sso.example.com", reason: expect.stringMatching(/access mode "sso"/) },
    ]);
    expect(plan.awaitingCertificate).toEqual(["www.example.com"]);
  });

  test("renderCaddyfile refuses it outright", () => {
    expect(() => render([www, sso])).toThrow(/cannot serve/);
  });
});

describe("Location policy (§3.5 fixtures)", () => {
  const policy = locationPolicy(checkedHttpRoute(www));
  const outcome = (location: string) => {
    const result = evaluateLocation(policy, location);
    return "status" in result ? 502 : result.location;
  };

  test.each<[string, string | 502]>([
    // Acceptance fixtures: MagicDNS name, IPv4 with a query and no path, IPv6 forms, ports, authority-only.
    ["//home.tail1234.ts.net/login", "https://www.example.com/login"],
    ["//100.101.102.103?x=1", "https://www.example.com?x=1"],
    ["http://[fd7a:115c:a1e0::6465:6667]/v6", "https://www.example.com/v6"],
    ["http://[fd7a:115c:a1e0:0:0:0:6465:6667]:3000/v6", "https://www.example.com/v6"],
    ["http://[FD7A:115C:A1E0:0000:0000:0000:6465:6667]#top", "https://www.example.com#top"],
    ["http://100.101.102.103:3000", "https://www.example.com"],
    ["https://home.tail1234.ts.net.:3000", "https://www.example.com"],
    ["//home.tail1234.ts.net", "https://www.example.com"],
    ["http://home/x?y#z", "https://www.example.com/x?y#z"],
    ["HTTP://HOME.TAIL1234.TS.NET/Case", "https://www.example.com/Case"],
    ["http://100.101.102.103:3000/next?x=1#frag", "https://www.example.com/next?x=1#frag"],
    // Untouched: relative, query-only, fragment-only, public absolute URLs, non-authority schemes.
    ["/login", "/login"],
    ["/", "/"],
    ["", ""],
    ["?page=2", "?page=2"],
    ["#section", "#section"],
    ["next/page", "next/page"],
    ["https://www.example.com/self", "https://www.example.com/self"],
    ["https://accounts.example.net/oauth?client=1", "https://accounts.example.net/oauth?client=1"],
    ["//cdn.example.org/x", "//cdn.example.org/x"],
    ["https://www.example.com:8443/x", "https://www.example.com:8443/x"],
    ["mailto:ops@example.com", "mailto:ops@example.com"],
    ["com.example.app:/callback", "com.example.app:/callback"],
    // Known authority on another port: a different service, never passed through.
    ["http://100.101.102.103:8080/x", 502],
    ["//home.tail1234.ts.net:22/", 502],
    // Unsupported IPv6 text forms and other tailnet machines.
    ["http://[fd7a:115c:a1e0:0::6465:6667]/", 502],
    ["http://[fd7a:115c:a1e0::6465:6667%25eth0]/", 502],
    ["http://[::ffff:100.101.102.103]/", 502],
    ["http://100.88.1.20/", 502],
    ["https://nas.tail1234.ts.net/", 502],
    ["https://evil.ts.net/", 502],
    // IPv4 forms browsers normalise to the target.
    ["//1684366951/", 502],
    ["//100.101.102.0x67/", 502],
    ["//0x64.0x65.0x66.0x67/", 502],
    ["//100.101.102.103./", 502],
    ["//100.101.102.0103/", 502],
    // Malformed or ambiguous authorities.
    ["https://user@www.example.com/", 502],
    ["https://www.example.com@100.101.102.103/", 502],
    ["///evil.example.net/", 502],
    ["/\\evil.example.net", 502],
    ["\\\\evil.example.net", 502],
    ["/\t/evil.example.net", 502],
    ["http://evil.example.net\t/", 502],
    ["//localhost/", 502],
    ["//bücher.example/", 502],
    ["//www.example.com%2F@evil/", 502],
    ["http:evil.example.net", 502],
    ["https:/x", 502],
    ["https:///x", 502],
    ["ws://100.101.102.103/", 502],
    ["ftp://files.example.net/", 502],
    // Internal tokens after the authority or in relative URLs.
    ["https://www.example.com/?next=http://100.101.102.103/", 502],
    ["//100.101.102.103/x?next=//home.tail1234.ts.net/", 502],
    ["/login?next=http%3A%2F%2Fhome.tail1234.ts.net%2F", 502],
    ["/go?to=100.64.0.1", 502],
    ["/go?to=fd7a:115c:a1e0::1", 502],
    // Repeated upstream values arrive joined with "," and are checked as one value.
    ["/ok,//100.88.1.20/", 502],
    ["//100.101.102.103/a,/b", "https://www.example.com/a,/b"],
  ])("%p -> %p", (location, expected) => {
    expect(outcome(location)).toBe(expected);
  });

  test("no outcome ever names a known internal authority", () => {
    const internal = /100\.101\.102\.103|home\.tail1234|fd7a|ts\.net|6465:6667/i;
    const seeds = [
      "//home.tail1234.ts.net",
      "//100.101.102.103",
      "http://[fd7a:115c:a1e0::6465:6667]",
      "https://HOME.tail1234.ts.net.",
      "//home",
    ];
    const suffixes = ["", "/", "?x=1", "#f", ":3000", ":3000/p?q#f", ":9", "/a/b?c=d&e", ":", ".", "@x"];
    for (const seed of seeds) {
      for (const suffix of suffixes) {
        const result = outcome(`${seed}${suffix}`);
        if (result !== 502) expect(result).not.toMatch(internal);
      }
    }
  });

  test("patterns contain no Caddyfile placeholder braces", () => {
    const sources = [
      policy.rewrite!.pattern,
      ...policy.rejects.flatMap((reject) => [reject.match ?? "", reject.notMatch ?? ""]),
    ];
    for (const source of sources) expect(source).not.toMatch(/[{}]/);
  });
});

// ---- Injection fuzz -----------------------------------------------------------------------------------------

/** Deterministic PRNG so a failure reproduces. */
function prng(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 2 ** 32;
  };
}

const PAYLOADS = [
  "\n}\nINJECTED {\n  respond pwned\n}\n",
  '" INJECTED "',
  "`INJECTED`",
  "{$INJECTED}",
  "{env.INJECTED}",
  "} INJECTED {",
  "\r\nINJECTED",
  " import INJECTED",
  "# INJECTED",
  "\\\nINJECTED",
  "\u0000INJECTED",
  "\tINJECTED",
  ";INJECTED",
  "/INJECTED*",
];

describe("injection fuzz (§3.5)", () => {
  const random = prng(0xf009);
  const pick = <T>(items: readonly T[]) => items[Math.floor(random() * items.length)]!;
  const mutate = (value: string) => {
    const payload = pick(PAYLOADS);
    const at = Math.floor(random() * (value.length + 1));
    return value.slice(0, at) + payload + value.slice(at);
  };

  type Field = (route: EdgeHttpRoute) => EdgeHttpRoute;
  const fields: Record<string, Field> = {
    id: (route) => ({ ...route, id: mutate(route.id) }),
    hostname: (route) => ({ ...route, hostname: mutate(route.hostname) }),
    stableId: (route) => ({ ...route, stableId: mutate(route.stableId) }),
    ip: (route) => ({ ...route, ip: mutate(route.ip) }),
    access: (route) => ({ ...route, access: mutate(route.access) as "public" }),
    redirectTo: (route) => ({ ...route, redirectTo: mutate("www.example.net") }),
    bypassPaths: (route) => ({ ...route, bypassPaths: [mutate("/webhooks/*")] }),
    internalNames: (route) => ({ ...route, internalNames: [mutate("home.tail1234.ts.net")] }),
    internalIps: (route) => ({ ...route, internalIps: [mutate("fd7a:115c:a1e0::1")] }),
    responseHeaderTimeout: (route) => ({ ...route, options: { responseHeaderTimeout: mutate("60s") } }),
    streamCloseDelay: (route) => ({ ...route, options: { streamCloseDelay: mutate("5m") } }),
    streamTimeout: (route) => ({ ...route, options: { streamTimeout: mutate("1h") } }),
    upstreamHost: (route) => ({ ...route, options: { upstreamHost: mutate("public") as "public" } }),
    maxBodyMb: (route) => ({ ...route, options: { maxBodyMb: mutate("25") as unknown as number } }),
    port: (route) => ({
      ...route,
      port: pick([Number.NaN, Number.POSITIVE_INFINITY, -1, 3000.5, mutate("3000")]) as number,
    }),
  };
  const ROUNDS = 200;

  for (const [name, field] of Object.entries(fields)) {
    test(`${name}: ${ROUNDS} mutations either fail validation or render nothing injected`, () => {
      let rendered = 0;
      for (let round = 0; round < ROUNDS; round++) {
        const route = field(random() < 0.5 ? www : { ...apex });
        let caddyfile: string;
        try {
          caddyfile = renderCaddyfile({
            ...base,
            adminMode: "tailnet",
            // Certificates use the plain hostname: a mutated one never gets a site (nor reaches tls).
            certificates: issued(www.hostname, apex.hostname),
            httpRoutes: [route],
          });
        } catch (error) {
          expect(error).toBeInstanceOf(ValidationError);
          continue;
        }
        rendered++;
        expect(caddyfile).not.toContain("INJECTED");
        expect(caddyfile).not.toMatch(/\{\$|\{env\./);
        expect(caddyfile.includes("\u0000") || caddyfile.includes("\r")).toBe(false);
        // Braces stay balanced outside quoted tokens, so no block can be closed or opened early.
        let depth = 0;
        for (const line of caddyfile.split("\n")) {
          const unquoted = line.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/\{[a-z_.$>*0-9]+\}/gi, "");
          for (const char of unquoted) {
            if (char === "{") depth++;
            if (char === "}") depth--;
            expect(depth).toBeGreaterThanOrEqual(0);
          }
        }
        expect(depth).toBe(0);
      }
      // Fields whose bad values are dropped rather than refused must still render.
      if (name === "internalNames") expect(rendered).toBe(ROUNDS);
    });
  }
});
