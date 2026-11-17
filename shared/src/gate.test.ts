// FD-11 (docs/design/front-door.md §3.9.3-§3.9.5): return-path validation, the raw-URI bypass guard,
// bypass-path validation, the WebSocket Origin and unsafe-method CSRF contract, and the revocation
// deadline applied to the edge lease.
import { describe, expect, test } from "bun:test";

import { caddyLongLivedStreams, routeIdentityKey } from "./edge-withdrawal.ts";
import { ValidationError } from "./errors.ts";
import {
  GATE_REVOCATION_DEADLINE_MS,
  bypassMatches,
  checkAllowedOrigins,
  checkBypassPaths,
  checkLoginNext,
  checkRawRequestUri,
  checkReturnPath,
  gateOriginDecision,
  gateWantsRedirect,
  parseCookies,
  routesAfterRevocations,
} from "./gate.ts";

describe("rd return path (no open redirect)", () => {
  test.each(["/", "/dashboard", "/a/b?x=1&y=%2F#frag", "/%2F%2Fevil.com", "/.well-known/x"])(
    "accepts %p",
    (rd) => expect(checkReturnPath(rd)).toBe(rd),
  );

  test.each([
    "//evil.com",
    "https://evil.com",
    "/\\evil.com",
    "\\\\evil.com",
    "/ok\r\nSet-Cookie: x=1",
    "/ok\nx",
    "/ok\u0000",
    "evil.com",
    "",
    `/${"a".repeat(2048)}`,
  ])("refuses %p", (rd) => expect(() => checkReturnPath(rd)).toThrow(ValidationError));

  test("next on the login page is only a relative /gate/authorize path", () => {
    expect(checkLoginNext("/gate/authorize?route=rt_a&state=s&rd=%2F")).toBe(
      "/gate/authorize?route=rt_a&state=s&rd=%2F",
    );
    for (const next of ["https://evil.com/gate/authorize?x", "//evil.com", "/gate/login", "/gate/authorize"])
      expect(checkLoginNext(next)).toBeNull();
  });
});

describe("raw request URI guard (§3.9.5)", () => {
  test.each([
    ["/webhooks/github", "/webhooks/github"],
    ["/webhooks/github?sig=a%2Fb;c", "/webhooks/github"],
    ["/webhooks/%61bc", "/webhooks/abc"],
    ["/webhooks/", "/webhooks/"],
  ])("accepts %p", (uri, path) => expect(checkRawRequestUri(uri)).toEqual({ ok: true, path }));

  test.each([
    "/webhooks/..;/admin",
    "/webhooks/..%3b/admin",
    "/webhooks/..%3B/admin",
    "/webhooks/../admin",
    "/webhooks/./admin",
    "/webhooks/x;y",
    "/webhooks\\..\\admin",
    "/webhooks/..\\admin",
    "/webhooks/%2e%2e/admin",
    "/webhooks/%2E%2E/admin",
    "/webhooks/.%2e/admin",
    "/webhooks%2f..%2fadmin",
    "/webhooks/%5c..%5cadmin",
    "/webhooks/%5C",
    "/webhooks/%252e%252e/admin",
    "/webhooks/%25252e",
    "/webhooks/%2",
    "/webhooks/%zz",
    "/webhooks/%",
    "/webhooks/x?a=%g1",
    "/webhooks//admin",
    "/webhooks/café",
    "/webhooks/a b",
    "/webhooks/%00",
    "webhooks/x",
    "",
  ])("refuses %p", (uri) => expect(checkRawRequestUri(uri).ok).toBe(false));

  test("bypass matching is a case-sensitive prefix or exact match", () => {
    expect(bypassMatches("/webhooks/a", ["/webhooks/*"])).toBe(true);
    expect(bypassMatches("/WEBHOOKS/a", ["/webhooks/*"])).toBe(false);
    expect(bypassMatches("/hook", ["/hook"])).toBe(true);
    expect(bypassMatches("/hook/x", ["/hook"])).toBe(false);
    expect(bypassMatches("/admin", ["/webhooks/*"])).toBe(false);
  });
});

describe("bypass paths", () => {
  test("valid paths are kept once", () => {
    expect(checkBypassPaths(["/webhooks/*", "/hook", "/webhooks/*", "/api/v1/public*"])).toEqual([
      "/webhooks/*",
      "/hook",
      "/api/v1/public*",
    ]);
  });

  test.each([
    "/",
    "/*",
    "*",
    "",
    "/.ark/gate/*",
    "/.ark/gate/callback",
    "/.ark",
    "/.ark*",
    "/.a*",
    "/.*",
    "/webhooks/../admin",
    "/./x",
    "/web hooks",
    "/webhooks/*/x",
    "/x{y}",
    "webhooks",
  ])("refuses %p", (path) => expect(() => checkBypassPaths([path])).toThrow(ValidationError));

  test("at most 32", () => {
    expect(() => checkBypassPaths(Array.from({ length: 33 }, (_, i) => `/p${i}`))).toThrow(/32/);
  });
});

describe("Origin and CSRF contract (§3.9.4)", () => {
  const routeHost = "b.example.com";
  const decide = (
    method: string,
    origin: string | null,
    upgrade: string | null = null,
    allowed: string[] = [],
  ) => gateOriginDecision({ method, origin, upgrade, routeHost, allowedOrigins: allowed }).ok;

  test("a route can open a WebSocket to itself; a sibling route cannot", () => {
    expect(decide("GET", "https://b.example.com", "websocket")).toBe(true);
    expect(decide("GET", "https://B.Example.com", "websocket")).toBe(true);
    expect(decide("GET", "https://a.example.com", "websocket")).toBe(false);
  });

  test("missing, null, suffix, http and port-shifted origins are refused for upgrades", () => {
    for (const origin of [
      null,
      "",
      "null",
      "https://evil-b.example.com",
      "https://b.example.com.evil.com",
      "http://b.example.com",
      "https://b.example.com:8443",
      "https://example.com",
    ])
      expect(decide("GET", origin, "websocket")).toBe(false);
  });

  test("explicit owner-approved exceptions work", () => {
    const allowed = checkAllowedOrigins(["https://a.example.com"]);
    expect(decide("GET", "https://a.example.com", "websocket", allowed)).toBe(true);
    expect(decide("POST", "https://a.example.com", null, allowed)).toBe(true);
    expect(decide("POST", "https://c.example.com", null, allowed)).toBe(false);
  });

  test("unsafe methods need the Origin; safe methods do not", () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "TRACE", "PROPFIND"]) {
      expect(decide(method, null)).toBe(false);
      expect(decide(method, "null")).toBe(false);
      expect(decide(method, "https://a.example.com")).toBe(false);
      expect(decide(method, "https://b.example.com")).toBe(true);
    }
    for (const method of ["GET", "HEAD", "OPTIONS"]) expect(decide(method, null)).toBe(true);
  });

  test("origin exceptions are normalised https origins only", () => {
    expect(
      checkAllowedOrigins([
        "HTTPS://A.example.com:443",
        "https://a.example.com",
        "https://x.example.com:8443",
      ]),
    ).toEqual(["https://a.example.com", "https://x.example.com:8443"]);
    for (const origin of [
      "http://a.example.com",
      "https://a.example.com/",
      "https://*.example.com",
      "null",
      "a.example.com",
    ])
      expect(() => checkAllowedOrigins([origin])).toThrow(ValidationError);
  });
});

describe("check redirect or 401", () => {
  test("only HTML GET/HEAD navigations redirect; XHR and upgrades get 401", () => {
    expect(gateWantsRedirect({ method: "GET", accept: "text/html,application/xhtml+xml" })).toBe(true);
    expect(gateWantsRedirect({ method: "HEAD", accept: "text/html" })).toBe(true);
    expect(gateWantsRedirect({ method: "GET", accept: "application/json" })).toBe(false);
    expect(gateWantsRedirect({ method: "GET", accept: "*/*" })).toBe(false);
    expect(gateWantsRedirect({ method: "POST", accept: "text/html" })).toBe(false);
    expect(gateWantsRedirect({ method: "GET", accept: "text/html", upgrade: "websocket" })).toBe(false);
    expect(gateWantsRedirect({ method: "GET", accept: "text/htmlx" })).toBe(false);
  });

  test("cookies keep duplicates so they can be refused", () => {
    expect(parseCookies("a=1; __Host-ark_gate=x; __Host-ark_gate=y").get("__Host-ark_gate")).toEqual([
      "x",
      "y",
    ]);
  });
});

const identity = (id: string, port: number) =>
  routeIdentityKey({ id, hostname: `${id}.example.com`, stableId: "n1", ip: "100.64.0.9", port });

describe("revocation deadline (§3.9.3)", () => {
  const routes = [{ id: "rt_a" }, { id: "rt_b" }];
  const now = new Date("2026-11-17T12:00:00Z");
  const at = (ms: number) => new Date(now.getTime() - ms).toISOString();

  test("a pending revocation within 5 s changes nothing; an overdue one withdraws its route", () => {
    expect(
      routesAfterRevocations(
        routes,
        [{ id: "r1", routeId: "rt_a", createdAt: at(GATE_REVOCATION_DEADLINE_MS) }],
        now,
      ),
    ).toEqual({ routes, overdue: [] });
    expect(
      routesAfterRevocations(
        routes,
        [{ id: "r1", routeId: "rt_a", createdAt: at(GATE_REVOCATION_DEADLINE_MS + 1) }],
        now,
      ),
    ).toEqual({ routes: [{ id: "rt_b" }], overdue: ["rt_a"] });
  });

  test("handlers of revoked routes whose streams outlive 5m are found for the Caddy stop", () => {
    const config = {
      apps: {
        http: {
          servers: {
            s: {
              routes: [
                {
                  handle: [
                    { handler: "vars", ark_tailnet_route: identity("rt_a", 3000) },
                    { handler: "reverse_proxy", upstreams: [{ dial: "api:3000" }] },
                    {
                      handler: "reverse_proxy",
                      stream_close_delay: 3_600_000_000_000,
                      upstreams: [{ dial: "100.64.0.9:3000" }],
                    },
                  ],
                },
                {
                  handle: [
                    { handler: "vars", ark_tailnet_route: identity("rt_b", 3001) },
                    {
                      handler: "reverse_proxy",
                      stream_close_delay: 300_000_000_000,
                      upstreams: [{ dial: "100.64.0.9:3001" }],
                    },
                  ],
                },
              ],
            },
          },
        },
      },
    };
    expect(caddyLongLivedStreams(config, new Set(["rt_a", "rt_b"]), 300_000)).toEqual(["100.64.0.9:3000"]);
    expect(caddyLongLivedStreams(config, new Set(["rt_b"]), 300_000)).toEqual([]);
  });
});

/** Caddy `path` semantics for the allowlists: exact, or a prefix when the pattern ends with `*`. */
const matches = (pattern: string, path: string) =>
  pattern.endsWith("*") ? path.startsWith(pattern.slice(0, -1)) : pattern === path;
const allowlists = (caddyfile: string) =>
  [...caddyfile.matchAll(/^\s*@(?:browserApi|adminAuth|gateApi) path (.+)$/gm)].flatMap((match) =>
    match[1]!.trim().split(/\s+/),
  );

describe("edge-only handlers are on no public or tailnet allowlist (§3.3, §3.9.4)", () => {
  test("the public admin site, the login origin and the tailnet gateway never forward /api/gate/*", async () => {
    const { renderCaddyfile } = await import("./edge.ts");
    const { GATE_EDGE_API_PATHS } = await import("./gate.ts");
    const rendered = renderCaddyfile({
      adminMode: "public",
      adminHostname: "admin.example.com",
      challengeDir: "/var/lib/ark/acme",
      apiUpstream: "api:3000",
      gate: { hostname: "login.example.com" },
      certificates: ["admin.example.com", "login.example.com"].map((hostname) => ({
        hostname,
        status: "issued",
        fullchain: `/c/${hostname}.pem`,
        privkey: `/k/${hostname}.pem`,
      })),
    });
    const tailnet = await Bun.file(new URL("../../infra/platform/TailnetCaddyfile", import.meta.url)).text();
    for (const [name, caddyfile] of [
      ["public edge", rendered],
      ["tailnet gateway", tailnet],
    ] as const) {
      const patterns = allowlists(caddyfile);
      expect(patterns.length, name).toBeGreaterThan(5);
      for (const path of [...GATE_EDGE_API_PATHS, "/api/gate/users"])
        expect(
          patterns.filter((pattern) => matches(pattern, path)),
          `${name} ${path}`,
        ).toEqual([]);
    }
  });
});
