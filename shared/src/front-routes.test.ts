import { describe, expect, test } from "bun:test";
import { join } from "node:path";

import { aaaaAllowed, routeAddressRecords } from "./dns-plan.ts";
import { renderCaddyfile } from "./edge.ts";
import {
  ROUTE_RECORD_PURPOSE,
  UnsupportedRouteError,
  assertSupportedAccessMode,
  assertSupportedRouteKind,
  frontRouteCreateInput,
  frontRouteUpdateInput,
  looseningChanges,
  normalizeRedirectTo,
  normalizeRouteHostname,
  routeDomainFor,
} from "./front-routes.ts";

const base = {
  zone: "example.com",
  publicIpv4: "203.0.113.10",
  publicIpv6: "2001:db8::10",
  purpose: ROUTE_RECORD_PURPOSE,
};

describe("route address records (§3.13.1)", () => {
  test("apex and www both get an A record with the right relative name", () => {
    for (const [hostname, relative] of [
      ["example.com", "@"],
      ["www.example.com", "www"],
      ["app.eu.example.com", "app.eu"],
    ] as const) {
      const records = routeAddressRecords({ ...base, hostname, ipv6Status: "unchecked", aaaaEnabled: true });
      expect(records).toEqual([
        {
          type: "A",
          name: hostname,
          relativeName: relative,
          value: "203.0.113.10",
          ttl: 300,
          purpose: ROUTE_RECORD_PURPOSE,
          required: true,
        },
      ]);
    }
  });

  test("AAAA only when the IPv6 preflight passed and the domain switch is on; then it is required", () => {
    const cases: Array<[string, boolean, string | null, boolean]> = [
      ["passed", true, "2001:db8::10", true],
      ["passed", false, "2001:db8::10", false],
      ["unchecked", true, "2001:db8::10", false],
      ["failed", true, "2001:db8::10", false],
      ["not_present", true, "2001:db8::10", false],
      ["passed", true, null, false],
    ];
    for (const [ipv6Status, aaaaEnabled, publicIpv6, expected] of cases) {
      expect(aaaaAllowed({ ipv6Status, aaaaEnabled, publicIpv6 })).toBe(expected);
      const records = routeAddressRecords({
        ...base,
        publicIpv6,
        hostname: "www.example.com",
        ipv6Status,
        aaaaEnabled,
      });
      const aaaa = records.find((record) => record.type === "AAAA");
      expect([ipv6Status, aaaaEnabled, publicIpv6, Boolean(aaaa)]).toEqual([
        ipv6Status,
        aaaaEnabled,
        publicIpv6,
        expected,
      ]);
      if (aaaa) expect(aaaa).toMatchObject({ value: "2001:db8::10", required: true, relativeName: "www" });
    }
  });

  test("a hostname outside the zone is refused", () => {
    expect(() =>
      routeAddressRecords({ ...base, hostname: "www.example.org", ipv6Status: "passed", aaaaEnabled: true }),
    ).toThrow(/not inside/);
  });
});

describe("route request policy", () => {
  test("http, tls and tcp routes can be created; postgres waits for FD-26", () => {
    expect(assertSupportedRouteKind(undefined)).toBe("http");
    for (const kind of ["http", "tls", "tcp"] as const) expect(assertSupportedRouteKind(kind)).toBe(kind);
    for (const kind of ["postgres", "udp"]) {
      expect(() => assertSupportedRouteKind(kind)).toThrow(UnsupportedRouteError);
    }
  });

  test("sso and the omitted (schema default sso) mode are refused until FD-11", () => {
    expect(() => assertSupportedAccessMode("public", "create")).not.toThrow();
    expect(() => assertSupportedAccessMode(undefined, "create")).toThrow(/accessMode is required.*"sso"/);
    expect(() => assertSupportedAccessMode("sso", "create")).toThrow(/not supported yet.*FD-11/);
    expect(() => assertSupportedAccessMode("sso", "enable")).toThrow(/cannot be enabled/);
    expect(() => assertSupportedAccessMode("sso", "update")).toThrow(UnsupportedRouteError);
  });

  test("hostnames: normalized, and tailnet names refused", () => {
    expect(normalizeRouteHostname("WWW.Example.COM.")).toBe("www.example.com");
    expect(() => normalizeRouteHostname("home.tail1234.ts.net")).toThrow(/ts\.net/);
    expect(() => normalizeRouteHostname("localhost")).toThrow();
  });

  test("the most specific domain claim wins; nothing outside a claim matches", () => {
    const claims = [
      { id: "d1", name: "example.com", status: "verified" },
      { id: "d2", name: "eu.example.com", status: "draft" },
    ];
    expect(routeDomainFor("example.com", claims)?.id).toBe("d1");
    expect(routeDomainFor("www.example.com", claims)?.id).toBe("d1");
    expect(routeDomainFor("app.eu.example.com", claims)?.id).toBe("d2");
    expect(routeDomainFor("badexample.com", claims)).toBeNull();
    expect(routeDomainFor("example.org", claims)).toBeNull();
  });

  test("redirectTo stays inside the domain and differs from the route", () => {
    const route = { hostname: "example.com", zone: "example.com" };
    expect(normalizeRedirectTo("WWW.example.com", route)).toBe("www.example.com");
    expect(() => normalizeRedirectTo("example.com", route)).toThrow(/different/);
    expect(() => normalizeRedirectTo("www.evil.com", route)).toThrow(/inside the route's domain/);
  });

  test("schemas are strict and require an explicit change", () => {
    expect(() =>
      frontRouteCreateInput.parse({ hostname: "a.example.com", target: "x", targetPort: 1, bypassPaths: [] }),
    ).toThrow();
    expect(() =>
      frontRouteCreateInput.parse({ hostname: "a.example.com", target: "x", targetPort: 0 }),
    ).toThrow();
    expect(() => frontRouteUpdateInput.parse({})).toThrow(/at least one/);
    expect(frontRouteUpdateInput.parse({ redirectTo: null })).toEqual({ redirectTo: null });
  });

  test("loosening: target, port, re-confirmation, sso -> public, removing a redirect, sensitive ports", () => {
    const current = {
      targetInput: "home.tail1234.ts.net",
      targetPort: 3000,
      accessMode: "public",
      redirectTo: "www.example.com",
      status: "ready",
    };
    expect(looseningChanges(current, { targetInput: "nas.tail1234.ts.net" })).toEqual(["target"]);
    expect(looseningChanges(current, { targetPort: 8080 })).toEqual(["targetPort"]);
    expect(looseningChanges(current, { targetInput: current.targetInput })).toEqual([]);
    expect(
      looseningChanges({ ...current, status: "identity_mismatch" }, { targetInput: current.targetInput }),
    ).toEqual(["reconfirmTarget"]);
    expect(looseningChanges({ ...current, accessMode: "sso" }, { accessMode: "public" })).toEqual([
      "accessMode",
    ]);
    expect(looseningChanges(current, { redirectTo: null })).toEqual(["redirectRemoved"]);
    expect(looseningChanges({ ...current, redirectTo: null }, { redirectTo: "www.example.com" })).toEqual([]);
    expect(looseningChanges(current, { redirectTo: "app.example.com" })).toEqual([]);
    expect(looseningChanges(current, { allowSensitivePort: true })).toEqual(["allowSensitivePort"]);
  });
});

/** Caddy `path` matcher semantics for the patterns used here: `*` matches any run of characters. */
const literal = (part: string) => part.replace(/[.+?^$(){}|[\]\\]/g, "\\$&");

function caddyPathMatches(patterns: string[], path: string) {
  return patterns.some((pattern) =>
    new RegExp(`^${pattern.split("*").map(literal).join(".*")}$`, "i").test(path),
  );
}

function matcher(caddyfile: string, name: string) {
  const line = caddyfile.split("\n").find((item) => item.trim().startsWith(`@${name} path `));
  if (!line) throw new Error(`@${name} matcher not found`);
  return line.trim().split(/\s+/).slice(2);
}

describe("admin path allowlists (§3.3)", () => {
  const routePaths = [
    "/api/front/routes",
    "/api/front/routes/rt_0123abcd",
    "/api/front/routes/rt_0123abcd/enable",
    "/api/front/routes/rt_0123abcd/disable",
    "/api/front/routes/rt_0123abcd/acl",
  ];
  const publicAdmin = renderCaddyfile({
    adminMode: "public",
    adminHostname: "admin.example.com",
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
    certificates: [
      {
        hostname: "admin.example.com",
        status: "issued",
        fullchain: "/var/lib/ark/certs/admin.example.com/fullchain.pem",
        privkey: "/var/lib/ark/certs/admin.example.com/privkey.pem",
      },
    ],
  });

  test("every route API path reaches the API through the public admin site and the tailnet gateway", async () => {
    const tailnetGateway = await Bun.file(
      join(import.meta.dir, "../../infra/platform/TailnetCaddyfile"),
    ).text();
    for (const [name, caddyfile] of [
      ["shared/src/edge.ts", publicAdmin],
      ["infra/platform/TailnetCaddyfile", tailnetGateway],
    ] as const) {
      const allowed = matcher(caddyfile, "browserApi");
      const internal = matcher(caddyfile, "internal");
      for (const path of routePaths) {
        expect([name, path, caddyPathMatches(allowed, path), caddyPathMatches(internal, path)]).toEqual([
          name,
          path,
          true,
          false,
        ]);
      }
      // Sanity check of the matcher: unknown API paths stay outside the allowlist.
      expect(caddyPathMatches(allowed, "/api/frontdoor")).toBe(false);
    }
  });
});
