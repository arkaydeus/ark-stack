// FD-23 (docs/design/front-door.md §5): HTTP route rate limits and HTTP mTLS, as rendered into the route
// site blocks. The runtime behaviour through HAProxy and the custom Caddy build is in
// scripts/test-edge-http-controls.ts.
import { describe, expect, test } from "bun:test";

import { edgeCertificatePaths, planEdge, renderCaddyfile, TAILNET_ROUTE_MARKER } from "./edge.ts";
import {
  HTTP_CLIENT_CERTIFICATE_LIMIT,
  checkedHttpRoute,
  httpRateLimit,
  httpRouteSiteBody,
  httpRouteTlsOptions,
  rateLimitPerSecond,
  type EdgeHttpRoute,
} from "./edge-http.ts";
import { ValidationError } from "./errors.ts";

const www: EdgeHttpRoute = {
  id: "rt_k3x9",
  hostname: "www.example.com",
  stableId: "nHOME",
  ip: "100.101.102.103",
  port: 3000,
  access: "public",
};
const der = (seed: number) => Buffer.alloc(300, seed).toString("base64");
const ca = der(1);
const leafA = der(2);
const leafB = der(3);

function render(routes: EdgeHttpRoute[]) {
  return renderCaddyfile({
    challengeDir: "/var/lib/ark/acme",
    apiUpstream: "api:3000",
    adminMode: "tailnet",
    certificates: routes.map((route) => ({
      hostname: route.hostname,
      status: "issued",
      ...edgeCertificatePaths(route.hostname),
    })),
    httpRoutes: routes,
  });
}

function site(caddyfile: string, address: string) {
  const start = caddyfile.indexOf(`\n${address} {\n`);
  const end = caddyfile.indexOf("\n}\n", start + 1);
  return caddyfile.slice(start + 1, end + 3);
}

describe("rate limit values (front_routes.rate_limit)", () => {
  test("accepts exact bounds and refuses everything else", () => {
    expect(httpRateLimit(null)).toBeNull();
    expect(httpRateLimit(undefined)).toBeNull();
    expect(httpRateLimit({ requests: 1, window: "1s" })).toEqual({ requests: 1, window: "1s" });
    expect(httpRateLimit({ requests: 100_000, window: "1h" })).toEqual({ requests: 100_000, window: "1h" });
    expect(httpRateLimit({ requests: 30, window: "3600s" })).toEqual({ requests: 30, window: "3600s" });
    for (const bad of [
      { requests: 0, window: "1m" },
      { requests: 100_001, window: "1m" },
      { requests: 1.5, window: "1m" },
      { requests: "10", window: "1m" },
      { requests: 10, window: "500ms" },
      { requests: 10, window: "2h" },
      { requests: 10, window: "0s" },
      { requests: 10, window: "1d" },
      { requests: 10, window: "1m}" },
      { requests: 10 },
      { requests: 10, window: "1m", key: "{http.request.header.X}" },
      [10, "1m"],
      "10/1m",
    ]) {
      expect(() => httpRateLimit(bad)).toThrow(ValidationError);
    }
  });

  test("compares sustained rates for the loosening check", () => {
    expect(rateLimitPerSecond({ requests: 60, window: "1m" })).toBe(1);
    expect(rateLimitPerSecond({ requests: 10, window: "1s" })).toBe(10);
    expect(rateLimitPerSecond(null)).toBe(Number.POSITIVE_INFINITY);
  });
});

describe("rendered rate limits", () => {
  test("routes without controls render exactly as before: no rate_limit, no 429 handler, a bare tls line", () => {
    const caddyfile = render([www, { ...www, id: "rt_sso1", hostname: "sso.example.com", access: "sso" }]);
    expect(caddyfile).not.toContain("rate_limit");
    expect(caddyfile).not.toContain("handle_errors 429");
    expect(caddyfile).not.toContain("client_auth");
    expect(site(caddyfile, "www.example.com")).toContain(
      "  tls /var/lib/ark/certs/www.example.com/fullchain.pem /var/lib/ark/certs/www.example.com/privkey.pem\n  import ark_route_base\n",
    );
    expect(caddyfile).toContain("# rt_k3x9 www.example.com: public access\n");
    expect(httpRouteTlsOptions(checkedHttpRoute(www))).toBe("");
  });

  test("a per-route zone keyed by the PROXY v2 client address, with a static 429 that hides Server", () => {
    const body = httpRouteSiteBody(checkedHttpRoute({ ...www, rateLimit: { requests: 20, window: "10s" } }));
    expect(body).toContain(`  rate_limit {
    zone ark_rt_k3x9 {
      key {remote_host}
      events 20
      window 10s
    }
  }
  handle_errors 429 {
    header -Server
    respond "Too many requests." 429
  }
`);
    // Site-level, so the plugin's registered order puts it before every handle and the upstream.
    expect(body.indexOf("rate_limit {")).toBeLessThan(body.indexOf("handle {"));
  });

  test("on an SSO route the limit is site-level, ahead of forward_auth and the gate handlers", () => {
    const body = httpRouteSiteBody(
      checkedHttpRoute({
        ...www,
        access: "sso",
        bypassPaths: ["/webhooks/*"],
        rateLimit: { requests: 5, window: "1m" },
      }),
    );
    expect(body.indexOf("  rate_limit {")).toBeLessThan(body.indexOf("  handle /.ark/gate/callback {"));
    expect(body.indexOf("  rate_limit {")).toBeLessThan(body.indexOf("forward_auth"));
    expect(body.match(/rate_limit \{/g)).toHaveLength(1);
  });

  test("a limited redirect runs the limit before the redirect in an explicit route block", () => {
    const body = httpRouteSiteBody(
      checkedHttpRoute({
        ...www,
        id: "rt_a1b2",
        hostname: "example.com",
        redirectTo: "www.example.com",
        rateLimit: { requests: 5, window: "10s" },
      }),
    );
    expect(body).toContain(`  route {
    rate_limit {
      zone ark_rt_a1b2 {`);
    expect(body).toContain("    redir https://www.example.com{uri} 308\n  }\n  handle_errors 429 {");
  });

  test("an invalid stored limit omits the route instead of serving it unlimited", () => {
    const plan = planEdge({
      adminMode: "tailnet",
      endpoints: [{ id: "end_www", kind: "route", hostname: www.hostname, exposure: "public" }],
      certificates: [{ endpointId: "end_www", status: "issued", lastDeployedAt: new Date() }],
      httpRoutes: [{ ...www, rateLimit: { requests: 0, window: "1m" } }],
    });
    expect(plan.httpRoutes).toEqual([]);
    expect(plan.omitted[0]?.reason).toContain("rateLimit.requests");
  });
});

describe("rendered HTTP mTLS (client_ca_id)", () => {
  test("requires and verifies a certificate from the route CA, then admits exactly the listed leaves", () => {
    const route = { ...www, clientAuth: { caCertificate: ca, certificates: [leafB, leafA, leafA] } };
    const caddyfile = render([route]);
    const block = site(caddyfile, "www.example.com");
    expect(block).toContain(
      `  tls /var/lib/ark/certs/www.example.com/fullchain.pem /var/lib/ark/certs/www.example.com/privkey.pem {
    client_auth {
      mode require_and_verify
      trust_pool inline {
        trust_der ${ca}
      }`,
    );
    // Duplicates collapse and the order is stable; each leaf is one quoted PEM token.
    const pems = [
      ...block.matchAll(
        / {8}pem "(-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----)"\n/g,
      ),
    ];
    expect(pems.map((match) => match[1]!.split("\n").slice(1, -1).join(""))).toEqual(
      [leafA, leafB].toSorted(),
    );
    expect(caddyfile).toContain(
      `# rt_k3x9 www.example.com: public access with a client certificate\n${TAILNET_ROUTE_MARKER} rt_k3x9 100.101.102.103:3000\n`,
    );
  });

  test("an empty certificate list renders a leaf verifier that admits nobody", () => {
    expect(
      httpRouteTlsOptions(checkedHttpRoute({ ...www, clientAuth: { caCertificate: ca, certificates: [] } })),
    ).toContain("      verifier leaf {\n      }\n");
  });

  test("combines with the login gate: the TLS handshake and forward_auth both apply", () => {
    const caddyfile = render([
      { ...www, access: "sso", clientAuth: { caCertificate: ca, certificates: [leafA] } },
    ]);
    const block = site(caddyfile, "www.example.com");
    expect(block).toContain("client_auth {");
    expect(block).toContain("uri /api/gate/check?route=rt_k3x9");
  });

  test("an unusable CA or certificate fails closed: the route is omitted, never served without mTLS", () => {
    for (const clientAuth of [
      { caCertificate: "", certificates: [] },
      { caCertificate: `${ca}"`, certificates: [] },
      { caCertificate: ca, certificates: ['MII"} respond 200 {'] },
      { caCertificate: ca, certificates: [`${leafA}\n`] },
      { caCertificate: ca.slice(0, -1), certificates: [] },
      { caCertificate: ca, certificates: "nope" as unknown as string[] },
    ]) {
      const plan = planEdge({
        adminMode: "tailnet",
        endpoints: [{ id: "end_www", kind: "route", hostname: www.hostname, exposure: "public" }],
        certificates: [{ endpointId: "end_www", status: "issued", lastDeployedAt: new Date() }],
        httpRoutes: [{ ...www, clientAuth }],
      });
      expect(plan.httpRoutes).toEqual([]);
      expect(plan.omitted.map((item) => item.id)).toEqual([www.id]);
      expect(() => render([{ ...www, clientAuth }])).toThrow(ValidationError);
    }
  });

  test("refuses more certificates than the renderer supports", () => {
    const certificates = Array.from({ length: HTTP_CLIENT_CERTIFICATE_LIMIT + 1 }, (_, index) =>
      Buffer.from(`${index}`.padStart(80, "x")).toString("base64"),
    );
    expect(() => checkedHttpRoute({ ...www, clientAuth: { caCertificate: ca, certificates } })).toThrow(
      "at most 500",
    );
  });
});
