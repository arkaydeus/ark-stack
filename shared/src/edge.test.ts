import { describe, expect, test } from "bun:test";

import {
  currentEdgeCertificates,
  edgeCertificatePaths,
  planEdge,
  renderCaddyfile,
  type EdgeCertificate,
} from "./edge.ts";

const base = { challengeDir: "/var/lib/ark/acme", apiUpstream: "api:3000" } as const;

function certificate(hostname: string, status: string): EdgeCertificate {
  return { hostname, status, ...edgeCertificatePaths(hostname) };
}

// The site blocks of a rendered Caddyfile, keyed by their address.
function sites(caddyfile: string) {
  return new Map(
    [...caddyfile.matchAll(/^(\S+) \{\n([\s\S]*?)^\}$/gm)]
      .filter(([, address]) => address !== "{")
      .map(([, address, body]) => [address, body]),
  );
}

describe("edge Caddyfile certificates", () => {
  const certificates = [
    certificate("admin.example.com", "issued"),
    certificate("example.com", "issued"),
    certificate("www.example.com", "issued"),
    certificate("pending.example.com", "pending"),
    certificate("failed.example.com", "failed"),
    certificate("untrusted.example.com", "untrusted"),
  ];
  const caddyfile = renderCaddyfile({
    ...base,
    adminMode: "public",
    adminHostname: "admin.example.com",
    certificates,
    appRoutes: [
      { hostname: "example.com" },
      { hostname: "www.example.com", upstream: "app:8080" },
      { hostname: "pending.example.com" },
      { hostname: "failed.example.com", upstream: "app:8080" },
      { hostname: "untrusted.example.com" },
      { hostname: "nocert.example.com" },
    ],
  });
  const rendered = sites(caddyfile);

  test("renders only hostnames whose certificate is issued, each with its tls files", () => {
    expect([...rendered.keys()]).toEqual([":80", "admin.example.com", "example.com", "www.example.com"]);
    for (const hostname of ["admin.example.com", "example.com", "www.example.com"]) {
      expect(rendered.get(hostname)).toStartWith(
        `  tls /var/lib/ark/certs/${hostname}/fullchain.pem /var/lib/ark/certs/${hostname}/privkey.pem\n`,
      );
    }
    for (const hostname of ["pending", "failed", "untrusted", "nocert"]) {
      expect(caddyfile).not.toContain(`${hostname}.example.com`);
    }
  });

  test("every HTTPS site carries exactly one tls directive and Caddy automation is off", () => {
    expect(caddyfile.match(/^ {2}tls /gm)).toHaveLength(rendered.size - 1);
    expect(caddyfile).toContain("\n  auto_https off\n");
  });

  test("the admin site is not rendered without an issued certificate", () => {
    for (const status of ["pending", "failed"]) {
      const output = renderCaddyfile({
        ...base,
        adminMode: "public",
        adminHostname: "admin.example.com",
        certificates: [certificate("admin.example.com", status)],
      });
      expect(output).not.toContain("admin.example.com");
      expect(output).not.toContain("reverse_proxy");
    }
  });

  test(":80 serves challenges, redirects served hostnames with 308 and answers 404 otherwise", () => {
    const http = rendered.get(":80") ?? "";
    const challenge = http.indexOf("@challenge path /.well-known/acme-challenge/*");
    const known = http.indexOf("@known host admin.example.com example.com www.example.com\n");
    const redirect = http.indexOf("redir https://{host}{uri} 308");
    const fallback = http.indexOf('respond "Ark Stack challenge edge" 404');
    expect(challenge).toBeGreaterThanOrEqual(0);
    expect(challenge < known && known < redirect && redirect < fallback).toBe(true);
    expect(http).toContain("root * /var/lib/ark/acme");
  });

  test(":80 has no redirect matcher when no hostname is served", () => {
    const output = renderCaddyfile({ ...base, adminMode: "tailnet" });
    expect(output).not.toContain("@known");
    expect(output).not.toContain("tls ");
    expect(output).toContain('respond "Ark Stack challenge edge" 404');
  });

  test("unrouted endpoints answer a fixed 503 that names no internal host", () => {
    const body = rendered.get("example.com") ?? "";
    expect(body).toContain('respond "This hostname is not routed yet." 503');
    expect(body).toContain("header -Server");
    expect(body).not.toContain("reverse_proxy");
    expect(caddyfile).not.toContain("app-edge");
    expect(rendered.get("www.example.com")).toContain("reverse_proxy app:8080");
  });

  test("rejects values that could inject Caddyfile syntax", () => {
    const render = (overrides: Partial<EdgeCertificate>, upstream?: string) =>
      renderCaddyfile({
        ...base,
        adminMode: "tailnet",
        certificates: [{ ...certificate("app.example.com", "issued"), ...overrides }],
        appRoutes: [{ hostname: "app.example.com", upstream }],
      });
    expect(() => render({ hostname: "app.example.com {\n" })).toThrow();
    expect(() => render({ hostname: "App.Example.com" })).toThrow();
    expect(() => render({ fullchain: "/certs/x.pem }\nevil {" })).toThrow();
    expect(() => render({ privkey: "/certs/../../etc/shadow" })).toThrow();
    expect(() => render({ privkey: "relative/privkey.pem" })).toThrow();
    expect(() => render({}, "app:8080\n}\nevil.example.com {")).toThrow();
    expect(() =>
      renderCaddyfile({
        ...base,
        adminMode: "tailnet",
        certificates: [certificate("app.example.com", "issued"), certificate("app.example.com", "pending")],
      }),
    ).toThrow();
  });
});

const at = (minute: number) => new Date(Date.UTC(2026, 10, 16, 12, minute));

describe("edge plan", () => {
  const endpointRows = [
    { id: "end_admin", kind: "admin", hostname: "admin.example.com", exposure: "public" },
    { id: "end_apex", kind: "http", hostname: "example.com", exposure: "public" },
    { id: "end_www", kind: "http", hostname: "www.example.com", exposure: "public" },
    { id: "end_renewing", kind: "http", hostname: "renew.example.com", exposure: "public" },
    { id: "end_private", kind: "http", hostname: "private.example.com", exposure: "private" },
    { id: "end_db", kind: "database", hostname: "db.example.com", exposure: "public" },
  ];
  const certificateRows = [
    { endpointId: "end_admin", status: "issued", lastDeployedAt: at(1) },
    { endpointId: "end_apex", status: "untrusted", lastDeployedAt: at(1) },
    { endpointId: "end_apex", status: "issued", lastDeployedAt: at(5) },
    { endpointId: "end_www", status: "pending", lastDeployedAt: null },
    // The newest row wins: an older issued certificate no longer matches the files on disk.
    { endpointId: "end_renewing", status: "issued", lastDeployedAt: at(1) },
    { endpointId: "end_renewing", status: "failed", lastDeployedAt: at(9) },
    { endpointId: "end_db", status: "issued", lastDeployedAt: at(1) },
  ];

  test("picks the most recently deployed certificate per endpoint", () => {
    expect(
      currentEdgeCertificates({ endpoints: endpointRows, certificates: certificateRows }).map((item) => [
        item.hostname,
        item.status,
      ]),
    ).toEqual([
      ["admin.example.com", "issued"],
      ["example.com", "issued"],
      ["www.example.com", "pending"],
      ["renew.example.com", "failed"],
      ["db.example.com", "issued"],
    ]);
  });

  test("public http endpoints become unrouted routes, never a placeholder upstream", () => {
    const plan = planEdge({
      adminMode: "public",
      adminHostname: "admin.example.com",
      endpoints: endpointRows,
      certificates: certificateRows,
    });
    expect(plan.appRoutes).toEqual([
      { hostname: "example.com" },
      { hostname: "www.example.com" },
      { hostname: "renew.example.com" },
    ]);
    expect(plan.certificates.map((item) => item.hostname)).toEqual([
      "admin.example.com",
      "example.com",
      "www.example.com",
      "renew.example.com",
    ]);
    expect(plan.awaitingCertificate).toEqual(["renew.example.com", "www.example.com"]);
    const caddyfile = renderCaddyfile({ ...base, ...plan });
    expect([...sites(caddyfile).keys()]).toEqual([":80", "admin.example.com", "example.com"]);
    expect(caddyfile).not.toContain("app-edge");
    expect(caddyfile).not.toContain("reverse_proxy app");
  });

  test("tailnet admin mode serves no admin site", () => {
    const plan = planEdge({
      adminMode: "tailnet",
      adminHostname: "admin.example.com",
      endpoints: endpointRows,
      certificates: certificateRows,
    });
    expect(plan.adminHostname).toBeUndefined();
    expect(renderCaddyfile({ ...base, ...plan })).not.toContain("admin.example.com");
  });
});

describe("tailnet routes (front door §3.2, FD-06)", () => {
  const route = { id: "rt_k3x9", hostname: "www.example.com", ip: "100.101.102.103", port: 3000 };
  const v6 = { id: "rt_v6", hostname: "v6.example.com", ip: "fd7a:115c:a1e0::103", port: 8080 };
  const certificates = [certificate("www.example.com", "issued"), certificate("v6.example.com", "issued")];

  test("renders an allowed route with its pinned address and a marker, and redirects it on :80", () => {
    const caddyfile = renderCaddyfile({
      ...base,
      adminMode: "tailnet",
      certificates,
      tailnetRoutes: [route, v6],
    });
    expect(caddyfile).toContain("# ark-tailnet-route rt_k3x9 100.101.102.103:3000\nwww.example.com {");
    expect(sites(caddyfile).get("www.example.com")).toContain("reverse_proxy 100.101.102.103:3000");
    expect(sites(caddyfile).get("v6.example.com")).toContain("reverse_proxy [fd7a:115c:a1e0::103]:8080");
    expect(sites(caddyfile).get(":80")).toContain("@known host www.example.com v6.example.com");
    expect(caddyfile).toContain("grace_period 5s");
  });

  test("the closed variant renders no tailnet route at all", () => {
    const closed = renderCaddyfile({ ...base, adminMode: "tailnet", certificates });
    expect(closed).not.toContain("ark-tailnet-route");
    expect(closed).not.toContain("100.101.102.103");
    expect([...sites(closed).keys()]).toEqual([":80"]);
  });

  test("a route without an issued certificate is not rendered", () => {
    const caddyfile = renderCaddyfile({
      ...base,
      adminMode: "tailnet",
      certificates: [],
      tailnetRoutes: [route],
    });
    expect(caddyfile).not.toContain("100.101.102.103");
  });

  test("refuses non-tailnet, reserved or non-canonical targets and bad ids", () => {
    for (const bad of [
      { ...route, ip: "172.17.0.2" },
      { ...route, ip: "100.100.100.100" },
      { ...route, ip: "fd7a:115c:a1e0:0::103" },
      { ...route, ip: "100.101.102.103:3000" },
      { ...route, port: 0 },
      { ...route, id: "rt_K3X9\nreverse_proxy 10.0.0.1:80" },
    ]) {
      expect(() =>
        renderCaddyfile({ ...base, adminMode: "tailnet", certificates, tailnetRoutes: [bad] }),
      ).toThrow();
    }
  });

  test("planEdge waits for the route's certificate", () => {
    const plan = planEdge({ adminMode: "tailnet", endpoints: [], certificates: [], tailnetRoutes: [route] });
    expect(plan.tailnetRoutes).toEqual([route]);
    expect(plan.awaitingCertificate).toEqual(["www.example.com"]);
  });
});
