// The login origin's site block and path allowlist (docs/design/front-door.md §3.5, §3.9.1, FD-10).
import { describe, expect, test } from "bun:test";

import {
  GATE_LOGIN_SITE_COMMENT,
  edgeCertificatePaths,
  gateLoginSiteBody,
  planEdge,
  renderCaddyfile,
  servedHttpHostnames,
} from "./edge.ts";
import {
  GATE_ENROLLMENT_AUTH_PATHS,
  GATE_LOGIN_AUTH_PATHS,
  gateSettingsInput,
  isGateLoginPath,
} from "./gate-login.ts";

const loginHost = "login.example.com";
const base = { challengeDir: "/var/lib/ark/acme", apiUpstream: "api:3000" } as const;
const issued = (hostname: string) => ({ hostname, status: "issued", ...edgeCertificatePaths(hostname) });

/** The §3.5 login-origin site block, as written in the design document (tabs as two spaces). */
const DOCUMENT_SITE = `# Gate login origin: only login, MFA and gate endpoints
login.example.com {
  bind 127.0.0.1
  tls /var/lib/ark/certs/login.example.com/fullchain.pem /var/lib/ark/certs/login.example.com/privkey.pem
  import ark_route_base
  header Strict-Transport-Security "max-age=31536000"
  request_body {
    max_size 64KB
  }
  @gateApi path /api/auth/sign-in/email /api/auth/sign-out /api/auth/get-session /api/auth/two-factor/verify-totp /api/auth/two-factor/verify-backup-code /api/auth/two-factor/enable /api/auth/two-factor/get-totp-uri
  @gatePages path /gate/*
  handle @gateApi {
    reverse_proxy api:3000 {
      header_up X-Ark-Edge-Token {env.ARK_EDGE_GATE_TOKEN}
    }
  }
  handle @gatePages {
    reverse_proxy api:3000
  }
  handle {
    respond 404
  }
}
`;

describe("login origin site block (§3.5)", () => {
  const caddyfile = renderCaddyfile({
    ...base,
    adminMode: "tailnet",
    gate: { hostname: loginHost },
    certificates: [issued(loginHost)],
  });

  test("renders the document's login-origin site block exactly", () => {
    expect(caddyfile).toContain(DOCUMENT_SITE);
  });

  test("brings the shared route snippets, redirects the login host on :80 and never embeds the token", () => {
    expect(caddyfile).toContain("(ark_route_base) {");
    expect(caddyfile).toContain("request_header -X-Ark-*");
    expect(caddyfile).toMatch(/@known host login\.example\.com\n/);
    expect(caddyfile).not.toMatch(/X-Ark-Edge-Token (?!\{env\.ARK_EDGE_GATE_TOKEN\})/);
  });

  test("is not rendered without an issued certificate, and a host cannot be both admin and login", () => {
    const pending = renderCaddyfile({
      ...base,
      adminMode: "tailnet",
      gate: { hostname: loginHost },
      certificates: [{ ...issued(loginHost), status: "pending" }],
    });
    expect(pending).not.toContain(GATE_LOGIN_SITE_COMMENT);
    expect(() =>
      renderCaddyfile({
        ...base,
        adminMode: "public",
        adminHostname: loginHost,
        gate: { hostname: loginHost },
        certificates: [issued(loginHost)],
      }),
    ).toThrow(/listed more than once/);
  });

  test("refuses an injected upstream or hostname", () => {
    expect(() => gateLoginSiteBody("api:3000 {\n respond hi")).toThrow(/not host:port/);
    expect(() =>
      renderCaddyfile({ ...base, adminMode: "tailnet", gate: { hostname: "login.example.com {" } }),
    ).toThrow();
  });

  test("the plan serves the login host like the admin host and lists it in the 443 map", () => {
    const plan = planEdge({
      adminMode: "tailnet",
      gateHostname: loginHost,
      endpoints: [{ id: "ep_gate", kind: "gate", hostname: loginHost, exposure: "public" }],
      certificates: [{ endpointId: "ep_gate", status: "issued", lastDeployedAt: new Date() }],
    });
    expect(plan.gateHostname).toBe(loginHost);
    expect(servedHttpHostnames(plan)).toEqual([loginHost]);
    const waiting = planEdge({
      adminMode: "tailnet",
      gateHostname: loginHost,
      endpoints: [{ id: "ep_gate", kind: "gate", hostname: loginHost, exposure: "public" }],
      certificates: [],
    });
    expect(waiting.awaitingCertificate).toEqual([loginHost]);
    expect(servedHttpHostnames(waiting)).toEqual([]);
    const disabled = planEdge({
      adminMode: "tailnet",
      endpoints: [{ id: "ep_gate", kind: "gate", hostname: loginHost, exposure: "public" }],
      certificates: [{ endpointId: "ep_gate", status: "issued", lastDeployedAt: new Date() }],
    });
    expect(servedHttpHostnames(disabled)).toEqual([]);
  });
});

describe("login origin path allowlist", () => {
  test("allows exactly the login API paths and the gate pages", () => {
    for (const path of GATE_LOGIN_AUTH_PATHS) expect(isGateLoginPath(path), path).toBe(true);
    for (const path of ["/gate/login", "/gate/authorize", "/gate/"])
      expect(isGateLoginPath(path), path).toBe(true);
    for (const path of [
      "/api/state",
      "/api/internal/jobs",
      "/api/gate/check",
      "/api/health",
      "/api/auth/sign-up/email",
      "/api/auth/two-factor/disable",
      "/api/auth/sign-in/email/",
      "/api/auth/Sign-In/email",
      "/api/auth/sign-in%2Femail",
      "/gate",
      "/",
    ]) {
      expect(isGateLoginPath(path), path).toBe(false);
    }
  });

  test("the enrollment-only endpoints are on the login allowlist", () => {
    for (const path of GATE_ENROLLMENT_AUTH_PATHS) expect(isGateLoginPath(`/api/auth${path}`)).toBe(true);
  });
});

describe("gate settings input (R1)", () => {
  test("public needs a hostname, disabled takes none, and no other mode exists", () => {
    expect(gateSettingsInput.parse({ mode: "public", hostname: loginHost })).toEqual({
      mode: "public",
      hostname: loginHost,
    });
    expect(gateSettingsInput.parse({ mode: "disabled" })).toEqual({ mode: "disabled" });
    for (const value of [
      { mode: "public" },
      { mode: "tailnet", hostname: loginHost },
      { mode: "disabled", hostname: loginHost },
      { mode: "public", hostname: loginHost, extra: true },
    ]) {
      expect(gateSettingsInput.safeParse(value).success, JSON.stringify(value)).toBe(false);
    }
  });
});
