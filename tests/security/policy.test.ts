import { describe, expect, test } from "bun:test";

import {
  adoptionPreview,
  assertGranted,
  canViewProject,
  clientAllowed,
  compareInventory,
  funnelDisabled,
  hasRole,
  nftAllowlist,
  renderTailscaleServe,
  validateComposeSource,
} from "../../shared/src/index.ts";

describe("cross-project authorization", () => {
  test("operators cannot view projects they were not granted", () => {
    const access = { userId: "u1", role: "operator" as const, projectIds: ["p1"], domainIds: [] };
    expect(canViewProject(access, "p1")).toBe(true);
    expect(canViewProject(access, "p2")).toBe(false);
    expect(hasRole(access, "owner")).toBe(false);
    expect(() => assertGranted(access, { projectId: "p2" })).toThrow(/project/);
  });
});

describe("compose privilege boundary", () => {
  test("rejects host path escape attempts", () => {
    const result = validateComposeSource(`
services:
  x:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    volumes:
      - ../:/host
`);
    expect(result.ok).toBe(false);
  });

  test("rejects interpolated docker.sock mounts and host-IP reserved ports", () => {
    const interpolated = validateComposeSource(`
services:
  x:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    volumes:
      - "\${X:-/var/run}/docker.sock:/sock"
`);
    const reserved = validateComposeSource(`
services:
  x:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "0.0.0.0:25:8080"
`);
    expect(interpolated.ok).toBe(false);
    expect(reserved.ok).toBe(false);
  });
});

describe("admin and import boundaries", () => {
  test("keeps Tailscale Funnel disabled and never imports owners", () => {
    expect(funnelDisabled(renderTailscaleServe())).toBe(true);
    expect(
      compareInventory({ source: "orkmail", domains: [] }, { source: "orkmail", domains: ["a.com"] })
        .ownersImported,
    ).toBe(false);
    expect(clientAllowed(["192.168.0.0/16"], "10.0.0.1").allowed).toBe(false);
    expect(clientAllowed(["2001:db8::/32"], "2001:db8::1").allowed).toBe(true);
    expect(nftAllowlist(["2001:db8::/32"])).toContain("ip6 saddr");
    expect(nftAllowlist(["2001:db8::/32"])).toContain("hook input");
    expect(adoptionPreview("services:\n  x:\n    privileged: true\n").ok).toBe(false);
  });
});
