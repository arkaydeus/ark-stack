import { describe, expect, test } from "bun:test";

import { chooseCloudflareMutation } from "./cloudflare.ts";
import { funnelDisabled, renderCaddyfile, renderTailscaleServe } from "./edge.ts";
import { compareInventory } from "./import-inventory.ts";
import { generateInstallSecrets, hostLossChecklist, mergeInstallEnv } from "./install.ts";
import { pgbouncerUserlist } from "./pgbouncer.ts";
import { renderDbIngress } from "./db-ingress.ts";
import { firstComposeImage, pinComposeImage, registryManifestUrl } from "./registry.ts";
import { deriveSesSmtpPassword, signAwsRequest } from "./ses.ts";
import { buildStalwartPlan, jmapCall } from "./stalwart.ts";

describe("provider adapters", () => {
  test("derives the SES SMTP password the same way AWS documents", () => {
    const password = deriveSesSmtpPassword("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1");
    const other = deriveSesSmtpPassword("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "eu-west-1");
    expect(Buffer.from(password, "base64")[0]).toBe(0x04);
    expect(password).not.toBe(other);
    expect(password.length).toBeGreaterThan(20);
  });

  test("signs SES requests with SigV4 headers", () => {
    const signed = signAwsRequest({
      method: "GET",
      path: "/v2/email/account",
      region: "eu-west-1",
      service: "ses",
      accessKey: "AKIATEST",
      secretKey: "secret",
      now: new Date("2026-01-02T03:04:05Z"),
    });
    expect(signed.headers.authorization).toContain(
      "AWS4-HMAC-SHA256 Credential=AKIATEST/20260102/eu-west-1/ses/aws4_request",
    );
    expect(signed.url).toBe("https://email.eu-west-1.amazonaws.com/v2/email/account");
  });

  test("refuses ambiguous Cloudflare edits", () => {
    expect(() =>
      chooseCloudflareMutation(
        [
          { id: "1", content: "a" },
          { id: "2", content: "b" },
        ],
        { type: "MX", name: "example.com", content: "mail.example.com", ttl: 300, priority: 10 },
      ),
    ).toThrow(/Resolve them manually/);
  });

  test("builds a Stalwart plan that never enables open relay", () => {
    const { plan, outbound } = buildStalwartPlan({
      hostname: "mail.example.com",
      domains: [{ name: "example.com", enabled: true }],
      mailboxes: [
        { address: "a@example.com", displayName: "A", quotaGb: 1, password: "x", lifecycle: "active" },
      ],
      aliases: [],
      outboundPaused: true,
    });
    expect(JSON.stringify(plan)).toContain('allowRelaying":false');
    expect(outbound.paused).toBe(true);
    expect(jmapCall("x:Account/get", { ids: ["1"] }).using[1]).toBe("urn:stalwart:jmap");
  });

  test("omits privileged roles from the public userlist and disables Funnel", () => {
    const list = pgbouncerUserlist([
      { name: "orders_runtime", password: "a" },
      { name: "orders_owner", password: "b" },
    ]);
    expect(list).toContain("orders_runtime");
    expect(list).not.toContain("orders_owner");
    expect(funnelDisabled(renderTailscaleServe())).toBe(true);
    expect(
      renderCaddyfile({ adminMode: "tailnet", challengeDir: "/acme", apiUpstream: "api:3000" }),
    ).not.toContain("admin.");
    expect(
      renderCaddyfile({
        adminMode: "public",
        adminHostname: "admin.example.com",
        challengeDir: "/acme",
        apiUpstream: "api:3000",
        certificates: [
          {
            hostname: "admin.example.com",
            status: "issued",
            fullchain: "/certs/admin.example.com/fullchain.pem",
            privkey: "/certs/admin.example.com/privkey.pem",
          },
        ],
      }),
    ).toContain("respond @unknownApi 404");
    expect(registryManifestUrl("docker.io/library/nginx:1.27.3").url).toContain("/nginx/manifests/1.27.3");
    expect(
      registryManifestUrl("quay.io/prometheus/node-exporter:v1.8.2").url.startsWith("https://quay.io/v2/"),
    ).toBe(true);
    expect(registryManifestUrl("public.ecr.aws/docker/library/nginx:1.27.3").host).toBe("public.ecr.aws");
    expect(registryManifestUrl("docker.io/ghcr.io.example/app:1").host).toBe("docker.io");
    expect(renderDbIngress()).toContain("hook input");
    expect(renderDbIngress()).toContain("hook forward");
    expect(
      pinComposeImage(
        "services:\n  x:\n    image: docker.io/library/nginx:1.27.3\n",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      ),
    ).toContain("@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    expect(
      compareInventory(
        { source: "orkmail", domains: ["a.com"] },
        { source: "orkmail", domains: ["a.com", "b.com"] },
      ).importable.domains,
    ).toEqual(["b.com"]);
    expect(firstComposeImage("services:\n  x:\n    image: docker.io/library/nginx:1.27.3\n")).toBe(
      "docker.io/library/nginx:1.27.3",
    );
    const secrets = generateInstallSecrets();
    expect(secrets.ARK_SETUP_TOKEN.length).toBeGreaterThan(16);
    expect(mergeInstallEnv("ARK_SETUP_TOKEN=keep\n", secrets)).toContain("ARK_SETUP_TOKEN=keep");
    expect(hostLossChecklist[0]).toContain("ARK_ROOT_KEY");
  });
});
