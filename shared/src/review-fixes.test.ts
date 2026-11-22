import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { assertCidrs, clientAllowed, parseCidr, parseIpv6 } from "./cidr.ts";
import { renderDbIngress } from "./db-ingress.ts";
import { chooseCloudflareMutation } from "./cloudflare.ts";
import { canonicalizeComposeSource, validateComposeSource } from "./compose-policy.ts";
import { generatePassword } from "./crypto.ts";
import { validateMaintenanceBundle, bundleDigest } from "./maintenance.ts";
import { literal } from "./provision-sql.ts";
import { redactValue } from "./redact.ts";
import { projectInput, reservedProjectSlugs } from "./schemas.ts";

const DIGEST = `sha256:${"a".repeat(64)}`;
const IMAGE = `docker.io/library/nginx:1.27.3@${DIGEST}`;

function service(fields: string) {
  return `services:\n  web:\n    image: ${IMAGE}\n${fields}`;
}

describe("compose policy port and mount coverage", () => {
  test("rejects a published port range in the long syntax as well as the short one", () => {
    const longForm = validateComposeSource(
      service('    ports:\n      - target: 80\n        published: "80-81"\n'),
    );
    expect(longForm.ok).toBe(false);
    const shortForm = validateComposeSource(service('    ports:\n      - "80-81:80"\n'));
    expect(shortForm.ok).toBe(false);
  });

  test("rejects a reserved host port declared in the long syntax", () => {
    const result = validateComposeSource(service("    ports:\n      - target: 80\n        published: 25\n"));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.violations.map((item) => item.message).join(" ")).toContain("reserved");
  });

  test("accepts an ordinary long-syntax published port", () => {
    const result = validateComposeSource(
      service("    ports:\n      - target: 80\n        published: 8088\n"),
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.ports).toEqual([8088]);
  });

  test("allows only volume and tmpfs mount types", () => {
    for (const type of ["image", "bind", "cluster", "npipe"]) {
      const result = validateComposeSource(
        service(
          `    volumes:\n      - type: ${type}\n        source: evil.example/x:1\n        target: /data\n`,
        ),
      );
      expect(result.ok).toBe(false);
    }
  });

  test("requires an immutable digest so the agent can actually pull the image", () => {
    expect(validateComposeSource("services:\n  web:\n    image: docker.io/library/nginx:1.27.3\n").ok).toBe(
      false,
    );
    expect(validateComposeSource("services:\n  web:\n    image: docker.io/library/nginx:latest\n").ok).toBe(
      false,
    );
    expect(validateComposeSource(`services:\n  web:\n    image: ${IMAGE}\n`).ok).toBe(true);
  });

  test("every shipped template passes the policy it is meant to demonstrate", () => {
    const dir = join(import.meta.dir, "..", "..", "templates");
    const files = readdirSync(dir).filter((name) => name.endsWith(".yml"));
    expect(files.length).toBeGreaterThan(0);
    for (const name of files) {
      const text = readFileSync(join(dir, name), "utf8");
      const result = validateComposeSource(text);
      if (!result.ok) {
        throw new Error(`${name}: ${result.violations.map((item) => item.message).join(" ")}`);
      }
      expect(() => canonicalizeComposeSource(text)).not.toThrow();
    }
  });
});

describe("CIDR parsing and the generated nft policy", () => {
  test("parses IPv4-in-IPv6 forms without losing the leading groups", () => {
    const mapped = parseIpv6("::ffff:1.2.3.4");
    expect(mapped).not.toBeNull();
    expect(Array.from(mapped!.slice(10))).toEqual([0xff, 0xff, 1, 2, 3, 4]);
    expect(Array.from(parseIpv6("0:0:0:0:0:ffff:1.2.3.4")!)).toEqual(Array.from(mapped!));
    const nat64 = parseIpv6("64:ff9b::1.2.3.4");
    expect(nat64).not.toBeNull();
    expect(Array.from(nat64!.slice(0, 4))).toEqual([0x00, 0x64, 0xff, 0x9b]);
  });

  test("rejects malformed IPv6 CIDRs that nft would refuse to load", () => {
    expect(parseCidr("::::/64").ok).toBe(false);
    expect(parseCidr("1:2:3:4:5:6:7:8:9/64").ok).toBe(false);
    expect(parseCidr("2001:db8::/32").ok).toBe(true);
    expect(() => assertCidrs(["::::/64"])).toThrow(/Invalid CIDR/);
  });

  test("matches an uppercase IPv4-mapped client against an IPv4 allowlist", () => {
    expect(clientAllowed(["10.0.0.0/8"], "::FFFF:10.0.0.1").allowed).toBe(true);
    expect(clientAllowed(["10.0.0.0/8"], "::ffff:10.0.0.1").allowed).toBe(true);
    expect(clientAllowed(["10.0.0.0/8"], "192.0.2.1").allowed).toBe(false);
  });

  test("5432 still installs a readable limits table after moving CIDRs to HAProxy", () => {
    const open = renderDbIngress();
    expect(open).toContain("table inet ark_db_ingress {");
    // Only the per-source limits drop; neither hook jumps to an allowlist chain.
    expect(open).not.toContain("jump ark_db_allow");
    expect(open).toContain("jump ark_db_limits");
  });
});

const txt = (content: string) => ({ type: "TXT", name: "example.com", content, ttl: 300 });

describe("Cloudflare record safety", () => {
  test("adds an SPF record beside an unrelated TXT instead of destroying it", () => {
    expect(
      chooseCloudflareMutation([{ id: "1", content: "google-site-verification=xyz" }], txt("v=spf1 -all")),
    ).toEqual({
      action: "create",
    });
  });

  test("replaces an existing record of the same kind", () => {
    expect(
      chooseCloudflareMutation([{ id: "1", content: "v=spf1 include:old -all" }], txt("v=spf1 -all")),
    ).toEqual({ action: "update", id: "1" });
    expect(chooseCloudflareMutation([{ id: "1", content: "v=spf1 -all" }], txt("v=spf1 -all"))).toEqual({
      action: "keep",
      id: "1",
    });
  });

  test("refuses to take over an existing MX record", () => {
    expect(() =>
      chooseCloudflareMutation([{ id: "1", content: "mx.other.example", priority: 10 }], {
        type: "MX",
        name: "example.com",
        content: "mail.example.com",
        ttl: 300,
        priority: 10,
      }),
    ).toThrow(/Resolve it manually/);
  });
});

describe("secret handling", () => {
  test("redacts snake-case keys and credentials embedded in connection strings", () => {
    const redacted = redactValue({
      DATABASE_URL: "postgres://user:hunter2@host/db",
      SMTP_PASSWORD: "hunter2",
      AWS_SECRET_ACCESS_KEY: "hunter2",
      clientSecret: "hunter2",
      apiUrl: "https://example.test/path",
    }) as Record<string, string>;
    expect(JSON.stringify(redacted)).not.toContain("hunter2");
    expect(redacted.apiUrl).toBe("https://example.test/path");
    expect(redactValue("postgres://user:hunter2@host/db")).toBe("postgres://user:<redacted>@host/db");
  });

  test("generated passwords use an unbiased alphabet with no dollar-quote character", () => {
    const sample = Array.from({ length: 500 }, () => generatePassword(8)).join("");
    expect(sample).not.toContain("$");
    expect(new Set(sample).size).toBe(64);
  });

  test("a secret that could break out of the SQL dollar quote is refused", () => {
    expect(() => literal("abc$ark")).toThrow(/dollar-quote/);
    expect(() => literal("abc$ark$def")).toThrow(/dollar-quote/);
    expect(literal("ordinary-secret")).toBe("$ark$ordinary-secret$ark$");
  });
});

describe("maintenance bundles", () => {
  test.each(["ark-agent", "ark-stack-agent"])("%s requires stateful approval", (repository) => {
    const images = [`ghcr.io/example/${repository}:release@${DIGEST}`];
    const bundle = { version: "1", images, digest: bundleDigest(images) };

    expect(() => validateMaintenanceBundle({ ...bundle, allowStateful: false })).toThrow(
      "Refusing unattended stateful images",
    );
    expect(validateMaintenanceBundle({ ...bundle, allowStateful: true }).rollbackSafe).toBe(false);
  });

  test("a stateful image is never reported as rollback safe", () => {
    const images = [`docker.io/library/postgres:16@${DIGEST}`];
    const result = validateMaintenanceBundle({
      version: "1",
      images,
      digest: bundleDigest(images),
      allowStateful: true,
    });
    expect(result.rollbackSafe).toBe(false);
  });

  test("a stateless bundle stays rollback safe", () => {
    const images = [`docker.io/library/nginx:1.27.3@${DIGEST}`];
    const result = validateMaintenanceBundle({ version: "1", images, digest: bundleDigest(images) });
    expect(result.rollbackSafe).toBe(true);
  });
});

describe("project slugs", () => {
  test("platform stack names cannot be claimed by a workload project", () => {
    for (const slug of reservedProjectSlugs) {
      expect(projectInput.safeParse({ name: "x", slug }).success).toBe(false);
    }
    expect(projectInput.safeParse({ name: "x", slug: "shop" }).success).toBe(true);
  });
});
