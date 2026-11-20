import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
  anchors,
  checkDocs,
  checkMarkdown,
  context,
  checkFile,
  fullFiles,
  routeKey,
  routeMatches,
  slug,
} from "./check-docs.ts";

const root = join(import.meta.dir, "..");

describe("documentation check helpers", () => {
  test("GitHub heading slugs", () => {
    expect(slug("B1: Internet ↔ VPS public ports")).toBe("b1-internet--vps-public-ports");
    expect(slug("Login gate for SSO routes (FD-11)")).toBe("login-gate-for-sso-routes-fd-11");
    expect(slug("Front-door trust boundaries (B1–B10)")).toBe("front-door-trust-boundaries-b1b10");
    expect(slug("8. Vercel integration (FD-29): disabled until live proof")).toBe(
      "8-vercel-integration-fd-29-disabled-until-live-proof",
    );
    expect(slug("PostgreSQL router (5432)")).toBe("postgresql-router-5432");
  });

  test("repeated headings get numbered anchors; fenced lines are not headings", () => {
    const found = anchors("# A\n## Tests\n```sh\n# not a heading\n```\n## Tests\n");
    expect([...found]).toEqual(["a", "tests", "tests-1"]);
  });

  test("route keys treat parameters and placeholders alike", () => {
    expect(routeKey("get", "/api/settings/ipv6/preflight?operationId=<id>")).toBe(
      "GET /api/settings/ipv6/preflight",
    );
    const routes = [routeKey("put", "/api/backups/targets/:kind")];
    expect(routeMatches(routes, routeKey("PUT", "/api/backups/targets/s3"))).toBe(true);
    expect(routeMatches(routes, routeKey("POST", "/api/backups/targets/s3"))).toBe(false);
    expect(routeMatches(routes, routeKey("PUT", "/api/backups/targets/s3/extra"))).toBe(false);
  });
});

describe("documentation check", () => {
  const ctx = context(root);

  test("reports each kind of drift and accepts what exists", () => {
    const doc = [
      "# Title",
      "[ok](../operating.md#revocation) [own](#title) [gone](../nope.md) [bad](../operating.md#no-such-heading)",
      "Run `mise run test:pgbouncer` and `mise run test:does-not-exist`.",
      "See `scripts/check-docs.ts`, `shared/src/edge-l4.ts:32`, `scripts/missing-file.ts`.",
      "Call `POST /api/databases/:id/clients/:clientId/revoke` or `POST /api/databases/:id/explode`.",
      "Set `ARK_DB_CLIENT_CERT_B64`, `ARK_TEST_S3_*` and `ARK_NOT_A_REAL_SETTING`.",
      "HAProxy owns TCP 5432 and TCP 47123.",
      "```sh",
      "mise run edge:rejoin",
      "bun scripts/nope.ts",
      "```",
    ].join("\n");
    const problems = checkMarkdown(ctx, "docs/guides/fixture.md", doc, "full").map(
      ({ kind, detail }) => `${kind}: ${detail}`,
    );
    expect(problems.toSorted()).toEqual(
      [
        "anchor: docs/operating.md#no-such-heading",
        "endpoint: POST /api/databases/:id/explode",
        "env var: ARK_NOT_A_REAL_SETTING",
        "link: ../nope.md",
        "mise task: test:does-not-exist",
        "path: scripts/missing-file.ts",
        "path: scripts/nope.ts",
        "port: 47123",
      ].toSorted(),
    );
  });

  test.each([
    [
      "HTTP request lines",
      "```http\nPOST /api/databases/:id/clients/:clientId/revoke HTTP/1.1\nPOST /api/definitely-missing HTTP/1.1\n```",
      "endpoint: POST /api/definitely-missing",
    ],
    [
      "inline command paths",
      "Run `bun scripts/check-docs.ts` or `bun scripts/definitely-missing.ts`.",
      "path: scripts/definitely-missing.ts",
    ],
    [
      "line citations and host ports",
      "See `scripts/check-docs.ts:47124` and `Dockerfile:47124`. Connect to `localhost:47124`.",
      "port: 47124",
    ],
    ["both endpoints of port ranges", "TCP 20000–20049 and ports 20000-47123.", "port: 47123"],
    [
      "wildcards with fixed suffixes",
      "Set `ARK_DB_*_B64`, `ARK_TEST_S3_*` or `ARK_DB_*_NOT_REAL`.",
      "env var: ARK_DB_*_NOT_REAL",
    ],
    [
      "inline HTML images",
      '<img src="../../assets/brand/ark-stack-icon-256.png" alt=""> <img alt="" src="../../assets/brand/missing.png"> <img src="https://example.com/x.png">',
      "image: ../../assets/brand/missing.png",
    ],
  ])("checks %s", (_, doc, diagnostic) => {
    expect(
      checkMarkdown(ctx, "docs/guides/fixture.md", doc, "full").map(
        ({ kind, detail }) => `${kind}: ${detail}`,
      ),
    ).toEqual([diagnostic]);
  });

  test("checks published pages under guides and deeper folders in full", () => {
    const fixture = mkdtempSync(join(tmpdir(), "ark-docs-drift-"));
    try {
      const pages = ["docs/guides/fixture.md", "docs/features/deep/nested/fixture.md"];
      for (const file of pages) {
        mkdirSync(dirname(join(fixture, file)), { recursive: true });
        writeFileSync(join(fixture, file), "Call `POST /api/unknown-fixture`.");
      }
      writeFileSync(
        join(fixture, "docs/nav.json"),
        JSON.stringify({
          title: "Fixture",
          repository: "https://example.com/docs",
          sections: [{ title: "Guides", pages: pages.map((file) => ({ file })) }],
        }),
      );
      const fixtureContext = { ...ctx, root: fixture, tracked: new Set(pages) };
      expect(fullFiles(fixtureContext)).toEqual(pages.toSorted());
      expect(
        fullFiles(fixtureContext)
          .flatMap((file) => checkFile(fixtureContext, file, "full"))
          .map(({ file, kind }) => ({ file, kind })),
      ).toEqual(pages.toSorted().map((file) => ({ file, kind: "endpoint" })));
      expect(fullFiles(ctx)).toContain("docs/fix1-verification.md");
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  });

  test("the operator docs, guides and design links have no drift", () => {
    const problems = checkDocs(root).map(
      ({ file, line, kind, detail }) => `${file}:${line}: ${kind}: ${detail}`,
    );
    expect(problems).toEqual([]);
  });
});
