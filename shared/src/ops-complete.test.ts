import { describe, expect, test } from "bun:test";

import { adoptionPreview, classifyDiscovery } from "./adopt.ts";
import { assertCidrs, clientAllowed } from "./cidr.ts";
import { canMutateQueue, parseStalwartQueue } from "./mail-queue.ts";
import { bundleDigest, validateMaintenanceBundle } from "./maintenance.ts";
import { rotateRoleSql } from "./rotate.ts";
import { groupSchemaRows, schemaBrowserSql } from "./schema-browser.ts";

describe("remaining control-plane policies", () => {
  test("enforces CIDR allowlists and rotation SQL", () => {
    expect(assertCidrs(["10.0.0.0/8", "2001:db8::/32"])).toHaveLength(2);
    expect(() => assertCidrs(["999.1.1.1/33"])).toThrow(/Invalid CIDR/);
    expect(clientAllowed(["10.0.0.0/8"], "10.1.2.3").allowed).toBe(true);
    expect(clientAllowed(["10.0.0.0/8"], "8.8.8.8").allowed).toBe(false);
    expect(clientAllowed([], "8.8.8.8").allowed).toBe(true);
    expect(rotateRoleSql("orders_runtime", "n3w")).toContain("ALTER ROLE");
  });

  test("groups schema browser rows and keeps catalog SQL read-only", () => {
    expect(schemaBrowserSql).toContain("information_schema.columns");
    expect(
      groupSchemaRows([{ schema: "public", table: "orders", column: "id", type: "uuid" }]).public.orders,
    ).toHaveLength(1);
  });

  test("limits mail queue mutations and redacts bodies by omitting them", () => {
    const item = {
      id: "q1",
      recipient: "a@example.com",
      sender: "b@x.com",
      ageSeconds: 10,
      state: "queued" as const,
    };
    expect(canMutateQueue({ action: "delete", item, localDomains: ["example.com"] }).ok).toBe(false);
    expect(canMutateQueue({ action: "retry", item, localDomains: ["example.com"] }).ok).toBe(true);
    expect(parseStalwartQueue(`${JSON.stringify(item)}\n`)[0]?.id).toBe("q1");
  });

  test("treats unknown containers as unmanaged and refuses broken adopt compose", () => {
    const classified = classifyDiscovery(
      [
        {
          id: "1",
          name: "/shop",
          image: "nginx",
          state: "running",
          labels: { "com.docker.compose.service": "shop" },
        },
        {
          id: "2",
          name: "/pg",
          image: "postgres",
          state: "running",
          labels: { "com.docker.compose.project": "ark-platform" },
        },
      ],
      [],
    );
    expect(classified.unmanaged.map((item) => item.id)).toEqual(["1"]);
    expect(adoptionPreview("services:\n  x:\n    privileged: true\n").ok).toBe(false);
  });

  test("accepts only digest-matching maintenance bundles", () => {
    const images = [
      "ghcr.io/ark-stack/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];
    const digest = bundleDigest(images);
    expect(validateMaintenanceBundle({ version: "1.0.0", images, digest }).images).toEqual(images);
    expect(() =>
      validateMaintenanceBundle({
        version: "1.0.0",
        images: ["postgres:17"],
        digest: bundleDigest(["postgres:17"]),
      }),
    ).toThrow(/stateful/);
  });
});
