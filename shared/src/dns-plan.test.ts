import { describe, expect, test } from "bun:test";

import { buildDomainPlan, mergeSpf } from "./dns-plan.ts";

describe("DNS plan", () => {
  test("emits ownership, database, mail, and public admin records", () => {
    const plan = buildDomainPlan({
      baseDomain: "example.com",
      publicIpv4: "203.0.113.10",
      adminMode: "public",
      ownershipToken: "tok_abc",
      includeDatabase: true,
      includeMail: true,
    });
    const types = plan.records.map((record) => `${record.type}:${record.name}`);
    expect(types).toContain("TXT:_ark-stack.example.com");
    expect(types).toContain("A:db.example.com");
    expect(types).toContain("A:mail.example.com");
    expect(types).toContain("A:admin.example.com");
    expect(types).toContain("MX:example.com");
  });

  test("omits public admin records in tailnet mode", () => {
    const plan = buildDomainPlan({
      baseDomain: "example.com",
      publicIpv4: "203.0.113.10",
      adminMode: "tailnet",
      ownershipToken: "tok_abc",
      includeDatabase: false,
      includeMail: false,
    });
    expect(plan.records.some((record) => record.name.startsWith("admin."))).toBe(false);
  });

  test("merges SPF instead of creating a second policy", () => {
    expect(mergeSpf("v=spf1 include:_spf.google.com ~all", "v=spf1 include:amazonses.com -all")).toBe(
      "v=spf1 include:_spf.google.com include:amazonses.com -all",
    );
  });
});
