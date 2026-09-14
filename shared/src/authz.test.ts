import { describe, expect, test } from "bun:test";

import { privilegedRequestHash } from "./hash.ts";
import { assertGranted, hasMfaAssurance, protectLastOwner, assertPrivileged } from "./authz.ts";

const owner = { userId: "u1", role: "owner" as const, projectIds: [], domainIds: [] };

describe("authorization", () => {
  test("MFA is only assured after enrollment and a later session", () => {
    const enrolled = new Date("2026-01-02T00:00:00Z");
    expect(
      hasMfaAssurance({
        twoFactorEnabled: true,
        mfaEnrolledAt: enrolled,
        sessionCreatedAt: new Date("2026-01-01T00:00:00Z"),
      }),
    ).toBe(false);
    expect(
      hasMfaAssurance({
        twoFactorEnabled: true,
        mfaEnrolledAt: enrolled,
        sessionCreatedAt: new Date("2026-01-03T00:00:00Z"),
      }),
    ).toBe(true);
  });

  test("the last owner cannot be demoted", () => {
    expect(() => protectLastOwner(1, "operator")).toThrow(/last active owner/);
    expect(() => protectLastOwner(2, "operator")).not.toThrow();
  });

  test("privileged request hashes bind action and exact request", () => {
    const first = privilegedRequestHash("secret.reveal", { secretId: "sec_a" });
    const replay = privilegedRequestHash("secret.reveal", { secretId: "sec_a" });
    const other = privilegedRequestHash("secret.reveal", { secretId: "sec_b" });
    expect(first).toBe(replay);
    expect(first).not.toBe(other);
  });

  test("privileged actions require recent step-up", () => {
    expect(() => assertPrivileged(owner, "secret.reveal", new Date(Date.now() - 31 * 60 * 1000))).toThrow(
      /Re-authenticate/,
    );
    expect(() => assertPrivileged(owner, "secret.reveal", new Date())).not.toThrow();
  });

  test("scoped operators are denied ungranted projects and domains", () => {
    const operator = { userId: "u2", role: "operator" as const, projectIds: ["p1"], domainIds: ["d1"] };
    expect(() => assertGranted(operator, { projectId: "p2" })).toThrow(/project/);
    expect(() => assertGranted(operator, { domainId: "d2" }, "manage")).toThrow(/domain/);
    expect(() => assertGranted(operator, { projectId: "p1" })).not.toThrow();
  });
});
