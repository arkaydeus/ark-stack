// FD-26 (docs/design/front-door.md §3.8.3): one explicit pooler-wide source policy on public 5432.
import { describe, expect, test } from "bun:test";

import {
  POOLER_POLICY_BOUNDARY,
  checkPoolerPolicy,
  evaluatePoolerPolicy,
  poolerAdmission,
  poolerConflicts,
  poolerPolicyInput,
  poolerPolicyLoosens,
  poolerRequests,
  poolerRequestsFingerprint,
} from "./pooler-policy.ts";

const databaseA = { id: "mdb_a", name: "shop", exposure: "public", sourceCidrs: ["198.51.100.0/24"] };
const databaseB = { id: "mdb_b", name: "crm", exposure: "public", sourceCidrs: ["203.0.113.0/24"] };
const vercel = { id: "dbc_v", name: "vercel-prod", databaseId: "mdb_b", status: "active" };

describe("requests and conflicts", () => {
  test("only public databases and active Vercel clients of public databases are requests", () => {
    const requests = poolerRequests({
      databases: [databaseA, { ...databaseB, exposure: "private" }],
      vercelClients: [vercel, { ...vercel, id: "dbc_r", status: "revoked", databaseId: "mdb_a" }],
    });
    expect(requests.map((request) => request.source.id)).toEqual(["mdb_a"]);
    // A database without CIDRs requests an unrestricted pooler, as the pre-FD-26 open allowlist behaved.
    const open = poolerRequests({ databases: [{ ...databaseA, sourceCidrs: [] }] });
    expect(open[0]).toMatchObject({ unrestricted: true, key: "internet" });
  });

  test("two databases with disjoint CIDRs and an unrestricted Vercel client conflict", () => {
    const requests = poolerRequests({ databases: [databaseA, databaseB], vercelClients: [vercel] });
    const conflicts = poolerConflicts(requests);
    expect(conflicts.map((conflict) => conflict.reason).toSorted()).toEqual([
      "different_cidrs",
      "restricted_with_unrestricted",
    ]);
    expect(conflicts.find((item) => item.reason === "restricted_with_unrestricted")!.message).toContain(
      "Vercel client vercel-prod",
    );
  });

  test("identical requests do not conflict, and the fingerprint covers distinct requests only", () => {
    const same = poolerRequests({
      databases: [databaseA, { ...databaseB, sourceCidrs: databaseA.sourceCidrs }],
    });
    expect(poolerConflicts(same)).toEqual([]);
    expect(poolerRequestsFingerprint(same)).toBe(
      poolerRequestsFingerprint(poolerRequests({ databases: [databaseA] })),
    );
    expect(poolerRequestsFingerprint(same)).not.toBe(
      poolerRequestsFingerprint(poolerRequests({ databases: [databaseA, databaseB] })),
    );
  });
});

describe("publication state", () => {
  const conflicting = poolerRequests({ databases: [databaseA, databaseB], vercelClients: [vercel] });

  test("conflicting requests refuse publication until a common policy is explicitly reviewed", () => {
    // Even a policy that admits everybody's sources is not published without the review.
    const union = evaluatePoolerPolicy({
      requests: conflicting,
      policy: { sourceCidrs: ["198.51.100.0/24", "203.0.113.0/24"], allowInternet: false },
    });
    expect(union).toMatchObject({ status: "review_required", publishable: false, conflict: true });
    const stale = evaluatePoolerPolicy({
      requests: conflicting,
      policy: {
        sourceCidrs: [],
        allowInternet: true,
        internetConfirmedAt: new Date(),
        reviewedAt: new Date(),
        reviewedRequests: poolerRequestsFingerprint(poolerRequests({ databases: [databaseA] })),
      },
    });
    expect(stale.status).toBe("review_required");
    const reviewed = evaluatePoolerPolicy({
      requests: conflicting,
      policy: {
        sourceCidrs: [],
        allowInternet: true,
        internetConfirmedAt: new Date(),
        reviewedAt: new Date(),
        reviewedRequests: poolerRequestsFingerprint(conflicting),
      },
    });
    expect(reviewed).toMatchObject({
      status: "published",
      publishable: true,
      conflict: true,
      reviewed: true,
    });
    // The enforced policy is exactly the saved one: never a silent union of the database CIDRs.
    expect(reviewed.policy.rendered).toEqual(["0.0.0.0/0", "::/0"]);
    expect(reviewed.boundary).toBe(POOLER_POLICY_BOUNDARY);
  });

  test("a single matching request publishes without a separate review", () => {
    const requests = poolerRequests({ databases: [databaseA] });
    const evaluation = evaluatePoolerPolicy({
      requests,
      policy: { sourceCidrs: ["198.51.100.0/24"], allowInternet: false },
    });
    expect(evaluation).toMatchObject({ status: "published", matchesRequests: true });
    expect(evaluation.policy.rendered).toEqual(["198.51.100.0/24"]);
  });

  test("an empty policy denies all; allowInternet needs the owner's confirmation", () => {
    const requests = poolerRequests({ databases: [{ ...databaseA, sourceCidrs: [] }] });
    expect(evaluatePoolerPolicy({ requests, policy: { sourceCidrs: [], allowInternet: false } }).status).toBe(
      "deny_all",
    );
    expect(evaluatePoolerPolicy({ requests, policy: { sourceCidrs: [], allowInternet: true } }).status).toBe(
      "unconfirmed_internet",
    );
    expect(
      evaluatePoolerPolicy({
        requests,
        policy: { sourceCidrs: [], allowInternet: true, internetConfirmedAt: new Date() },
      }).status,
    ).toBe("published");
  });

  test("no public database: nothing is published; a near-open stored list is invalid", () => {
    expect(
      evaluatePoolerPolicy({
        requests: [],
        policy: { sourceCidrs: ["198.51.100.0/24"], allowInternet: false },
      }).status,
    ).toBe("no_public_databases");
    // A Vercel client alone (its database not public) is not a request either.
    expect(poolerRequests({ databases: [], vercelClients: [vercel] })).toEqual([]);
    expect(
      evaluatePoolerPolicy({
        requests: poolerRequests({ databases: [{ ...databaseA, sourceCidrs: ["0.0.0.0/0"] }] }),
        policy: { sourceCidrs: ["0.0.0.0/0"], allowInternet: false },
      }).status,
    ).toBe("invalid_policy");
  });
});

describe("admission reporting", () => {
  test("a B-source connection to database A is answered by the pooler-wide policy, never A's CIDRs", () => {
    const requests = poolerRequests({ databases: [databaseA, databaseB] });
    const evaluation = evaluatePoolerPolicy({
      requests,
      policy: {
        sourceCidrs: ["198.51.100.0/24", "203.0.113.0/24"],
        allowInternet: false,
        reviewedAt: new Date(),
        reviewedRequests: poolerRequestsFingerprint(requests),
      },
    });
    const fromB = poolerAdmission(evaluation, "203.0.113.9");
    expect(fromB).toMatchObject({ allowed: true, scope: "pooler-wide", databaseCidrsEnforced: false });
    expect(fromB.reason).not.toBe("source-not-allowlisted");
    expect(poolerAdmission(evaluation, "192.0.2.1")).toMatchObject({
      allowed: false,
      reason: "source-not-in-pooler-policy",
    });
    // Unpublished: nobody is admitted, whatever the request lists say.
    const unpublished = evaluatePoolerPolicy({
      requests,
      policy: { sourceCidrs: ["198.51.100.0/24"], allowInternet: false },
    });
    expect(poolerAdmission(unpublished, "198.51.100.1")).toMatchObject({
      allowed: false,
      reason: "pooler-review_required",
    });
  });
});

describe("saving the policy", () => {
  test("validation, loosening and the strict request body", () => {
    expect(
      checkPoolerPolicy({ sourceCidrs: [" 203.0.113.0/24 ", "203.0.113.0/24"], allowInternet: false }),
    ).toEqual({
      sourceCidrs: ["203.0.113.0/24"],
      allowInternet: false,
    });
    expect(() => checkPoolerPolicy({ sourceCidrs: ["0.0.0.0/1"], allowInternet: false })).toThrow(
      /allowInternet/,
    );
    expect(
      poolerPolicyLoosens(
        { sourceCidrs: ["203.0.113.0/24"], allowInternet: false },
        { sourceCidrs: [], allowInternet: true },
      ),
    ).toBe(true);
    expect(
      poolerPolicyLoosens(
        { sourceCidrs: ["203.0.113.0/24"], allowInternet: false },
        { sourceCidrs: ["203.0.113.0/24", "198.51.100.0/24"], allowInternet: false },
      ),
    ).toBe(true);
    expect(
      poolerPolicyLoosens(
        { sourceCidrs: ["203.0.113.0/24", "198.51.100.0/24"], allowInternet: false },
        { sourceCidrs: ["203.0.113.0/24"], allowInternet: false },
      ),
    ).toBe(false);
    expect(
      poolerPolicyLoosens(
        { sourceCidrs: [], allowInternet: true },
        { sourceCidrs: ["203.0.113.0/24"], allowInternet: false },
      ),
    ).toBe(false);
    expect(() => poolerPolicyInput.parse({ sourceCidrs: [], allowInternet: true })).toThrow();
    expect(() =>
      poolerPolicyInput.parse({
        sourceCidrs: [],
        allowInternet: true,
        reviewedRequests: "a".repeat(32),
        extra: 1,
      }),
    ).toThrow();
  });
});
