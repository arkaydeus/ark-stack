import { describe, expect, test } from "bun:test";

import { transition, staleObservation } from "./operations.ts";
import { classifySql, assertAliasGraph } from "./sql-guard.ts";
import { postgresIdent } from "./hostnames.ts";

describe("operations and guards", () => {
  test("rejects illegal operation transitions", () => {
    expect(() => transition("succeeded", "running")).toThrow(/cannot move/);
    expect(transition("queued", "running")).toBe("running");
  });

  test("stale observations are not healthy", () => {
    expect(staleObservation(null)).toBe(true);
    expect(staleObservation(new Date(Date.now() - 120_000))).toBe(true);
    expect(staleObservation(new Date())).toBe(false);
  });

  test("SQL workspace stays read-only by default", () => {
    expect(classifySql("select 1", true).writes).toBe(false);
    expect(() => classifySql("delete from orders", true)).toThrow(/read-only/);
    expect(() => classifySql("select 1; drop table x", true)).toThrow(/Multiple/);
  });

  test("alias loops are rejected", () => {
    expect(() =>
      assertAliasGraph([
        { address: "a@example.com", targets: ["b@example.com"] },
        { address: "b@example.com", targets: ["a@example.com"] },
      ]),
    ).toThrow(/loop/);
  });

  test("runtime identifiers stay within PostgreSQL limits", () => {
    expect(postgresIdent("orders", "_runtime")).toBe("orders_runtime");
    expect(() => postgresIdent("x".repeat(60), "_runtime")).toThrow(/exceeds/);
  });
});
