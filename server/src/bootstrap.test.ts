import { describe, expect, test } from "bun:test";

import { secureEqual } from "@ark-stack/shared";

describe("bootstrap token comparison", () => {
  test("rejects mismatched setup tokens without leaking length usefulness", () => {
    expect(secureEqual("aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb")).toBe(false);
    expect(secureEqual("short", "different-length")).toBe(false);
    expect(secureEqual("same-token-value", "same-token-value")).toBe(true);
  });
});
