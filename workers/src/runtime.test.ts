import { describe, expect, test } from "bun:test";

import { redactLogLine } from "@ark-stack/shared";

describe("worker log redaction", () => {
  test("strips canary secrets and control characters", () => {
    expect(redactLogLine("password=super-secret\u0007", ["super-secret"])).toBe("password=<redacted>");
  });
});
