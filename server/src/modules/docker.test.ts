import { describe, expect, test } from "bun:test";

import { childProcessEnv } from "./docker.ts";

describe("docker child environment", () => {
  test("preserves DOCKER_HOST for remote endpoints", () => {
    const previous = process.env.DOCKER_HOST;
    process.env.DOCKER_HOST = "unix:///tmp/custom.sock";
    try {
      expect(childProcessEnv().DOCKER_HOST).toBe("unix:///tmp/custom.sock");
    } finally {
      if (previous === undefined) delete process.env.DOCKER_HOST;
      else process.env.DOCKER_HOST = previous;
    }
  });
});
