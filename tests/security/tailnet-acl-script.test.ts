// The opt-in scratch-tailnet check (scripts/test-tailnet-acl.ts, FD-07) must skip cleanly without
// credentials, and must judge Tailscale's validate responses correctly. A local stand-in for
// `POST /api/v2/tailnet/{tailnet}/acl/validate` evaluates the posted policy's tests with the same
// evaluator the unit tests use, so the script's request shape and verdicts are covered without a
// real tailnet.

import { afterAll, describe, expect, test } from "bun:test";
import { join } from "node:path";

import { evaluatePolicyTests, parseHujson, type TailnetPolicy } from "../../shared/src/tailnet-acl.ts";

const script = join(import.meta.dir, "..", "..", "scripts", "test-tailnet-acl.ts");
const requests: Array<{ path: string; auth: string | null; type: string | null }> = [];

function serve(mode: "evaluate" | "accept-all") {
  return Bun.serve({
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      requests.push({
        path: url.pathname,
        auth: request.headers.get("authorization"),
        type: request.headers.get("content-type"),
      });
      if (request.headers.get("authorization") !== "Bearer tskey-api-test") {
        return Response.json({ message: "invalid token" }, { status: 401 });
      }
      const policy = parseHujson(await request.text()) as TailnetPolicy;
      const failures = mode === "evaluate" ? evaluatePolicyTests(policy) : [];
      if (!failures.length) return new Response("", { status: 200 });
      return Response.json({
        message: "test(s) failed",
        data: failures.map((item) => ({
          user: item.src,
          errors: [`address "${item.destination}": want: ${item.expected === "deny" ? "Drop" : "Accept"}`],
        })),
      });
    },
  });
}

const servers: Array<ReturnType<typeof Bun.serve>> = [];
afterAll(() => {
  for (const server of servers) server.stop(true);
});

async function run(env: Record<string, string | undefined>) {
  const child = Bun.spawn(["bun", script], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { stdout, stderr, code };
}

describe("scripts/test-tailnet-acl.ts", () => {
  test("skips cleanly with exit 0 when ARK_TEST_TS_POLICY_API_KEY is unset", async () => {
    const result = await run({});
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("test:tailnet-acl skipped");
  });

  test("passes when the snippet validates and the broad rules are rejected by its tests", async () => {
    const server = serve("evaluate");
    servers.push(server);
    requests.length = 0;
    const result = await run({
      ARK_TEST_TS_POLICY_API_KEY: "tskey-api-test",
      ARK_TEST_TS_TAILNET: "example.com",
      ARK_TEST_TS_API_URL: `http://127.0.0.1:${server.port}`,
    });
    expect(result.stderr).toBe("");
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("all 4 checks passed");
    expect(requests).toHaveLength(4);
    expect(requests.every((item) => item.path === "/api/v2/tailnet/example.com/acl/validate")).toBe(true);
    expect(requests[0]?.type).toBe("application/hujson");
  });

  test("fails when Tailscale would accept the broad rule", async () => {
    const server = serve("accept-all");
    servers.push(server);
    const result = await run({
      ARK_TEST_TS_POLICY_API_KEY: "tskey-api-test",
      ARK_TEST_TS_API_URL: `http://127.0.0.1:${server.port}`,
    });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("2 of 4 checks failed");
  });

  test("fails fast when the token is refused", async () => {
    const server = serve("evaluate");
    servers.push(server);
    const result = await run({
      ARK_TEST_TS_POLICY_API_KEY: "tskey-api-wrong",
      ARK_TEST_TS_API_URL: `http://127.0.0.1:${server.port}`,
    });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("the API refused the token (401");
  });
});
