import { afterEach, describe, expect, test } from "bun:test";

import { applyStalwartDevice } from "./providers.ts";

const originalFetch = globalThis.fetch;
const originalUrl = process.env.STALWART_URL;

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalUrl === undefined) delete process.env.STALWART_URL;
  else process.env.STALWART_URL = originalUrl;
});

describe("native Stalwart device credentials", () => {
  test("accepts only a native app-password id and one-time secret", async () => {
    process.env.STALWART_URL = "http://stalwart:8080";
    globalThis.fetch = (async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as { methodCalls: unknown[][] };
      expect(request.methodCalls[0]?.[0]).toBe("x:AppPassword/set");
      return Response.json({
        methodResponses: [
          ["x:AppPassword/set", { created: { device: { id: "native-1", secret: "once" } } }, "op"],
        ],
      });
    }) as typeof fetch;
    expect(
      await applyStalwartDevice({
        address: "owner@example.com",
        password: "primary",
        action: "create",
        label: "phone",
      }),
    ).toEqual({ nativeId: "native-1", secret: "once" });
  });

  test("fails partial native application instead of reporting success", async () => {
    process.env.STALWART_URL = "http://stalwart:8080";
    globalThis.fetch = (async () =>
      Response.json({
        methodResponses: [
          ["x:AppPassword/set", { notCreated: { device: { type: "invalidProperties" } } }, "op"],
        ],
      })) as unknown as typeof fetch;
    await expect(
      applyStalwartDevice({
        address: "owner@example.com",
        password: "primary",
        action: "create",
        label: "phone",
      }),
    ).rejects.toThrow(/native ID/);
  });
});
