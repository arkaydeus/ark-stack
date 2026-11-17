import { expect, test } from "bun:test";

import { createLoginHostCache } from "./origin-hosts.ts";

test("login-host read failure clears gate trust and retries without waiting for the TTL", async () => {
  let fail = false;
  let clock = 0;
  const cache = createLoginHostCache(
    async () => {
      if (fail) throw new Error("settings unavailable");
      return "login.example.test";
    },
    () => clock,
  );
  expect(await cache.refresh()).toBe("login.example.test");
  fail = true;
  clock = 5_001;
  await expect(cache.refresh()).rejects.toThrow("settings unavailable");
  expect(cache.current()).toBeNull();
  fail = false;
  expect(await cache.refresh()).toBe("login.example.test");
});

test("a forced refresh reads after an older in-flight read and concurrent requests join it", async () => {
  let release!: (host: string) => void;
  let calls = 0;
  const cache = createLoginHostCache(async () => {
    calls++;
    if (calls === 1)
      return new Promise<string>((resolve) => {
        release = resolve;
      });
    return "new.example.test";
  });
  const old = cache.refresh();
  await Promise.resolve();
  const forced = cache.refresh(true);
  const joined = cache.refresh();
  expect(calls).toBe(1);
  release("old.example.test");
  expect(await old).toBe("old.example.test");
  expect(await forced).toBe("new.example.test");
  expect(await joined).toBe("new.example.test");
  expect(cache.current()).toBe("new.example.test");
  expect(calls).toBe(2);
});

test("a forced refresh recovers after an in-flight failure", async () => {
  let reject!: (error: Error) => void;
  let calls = 0;
  const cache = createLoginHostCache(async () => {
    if (++calls === 1)
      return new Promise<string>((_, fail) => {
        reject = fail;
      });
    return null;
  });
  const old = cache.refresh();
  await Promise.resolve();
  const forced = cache.refresh(true);
  reject(new Error("database unavailable"));
  await expect(old).rejects.toThrow("database unavailable");
  expect(await forced).toBeNull();
  expect(calls).toBe(2);
});
