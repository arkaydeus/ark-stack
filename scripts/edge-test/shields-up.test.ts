import { expect, test } from "bun:test";

import { verifyShieldsUp } from "./shields-up.ts";

test("requires a positive control before claiming shields-up blocked the peer", async () => {
  const events: string[] = [];
  await verifyShieldsUp({
    setShieldsUp: async (enabled) => {
      events.push(`shields:${enabled}`);
    },
    waitUntilConnected: async () => {
      events.push("connected");
    },
    connect: async () => {
      events.push("blocked");
      return "no connection";
    },
  });
  expect(events).toEqual(["shields:false", "connected", "shields:true", "blocked"]);
});

test("an unreachable peer fails the check and restores shields-up", async () => {
  const settings: boolean[] = [];
  await expect(
    verifyShieldsUp({
      setShieldsUp: async (enabled) => {
        settings.push(enabled);
      },
      waitUntilConnected: async () => {
        throw new Error("missing policy grant");
      },
      connect: async () => {
        throw new Error("negative check must not run");
      },
    }),
  ).rejects.toThrow(/missing policy grant/);
  expect(settings).toEqual([false, true]);
});

test("a peer that can still connect with shields-up fails", async () => {
  await expect(
    verifyShieldsUp({
      setShieldsUp: async () => {},
      waitUntilConnected: async () => {},
      connect: async () => "connected",
    }),
  ).rejects.toThrow(/can still connect/);
});

test("preference changes that fail cannot produce a successful security claim", async () => {
  const settings: boolean[] = [];
  await expect(
    verifyShieldsUp({
      setShieldsUp: async (enabled) => {
        settings.push(enabled);
        if (!enabled) throw new Error("set failed");
      },
      waitUntilConnected: async () => {
        throw new Error("must not connect");
      },
      connect: async () => "no connection",
    }),
  ).rejects.toThrow(/set failed/);
  expect(settings).toEqual([false, true]);
});
