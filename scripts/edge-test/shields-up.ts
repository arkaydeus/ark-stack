/** Proves inbound refusal is caused by shields-up, rather than a missing policy grant or route. */
export async function verifyShieldsUp({
  setShieldsUp,
  connect,
  waitUntilConnected,
}: {
  setShieldsUp: (enabled: boolean) => Promise<unknown>;
  connect: () => Promise<string>;
  waitUntilConnected: () => Promise<unknown>;
}) {
  try {
    await setShieldsUp(false);
    // A real peer-to-edge connection is required before a negative result can prove anything.
    await waitUntilConnected();
  } finally {
    // Restore the shipped setting even if the positive control or preference change fails.
    await setShieldsUp(true);
  }
  if ((await connect()) !== "no connection") {
    throw new Error("FAILED: with --shields-up, a tailnet peer can still connect to the edge node.");
  }
}
