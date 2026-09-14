export function startOffhostHeartbeat() {
  const url = process.env.ARK_OFFHOST_HEARTBEAT_URL;
  const token = process.env.ARK_OFFHOST_HEARTBEAT_TOKEN;
  if (!url) return null;
  if (!token) throw new Error("ARK_OFFHOST_HEARTBEAT_TOKEN is required when off-host heartbeat is enabled.");
  const parsed = new URL(url);
  if (process.env.NODE_ENV === "production" && parsed.protocol !== "https:") {
    throw new Error("Production off-host heartbeat receivers must use HTTPS.");
  }
  const send = async () => {
    const response = await fetch(parsed, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ source: "ark-stack", status: "alive", at: new Date().toISOString() }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`Off-host heartbeat receiver returned ${response.status}.`);
  };
  void send().catch((error) =>
    console.error(error instanceof Error ? error.message : "Off-host heartbeat failed."),
  );
  return setInterval(() => {
    void send().catch((error) =>
      console.error(error instanceof Error ? error.message : "Off-host heartbeat failed."),
    );
  }, 60_000);
}
