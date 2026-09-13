export async function poll(kindPrefix: string) {
  const token = process.env.ARK_INTERNAL_TOKEN;
  const base = process.env.ARK_API_URL ?? "http://127.0.0.1:3000";
  if (!token) throw new Error("ARK_INTERNAL_TOKEN is required for workers.");
  const response = await fetch(`${base}/api/internal/jobs`, {
    headers: { authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error(`Worker poll failed: ${response.status}`);
  const body = (await response.json()) as { jobs: Array<{ id: string; kind: string }> };
  return body.jobs.filter((job) => job.kind.startsWith(kindPrefix));
}

export async function runWorker(name: string, prefix: string) {
  console.log(`${name} worker polling`);
  const tick = async () => {
    const jobs = await poll(prefix);
    if (jobs.length)
      console.log(
        `${name} saw ${jobs.length} queued jobs; the API coordinator executes adapters and records evidence.`,
      );
  };
  await tick();
  setInterval(
    () => void tick().catch((error) => console.error(error instanceof Error ? error.message : error)),
    4000,
  );
}
