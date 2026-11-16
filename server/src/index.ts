import { assertNoPlaceholderSecrets } from "@ark-stack/shared";

import { loadEnv } from "./env.ts";
import { reconcileDatabaseIngressOnStartup, startCoordinator } from "./coordinator.ts";
import { app } from "./app.ts";
import { startOffhostHeartbeat } from "./modules/offhost-heartbeat.ts";

const env = loadEnv();
assertNoPlaceholderSecrets(process.env);
if (process.env.ARK_BACKUP_REQUIRED === "1" && process.env.ARK_BACKUP_EXECUTE !== "1") {
  throw new Error("ARK_BACKUP_EXECUTE must be 1 when backup execution is required.");
}

if (process.env.ARK_SKIP_LISTEN !== "1") {
  // Queue on every API startup, including external-worker deployments. Fail startup if the
  // reconciliation cannot be recorded; apply errors remain visible as failed operations.
  await reconcileDatabaseIngressOnStartup();
  startOffhostHeartbeat();
  if (env.embeddedWorkers) {
    console.warn("ARK_EMBEDDED_WORKERS is enabled; provider adapters are running inside the API process.");
    startCoordinator();
  }
  Bun.serve({
    port: env.listenPort,
    fetch: app.fetch,
  });
  console.log(`Ark Stack API listening on ${env.listenPort}`);
}
