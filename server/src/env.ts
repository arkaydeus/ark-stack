function required(name: string, min = 1) {
  const value = process.env[name] ?? "";
  if (value.length < min)
    throw new Error(`${name} must be set${min > 1 ? ` and at least ${min} characters` : ""}`);
  return value;
}

export function loadEnv() {
  const workerRuntime = process.env.ARK_RUNTIME_ROLE === "worker";
  const apiSecret = (name: string, min = 1) =>
    workerRuntime ? (process.env[name] ?? `unused-by-worker-${name.toLowerCase()}`) : required(name, min);
  return {
    databaseUrl: required("DATABASE_URL"),
    authSecret: apiSecret("BETTER_AUTH_SECRET", 32),
    authUrl: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
    trustedOrigins: (process.env.BETTER_AUTH_TRUSTED_ORIGINS ?? "http://localhost:5173")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    trustedProxies: (process.env.ARK_TRUSTED_PROXIES ?? "127.0.0.1/32,::1/128")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    rootKey: required("ARK_ROOT_KEY", 32),
    rootKeyId: process.env.ARK_ROOT_KEY_ID ?? "k1",
    setupToken: apiSecret("ARK_SETUP_TOKEN"),
    internalToken: apiSecret("ARK_INTERNAL_TOKEN"),
    workerTokens: {
      database: process.env.ARK_DATABASE_WORKER_TOKEN ?? apiSecret("ARK_INTERNAL_TOKEN"),
      domains: process.env.ARK_DOMAIN_WORKER_TOKEN ?? apiSecret("ARK_INTERNAL_TOKEN"),
      mail: process.env.ARK_MAIL_WORKER_TOKEN ?? apiSecret("ARK_INTERNAL_TOKEN"),
      backup: process.env.ARK_BACKUP_WORKER_TOKEN ?? apiSecret("ARK_INTERNAL_TOKEN"),
    },
    agentToken: apiSecret("ARK_AGENT_TOKEN"),
    maintenanceToken: process.env.ARK_MAINTENANCE_TOKEN ?? "",
    metricsToken:
      process.env.ARK_METRICS_TOKEN ??
      (process.env.NODE_ENV === "production"
        ? apiSecret("ARK_METRICS_TOKEN")
        : apiSecret("ARK_INTERNAL_TOKEN")),
    embeddedWorkers: process.env.NODE_ENV !== "production" && process.env.ARK_EMBEDDED_WORKERS === "1",
    listenPort: Number(process.env.ARK_LISTEN_PORT ?? process.env.PORT ?? 3000),
    dnsStub: process.env.ARK_DNS_STUB === "1",
    appDatabaseUrl: process.env.DATABASE_APP_URL ?? "",
    certDir: process.env.ARK_CERT_DIR ?? "",
    composeDir: process.env.ARK_COMPOSE_DIR ?? "",
  };
}

export type Env = ReturnType<typeof loadEnv>;
