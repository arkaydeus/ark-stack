function required(name: string, min = 1) {
  const value = process.env[name] ?? "";
  if (value.length < min)
    throw new Error(`${name} must be set${min > 1 ? ` and at least ${min} characters` : ""}`);
  return value;
}

export function loadEnv() {
  return {
    databaseUrl: required("DATABASE_URL"),
    authSecret: required("BETTER_AUTH_SECRET", 32),
    authUrl: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
    trustedOrigins: (process.env.BETTER_AUTH_TRUSTED_ORIGINS ?? "http://localhost:5173")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    rootKey: required("ARK_ROOT_KEY", 32),
    rootKeyId: process.env.ARK_ROOT_KEY_ID ?? "k1",
    setupToken: required("ARK_SETUP_TOKEN"),
    internalToken: required("ARK_INTERNAL_TOKEN"),
    agentToken: required("ARK_AGENT_TOKEN"),
    maintenanceToken: process.env.ARK_MAINTENANCE_TOKEN ?? "",
    embeddedWorkers: process.env.ARK_EMBEDDED_WORKERS !== "0",
    listenPort: Number(process.env.ARK_LISTEN_PORT ?? process.env.PORT ?? 3000),
    dnsStub: process.env.ARK_DNS_STUB === "1",
    appDatabaseUrl: process.env.DATABASE_APP_URL ?? "",
    certDir: process.env.ARK_CERT_DIR ?? "",
    composeDir: process.env.ARK_COMPOSE_DIR ?? "",
  };
}

export type Env = ReturnType<typeof loadEnv>;
