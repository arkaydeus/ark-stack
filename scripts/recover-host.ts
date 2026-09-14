import { hostLossChecklist } from "@ark-stack/shared";

const ready = {
  rootKey: Boolean(process.env.ARK_ROOT_KEY),
  databaseUrl: Boolean(process.env.DATABASE_URL),
  authSecret: Boolean(process.env.BETTER_AUTH_SECRET),
  setupToken: Boolean(process.env.ARK_SETUP_TOKEN),
};

console.log(
  JSON.stringify(
    {
      ready,
      checklist: hostLossChecklist,
      restore: {
        isolatedCompose: "infra/restore/docker-compose.yml",
        execute: process.env.ARK_BACKUP_EXECUTE === "1",
        warning:
          "Do not boot a duplicate Tailscale identity. Disable reconciliation, outbound mail, and public ingress until verification completes.",
      },
    },
    null,
    2,
  ),
);

if (!ready.rootKey || !ready.databaseUrl) process.exit(1);
