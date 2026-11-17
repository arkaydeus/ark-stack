// FD-30: the shipped Compose definition keeps backup-ts's LocalAPI and SOCKS5 proxy away from every
// service but the backup worker, and sets no process-wide proxy anywhere (tailnet-compose.ts).
import { expect, test } from "bun:test";

import { loadCompose, tailnetComposeClaims } from "./tailnet-compose.ts";

test("backup-ts isolation and proxy scoping in infra/platform/docker-compose.yml", async () => {
  const claims = tailnetComposeClaims(await loadCompose());
  expect(claims.length).toBeGreaterThanOrEqual(12);
  expect(claims.filter((item) => !item.ok)).toEqual([]);
});

test("a proxy variable on any service, or a socket mount on the API, is caught", async () => {
  const compose = await loadCompose();
  const tampered = structuredClone(compose);
  (tampered.services["backup-worker"]!.environment as Record<string, string>).HTTP_PROXY =
    "socks5://backup-ts:1055";
  tampered.services.api!.volumes = [...(tampered.services.api!.volumes ?? []), "ark_backup_ts_socket:/x:ro"];
  const failed = tailnetComposeClaims(tampered)
    .filter((item) => !item.ok)
    .map((item) => item.claim);
  expect(failed).toContain(
    "no service sets a process-wide proxy variable (S3, API and executor calls are never proxied)",
  );
  expect(failed).toContain("api cannot read backup-ts's LocalAPI (no socket mount)");
});
