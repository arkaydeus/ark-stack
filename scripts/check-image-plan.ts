import assert from "node:assert/strict";
import { join } from "node:path";

export const imageTargets = [
  "agent",
  "app",
  "app-postgres",
  "backup-worker",
  "database-ingress",
  "database-worker",
  "domain-worker",
  "edge-caddy",
  "edge-watchdog",
  "haproxy-validator",
  "mail-worker",
  "postgres",
];
export const imageSource = "https://github.com/arkaydeus/ark-stack";

type BakeTarget = {
  annotations?: string[];
  attest?: (string | { type?: string; mode?: string; disabled?: boolean })[];
  labels?: Record<string, string>;
};

export function checkImagePlan(plan: {
  group?: { default?: { targets?: string[] } };
  target?: Record<string, BakeTarget>;
}) {
  assert.deepEqual(
    plan.group?.default?.targets?.toSorted(),
    imageTargets,
    "Bake must build all platform images",
  );
  for (const name of imageTargets) {
    const target = plan.target?.[name];
    assert(target, `Missing Bake target ${name}`);
    assert(
      target.annotations?.includes(`index:org.opencontainers.image.source=${imageSource}`),
      `${name}: missing index source annotation`,
    );
    assert.equal(
      target.labels?.["org.opencontainers.image.source"],
      imageSource,
      `${name}: missing source label`,
    );
    assert(
      target.attest?.some((attest) =>
        typeof attest === "string"
          ? attest === "type=provenance,mode=min"
          : attest.type === "provenance" && attest.mode === "min" && !attest.disabled,
      ),
      `${name}: minimal provenance must be enabled`,
    );
  }
}

if (import.meta.main) {
  const child = Bun.spawn(["docker", "buildx", "bake", "--print"], {
    cwd: join(import.meta.dir, ".."),
    stdout: "pipe",
    stderr: "inherit",
  });
  const [code, output] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  assert.equal(code, 0, "Bake --print failed");
  checkImagePlan(JSON.parse(output));
  console.log(
    `All ${imageTargets.length} Bake targets retain index source annotations and minimal provenance.`,
  );
}
