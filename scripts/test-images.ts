// The one source of truth for the Bun image the Docker test harnesses and helper containers run.
// It is the same multi-arch index pin as the Dockerfile runtime stage. Places that cannot import it
// (Dockerfiles, docs) keep a literal; scripts/test-images.test.ts fails if any literal differs from
// it, or if any other Bun pin in the repository (mise, packageManager, CI, the Dockerfile's default
// and Alpine stages) names a different Bun version.
export const bunImage =
  "oven/bun:1.4.5-slim@sha256:b780593f3e10918cbdaec3d5a08d52224b9198069a65eb47812085c2ec007643";
