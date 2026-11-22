// The one source of truth for the Bun image the Docker test harnesses and helper containers run.
// It is the same multi-arch index pin as the Dockerfile runtime stage. Places that cannot import it
// (Dockerfiles, docs) keep a literal; scripts/test-images.test.ts fails if any literal differs from
// it, or if any other Bun pin in the repository (mise, packageManager, CI, the Dockerfile's default
// and Alpine stages) names a different Bun version.
export const bunImage =
  "oven/bun:1.4.4-slim@sha256:1846adf22496bd711036aae8be147e57bdebbaea2e5264e3e0b5af1db187d9a4";
