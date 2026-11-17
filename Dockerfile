FROM oven/bun:1.4.2@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895 AS build
WORKDIR /app
COPY package.json bun.lock bunfig.toml tsconfig.base.json ./
COPY shared/package.json shared/package.json
COPY server/package.json server/package.json
COPY web/package.json web/package.json
COPY workers/package.json workers/package.json
RUN bun install --frozen-lockfile
COPY shared shared
COPY server server
COPY web web
COPY workers workers
COPY scripts scripts
RUN bun run --cwd web build
# The restricted HAProxy validator runs on the HAProxy (Alpine) image, so it ships as one bundle.
RUN bun build workers/src/haproxy-validator.ts --target=bun --outfile=/app/dist/haproxy-validator.js

FROM oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61 AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build --chown=bun:bun /app /app
USER bun
CMD ["bun", "run", "--cwd", "server", "start"]

FROM runtime AS database-worker
USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends nftables \
  && rm -rf /var/lib/apt/lists/*
USER bun

FROM database-worker AS database-ingress
USER root

FROM runtime AS backup-worker
USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends pgbackrest restic \
  && rm -rf /var/lib/apt/lists/*
USER bun

FROM goacme/lego:v4.26.0@sha256:39e65153badce8c67fa16caed2f89ebb15db5747ffbbd502603ce0bbaf2ed218 AS lego

FROM runtime AS domain-worker
USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl \
  && rm -rf /var/lib/apt/lists/*
COPY --from=lego /lego /usr/local/bin/lego
USER bun

# Edge-local lease watchdog (docs/design/front-door.md §3.2, FD-06): the runtime image with nothing
# added. It runs as `bun` with no capabilities, database credential or socket mounts.
FROM runtime AS edge-watchdog

# Restricted HAProxy configuration validator (docs/design/front-door.md §3.8.6, FD-25). The base is the
# exact edge-l4 image digest, so `haproxy -c` runs the same HAProxy and OpenSSL build that serves.
# Bun (musl build) runs the socket daemon as the image's non-root `haproxy` user (uid 99).
FROM oven/bun:1.4.2-alpine@sha256:d888c0ae6c86d7866ff10c5aafdd9077b36aee6455b33dd270fb93c0dd5cef6f AS bun-alpine

FROM haproxy:3.2.26-alpine@sha256:1c3568e520453cc8ba98c39501febcf450429c80e6cc27ecad779961d76e597c AS haproxy-validator
USER root
RUN apk add --no-cache libstdc++ libgcc
COPY --from=bun-alpine /usr/local/bin/bun /usr/local/bin/bun
COPY --from=build /app/dist/haproxy-validator.js /opt/ark/haproxy-validator.js
USER haproxy
ENTRYPOINT ["/usr/local/bin/bun", "/opt/ark/haproxy-validator.js"]
CMD []

# Keep mail-worker last: Compose services that build without a target (api, migrate) use the last stage.
FROM runtime AS mail-worker
