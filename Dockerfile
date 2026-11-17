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

FROM restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510 AS restic

FROM runtime AS backup-worker
USER root
# pgBackRest stays for the isolated restore runner; backups themselves run in the PostgreSQL images'
# executors (FD-21). restic is the pinned upstream static binary, not Debian's older package.
RUN apt-get update \
  && apt-get install -y --no-install-recommends pgbackrest \
  && rm -rf /var/lib/apt/lists/*
COPY --from=restic /usr/bin/restic /usr/local/bin/restic
USER bun

# pgBackRest executor bundle for the PostgreSQL images (docs/design/front-door.md §3.18.1, FD-21). It
# imports only shared/src/pg-backup.ts, so it builds without the workspace dependencies.
FROM oven/bun:1.4.2@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895 AS pg-executor-build
WORKDIR /src
COPY shared/src/pg-backup.ts shared/src/pg-backup.ts
COPY workers/src/pg-executor.ts workers/src/pg-executor.ts
RUN bun build workers/src/pg-executor.ts --target=bun --outfile=/out/pg-executor.js

# Platform cluster (`postgres`): the pinned upstream image plus pgBackRest (PGDG, pinned per Debian
# release), the executor and the fenced archive_command. Debian's /etc/pgbackrest.conf declares a
# repo1 at /var/lib/pgbackrest; it is removed so the encrypted posix repo2 is the only repository.
FROM postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929 AS postgres-backup
ARG PGBACKREST_VERSION=2.60.0-1.pgdg13+1
RUN apt-get update \
  && apt-get install -y --no-install-recommends "pgbackrest=${PGBACKREST_VERSION}" \
  && rm -rf /var/lib/apt/lists/* /etc/pgbackrest.conf \
  && mkdir -p /etc/pgbackrest && printf '[global]\n' > /etc/pgbackrest/pgbackrest.conf
COPY --from=oven/bun:1.4.2@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895 /usr/local/bin/bun /usr/local/bin/bun
COPY --from=pg-executor-build /out/pg-executor.js /opt/ark/pg-executor.js
COPY infra/backup/ark-postgres-entrypoint.sh /usr/local/bin/ark-postgres-entrypoint
ENV PGBACKREST_REPO2_TYPE=posix \
  PGBACKREST_REPO2_PATH=/var/lib/pgbackrest/repo2 \
  PGBACKREST_REPO2_CIPHER_TYPE=aes-256-cbc \
  PGBACKREST_REPO2_RETENTION_FULL=9999999 \
  PGBACKREST_EXPIRE_AUTO=n \
  PGBACKREST_PG1_PATH=/var/lib/postgresql/data \
  PGBACKREST_PG1_SOCKET_PATH=/var/run/postgresql \
  PGBACKREST_START_FAST=y \
  PGBACKREST_LOG_LEVEL_FILE=off \
  PGBACKREST_LOG_LEVEL_CONSOLE=warn \
  PGBACKREST_LOCK_PATH=/tmp/pgbackrest
ENTRYPOINT ["/usr/local/bin/ark-postgres-entrypoint"]
CMD ["postgres"]

# App cluster (`app-postgres`): the same layer on the pinned pgvector image (Debian 12).
FROM pgvector/pgvector:pg17@sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f AS app-postgres-backup
ARG PGBACKREST_VERSION=2.60.0-1.pgdg12+1
RUN apt-get update \
  && apt-get install -y --no-install-recommends "pgbackrest=${PGBACKREST_VERSION}" \
  && rm -rf /var/lib/apt/lists/* /etc/pgbackrest.conf \
  && mkdir -p /etc/pgbackrest && printf '[global]\n' > /etc/pgbackrest/pgbackrest.conf
COPY --from=oven/bun:1.4.2@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895 /usr/local/bin/bun /usr/local/bin/bun
COPY --from=pg-executor-build /out/pg-executor.js /opt/ark/pg-executor.js
COPY infra/backup/ark-postgres-entrypoint.sh /usr/local/bin/ark-postgres-entrypoint
ENV PGBACKREST_REPO2_TYPE=posix \
  PGBACKREST_REPO2_PATH=/var/lib/pgbackrest/repo2 \
  PGBACKREST_REPO2_CIPHER_TYPE=aes-256-cbc \
  PGBACKREST_REPO2_RETENTION_FULL=9999999 \
  PGBACKREST_EXPIRE_AUTO=n \
  PGBACKREST_PG1_PATH=/var/lib/postgresql/data \
  PGBACKREST_PG1_SOCKET_PATH=/var/run/postgresql \
  PGBACKREST_START_FAST=y \
  PGBACKREST_LOG_LEVEL_FILE=off \
  PGBACKREST_LOG_LEVEL_CONSOLE=warn \
  PGBACKREST_LOCK_PATH=/tmp/pgbackrest
ENTRYPOINT ["/usr/local/bin/ark-postgres-entrypoint"]
CMD ["postgres"]

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
