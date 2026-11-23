FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d AS build
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

FROM oven/bun:1.4.4-slim@sha256:1846adf22496bd711036aae8be147e57bdebbaea2e5264e3e0b5af1db187d9a4 AS runtime
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
FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d AS pg-executor-build
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
COPY --from=oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d /usr/local/bin/bun /usr/local/bin/bun
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
COPY --from=oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d /usr/local/bin/bun /usr/local/bin/bun
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
FROM oven/bun:1.4.4-alpine@sha256:4cf82f5686b196504fe119db3fcd9185b191f82ece82c40680e597228ec6070a AS bun-alpine

FROM haproxy:3.2.26-alpine@sha256:1c3568e520453cc8ba98c39501febcf450429c80e6cc27ecad779961d76e597c AS haproxy-validator
USER root
RUN apk add --no-cache libstdc++ libgcc
COPY --from=bun-alpine /usr/local/bin/bun /usr/local/bin/bun
COPY --from=build /app/dist/haproxy-validator.js /opt/ark/haproxy-validator.js
USER haproxy
ENTRYPOINT ["/usr/local/bin/bun", "/opt/ark/haproxy-validator.js"]
CMD []

# Edge Caddy (docs/design/front-door.md FD-23): the pinned official Caddy 2.11.9 image, with its binary
# replaced by an xcaddy build of the same Caddy release plus github.com/mholt/caddy-ratelimit (an
# unofficial plugin) for HTTP route rate limits. The builder is the official 2.11.9 builder by digest.
# The plugin is pinned to one tagged version; Go verifies every module against the checksum database,
# and the build checks the expected upstream module hash before applying the local memory budget.
# The binary reports v2.11.9 and carries the rate_limit handler. The filesystem, users and file
# capability come from the official image. The bump procedure is in docs/operating.md ("Third-party image pins").
FROM caddy:2.11.9-builder@sha256:f9beaa5ddbe7df6f26ebbcf9cbf44e05a1917b9bba464f0c3229038d7e2e6e13 AS edge-caddy-build
ARG CADDY_VERSION=v2.11.9
ARG CADDY_RATELIMIT_MODULE=github.com/mholt/caddy-ratelimit
ARG CADDY_RATELIMIT_VERSION=v0.1.0
ARG CADDY_RATELIMIT_SUM=h1:73lOvdSLSoBGPT5l61nrTzh9liax+IDfXeQDtfzNcZ4=
# The capability is set in the runtime stage, as the official image does.
ENV XCADDY_SETCAP=0
COPY infra/edge-caddy/ /build/ark-edge-caddy/
RUN set -eu; \
  module="$(go mod download -json "$CADDY_RATELIMIT_MODULE@$CADDY_RATELIMIT_VERSION")"; \
  sum="$(echo "$module" | awk -F '"' '/"Sum":/ { print $4 }')"; \
  test "$sum" = "$CADDY_RATELIMIT_SUM"; \
  source="$(echo "$module" | awk -F '"' '/"Dir":/ { print $4 }')"; \
  cp -R "$source" /build/ark-bounded-ratelimit; chmod -R u+w /build/ark-bounded-ratelimit; \
  git -C /build/ark-bounded-ratelimit apply --unidiff-zero /build/ark-edge-caddy/ratelimit-budget.patch; \
  cp /build/ark-edge-caddy/ratelimit-budget_test.go /build/ark-bounded-ratelimit/; \
  (cd /build/ark-bounded-ratelimit; go mod edit -require "github.com/caddyserver/caddy/v2@$CADDY_VERSION"; \
    go test -mod=mod -run "^TestArkRateLimitBudget$" .); \
  xcaddy build "$CADDY_VERSION" --with "$CADDY_RATELIMIT_MODULE@$CADDY_RATELIMIT_VERSION=/build/ark-bounded-ratelimit" --output /out/caddy; \
  /out/caddy version | grep -q "^$CADDY_VERSION "; \
  /out/caddy list-modules | grep -qx http.handlers.rate_limit

FROM caddy:2.11.9@sha256:4e2425f6009577e7c651010f16679c28f7d12df3e7b1914f941a7a3370746b3c AS edge-caddy
COPY --from=edge-caddy-build /out/caddy /usr/bin/caddy
RUN setcap cap_net_bind_service=p /usr/bin/caddy && caddy version | grep -q '^v2.11.9 ' \
  && caddy list-modules | grep -qx http.handlers.rate_limit

# Keep mail-worker last: Compose services that build without a target (api, migrate) use the last stage.
FROM runtime AS mail-worker
