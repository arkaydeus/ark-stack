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

FROM runtime AS mail-worker
