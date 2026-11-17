#!/bin/sh
# Entrypoint of the Ark PostgreSQL images (docs/design/front-door.md §3.18.1, FD-21).
#
# With a repo2 cipher pass and valid executor token configured it turns on WAL archiving into the encrypted local pgBackRest
# repo2. archive-push holds the executor lock shared: while a stage copies the repository (exclusive)
# it waits, then fails after 60 s, and PostgreSQL keeps the segment in pg_wal and retries, so WAL is
# fenced, never dropped (pgBackRest requires the literal `pgbackrest` in archive_command). It also supervises the pgBackRest executor as `postgres`.
# Without one, archiving stays off and backup health reports the cluster as not backed up: WAL is
# never accepted by an archive_command that cannot store it.
set -eu

: "${ARK_PG_STANZA:?ARK_PG_STANZA names the pgBackRest stanza for this cluster}"
ARK_PG_EXECUTOR_TOKEN="${ARK_PG_EXECUTOR_TOKEN:-}"
export PGBACKREST_PG1_USER="${PGBACKREST_PG1_USER:-${POSTGRES_USER:-postgres}}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p /var/lib/pgbackrest/repo2 /var/lib/pgbackrest-staging /var/log/pgbackrest /tmp/pgbackrest
  chown postgres:postgres /var/lib/pgbackrest /var/lib/pgbackrest/repo2 /var/lib/pgbackrest-staging /var/log/pgbackrest /tmp/pgbackrest
  # Group-readable for the restic exporter, which reads staged copies through the postgres group.
  chmod 0750 /var/lib/pgbackrest /var/lib/pgbackrest/repo2 /var/lib/pgbackrest-staging
fi

if [ "${1:-postgres}" = "postgres" ] && [ -n "${PGBACKREST_REPO2_CIPHER_PASS:-}" ] && [ "${#ARK_PG_EXECUTOR_TOKEN}" -ge 24 ]; then
  [ "$#" -eq 0 ] && set -- postgres
  set -- "$@" \
    -c wal_level=replica \
    -c archive_mode=on \
    -c "archive_command=flock -s -w 60 /var/lib/pgbackrest/ark-executor.lock pgbackrest --stanza=${ARK_PG_STANZA} archive-push %p" \
    -c "archive_timeout=${ARK_PG_ARCHIVE_TIMEOUT:-60}"
  # Double fork: the supervisor is re-parented to the container init (Compose `init: true`), never
  # to the postmaster, which must not see unknown children.
  ( (
    while :; do
      gosu postgres bun /opt/ark/pg-executor.js || true
      sleep 2
    done
  ) & )
elif [ "${1:-postgres}" = "postgres" ]; then
  echo "ark-postgres: a cipher pass and executor token of at least 24 characters are required; WAL archiving and backups are disabled" >&2
fi

exec docker-entrypoint.sh "$@"
