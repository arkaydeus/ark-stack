#!/bin/sh
set -eu

psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=runtime_password="$ARK_API_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE ark_runtime LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE', :'runtime_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ark_runtime') \gexec
SELECT format('ALTER ROLE ark_runtime WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE', :'runtime_password') \gexec
SQL
