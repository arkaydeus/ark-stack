export function pgbouncerConfig(input: {
  mappings: Array<{ database: string; host: string }>;
  poolMode?: "transaction" | "session";
  listenPort?: number;
  certificateDir?: string;
}) {
  const databases = input.mappings
    .map((item) => `${item.database} = host=${item.host} dbname=${item.database}`)
    .join("\n");
  return `[databases]
${databases}

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = ${input.listenPort ?? 5432}
auth_type = scram-sha-256
auth_file = /var/lib/ark/pgbouncer/userlist.txt
pool_mode = ${input.poolMode ?? "transaction"}
ignore_startup_parameters = extra_float_digits
client_tls_sslmode = require
client_tls_cert_file = ${input.certificateDir ?? "/var/lib/ark/certs/database"}/fullchain.pem
client_tls_key_file = ${input.certificateDir ?? "/var/lib/ark/certs/database"}/privkey.pem
# Backend traffic stays on the isolated database-management bridge, which is not
# published. Client TLS remains required at the public ingress boundary.
server_tls_sslmode = disable
max_client_conn = 200
default_pool_size = 20
admin_users =
`;
}

export function pgbouncerUserlist(users: Array<{ name: string; password: string }>) {
  return users
    .filter((user) => !/_(owner|migration|backup|monitor)$/.test(user.name))
    .map((user) => `"${user.name}" "${user.password}"`)
    .join("\n");
}

export function authQuerySql() {
  return `
CREATE SCHEMA IF NOT EXISTS pgbouncer;
REVOKE ALL ON SCHEMA pgbouncer FROM PUBLIC;
CREATE OR REPLACE FUNCTION pgbouncer.user_lookup(IN i_username text, OUT uname text, OUT phash text)
RETURNS record
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pgbouncer, pg_temp
AS $$
BEGIN
  SELECT usename, passwd INTO uname, phash FROM pg_catalog.pg_shadow WHERE usename = i_username;
END;
$$;
REVOKE ALL ON FUNCTION pgbouncer.user_lookup(text) FROM PUBLIC;
`;
}
