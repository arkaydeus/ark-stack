import { quoteIdent } from "./hostnames.ts";
import { literal } from "./provision-sql.ts";

export function rotateRoleSql(role: string, password: string) {
  return `ALTER ROLE ${quoteIdent(role)} PASSWORD ${literal(password)}`;
}

export function terminateRoleSessionsSql(role: string, database?: string) {
  const dbFilter = database ? ` AND datname = ${literal(database)}` : "";
  return `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ${literal(role)}${dbFilter} AND pid <> pg_backend_pid()`;
}
