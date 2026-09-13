export const schemaBrowserSql = `
SELECT
  c.table_schema AS schema,
  c.table_name AS table,
  c.column_name AS column,
  c.data_type AS type,
  c.is_nullable AS nullable
FROM information_schema.columns c
WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema', 'pgbouncer')
ORDER BY c.table_schema, c.table_name, c.ordinal_position
`;

export const schemaSizeSql = `
SELECT n.nspname AS schema, c.relname AS table,
  pg_size_pretty(pg_total_relation_size(c.oid)) AS size
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY pg_total_relation_size(c.oid) DESC
`;

export function groupSchemaRows(
  rows: Array<{ schema: string; table: string; column: string; type: string; nullable?: string }>,
) {
  const schemas: Record<
    string,
    Record<string, Array<{ column: string; type: string; nullable?: string }>>
  > = {};
  for (const row of rows) {
    schemas[row.schema] ??= {};
    schemas[row.schema][row.table] ??= [];
    schemas[row.schema][row.table].push({ column: row.column, type: row.type, nullable: row.nullable });
  }
  return schemas;
}
