import { postgresIdent, quoteIdent } from "./hostnames.ts";

export type DatabaseRoleKind = "owner" | "migration" | "runtime" | "readonly";

export type ProvisionPlan = {
  database: string;
  testDatabase?: string;
  roles: Array<{ kind: DatabaseRoleKind; name: string; password: string }>;
  statements: string[];
  extensionStatements: string[];
};

export function buildProvisionPlan(input: {
  name: string;
  passwords: Record<DatabaseRoleKind, string>;
  withPgvector: boolean;
  withTestDatabase: boolean;
}): ProvisionPlan {
  const database = postgresIdent(input.name);
  const testDatabase = input.withTestDatabase ? postgresIdent(`${input.name}_test`) : undefined;
  const roles = (Object.keys(input.passwords) as DatabaseRoleKind[]).map((kind) => ({
    kind,
    name: postgresIdent(input.name, `_${kind}`),
    password: input.passwords[kind],
  }));
  const statements: string[] = [
    `CREATE DATABASE ${quoteIdent(database)}`,
    ...roles.map((role) =>
      role.kind === "owner"
        ? `CREATE ROLE ${quoteIdent(role.name)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE`
        : `CREATE ROLE ${quoteIdent(role.name)} LOGIN PASSWORD ${literal(role.password)} NOSUPERUSER NOCREATEDB NOCREATEROLE`,
    ),
    `REVOKE ALL ON DATABASE ${quoteIdent(database)} FROM PUBLIC`,
    `GRANT CONNECT, TEMPORARY ON DATABASE ${quoteIdent(database)} TO ${roles.map((role) => quoteIdent(role.name)).join(", ")}`,
    `ALTER DATABASE ${quoteIdent(database)} OWNER TO ${quoteIdent(roleName(roles, "owner"))}`,
  ];
  if (testDatabase) {
    statements.push(
      `CREATE DATABASE ${quoteIdent(testDatabase)}`,
      `REVOKE ALL ON DATABASE ${quoteIdent(testDatabase)} FROM PUBLIC`,
      `GRANT CONNECT, TEMPORARY ON DATABASE ${quoteIdent(testDatabase)} TO ${quoteIdent(roleName(roles, "owner"))}, ${quoteIdent(roleName(roles, "migration"))}`,
      `ALTER DATABASE ${quoteIdent(testDatabase)} OWNER TO ${quoteIdent(roleName(roles, "owner"))}`,
    );
  }
  const owner = quoteIdent(roleName(roles, "owner"));
  const migration = quoteIdent(roleName(roles, "migration"));
  const runtime = quoteIdent(roleName(roles, "runtime"));
  const readonly = quoteIdent(roleName(roles, "readonly"));
  const extensionStatements = [
    `REVOKE ALL ON SCHEMA public FROM PUBLIC`,
    `GRANT USAGE, CREATE ON SCHEMA public TO ${owner}, ${migration}`,
    `GRANT USAGE ON SCHEMA public TO ${runtime}, ${readonly}`,
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${runtime}`,
    `GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${readonly}`,
    `GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO ${runtime}`,
    `GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO ${readonly}`,
    `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC`,
    `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ${runtime}, ${readonly}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migration} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${runtime}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migration} IN SCHEMA public GRANT SELECT ON TABLES TO ${readonly}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migration} IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ${runtime}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migration} IN SCHEMA public GRANT SELECT ON SEQUENCES TO ${readonly}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migration} IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migration} IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO ${runtime}, ${readonly}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${runtime}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT SELECT ON TABLES TO ${readonly}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ${runtime}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT SELECT ON SEQUENCES TO ${readonly}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO ${runtime}, ${readonly}`,
  ];
  if (input.withPgvector) extensionStatements.unshift(`CREATE EXTENSION IF NOT EXISTS vector`);
  return { database, testDatabase, roles, statements, extensionStatements };
}

function roleName(roles: ProvisionPlan["roles"], kind: DatabaseRoleKind) {
  const role = roles.find((item) => item.kind === kind);
  if (!role) throw new Error(`Missing ${kind} role in the provision plan.`);
  return role.name;
}

export function literal(value: string) {
  // `$ark` alone is enough to break out: a value ending in `$ark` closes the literal early
  // when the closing tag is appended.
  if (value.includes("$ark")) throw new Error("Generated secret collided with the SQL dollar-quote tag.");
  return `$ark$${value}$ark$`;
}

export function publicPoolerAdmission(input: {
  database: string;
  runtimeRole: string;
  exposure: "public" | "private";
}) {
  if (input.exposure !== "public")
    return { allowed: false, reason: "Database is private; public PgBouncer must not map it." };
  if (/_(owner|migration|backup|monitor)$/.test(input.runtimeRole)) {
    return { allowed: false, reason: "Privileged roles cannot be admitted on the public listener." };
  }
  return { allowed: true, mapping: `${input.database} = host=app-postgres dbname=${input.database}` };
}
