// Runs the pooling assertions in the same pinned Linux Bun image as database-worker.
import postgres from "postgres";

const {
  shop,
  preview,
  appRole,
  limitedRole,
  appPassword,
  limitedPassword,
  database,
  limitedClientConnections,
  serverCa,
} = await Bun.file("/probe/client.json").json();
const checks: Array<{ check: string; outcome: string }> = [];
function record(check: string, outcome: string) {
  checks.push({ check, outcome });
}

// ---- max_user_client_connections -------------------------------------------------------------
const connect = async (
  credentials: { certPem: string; keyPem: string },
  role: string,
  password: string,
  max = 1,
) =>
  postgres({
    host: "pgbouncer-public",
    port: 5432,
    database,
    username: role,
    password,
    max,
    connect_timeout: 10,
    idle_timeout: 0,
    onnotice: () => undefined,
    ssl: {
      ca: serverCa,
      cert: credentials.certPem,
      key: credentials.keyPem,
      servername: "pgbouncer-public",
      minVersion: "TLSv1.3",
    },
  });
const held: Array<{ sql: Awaited<ReturnType<typeof connect>>; reserved: { release: () => void } }> = [];
try {
  for (let index = 0; index < limitedClientConnections; index++) {
    const sql = await connect(preview, limitedRole, limitedPassword);
    const reserved = await sql.reserve();
    await reserved`SELECT 1`;
    held.push({ sql, reserved });
  }
  const extra = await connect(preview, limitedRole, limitedPassword);
  const overflow = await extra`SELECT 1`.then(
    () => null,
    (error: Error) => error,
  );
  await extra.end({ timeout: 2 });
  if (!overflow || !/max_user_client_connections/.test(overflow.message)) {
    throw new Error(
      `Connection ${limitedClientConnections + 1} for ${limitedRole} was not refused: ${overflow?.message}`,
    );
  }
  const other = await connect(shop, appRole, appPassword);
  await other`SELECT 1`;
  await other.end({ timeout: 2 });
  record(
    `max_user_client_connections=${limitedClientConnections} for ${limitedRole}`,
    `connection ${limitedClientConnections + 1} refused — ${overflow.message}; ${appRole} unaffected`,
  );
} finally {
  for (const item of held) {
    item.reserved.release();
    await item.sql.end({ timeout: 2 });
  }
}

// ---- Prepared statements in transaction mode (postgres.js default prepare: true) ------------
const pooled = await connect(shop, appRole, appPassword, 4);
const second = await connect(preview, limitedRole, limitedPassword, 1);
try {
  const statements = await Promise.all(
    Array.from({ length: 60 }, (_, index) =>
      index % 3 === 0
        ? pooled`SELECT ${index}::int + 1 AS value`.then((rows) => Number(rows[0]!.value) === index + 1)
        : index % 3 === 1
          ? pooled`SELECT ${String(index)}::text || 'x' AS value`.then(
              (rows) => rows[0]!.value === `${index}x`,
            )
          : second`SELECT ${index}::bigint * 2 AS value`.then((rows) => Number(rows[0]!.value) === index * 2),
    ),
  );
  if (!statements.every(Boolean)) throw new Error("A prepared statement returned a wrong value.");
  const inTransaction = await pooled.begin(async (tx) => {
    const first = await tx`SELECT ${1}::int AS value`;
    const again = await tx`SELECT ${2}::int AS value`;
    return Number(first[0]!.value) + Number(again[0]!.value);
  });
  if (inTransaction !== 3) throw new Error("Prepared statements inside a transaction failed.");
  record(
    "postgres.js prepare: true in transaction mode",
    "60 concurrent named prepared statements on 2 clients and a transaction succeeded",
  );
} finally {
  await pooled.end({ timeout: 2 });
  await second.end({ timeout: 2 });
}

console.log(JSON.stringify({ ok: true, checks }));
