import { createToken } from "@ark-stack/shared";

import { sql } from "./db.ts";

const command = process.argv[2] ?? "help";

if (command === "help") {
  console.log(`ark recover commands:
  status          Show bootstrap and owner state
  owners          List platform owners
  reset-setup     Re-open local setup only when no users exist
`);
  process.exit(0);
}

if (command === "status") {
  const [setup] = await sql`SELECT * FROM platform_setup WHERE id='default'`;
  const [counts] = await sql`SELECT count(*)::int AS users FROM "user"`;
  console.log(
    JSON.stringify(
      {
        setup,
        users: counts.users,
        setupTokenConfigured: Boolean(process.env.ARK_SETUP_TOKEN),
        recoveryHint:
          "Use an SSH tunnel and a registered browser origin (http://localhost:3000 by default) with the host setup token.",
      },
      null,
      2,
    ),
  );
}

if (command === "owners") {
  const rows = await sql`SELECT u.email, a.role FROM "user" u JOIN platform_access a ON a.user_id=u.id`;
  console.log(JSON.stringify(rows, null, 2));
}

if (command === "reset-setup") {
  const [counts] = await sql`SELECT count(*)::int AS users FROM "user"`;
  if (counts.users > 0) {
    console.error(
      "Refusing to reopen setup while users exist. Demote owners through the UI or a reviewed SQL break-glass.",
    );
    process.exit(1);
  }
  await sql`UPDATE platform_setup SET completed=false, wizard_completed=false, bootstrap_closed_at=null WHERE id='default'`;
  console.log(`Setup reopened. Suggested token: ${createToken(24)}`);
}

await sql.end();
