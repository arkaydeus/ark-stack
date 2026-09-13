import { readFile } from "node:fs/promises";

import { compareInventory, type ExternalInventory } from "@ark-stack/shared";

import { db, sql } from "../server/src/db.ts";
import { domainClaims, managedDatabases, services } from "../server/src/schema.ts";

const file = process.argv[2];
if (!file) {
  console.error("Usage: bun scripts/import.ts <inventory.json>");
  process.exit(1);
}

const incoming = JSON.parse(await readFile(file, "utf8")) as ExternalInventory;
if (!incoming.source) {
  console.error("Inventory must include source: orkmail | pgstack | compose");
  process.exit(1);
}

const local: ExternalInventory = {
  source: incoming.source,
  domains: (await db.select().from(domainClaims)).map((item) => item.name),
  databases: (await db.select().from(managedDatabases)).map((item) => item.name),
  services: (await db.select().from(services)).map((item) => item.name),
};

const result = compareInventory(local, incoming);
console.log(
  JSON.stringify(
    {
      ...result,
      note: "Owners are never imported. Review conflicts, restore-test source backups, then cut over one low-risk resource.",
    },
    null,
    2,
  ),
);
await sql.end();
process.exit(0);
