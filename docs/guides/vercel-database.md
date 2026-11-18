# Database access from Vercel (PgBouncer mTLS)

This guide takes a Next.js app on Vercel from an empty project to a working query against an Ark database. It also covers the 90-day client-certificate rollover. It follows the design in [`docs/design/front-door.md` §3.10 and §3.12](../design/front-door.md#312-vercel-side-guide) and describes the system as built (FD-16, FD-17, FD-28 and FD-29).

Vercel functions have no stable egress addresses, so Ark does not allowlist them by IP. Each connection must pass all of these:

- TLS 1.3 to PgBouncer, with Ark's publicly trusted certificate for the database hostname;
- a **client certificate** from the app environment's own private CA (`client_tls_sslmode = verify-full`);
- **SCRAM** for that environment's login role. The default role is `runtime` in production and `readonly` in other environments. The issuing owner can explicitly choose either role;
- the per-source nftables limits on 5432 and the pooler-wide source policy in HAProxy.

Vercel Static IPs are not used (decision R2).

For a disposable local connectivity check before and after rollover, see [Verification](#verification).

## Contents

1. [Before you start](#1-before-you-start)
2. [Create the database and open the pooler](#2-create-the-database-and-open-the-pooler)
3. [Issue a client certificate](#3-issue-a-client-certificate)
4. [Set the Vercel environment variables](#4-set-the-vercel-environment-variables)
5. [Connect from Next.js](#5-connect-from-nextjs)
6. [90-day lifetime and rollover alerts](#6-90-day-lifetime-and-rollover-alerts)
7. [Manual rollover](#7-manual-rollover)
8. [Vercel integration (FD-29): disabled until live proof](#8-vercel-integration-fd-29-disabled-until-live-proof)
9. [Revoking a client](#9-revoking-a-client)
10. [Troubleshooting](#10-troubleshooting)
11. [Verification](#verification)

## 1. Before you start

On the Ark side you need:

- An Ark install whose domain wizard has created the application cluster's **database endpoint**, for example `db.example.com`. Its A (and, after the IPv6 preflight, AAAA) record must resolve, and it must have an **issued** Let's Encrypt certificate. A staging or development certificate is never trusted. See [Public certificates](../operating.md#public-certificates).
- An owner account with MFA enrolled. Every call below is owner-only. Issuing, revealing and rolling over also need a step-up grant: your password, bound to the exact request.
- Access to the admin origin. It is usually tailnet-only (`adminMode: "tailnet"`).

On your side you need:

- A TypeScript Next.js project using the App Router and linked to a Vercel project (`vercel link`). A fresh `npx create-next-app@latest` works. If you chose a `src/` directory, put the example files under it.
- The Vercel CLI. `vercel env add … --sensitive` and `--force` exist in CLI 63.x. Branch-scoped Preview variables (`--environment preview --git-branch`) need CLI 64.7.0 or later (64.6.0 was never published, and 64.5.0 rejects `--environment preview --git-branch`).
- `jq`, `base64` and `openssl`, to save and check the files.

> **There is no UI yet for issuing, revealing or rolling over database clients.** These are API calls. The UI only has the **Vercel rollover** panel for the optional integration and the pooler policy editor. The quickest way to make the calls is from the browser's developer console on the admin origin. That page already holds your session cookie, and it sends the `Origin` header that Ark requires on every mutation (`content-type: application/json`, trusted origin). Paste this helper once:
>
> ```js
> const ark = async (method, path, body) => {
>   const response = await fetch(path, {
>     method,
>     headers: { "content-type": "application/json" },
>     body: body === undefined ? undefined : JSON.stringify(body),
>   });
>   if (!response.ok) throw new Error(`${response.status} ${await response.text()}`);
>   return response.json();
> };
> // A single-use step-up grant bound to the exact request (POST /api/step-up, 10 minutes).
> const stepUp = (action, request) =>
>   ark("POST", "/api/step-up", { password: prompt("Ark password"), action, request });
> ```

## 2. Create the database and open the pooler

1. **Create a public database**, in the **Databases** view or with `POST /api/databases`:

   ```js
   const { id: databaseId } = await ark("POST", "/api/databases", { name: "appdb", exposure: "public" });
   ```

   The worker provisions `appdb_owner`, `appdb_migration`, `appdb_runtime` and `appdb_readonly`, revokes `PUBLIC`, and maps the database into PgBouncer once a client is admitted. Run your migrations as `appdb_migration`. Tables it creates are granted to `appdb_runtime` (read and write) and `appdb_readonly` (`SELECT`) through default privileges.

2. **Allow Vercel through the pooler-wide policy.** Classic PostgreSQL negotiation carries no database name, so one source policy covers every public database on 5432 ([PostgreSQL router](../operating.md#postgresql-router-5432)). Vercel clients need **Allow the internet**. In the databases view, open **Public database port (5432)**, tick **Allow the internet** and save with your password. Through the API, read the current requests, then save with an `exposure.public` step-up bound to the exact body:

   ```js
   const policy = await ark("GET", "/api/databases/pooler-policy");
   const body = { sourceCidrs: [], allowInternet: true, reviewedRequests: policy.requestsFingerprint };
   await stepUp("exposure.public", body);
   await ark("PUT", "/api/databases/pooler-policy", body);
   ```

   Roles, passwords and client certificates remain the gate. Per-source limits still apply: 128 concurrent connections and 30 new connections per second, with a burst of 60, per IPv4 address or IPv6 /64. Change them with `PUT /api/settings/db-ingress` ([Public database port limits](../operating.md#public-database-port-limits)). Vercel functions share AWS egress addresses, so keep the limits generous.

3. **Pin the function region next to the VPS.** Ark's region setting (Settings → Region, default `us-east`) suggests the Vercel region and the `vercel.json` snippet. For `us-east` it is:

   ```json
   { "regions": ["iad1"] }
   ```

## 3. Issue a client certificate

Before generating keys or saving either reveal, prepare a private directory on a trusted machine. Keep the linked Vercel project as your working directory and use the paths below for secret files. Reopen this shell or prepare a new private directory if you rotate from a different session.

```bash
umask 077
secrets_dir=$(mktemp -d "${TMPDIR:-/tmp}/ark-db-client.XXXXXXXX")
printf '%s\n' "$secrets_dir"
```

One client is one app environment. The login role is `<database>_<client>_<environment>`, for example `appdb_storefront_production`. Client and environment names are lowercase letters and digits only. Production defaults to `runtime`, and every other environment defaults to `readonly`. An explicit `roleKind` overrides the default. For Preview, use `environment: "preview", roleKind: "readonly"` and verify `readOnly: true` in the issue response. A read-only role is refused `INSERT`, `UPDATE` and `DELETE`. Each client gets its own private CA, its own password and a 90-day certificate.

**Advanced: bring your own key.** If you want Ark to sign a CSR, generate a private key and its PEM PKCS#10 request inside the private directory. For example, for the production role above:

```bash
client_key="$secrets_dir/local-client.key"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj '/CN=appdb_storefront_production' -keyout "$client_key" -out "$secrets_dir/client.csr"
```

Set `csrPem` on `issueBody` below to the full contents of `client.csr` (at most 16 KiB) before requesting step-up, and use that same body in the issue call. Ark signs the CSR and returns `privateKey: null` in the reveal. Keep `client_key` pointing at your locally generated key for §4. A CSR client needs a new CSR at each rollover (§7).

```js
const issueBody = { name: "storefront", environment: "production" };
await stepUp("credential.rotate", { databaseId, ...issueBody });
const { clientId, operationId, role, readOnly } = await ark(
  "POST",
  `/api/databases/${databaseId}/clients`,
  issueBody,
);
```

The `database.client_issue` operation creates the role and CA, signs the certificate, rewrites PgBouncer's CA bundle and userlist, and reloads PgBouncer over its admin socket. Wait until `GET /api/databases/:id/clients` shows the client with `status: "active"`. It is `"provisioning"` until issuance completes. The Operations list in the UI shows the same.

**Reveal once.** The password and any Ark-generated private key are shown exactly once. The sealed key is deleted in the same transaction, and a second reveal returns 409. Save the response to `reveal.json` inside the private directory before closing the console:

```js
await stepUp("secret.reveal", { databaseId, clientId });
const reveal = await ark("POST", `/api/databases/${databaseId}/clients/${clientId}/reveal`);
copy(JSON.stringify(reveal)); // Chrome/Edge devtools; save in the private directory and clear the clipboard
```

Extract the PEM with `jq -j` to preserve the exact bytes Ark base64-encodes in `reveal.vercel.env`. Run the key extraction only for an Ark-generated key. For a CSR client, keep `client_key` set to your matching local key and skip its assignment and extraction below.

```bash
jq -e -j .certificate.pem "$secrets_dir/reveal.json" > "$secrets_dir/client.crt"
client_key="$secrets_dir/client.key"
jq -e -j '.privateKey | strings' "$secrets_dir/reveal.json" > "$client_key" # generated key only
openssl x509 -in "$secrets_dir/client.crt" -noout -subject -issuer -enddate
# subject=CN=appdb_storefront_production
# issuer=CN=Ark db-client CA storefront/production, serialNumber=pca-…
# notAfter=…   (90 days)
```

The reveal includes the following fields.

- `server`: the host, port 5432, database, user, `sslmode=verify-full` and TLS 1.3;
- `vercel.env`: the environment values, with PEM files already base64-encoded;
- `vercel.commands`: the commands below with your names filled in;
- `vercel.nodePostgres`: the module from §5;
- `vercel.vercelJson`: the region snippet.

`GET /api/databases/:id/clients/:clientId/vercel` returns the same guide with placeholders instead of secrets, at any time.

## 4. Set the Vercel environment variables

The PEM values are base64-encoded into single lines. This is Ark's convention: it avoids multi-line handling in env vars. Run these in the linked project. For a preview client, replace `production` with `preview`, or with `--environment preview --git-branch <branch>` to scope it to one branch.

```bash
vercel env add ARK_DB_HOST production          # db.example.com
vercel env add ARK_DB_NAME production          # appdb
vercel env add ARK_DB_USER production          # appdb_storefront_production
vercel env add ARK_DB_PASSWORD production --sensitive
base64 -i "$secrets_dir/client.crt" | tr -d '\n' | vercel env add ARK_DB_CLIENT_CERT_B64 production --sensitive
base64 -i "$client_key" | tr -d '\n' | vercel env add ARK_DB_CLIENT_KEY_B64 production --sensitive
```

- `vercel env add` reads the value from stdin when it is piped, and prompts otherwise. `--sensitive` stores the value as a Secret.
- Generated passwords use the characters `!@#%^&*`. When you copy one into a local `.env` file (for `next dev`), **single-quote it**, because a `#` starts a comment in dotenv files. `vercel env pull` writes quoted values for you.
- `base64 -i FILE` works with both macOS and GNU `base64`.
- Once you've verified delivery, remove the reveal JSON and temporary PEM copies from the private directory. Keep any private key you need for future deployments in your secret store.

## 5. Connect from Next.js

Install the driver and Vercel's helper:

```bash
npm install pg @vercel/functions
npm install -D @types/pg
```

Create `lib/db.ts`. This is the module Ark returns as `vercel.nodePostgres`:

```ts
// lib/db.ts — module scope, so one pool is reused per function instance
import { Pool } from "pg";
import { attachDatabasePool } from "@vercel/functions";

const pem = (name: string) => Buffer.from(process.env[name] ?? "", "base64").toString("utf8");

export const pool = new Pool({
  host: process.env.ARK_DB_HOST, // hostname, not IP: node-postgres then sets SNI itself
  port: 5432,
  database: process.env.ARK_DB_NAME,
  user: process.env.ARK_DB_USER,
  password: process.env.ARK_DB_PASSWORD,
  ssl: {
    rejectUnauthorized: true, // server cert is public Let's Encrypt; no custom CA needed
    minVersion: "TLSv1.3",
    cert: pem("ARK_DB_CLIENT_CERT_B64"),
    key: pem("ARK_DB_CLIENT_KEY_B64"),
  },
  max: 5,
  idleTimeoutMillis: 5_000,
  connectionTimeoutMillis: 5_000,
});
attachDatabasePool(pool);
```

Then create `app/api/db-check/route.ts` for the connectivity check. This works on an empty database and returns only a status.

```ts
import { connection } from "next/server";
import { pool } from "@/lib/db";

export async function GET() {
  await connection(); // run the database check for each request, including with Cache Components
  await pool.query("SELECT 1 AS ok");
  return Response.json({ ok: true });
}
```

Run `npm run build`, deploy with `vercel deploy --prod`, then open `/api/db-check` and check for `{"ok":true}`. Remove the check route once you have your application's own health check.

- **Keep `sslmode`, `sslcert`, `sslkey` and `sslrootcert` out of any connection string.** If node-postgres sees one of them, it replaces the whole `ssl` object.
- **`attachDatabasePool`** releases idle pool clients before a function suspends. Keep the pool at module scope, with a low idle timeout and a `max` above 1.
- **Transaction pooling.** PgBouncer runs in transaction mode with `max_prepared_statements = 200`, so prepared statements work. Session state, such as `SET`, advisory locks and `LISTEN`, does not survive between transactions.

**postgres.js** also works. `attachDatabasePool` rejects a postgres.js `sql` instance (`Unsupported database pool type` in `@vercel/functions` 3.11.3), so close idle sockets quickly yourself:

```ts
// lib/sql.ts
import postgres from "postgres";

const pem = (name: string) => Buffer.from(process.env[name] ?? "", "base64").toString("utf8");

export const sql = postgres({
  host: process.env.ARK_DB_HOST,
  port: 5432,
  database: process.env.ARK_DB_NAME,
  username: process.env.ARK_DB_USER,
  password: process.env.ARK_DB_PASSWORD,
  ssl: {
    rejectUnauthorized: true,
    minVersion: "TLSv1.3",
    servername: process.env.ARK_DB_HOST,
    cert: pem("ARK_DB_CLIENT_CERT_B64"),
    key: pem("ARK_DB_CLIENT_KEY_B64"),
  },
  max: 5,
  idle_timeout: 5, // seconds; closes idle sockets quickly since there is no suspend hook
  connect_timeout: 10,
});
```

**Driver mode.** These snippets use classic negotiation (`SSLRequest`). HAProxy recognises that preamble on 5432 and sends it to PgBouncer. Direct TLS (`sslnegotiation: "direct"`, node-postgres 8.22+ and postgres.js 4.1.1) also works with SNI set to the database hostname, and saves one round trip per new connection. It is optional.

## 6. 90-day lifetime and rollover alerts

Certificates last 90 days. The env var names never change: a rollover only replaces the values of `ARK_DB_CLIENT_CERT_B64` and `ARK_DB_CLIENT_KEY_B64`. The role and password stay the same.

| When          | What Ark does                                                                                                                                                                                                                                                                                                                      |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T−30 (day 60) | The daily `database.client_rollover` job issues the successor N+1 from a **fresh CA**, adds both CAs to the bundle and reloads PgBouncer. The successor is `pending`. Alert `db-client-rollover:<client>` opens at `info`. A CSR client gets `needs_csr` instead.                                                                  |
| T−14          | The same alert escalates to `warning`, clears any acknowledgement and notifies again.                                                                                                                                                                                                                                              |
| T−7           | `critical`. It stays critical after expiry if no successor was delivered.                                                                                                                                                                                                                                                          |
| T (not_after) | TLS rejects new handshakes with certificate N.                                                                                                                                                                                                                                                                                     |
| by T + 5 s    | At T a retirement task removes N's CA and drains **every** session of the role, successor sessions included, because PgBouncer cannot tell certificates apart. This normally finishes within about 0.1 s. T + 5 s is the deadline: a watchdog fences or stops PgBouncer if the drain misses it (`db-client-retire:<certificate>`). |

Delivering the successor resolves the alert: a manual confirmation (§7) or the integration (§8). Prometheus exports `ark_db_client_rollover_pending{severity}` and `ark_db_client_retirement_failures` (`infra/monitoring/alerts.yml`).

`GET /api/databases/:id/clients/:clientId/rollover` shows where a client is in its cycle in `status` (`none` → `pending` → `delivered` → `retired`). `current` is the certificate in use, `successor` the pending one and `predecessor` the generation it replaces. `retirementDeadline` is when the expiring generation's sessions must be drained (its `notAfter` + 5 s), and `history` lists every generation of the client with its status. The response also carries `nextRolloverAt`, any open rollover `alert` and the manual `guide`. After confirmation (§7), `successor` and `predecessor` are both `null`: the superseded generation appears only in `history`.

## 7. Manual rollover

The manual path is the default and the recommended one for production apps that hold sensitive data. In steady state it means one reveal and one redeploy about every 60 days, with a 30-day window. You can also start a rollover early, for example to test this procedure or to replace a key you suspect has leaked.

1. **Issue the successor if needed.** Skip this when the T−30 job has already issued one. For a CSR client, generate a fresh key and CSR as in §3, using the same login role in the subject and distinct paths such as `local-client-next.key` and `client-next.csr`. Keep that key for deployment. Send `rolloverBody` as the POST body and include all its fields in the step-up binding.

   ```js
   const successorCsr = ""; // For a CSR client, paste the full PEM from client-next.csr inside backticks.
   const rolloverBody = successorCsr ? { csrPem: successorCsr } : {};
   await stepUp("credential.rotate", { databaseId, clientId, rollover: true, ...rolloverBody });
   await ark("POST", `/api/databases/${databaseId}/clients/${clientId}/rollover`, rolloverBody);
   ```

   Wait for the `database.client_rollover` operation. `GET …/rollover` then shows `status: "pending"`.

2. **Reveal the successor once.** This works only after PgBouncer has reloaded with both CAs:

   ```js
   await stepUp("secret.reveal", { databaseId, clientId, rollover: true });
   const next = await ark("POST", `/api/databases/${databaseId}/clients/${clientId}/rollover/reveal`);
   copy(JSON.stringify(next)); // save as reveal-next.json in the private directory from §3
   ```

   The response contains:

   - `certificate` and `privateKey` (`null` for a CSR client);
   - `guide`, with the commands and the base64 values in `guide.env`;
   - `predecessor`, the certificate being replaced and its `notAfter`;
   - `confirm`, the exact confirmation call.

3. **Extract the successor certificate and select its key.** For an Ark-generated key, extract it from the reveal. For a CSR client, skip the `next_key` assignment and key extraction below, and set `next_key="$secrets_dir/local-client-next.key"` (or the path where you saved the new key).

   ```bash
   jq -e -j .certificate.pem "$secrets_dir/reveal-next.json" > "$secrets_dir/client-next.crt"
   next_key="$secrets_dir/client-next.key"
   jq -e -j '.privateKey | strings' "$secrets_dir/reveal-next.json" > "$next_key" # generated key only
   ```

   Check that the public keys printed by these two commands match before uploading either file:

   ```bash
   openssl x509 -in "$secrets_dir/client-next.crt" -pubkey -noout
   openssl pkey -in "$next_key" -pubout
   ```

   Replace the two values and redeploy:

   ```bash
   base64 -i "$secrets_dir/client-next.crt" | tr -d '\n' | vercel env add ARK_DB_CLIENT_CERT_B64 production --sensitive --force
   base64 -i "$next_key" | tr -d '\n' | vercel env add ARK_DB_CLIENT_KEY_B64 production --sensitive --force
   vercel deploy --prod        # or redeploy from the dashboard
   ```

   For a branch-scoped Preview client, use `--environment preview --git-branch=<branch>` and redeploy that branch. Env changes apply only to new deployments.

4. **Check database access** on the new deployment using `/api/db-check` or your application's health check.
5. **Confirm delivery in Ark.** This needs MFA but no step-up:

   ```js
   await ark("POST", next.confirm.path, next.confirm.body); // …/rollover/confirm {certificateId}
   ```

   The successor becomes `current` and the predecessor `superseded`. The alert resolves, and `GET …/rollover` reports `delivered`. Confirmation needs no PgBouncer reload and requires the one-time reveal. Remove the temporary bundle and PEM copies as in §4.

The old certificate keeps admitting **new** connections until its own `notAfter`. Its role is then drained by `notAfter + 5 s`, so an old deployment that is still running stops working at that point. Redeploy any time inside the window. Delivery is not observed use: Ark cannot see which certificate a session used.

**Emergency revocation of one generation.** If a successor's key may have leaked during the overlap, revoke the whole client (§9) and issue a new one. Removing a single generation is part of the retirement machinery (§3.10.4 of the design); it is not a separate API call.

## 8. Vercel integration (FD-29): disabled until live proof

The integration would automate §7. It would write both sensitive variables through the Vercel API (`POST /v10/projects/{id}/env?upsert=true`), trigger a verified deploy hook, wait for the exact deployment to become READY and record delivery. It is **off by default**, opt-in per client, and owner-only with a `credential.rotate` step-up. Today it **cannot be connected**:

- `PUT /api/databases/:id/clients/:clientId/vercel-integration` refuses connections while the source-controlled live scope proof in `server/src/modules/vercel-api.ts` is unrecorded. `GET …/vercel-integration` returns `connectEnabled: false`, and the **Vercel rollover** panel in the Databases view explains why.
- Ark stores only a **project-scoped, expiring** Vercel token, which you must give an expiry (default 1 year, with an alert 30 days before). It refuses any token that can see another project or whose scope cannot be proven from Vercel's metadata. A token with no expiry and a team or account token are refused too. Without that proof it uses the manual path. No team token, OAuth app or Vercel Integration is offered.
- **Trade-off.** A project token can deploy code to that project. If the VPS is compromised, the attacker could ship code to the app's production domain. Without the integration, a VPS compromise exposes the database but not the Vercel app. Prefer it for preview environments.

**How connection gets enabled.**

1. An owner runs the opt-in live checks against **disposable** Vercel projects:

   ```bash
   ARK_TEST_VERCEL_PROJECT_ID=prj_… ARK_TEST_VERCEL_TEAM_ID=team_… \
   ARK_TEST_VERCEL_OTHER_PROJECT_ID=prj_… ARK_TEST_VERCEL_PROJECT_TOKEN=… \
   bun --no-env-file test server/src/vercel-live.test.ts
   ```

   The variables for the refusal fixtures, hook delivery and env inheritance are listed under [Opt-in live test suites](../operating.md#opt-in-live-test-suites).

2. They record the reviewed, redacted evidence in `server/src/modules/vercel-api.ts`.
3. That change ships in a release.

Until then, every rollover is manual.

## 9. Revoking a client

```js
await stepUp("credential.rotate", { databaseId, clientId });
await ark("POST", `/api/databases/${databaseId}/clients/${clientId}/revoke`);
```

`database.client_revoke` runs these steps in order:

1. It removes **every** CA generation of the client from the bundle.
2. It rotates the role's password to a value nobody sees and sets the role `NOLOGIN`.
3. It reloads PgBouncer.
4. It runs `KILL_CLIENT` on the role's live sessions.
5. It deletes any Vercel integration credentials.

New handshakes then fail with `unknown ca`, and established sessions are closed. Other clients are unaffected. See [Revocation](../operating.md#revocation) for routes and gate users.

## 10. Troubleshooting

| Symptom                                                                                                                                                          | Cause and fix                                                                                                                                                            |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tlsv13 alert certificate required`                                                                                                                              | The client sent no certificate. `ARK_DB_CLIENT_CERT_B64` or `ARK_DB_CLIENT_KEY_B64` is empty or unset for this environment.                                              |
| `tlsv1 alert unknown ca`                                                                                                                                         | The certificate's CA is no longer trusted: the client was revoked, or this generation was retired. Redeploy with the current certificate.                                |
| `SASL authentication failed`                                                                                                                                     | Wrong password. In a local `.env`, check that the password is single-quoted (`#` truncates it).                                                                          |
| `certificate has expired`                                                                                                                                        | The deployment still runs certificate N after T. Complete §7.                                                                                                            |
| `self-signed certificate` / `self-signed certificate in certificate chain` / `unable to verify the first certificate` / `unable to get local issuer certificate` | The database hostname is not serving a trusted Let's Encrypt certificate yet (staging or development certificate). Finish issuance; do not disable `rejectUnauthorized`. |
| Connection times out, or is refused at the TCP level                                                                                                             | The pooler policy does not allow the source (§2), or per-source limits are exceeded (`ArkDatabaseIngressDrops`).                                                         |
| `permission denied for table …` on `INSERT`/`UPDATE`/`DELETE`                                                                                                    | Check the client's `readOnly` flag and the table grants. Preview and other non-production clients use read-only roles by default.                                        |

## Verification

Use a disposable Ark installation with its own application PostgreSQL and PgBouncer. Set up the database hostname and TLS as in §1, create the public `appdb` and allow your test source as in §2, then issue and reveal a test client as in §3. The query needs no migrations or fixture data. On a loopback fixture, use a server certificate that matches the host in the reveal, publish PgBouncer on loopback port 5432, and set `NODE_EXTRA_CA_CERTS` to the fixture’s server CA before running Node. Keep hostname and certificate verification on.

In an empty working directory with Node 22, install the drivers, then save both modules from §5 under `lib/`:

```bash
npm init -y
npm pkg set type=module
npm install pg @vercel/functions postgres
mkdir -p lib
```

Save this as `query.ts`:

```ts
import { pool } from "./lib/db.ts";

try {
  const { rows } = await pool.query("SELECT 1 AS ok");
  if (rows[0]?.ok !== 1) throw new Error("Unexpected connectivity result");
  console.log(JSON.stringify(rows[0]));
} finally {
  await pool.end();
}
```

To check postgres.js too, save this as `query-postgresjs.ts`:

```ts
import { sql } from "./lib/sql.ts";

try {
  const [row] = await sql`SELECT 1 AS ok`;
  if (row?.ok !== 1) throw new Error("Unexpected connectivity result");
  console.log(JSON.stringify(row));
} finally {
  await sql.end();
}
```

Instead of uploading to Vercel for this local check, save the same values in the private directory from §3. Use the matching `client_key` from issuance:

```bash
umask 077
{
  printf 'ARK_DB_HOST=%s\n' "$(jq -r .server.host "$secrets_dir/reveal.json")"
  printf 'ARK_DB_NAME=%s\n' "$(jq -r .server.database "$secrets_dir/reveal.json")"
  printf 'ARK_DB_USER=%s\n' "$(jq -r .role "$secrets_dir/reveal.json")"
  printf "ARK_DB_PASSWORD='%s'\n" "$(jq -r .password "$secrets_dir/reveal.json")"
  printf 'ARK_DB_CLIENT_CERT_B64=%s\n' "$(base64 -i "$secrets_dir/client.crt" | tr -d '\n')"
  printf 'ARK_DB_CLIENT_KEY_B64=%s\n' "$(base64 -i "$client_key" | tr -d '\n')"
} > "$secrets_dir/initial.env"
node --experimental-strip-types --env-file="$secrets_dir/initial.env" query.ts
node --experimental-strip-types --env-file="$secrets_dir/initial.env" query-postgresjs.ts
```

Both commands should print `{"ok":1}`. Issue, reveal and check the successor key pair using §7. Use the locally verified pair to replace the two certificate variables, then run the same scripts with the successor:

```bash
grep -v '^ARK_DB_CLIENT_' "$secrets_dir/initial.env" > "$secrets_dir/next.env"
{
  printf 'ARK_DB_CLIENT_CERT_B64=%s\n' "$(base64 -i "$secrets_dir/client-next.crt" | tr -d '\n')"
  printf 'ARK_DB_CLIENT_KEY_B64=%s\n' "$(base64 -i "$next_key" | tr -d '\n')"
} >> "$secrets_dir/next.env"
node --experimental-strip-types --env-file="$secrets_dir/next.env" query.ts
node --experimental-strip-types --env-file="$secrets_dir/next.env" query-postgresjs.ts
```

Confirm delivery in Ark once the successor passes. While the two certificates overlap, the initial credentials should still work. After retirement, a fresh process using `initial.env` should fail TLS and the same process using `next.env` should still succeed. Remove the temporary files when done.

The local check ran both drivers and a fresh Next.js 16.4.6 production build against an empty database through the actual Compose `app-postgres` and `pgbouncer-public` services before and after CSR rollover. It used a test platform database from `mise run test:db:up`, a loopback server certificate and local env files. The fixture called Ark modules directly and simulated retirement by reloading the reduced CA bundle. For the real retirement drain and reconnection, run `mise run test:pgbouncer` with the [disposable database setup](../operating.md#local-acceptance). The owner API checks in `server/src/db-clients.test.ts` and `server/src/db-client-rollover.test.ts` cover the session and step-up gates. A disposable API check also verified the documented CSR binding and the Preview role override. Live Vercel delivery requires the separate opt-in suite.
