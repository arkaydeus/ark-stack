# Database access from Vercel (PgBouncer mTLS)

This guide takes a Next.js app on Vercel from an empty project to a working query against an Ark database. It also covers the 90-day client-certificate rollover. It follows the design in [`docs/design/front-door.md` §3.10 and §3.12](../design/front-door.md#312-vercel-side-guide) and describes the system as built (FD-16, FD-17, FD-28 and FD-29).

Vercel functions have no stable egress addresses, so Ark does not allowlist them by IP. Each connection must pass all of these:

- TLS 1.3 to PgBouncer, with Ark's publicly trusted certificate for the database hostname;
- a **client certificate** from the app environment's own private CA (`client_tls_sslmode = verify-full`);
- **SCRAM** for that environment's login role, which is a `runtime` role (production) or a `readonly` role (every other environment);
- the per-source nftables limits on 5432 and the pooler-wide source policy in HAProxy.

Vercel Static IPs are not used (decision R2).

The steps were followed end to end against a local Ark stack, using the same drivers from an empty directory, with one manual rollover. The commands and output are in [Verification](#verification).

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

- A Next.js project linked to a Vercel project (`vercel link`). A fresh `npx create-next-app@latest` is fine.
- The Vercel CLI. `vercel env add … --sensitive` and `--force` exist in CLI 63.x. Branch-scoped Preview variables (`--environment preview --git-branch`) need CLI 64.6.0 or later.
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

One client is one app environment. The login role is `<database>_<client>_<environment>`, for example `appdb_storefront_production`. Client and environment names are lowercase letters and digits only. `production` gets a `runtime` role. Every other environment, `preview` included, gets a `readonly` role, which is refused `INSERT`, `UPDATE` and `DELETE`. Each client gets its own private CA, its own password and a 90-day certificate.

```js
const body = { name: "storefront", environment: "production" };
await stepUp("credential.rotate", { databaseId, ...body });
const { clientId, operationId, role } = await ark("POST", `/api/databases/${databaseId}/clients`, body);
```

The `database.client_issue` operation creates the role and CA, signs the certificate, rewrites PgBouncer's CA bundle and userlist, and reloads PgBouncer over its admin socket. Wait until `GET /api/databases/:id/clients` shows the client with `status: "active"`. It is `"provisioning"` until issuance completes. The Operations list in the UI shows the same.

**Reveal once.** The certificate's private key and the password are shown exactly once. The sealed key is deleted in the same transaction, and a second reveal returns 409, so save the response before closing the console:

```js
await stepUp("secret.reveal", { databaseId, clientId });
const reveal = await ark("POST", `/api/databases/${databaseId}/clients/${clientId}/reveal`);
copy(JSON.stringify(reveal)); // Chrome/Edge devtools; otherwise print it and save it as reveal.json
```

Save it as `reveal.json` on a trusted machine and write the two PEM files. Use `jq -j`, not `-r`. The extra newline that `-r` adds still gives a valid PEM, but its base64 then differs from the values Ark shows in `reveal.vercel.env`:

```bash
jq -j .certificate.pem reveal.json > client.crt
jq -j .privateKey      reveal.json > client.key && chmod 600 client.key
openssl x509 -in client.crt -noout -subject -issuer -enddate
# subject=CN=appdb_storefront_production
# issuer=CN=Ark db-client CA storefront/production, serialNumber=pca-…
# notAfter=…   (90 days)
```

The reveal also contains:

- `server`: the host, port 5432, database, user, `sslmode=verify-full` and TLS 1.3;
- `vercel.env`: every value, already base64-encoded;
- `vercel.commands`: the commands below with your names filled in;
- `vercel.nodePostgres`: the module from §5;
- `vercel.vercelJson`: the region snippet.

`GET /api/databases/:id/clients/:clientId/vercel` returns the same guide with placeholders instead of secrets, at any time.

**Advanced: bring your own key.** Send `csrPem` (a PEM PKCS#10 request of at most 16 KiB) in the issue body. Ark then signs it without ever holding the key, and the reveal returns `privateKey: null`. The CSR is parsed by Ark's own DER parser (`server/src/modules/x509.ts`). A CSR client cannot be rolled over automatically: at T−30 the rollover alert asks for a new CSR (see §7).

## 4. Set the Vercel environment variables

The PEM values are base64-encoded into single lines. This is Ark's convention: it avoids multi-line handling in env vars. Run these in the linked project. For a preview client, replace `production` with `preview`, or with `--environment preview --git-branch <branch>` to scope it to one branch.

```bash
vercel env add ARK_DB_HOST production          # db.example.com
vercel env add ARK_DB_NAME production          # appdb
vercel env add ARK_DB_USER production          # appdb_storefront_production
vercel env add ARK_DB_PASSWORD production --sensitive
base64 -i client.crt | tr -d '\n' | vercel env add ARK_DB_CLIENT_CERT_B64 production --sensitive
base64 -i client.key | tr -d '\n' | vercel env add ARK_DB_CLIENT_KEY_B64 production --sensitive
```

- `vercel env add` reads the value from stdin when it is piped, and prompts otherwise. `--sensitive` stores the value as a Secret.
- Generated passwords use the characters `!@#%^&*`. When you copy one into a local `.env` file (for `next dev`), **single-quote it**, because a `#` starts a comment in dotenv files. `vercel env pull` writes quoted values for you.
- `base64 -i FILE` works with both macOS and GNU `base64`.

## 5. Connect from Next.js

Install the driver and Vercel's helper:

```bash
npm install pg @vercel/functions
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

Then query from a route handler, for example `app/api/notes/route.ts`:

```ts
import { pool } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET() {
  const { rows } = await pool.query("SELECT id, body FROM notes ORDER BY id LIMIT 20");
  return Response.json(rows);
}
```

Deploy with `vercel deploy --prod` and open `/api/notes`.

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

| When          | What Ark does                                                                                                                                                                                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T−30 (day 60) | The daily `database.client_rollover` job issues the successor N+1 from a **fresh CA**, adds both CAs to the bundle and reloads PgBouncer. The successor is `pending`. Alert `db-client-rollover:<client>` opens at `info`. A CSR client gets `needs_csr` instead.    |
| T−14          | The same alert escalates to `warning`, clears any acknowledgement and notifies again.                                                                                                                                                                                |
| T−7           | `critical`. It stays critical after expiry if no successor was delivered.                                                                                                                                                                                            |
| T (not_after) | TLS rejects new handshakes with certificate N.                                                                                                                                                                                                                       |
| T + 5 s       | A retirement task removes N's CA and drains **every** session of the role, successor sessions included, because PgBouncer cannot tell certificates apart. A watchdog fences or stops PgBouncer if the drain misses this deadline (`db-client-retire:<certificate>`). |

Delivering the successor resolves the alert: a manual confirmation (§7) or the integration (§8). Prometheus exports `ark_db_client_rollover_pending{severity}` and `ark_db_client_retirement_failures` (`infra/monitoring/alerts.yml`).

`GET /api/databases/:id/clients/:clientId/rollover` shows where a client is in its cycle (`none` → `pending` → `delivered` → `retired`), the current and pending certificates, and the manual guide.

## 7. Manual rollover

The manual path is the default and the recommended one for production apps that hold sensitive data. In steady state it means one reveal and one redeploy about every 60 days, with a 30-day window. You can also start a rollover early, for example to test this procedure or to replace a key you suspect has leaked.

1. **(Early rollover only) issue the successor now.** Skip this when the T−30 job has already issued one. A CSR client must send `csrPem` here.

   ```js
   await stepUp("credential.rotate", { databaseId, clientId, rollover: true });
   await ark("POST", `/api/databases/${databaseId}/clients/${clientId}/rollover`, {});
   ```

   Wait for the `database.client_rollover` operation. `GET …/rollover` then shows `status: "pending"`.

2. **Reveal the successor once.** This works only after PgBouncer has reloaded with both CAs:

   ```js
   await stepUp("secret.reveal", { databaseId, clientId, rollover: true });
   const next = await ark("POST", `/api/databases/${databaseId}/clients/${clientId}/rollover/reveal`);
   copy(JSON.stringify(next)); // save as reveal-next.json
   ```

   The response contains:

   - `certificate` and `privateKey`;
   - `guide`, with the commands and the base64 values in `guide.env`;
   - `predecessor`, the certificate being replaced and its `notAfter`;
   - `confirm`, the exact confirmation call.

3. **Replace the two values and redeploy:**

   ```bash
   jq -j .certificate.pem reveal-next.json > client-next.crt
   jq -j .privateKey      reveal-next.json > client-next.key && chmod 600 client-next.key
   base64 -i client-next.crt | tr -d '\n' | vercel env add ARK_DB_CLIENT_CERT_B64 production --sensitive --force
   base64 -i client-next.key | tr -d '\n' | vercel env add ARK_DB_CLIENT_KEY_B64 production --sensitive --force
   vercel deploy --prod        # or redeploy from the dashboard
   ```

   For a branch-scoped Preview client, use `--environment preview --git-branch=<branch>` and redeploy that branch. Env changes apply only to new deployments.

4. **Check database access** on the new deployment, for example by opening `/api/notes`.
5. **Confirm delivery in Ark.** This needs MFA but no step-up:

   ```js
   await ark("POST", next.confirm.path, next.confirm.body); // …/rollover/confirm {certificateId}
   ```

   The successor becomes `current` and the predecessor `superseded`. The alert resolves, and `GET …/rollover` reports `delivered`. Confirmation needs no PgBouncer reload. A confirmation is refused if the successor was never revealed, because an unrevealed generated key cannot have been deployed.

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

| Symptom                                                              | Cause and fix                                                                                                                                                            |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tlsv13 alert certificate required`                                  | The client sent no certificate. `ARK_DB_CLIENT_CERT_B64` or `ARK_DB_CLIENT_KEY_B64` is empty or unset for this environment.                                              |
| `tlsv1 alert unknown ca`                                             | The certificate's CA is no longer trusted: the client was revoked, or this generation was retired. Redeploy with the current certificate.                                |
| `SASL authentication failed`                                         | Wrong password. In a local `.env`, check that the password is single-quoted (`#` truncates it).                                                                          |
| `certificate has expired`                                            | The deployment still runs certificate N after T. Complete §7.                                                                                                            |
| `self-signed certificate` / `unable to verify the first certificate` | The database hostname is not serving a trusted Let's Encrypt certificate yet (staging or development certificate). Finish issuance; do not disable `rejectUnauthorized`. |
| Connection times out, or is refused at the TCP level                 | The pooler policy does not allow the source (§2), or per-source limits are exceeded (`ArkDatabaseIngressDrops`).                                                         |
| `permission denied for table …` on `INSERT`/`UPDATE`/`DELETE`        | Preview and other non-production clients are read-only by design.                                                                                                        |

## Verification

The guide was followed on 18 November 2026 against a local stack. It ran the real `app-postgres` and `pgbouncer-public` Compose services from `infra/platform/docker-compose.yml`, with PgBouncer published on `127.0.0.1:5432`, and used the migrated platform database from `mise run test:db:up`.

**Ark side.** Ark's own modules performed each step: `issueDatabaseClient`, `revealDatabaseClient`, `databaseClientVercelGuide`, `issueSuccessor` (early), `revealRolloverSuccessor` and `confirmRolloverDelivery`, plus the database worker's `planPgbouncer` render and a `RELOAD` over the admin socket. These are the functions behind the API calls above. Two things were not exercised:

- The HTTP session, MFA and step-up layer, which `server/src/db-clients.test.ts` and `server/src/db-client-rollover.test.ts` cover.
- The production retirement drain. The walkthrough simulated it by planning N as retired, and `mise run test:pgbouncer` runs the real one.

**Reader side.** The reader steps ran in an empty directory with `npm install pg@8.23.1 @vercel/functions@3.11.3 postgres@4.1.1` and Node 22. The guide's own commands produced the files and env values, and §5's modules ran unchanged. Two things stood in for the real setup:

- `localhost` with a self-signed certificate (`NODE_EXTRA_CA_CERTS`) stood in for `db.example.com` and its Let's Encrypt certificate.
- A local `.env.local` stood in for `vercel env add`.

```text
[ark] client issued: role appdb_storefront_production
[ark] GET …/vercel commands:
vercel env add ARK_DB_HOST production          # localhost
vercel env add ARK_DB_NAME production          # appdb
vercel env add ARK_DB_USER production          # appdb_storefront_production
vercel env add ARK_DB_PASSWORD production --sensitive
base64 -i client.crt | tr -d '\n' | vercel env add ARK_DB_CLIENT_CERT_B64 production --sensitive
base64 -i client.key | tr -d '\n' | vercel env add ARK_DB_CLIENT_KEY_B64 production --sensitive
[ark] vercel.json: {"regions":["iad1"]}
+ jq -j .certificate.pem reveal.json > client.crt; jq -j .privateKey reveal.json > client.key
subject=CN=appdb_storefront_production
issuer=CN=Ark db-client CA storefront/production, serialNumber=pca-…
reveal vercel.env == shell-produced values for ARK_DB_HOST, ARK_DB_NAME, ARK_DB_USER, ARK_DB_PASSWORD, ARK_DB_CLIENT_CERT_B64, ARK_DB_CLIENT_KEY_B64
+ node --experimental-strip-types --env-file=.env.local query.ts            (lib/db.ts, node-postgres)
{"role":"appdb_storefront_production","db":"appdb","note":"hello from Ark","tls":"TLSv1.3"}
+ node --experimental-strip-types --env-file=.env.local query-postgresjs.ts (lib/sql.ts, postgres.js)
{"role":"appdb_storefront_production","notes":1}
+ same pool without ARK_DB_CLIENT_CERT_B64/KEY (expect refusal)
refused: … tlsv13 alert certificate required …
[ark] successor issued: {"outcome":"issued",…}   PgBouncer RELOAD; CA bundle now trusts 2 generation(s)
[ark] GET …/rollover: {"status":"pending",…}
+ base64 -i client-next.{crt,key} | tr -d '\n'  -> replace ARK_DB_CLIENT_CERT_B64 / ARK_DB_CLIENT_KEY_B64
rollover reveal guide.env == shell-produced values for ARK_DB_CLIENT_CERT_B64, ARK_DB_CLIENT_KEY_B64
+ (redeploy) query.ts with the new certificate
{"role":"appdb_storefront_production","db":"appdb","note":"hello from Ark","tls":"TLSv1.3"}
+ the old deployment's certificate still connects during the overlap
{"role":"appdb_storefront_production","db":"appdb","note":"hello from Ark","tls":"TLSv1.3"}
[ark] POST …/rollover/confirm: {"alreadyDelivered":false,"successor":{"rolloverState":"current",…},"predecessor":{"rolloverState":"superseded",…,"retirementDeadline":"<notAfter + 5 s>"}}
[ark] GET …/rollover after confirm: {"status":"delivered",…}
[ark] (predecessor retired) PgBouncer RELOAD; CA bundle now trusts 1 generation(s)
+ new certificate
{"role":"appdb_storefront_production","db":"appdb","note":"hello from Ark","tls":"TLSv1.3"}
+ old certificate (expect refusal)
refused: … tlsv1 alert unknown ca …
WALKTHROUGH PASSED
```

Two steps did not work as first written, and this guide now includes the fixes:

- Saving the PEMs with `jq -r` changed the base64 values.
- An unquoted password containing `#` was truncated in a dotenv file, which gave `SASL authentication failed`.
