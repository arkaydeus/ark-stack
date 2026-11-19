# Accounts, MFA and access

This page explains who can sign in to Ark and what they can do: the Better Auth setup, owner bootstrap, roles and the `platform_access` table, TOTP enrolment and step-up grants, sessions bound to the origin that minted them, the public login origin and gate users for SSO routes, revocation, the audit log, and how to recover from a lost second factor.

## Account types

Every account is a Better Auth user row in the control-plane database. What the account may do depends on which of two mutually exclusive tables it appears in.

| Account                | Marker                  | Signs in on      | Can do                                                                                  |
| ---------------------- | ----------------------- | ---------------- | --------------------------------------------------------------------------------------- |
| Administration account | a `platform_access` row | the admin origin | use the admin UI and API, within its role                                               |
| Gate user              | a `gate_users` row      | the login origin | pass the login gate of the SSO routes whose access list names it; nothing in Ark itself |

Database triggers (migration `server/drizzle/0029_gate_users.sql`) keep the two tables exclusive. A user with neither row can sign in but is refused by the admin API with `403` ("This account has no administration access"); a missing row never means "viewer".

## Better Auth configuration

Authentication is [Better Auth](https://better-auth.com) 1.7.25, configured in [`server/src/auth.ts`](../../server/src/auth.ts) and mounted by the API at `/api/auth/*`.

| Setting             | Value                                                                                                                                                   |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Credentials         | Email and password, minimum 12 characters                                                                                                               |
| Second factor       | Better Auth's two-factor plugin (TOTP and backup codes), issuer `Ark Stack`                                                                             |
| Storage             | Drizzle adapter on the control database, with transactions, so a failed sign-up rolls back the user                                                     |
| Secret              | `BETTER_AUTH_SECRET`, at least 32 characters                                                                                                            |
| Base URL            | Dynamic: `allowedHosts` is exactly the registered hosts ([below](#registered-hosts)), with no fallback; forwarded host and protocol headers are ignored |
| Trusted origins     | `BETTER_AUTH_TRUSTED_ORIGINS`                                                                                                                           |
| Extra user field    | `mfaEnrolledAt`, server-written, cleared when TOTP is disabled                                                                                          |
| Extra session field | `origin` (`admin` or `gate`), server-written, never taken from the browser                                                                              |
| Rate limits         | 60 requests per minute per client address on auth endpoints; 5 per minute on `/sign-in/email` and on `/two-factor/*`                                    |
| Client address      | Read only from Ark's own `X-Ark-Client-Ip` header ([Client addresses](#client-addresses-and-rate-limits))                                               |
| Session lifetime    | Better Auth's default (seven days, refreshed after a day of use); Ark does not override it                                                              |

There is no email flow. Password reset by email and email verification are not configured, so recovery never depends on the mail system Ark itself runs ([Lost factors and MFA reset](#lost-factors-and-mfa-reset)).

## Owner bootstrap

The first account is created with a one-time setup token.

1. `mise run host:install` generates `ARK_SETUP_TOKEN` (and every other secret) into `.env` without overwriting existing values, then prints `Setup URL: http://localhost:3000` and the token. A fresh install registers `http://localhost:3000` as `BETTER_AUTH_URL`.
2. Open `http://localhost:3000` through an SSH tunnel (see [Admin access modes](admin-access-modes.md#local-bootstrap-listener)). The UI calls `GET /api/setup/status`; while it reports `required`, the sign-in screen is **Create the owner**.
3. The form posts to `POST /api/auth/sign-up/email` with the token in an `x-setup-token` header. Under a PostgreSQL advisory lock, the API checks that setup is still open and compares the token in constant time. Only then does Better Auth create the user. On success the API inserts a `platform_access` row with role `owner`, and marks setup completed (`bootstrap_closed_at`).
4. Sign-up is then closed for good. Any later sign-up request gets `403` ("Administrator setup is closed or the token is invalid"). If a user row exists while setup is not marked complete, the request repairs that state by closing setup, and is refused.
5. The new owner must enrol TOTP before anything else ([MFA](#mfa-totp)) and then run the domain wizard.

The [recovery CLI](../operations/recovery.md#the-recover-cli) inspects bootstrap state and lists account roles. Its `reset-setup` command reopens setup only when no users exist at all, and prints a suggested new token. With users present it refuses. The installer never imports legacy users as owners ([Import](../operating.md#import)).

## Roles and permissions

### The `platform_access` row

Each administration account has one `platform_access` row: a `role` and two grant lists, `project_ids` and `domain_ids`. The roles and checks are in [`shared/src/authz.ts`](../../shared/src/authz.ts) and [`server/src/access.ts`](../../server/src/access.ts).

| Role       | Sees                                                              | Changes                                                                                   |
| ---------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `owner`    | everything                                                        | everything, including owner-only exposure and credential decisions                        |
| `operator` | projects and domains in its grant lists, and what belongs to them | resources in granted projects and domains; may request step-up grants except `role.grant` |
| `viewer`   | projects and domains in its grant lists                           | nothing                                                                                   |

Scope rules:

- A project is visible to an owner, or to a user whose `project_ids` contains it. A domain likewise with `domain_ids`.
- Managing a domain needs an owner, or an operator with the domain in `domain_ids`.
- A database belongs to its project when it has one, otherwise to the domain of its cluster's endpoint. A database with neither is owner-only. Mailboxes and aliases follow their domain, services their project.
- Resources with no project or domain (the `platform` target, for example) are owner-only.
- Creating a project or domain adds it to the creator's own grant list.
- Domain ownership tokens are redacted for users who cannot manage the domain.

`GET /api/state` applies the same filters: it returns only visible domains, projects, databases, mailboxes and services; alerts only to owners and operators; and the full audit list only to owners.

### Owner-only actions

Exposure decisions and anything that reveals topology are owner-only, whatever the step-up state:

- front-door routes, their client certificates and access lists, the ACL snippet and the tailnet observation (R12);
- gate users and the login origin settings;
- the admin mode, platform settings, region, public database port limits and the IPv6 preflight;
- the pooler-wide 5432 policy, database client certificates and the Vercel integration;
- off-VPS backup targets and the backup tailnet observation;
- Cloudflare-managed domains, AAAA publishing, host discovery, registry digest detection, import scans and signed maintenance.

Operators and viewers get `403` on these routes even with a valid grant.

### Changing roles

Ark has no screen or API for inviting further administrators, changing a role or editing grant lists. The only administration account the product creates is the bootstrap owner. The role model is still enforced on every request, and `shared/src/authz.ts` includes a last-owner guard (`protectLastOwner`) for that future workflow. Adding an operator or viewer today means a reviewed SQL change to `platform_access` on the host.

### Re-authorisation of queued work

Operations record the user who queued them. When the Docker agent claims, heartbeats or completes such an operation, the API checks that the actor still has a `platform_access` row and is not a viewer, and that an operator still has the needed scope. Work queued by a user who has since lost access fails instead of running. DNS publishing re-checks the publisher's role the same way.

## MFA (TOTP)

### Enrolment

An administration account must enrol TOTP before any mutation. The admin UI forces this: a session without MFA assurance only ever sees the enrolment screen ([Admin UI tour](admin-ui.md#screens-before-the-main-shell)).

1. The user confirms their password. Better Auth's `two-factor/enable` returns a TOTP URI and backup codes. The UI shows the manual secret and the codes once; nothing is stored in the browser.
2. The user enters a code. When `two-factor/verify-totp` succeeds, Better Auth enables two-factor, creates a fresh session and deletes the old one. Ark records the enrolment time in `mfa_enrolled_at` before the fresh session is created, so the new session is MFA-assured.
3. The user confirms they saved the recovery codes and continues to the wizard.

Better Auth stores the TOTP secret and backup codes in its `two_factor` table. Sign-in afterwards needs the password and then a TOTP code or one backup code.

### MFA assurance

A session is **MFA-assured** when the user has two-factor enabled, has an `mfa_enrolled_at`, and the session was created at or after that time. Sessions that predate enrolment are not assured; the UI asks the user to sign in again (**Refresh your assured session**). Every mutating admin route calls `requireMfa`, which answers `403` ("Enroll and verify administrator MFA before making changes") for an unassured session. Most reads still work.

### After enrolment

The UI offers no control to disable TOTP, re-enrol or regenerate backup codes. Better Auth's own endpoints for these exist and are reachable on the admin origin. Disabling TOTP clears `mfa_enrolled_at`, so the account loses MFA assurance until it enrols again. The supported path for a lost authenticator is the host recovery command ([below](#lost-factors-and-mfa-reset)).

### Lockout

- Better Auth counts consecutive failed second-factor verifications per account. Ark keeps the plugin's default: after 10 failures the account is locked for 15 minutes (`429`).
- Sign-in and two-factor requests are limited to 5 per minute per client address, other auth requests to 60 per minute.
- Failed step-up passwords lock that user's step-up for 15 minutes after 5 failures ([Step-up grants](#step-up-grants)).

## Step-up grants

A privileged action needs more than an assured session: a **single-use grant** minted by re-entering the password. The seven actions are:

| Action              | Used for (examples)                                                                                                                                            |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `secret.reveal`     | one-time credential reveals, SQL workspace queries, schema inspection, gate-user temporary passwords                                                           |
| `credential.rotate` | rotating database roles, issuing, revoking and rolling over database clients, issuing route client certificates, saving backup targets, the Vercel integration |
| `exposure.public`   | the admin mode, the login origin, creating, enabling or loosening routes, AAAA publishing, the pooler policy, per-database CIDRs                               |
| `restore.overwrite` | isolated restore tests and marking a restore verified                                                                                                          |
| `platform.update`   | applying image updates, signed maintenance, region and public database port limits                                                                             |
| `resource.delete`   | deleting aliases, routes and purging mailboxes                                                                                                                 |
| `role.grant`        | gate users and route access lists (owner only)                                                                                                                 |

**Minting.** `POST /api/step-up` takes `{ password, action, request }`. The caller must be an operator or owner with an MFA-assured session. The API verifies the password with Better Auth, then stores a grant bound to the user, the session, the action and `sha256` of `{ action, request }`, with keys sorted. It expires after 10 minutes. The response is `no-store`.

**Consuming.** The privileged route recomputes the hash from its own request (for example `{ adminMode }` for a mode change, or the exact JSON body for a route creation) and atomically marks one matching, unexpired, unconsumed grant as consumed. Routes validate their input and scope before consuming, so a typo or a `404` does not burn the grant. A missing or mismatched grant gives `403` ("Verify your password and MFA for `<action>` before continuing"). `role.grant` is refused for non-owners even with a grant.

**Failures.** Each wrong password writes an `auth.step_up_failed` audit event. Five failures within 15 minutes block further step-up attempts for that user with `429` until the window passes. The counter lives in the API process and resets when the API restarts. Successful grants are audited as `auth.step_up` with their action and expiry.

The UI collects step-up passwords inline on some forms and through **Settings → Sensitive-action verification** for the rest ([Step-up in the UI](admin-ui.md#step-up-in-the-ui)).

## Sessions, origins and cookies

### Registered hosts

The API answers session-bearing requests only for hosts it can name ([`server/src/origin-hosts.ts`](../../server/src/origin-hosts.ts)):

- **admin hosts:** the host of `BETTER_AUTH_URL` and of every `BETTER_AUTH_TRUSTED_ORIGINS` entry, fixed at start-up;
- **the login host:** `gate_login_hostname` while the login mode is `public`, re-read from the database at most every 5 seconds. A failed read clears it (fail closed), and it can never equal an admin host.

The canonical host is the `Host` header, which must be well formed and agree with the request URL. A first middleware in [`server/src/app.ts`](../../server/src/app.ts) refuses any other host with `421` ("This host is not a registered Ark origin") before Better Auth runs. On the login host only the login allowlist exists; every other path, `/api/health` included, is `404`. A few paths carry their own credentials and are answered for any host: `/api/internal/*` (worker and watchdog tokens), the four edge-only gate handlers (edge token), `/api/metrics/prometheus` (metrics token), `/api/health` and ACME challenges.

### Session origin

Every Better Auth session row has an `origin` column, `admin` or `gate` ([`server/src/session-origin.ts`](../../server/src/session-origin.ts)). It is decided by the server when the session is created:

- from the host of the request being served (an admin host gives `admin`, the login host `gate`), or
- from an explicit origin set by Ark's own server-side code, such as gate-user creation.

Sources must agree; a request for an unregistered host, contradictory sources or no source at all refuse the session. Gate users never get an `admin` session, whichever path asks. Better Auth itself then refuses to use a session on any origin other than the one that minted it ("This session belongs to another origin"). The admin API additionally requires an `admin` session presented on an admin host; a gate session gets `403` on every admin route.

### `__Host-` cookies

When `BETTER_AUTH_URL` is HTTPS, every Better Auth cookie is named `__Host-ark_stack.<name>` (`session_token`, `session_data`, `account_data`, `dont_remember`, `two_factor`, `trust_device`, `oauth_state`). Browsers only accept a `__Host-` cookie that is `Secure`, has `Path=/` and has no `Domain`, so a cookie is bound to exactly one host and no other site under the same parent domain can plant one. Cookies are also `HttpOnly` and `SameSite=Lax`. A request that names any auth cookie twice is refused with `400`.

With a plain-HTTP `BETTER_AUTH_URL` (local development and the installer's bootstrap default) the names are `ark_stack.<name>` without `Secure`. The login origin refuses to start without an HTTPS admin origin.

> [!NOTE]
> Moving `BETTER_AUTH_URL` from HTTP to HTTPS changes every cookie name, so each administrator signs in once more.

### Request checks on the admin API

For every `/api/*` route other than auth, setup status, health and internal routes, the API checks, in order:

1. The host is registered (`421` otherwise).
2. A Better Auth session exists (`401` "Sign in to continue").
3. The session's origin is `admin` and the request host is an admin host (`403`).
4. The user row still exists (`401`), and two-factor state is re-read from it.
5. A `platform_access` row exists (`403`).
6. For any method other than `GET`, `HEAD` and `OPTIONS`: the `Origin` header is exactly the origin of `BETTER_AUTH_URL` or a trusted origin (`403` "The request origin is not trusted"), and the body is `application/json` (`415`).

Bodies over 256 KiB are refused on `/api/*`. Each route then applies its own role, scope, MFA and step-up checks.

### Client addresses and rate limits

Rate limits and session records use the client address that [`server/src/client-ip.ts`](../../server/src/client-ip.ts) passes to Better Auth in `X-Ark-Client-Ip`. Any client-sent value is replaced. The address is the proxy's `X-Forwarded-For` only when the request carries the genuine `X-Ark-Edge-Token` (`ARK_EDGE_GATE_TOKEN`), is for a registered host and is one of that origin's exact auth paths. Otherwise it is the transport peer. No Docker subnet is trusted. `ARK_EDGE_PEER_ADDRESSES` can additionally pin the exact proxy addresses. The details are in [Edge Tailscale node](../operating.md#edge-tailscale-node).

## Gate users and the login origin

SSO ("Ark login") front-door routes admit only people who signed in on a separate public **login origin**, such as `login.example.com`. The flow, cookies and edge behaviour are described in [Login gate for SSO routes](../operating.md#login-gate-for-sso-routes-fd-11) and the [front-door guide](../guides/front-door.md#32-ark-login-sso-routes); this section covers the accounts.

### Enabling the login origin

`PUT /api/settings/gate` with `{ "mode": "public", "hostname": "login.<domain>" }` enables it. It is owner-only with MFA and an `exposure.public` grant bound to the exact body. The API refuses unless:

- `ARK_EDGE_GATE_TOKEN` is configured for the API;
- `BETTER_AUTH_URL` is HTTPS;
- a verified domain claim covers the hostname, and the public IPv4 address is set;
- the hostname is not an admin host and not used by another endpoint.

In one transaction Ark then writes the setting, a `gate` endpoint and its address records, and queues DNS verification, certificate issuance and an edge apply. The edge serves the login site only once its certificate is issued. The login host exposes only sign-in, sign-out, get-session, TOTP and backup-code verification, the two enrolment endpoints and the `/gate/*` pages. On it, Better Auth mutations must carry `Origin: https://<login host>`.

`{ "mode": "disabled" }` needs no step-up. It removes the endpoint, retires its address records, revokes every `gate` session and re-applies the edge. There is no UI for these settings; `GET /api/settings/gate` (owner) shows the current state.

### Gate user lifecycle

Owners manage gate users on the **Gate users** page or through the API ([`server/src/modules/gate-users.ts`](../../server/src/modules/gate-users.ts)):

| Step                | What happens                                                                                                                                                                                                                                           | Endpoint and grant                                                                    |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| Create              | Refused with `409` if the email exists. Better Auth creates the user server-side with a `gate` origin and a generated 24-character temporary password; the session that sign-up mints is deleted at once. The password is sealed as a one-time secret. | `POST /api/gate/users`, `role.grant` bound to `{ ...body, gateUsers: "create" }`      |
| Reveal the password | Decrypted and returned exactly once; a second reveal is `409` ("Delete the user and create it again").                                                                                                                                                 | `POST /api/gate/users/:id/temporary-password`, `secret.reveal`                        |
| First sign-in       | On the login origin only. Until TOTP is enrolled, the session can reach nothing but `/gate/enroll`; the gate check and authorize require MFA assurance.                                                                                                | none                                                                                  |
| Grant routes        | Access lists name individual users.                                                                                                                                                                                                                    | `PUT /api/front/routes/:id/access`, `role.grant` bound to `{ routeId, userIds }`      |
| Delete              | Deletes the user row; sessions, gate sessions, handoffs and route access cascade, and every affected route is drained.                                                                                                                                 | `DELETE /api/gate/users/:id`, `role.grant` bound to `{ gateUsers: "delete", userId }` |

On the login origin, the enrolment endpoints are allowed only for a gate session whose user has not enrolled yet. An enrolled gate user cannot change TOTP there, and cannot sign in on the admin origin, so a gate user who loses their authenticator is deleted and re-created.

### Gate sessions

A gate user's sign-in creates a login-origin session. Each SSO route then gets its own route session in a host-only `__Host-ark_gate` cookie, minted through a single-use handoff code that lives 60 seconds. A route session lasts at most 12 hours, ends after 2 hours idle, and never outlives the parent login session. Every gate check re-reads the route session, the parent session, the user's MFA state and the access list.

## Revocation

| Event                                        | Effect                                                                                                                                                                        |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Sign out** (admin UI)                      | Better Auth deletes the session.                                                                                                                                              |
| Admin **mode change** applied                | Every session row is deleted, admin and gate alike, so everyone signs in again. Route sessions cascade. ([Admin access modes](admin-access-modes.md#what-a-mode-change-does)) |
| Owner **MFA reset** (`mise run recover:mfa`) | The owner's TOTP secret, step-up grants and sessions are deleted.                                                                                                             |
| TOTP enabled, disabled or re-enrolled        | A trigger revokes all of that user's route sessions.                                                                                                                          |
| Login origin **disabled**                    | Every `gate` session is revoked.                                                                                                                                              |
| Gate user **deleted**                        | Its sessions, route sessions and access entries are removed.                                                                                                                  |
| User removed from a route's **access list**  | Their next request to that route is denied.                                                                                                                                   |
| `POST /gate/logout` on the login origin      | The login session ends, and with it every route session.                                                                                                                      |
| `POST /.ark/gate/logout` on a route          | That route's session ends.                                                                                                                                                    |
| Step-up grant used or 10 minutes old         | The grant can no longer be consumed.                                                                                                                                          |

Every revocation that touches a route session is journalled in the same transaction and queues a drain of the route's open connections. If the drain has not applied within 5 seconds, the edge watchdog withdraws the route and the API raises `Gate revocation not applied within 5 s`. The route, database-client and node revocation runbooks are in [Revocation](../operating.md#revocation).

> [!IMPORTANT]
> There is no "sign out everywhere" control for administration accounts. To end every admin session at once, apply a mode change, or reset the owner's MFA on the host.

## Audit log

Security-relevant actions write a row to `audit_events`: actor, role, action, resource type and ID, the related operation, and a detail object. Details pass through `redactValue` ([`shared/src/redact.ts`](../../shared/src/redact.ts)) first: values under keys that look like passwords, secrets, tokens, credentials, private keys or connection strings become `<redacted>`, as do credentials embedded in URLs.

The API's database role (`ark_runtime`) has only `SELECT` and `INSERT` on the table (migration `server/drizzle/0004_fix1_foundations.sql`), so no API path can edit or delete audit rows. Examples of recorded actions:

- `auth.step_up`, `auth.step_up_failed`;
- `secret.reveal` (one-time reveals, recorded in the same transaction that consumes the secret);
- `wizard.complete`, `settings.update`, `settings.mode`, `settings.region`, `settings.db_ingress`, `settings.ipv6_preflight`;
- `gate_user.create`, `gate_user.delete`;
- `mfa.recovery_reset` (written by the host recovery script);
- `edge.watchdog.<event>` from the edge watchdog.

The **Activity** page shows the latest 50 entries from `GET /api/state` (action, resource type, time). Owners see every entry; other roles see only their own. There is no audit export API; query the table on the host for older entries.

## Lost factors and MFA reset

Keep the recovery codes from enrolment and the generated `ARK_MFA_RECOVERY_TOKEN` off the host. A backup code replaces a TOTP code at sign-in (**Use a recovery code**).

If an owner has lost every factor, follow the [MFA recovery procedure](../operations/recovery.md#resetting-an-owners-mfa) for your deployment.

[`scripts/recover-mfa.ts`](../../scripts/recover-mfa.ts) requires the email, a confirmation string of exactly `RESET:<email>` and the recovery token (compared in constant time). In one transaction, under an advisory lock, it checks that the account is an owner, then deletes its `two_factor` row, its step-up grants and every session, clears `two_factor_enabled` and `mfa_enrolled_at`, and writes an `mfa.recovery_reset` audit event. The owner then signs in with their password and must enrol TOTP again before any change. The script only resets owners; it does not change passwords.

A forgotten password has no reset flow. Setup cannot be reopened while users exist (`reset-setup` refuses), so a lost owner password needs a reviewed database change on the host. Host-level recovery is covered in [Recovery](../operating.md#recovery) and [Recovery operations](../operations/recovery.md).
