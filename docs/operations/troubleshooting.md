# Troubleshooting

A symptom-first guide to the problems Ark Stack reports, drawn from the states, error messages and alerts in the code and the runbooks. Each entry gives the symptom as you see it, the cause, and the fix.

## Start with the evidence

Most problems are visible as a state, an alert or a failed operation before anything else. Check these first:

- **Latest operations** on the Overview screen. Every change runs as a durable operation; a `failed` one carries its error, and its step history carries evidence such as `edge-apply`, `certificate-issued` or `pgbouncer-reload-failed`. "Queued work is not a success." See [Operations and workers](operations-and-workers.md).
- **Alerts** on the Overview screen, and the **Alerts** page of Prometheus on `127.0.0.1:9090`. Each Prometheus rule and in-app alert key is explained in [Monitoring and alerts](../features/monitoring.md).
- **Container state and logs**: `docker compose --env-file .env -f infra/platform/docker-compose.yml ps` and `… logs <service>` (for example `domain-worker`, `edge`, `edge-l4`, `edge-watchdog`, `pgbouncer-public`, `database-ingress`).
- **Route and edge state**: `GET /api/front/tailnet` (owner) shows the latest tailnet generation, its lease, the last observation and each route's identity state and `last_error`.
- **Metrics**: from the host, `curl -fsS -H "Authorization: Bearer $(cat tmp/metrics.token)" http://127.0.0.1:3000/api/metrics/prometheus`.

## Startup and configuration

### The API refuses to start: "still has a published example placeholder"

- **Cause:** a secret such as `ARK_INTERNAL_TOKEN`, `ARK_METRICS_TOKEN` or `BETTER_AUTH_SECRET` is empty or still holds a value published in `.env.example` (the `dev-…` tokens, or anything starting with `change-me`). The startup guard refuses it. `ARK_EDGE_GATE_TOKEN` and `ARK_EDGE_WATCHDOG_TOKEN` may be empty, but not a published placeholder.
- **Fix:** let the installer generate the values (`mise run host:install`; it keeps existing `.env` values and fills missing ones), or replace the value by hand.

### The API refuses to start: off-host heartbeat errors

- **Symptom:** `ARK_OFFHOST_HEARTBEAT_TOKEN is required when off-host heartbeat is enabled.` or `Production off-host heartbeat receivers must use HTTPS.`
- **Cause:** `ARK_OFFHOST_HEARTBEAT_URL` is set without a token, or to a plain HTTP URL in production.
- **Fix:** set the generated token, use an HTTPS receiver, or clear the URL to disable the sender ([Off-host heartbeat](../features/monitoring.md#off-host-heartbeat)).

### The API refuses to start: "ARK_BACKUP_EXECUTE must be 1 when backup execution is required."

- **Cause:** the API process received `ARK_BACKUP_REQUIRED=1` and `ARK_BACKUP_EXECUTE` was not `1`. The shipped Compose configuration passes these settings only to the backup worker.
- **Fix:** set `ARK_BACKUP_EXECUTE=1` where pgBackRest or restic should actually run, or drop the requirement. Plan-only execution fails backup operations instead of reporting success ([Backups](../operating.md#backups)).

### `ArkApiDown` fires

- **Cause:** Prometheus cannot scrape `api:3000`. The API is down or unhealthy, the platform database is unreachable, the token in `tmp/metrics.token` differs from `ARK_METRICS_TOKEN` (scrapes get 401 `Invalid metrics credential.`), or `api` has left the `ark_monitoring` network.
- **Fix:** check the `api` container and the Prometheus **Targets** page; run the `curl` check above. See [ArkApiDown](../features/monitoring.md#arkapidown).

## Signing in and the admin API

### "This host is not a registered Ark origin." (421)

- **Cause:** the request's `Host` is not the host of `BETTER_AUTH_URL`, of an entry in `BETTER_AUTH_TRUSTED_ORIGINS`, or the login host. The API refuses unknown hosts before authentication, with no fallback.
- **Fix:** open the admin UI at its configured origin. For a fresh install, open `http://localhost:3000` through the tunnel. Keep it registered as described in [Local bootstrap listener](../features/admin-access-modes.md#local-bootstrap-listener).

### "The request origin is not trusted." (403)

- **Cause:** a state-changing request (anything but `GET`, `HEAD` and `OPTIONS`) arrived without an `Origin` header, or with one that is not `BETTER_AUTH_URL` or a trusted origin.
- **Fix:** send mutations from the admin origin in a browser, or set `Origin` to the admin origin when scripting.

### "This session cannot use the administration API." or "This account has no administration access." (403)

- **Cause:** the first means the session was minted on the login origin (a gate session) or is presented on a non-admin origin; admin and gate sessions are separate. The second means the account has no platform role: it is a gate-only user.
- **Fix:** sign in on the admin origin with an account that has an owner, operator or viewer role. Gate users are managed separately under **Gate users** ([Accounts and access](../features/accounts-and-access.md)).

### Every admin was signed out after an upgrade

- **Cause:** auth cookies are `__Host-` cookies over HTTPS. After the upgrade that introduced them, every admin signs in again once ([Edge Tailscale node](../operating.md#edge-tailscale-node)).
- **Fix:** sign in again.

### Step-up fails with "Too many failed verification attempts." (429)

- **Cause:** repeated wrong password or TOTP answers for a step-up grant.
- **Fix:** wait for the lockout window to pass, then request the grant again.

### Locked out, or an owner lost every MFA factor

- **Fix:** use the [recovery CLI](recovery.md#the-recover-cli) to inspect bootstrap state or follow the [owner MFA reset procedure](recovery.md#resetting-an-owners-mfa) to revoke every session and step-up grant and allow re-enrollment.

## Login gate (SSO routes)

### The login origin cannot be enabled (422 or 409)

`PUT /api/settings/gate` checks everything before writing. The messages name the cause:

| Message                                                                         | Fix                                                                             |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `ARK_EDGE_GATE_TOKEN is not configured for the API. …`                          | Configure the installer-generated token on `api`, `edge` and `tailnet-gateway`. |
| `The login origin needs an HTTPS admin origin (BETTER_AUTH_URL), …`             | Serve administration over HTTPS so cookies can be `__Host-` cookies.            |
| `No domain claim covers <host>. …` or `The domain <name> is not verified yet …` | Add the domain and publish its ownership record, then verify it.                |
| `Set the server's public IPv4 address before enabling the login origin.`        | Set the public IPv4 address in the domain wizard or settings.                   |
| `<host> is the administration origin; choose another hostname.`                 | Pick a different hostname, for example `login.<domain>`.                        |
| `<host> is already used by the <kind> endpoint.`                                | Choose a hostname no other endpoint uses.                                       |

After a successful save, Ark creates the address records, verifies DNS and issues the certificate; the login site serves only once that finishes, so the [awaiting_dns](#an-endpoint-stays-in-awaiting_dns) and [certificate](#certificates-stay-untrusted-or-the-route-waits-in-issuing_certificate) entries apply.

### Gate sign-in is refused or rate-limited

- **Cause:** sign-in and two-factor attempts are limited to 5 per minute per client address. The API takes the client address from the edge or tailnet gateway only on the exact auth paths and only with the genuine `ARK_EDGE_GATE_TOKEN`. Admin sign-ins without the token fall back to the transport peer, so everyone behind that proxy shares one bucket ([Edge Tailscale node](../operating.md#edge-tailscale-node), "Gate login origin").
- **Fix:** wait a minute. If unrelated users are throttled together, check that the same token is configured on `api`, `edge` and `tailnet-gateway`.

### "Your account does not have access to this site." (403)

- **Cause:** the user signed in but is not on the route's access list.
- **Fix:** add them with `PUT /api/front/routes/:id/access` (owner, MFA, `role.grant` step-up), or on the route's access list in the UI.

### "This site is not available." (404)

- **Cause:** the authorize request names a route that does not exist, is not an `http` route in `sso` mode, or is disabled.
- **Fix:** enable the route, or check that it is in `sso` access mode.

### "Two-factor authentication is required. Sign in again after enrolling an authenticator."

- **Cause:** the login session has no MFA assurance. Gate users are forced through TOTP enrolment.
- **Fix:** enrol an authenticator on the login origin, then sign in again.

### An app behind an SSO route gets 401, 403 or 400 instead of a page

- **401 with `WWW-Authenticate: Ark-Gate`:** a request that does not accept HTML (XHR, `Accept: application/json`) had no route session. Load a page first so the browser goes through the gate.
- **403 on a WebSocket upgrade or `POST`/`PUT`/`PATCH`/`DELETE`:** the request came from another origin, or had no `Origin` or `Origin: null`. Add the calling origin to the route's `allowedOrigins` (needs `exposure.public`).
- **400 on a bypass path:** the raw-URI guard rejected dot segments, `;`, backslashes or encoded dots, slashes, backslashes or `%`. Fix the caller's URL.

Details are in [Login gate for SSO routes](../operating.md#login-gate-for-sso-routes-fd-11).

### "Gate revocation not applied within 5 s; the edge withdrew route(s) …"

- **Cause:** a revocation (a user removed from a route, a gate user deleted, an HTTP mTLS certificate revoked) queued an `edge.drain` that did not finish in time, so the watchdog withdrew the route. The alert key is `gate-revocation-overdue`.
- **Fix:** check the `edge.drain` operations with `reason: gate_revocation` and the domain worker. Drains retry with backoff from 10 seconds to 5 minutes; the route returns after a successful drain and reload.

## Domains, DNS and certificates

### An endpoint stays in `awaiting_dns`

`domain.verify` keeps an endpoint in `awaiting_dns` until its ownership proof and required records resolve publicly and nothing blocks a certificate. The domain's last error names the reason:

| Message                                                                             | Cause and fix                                                                                                                                  |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `Domain ownership challenge is missing or does not match this installation.`        | Ark's records for the domain have no `_ark-stack.<domain>` ownership TXT record with this installation's token. Check the domain's DNS review. |
| `DNS ownership proof _ark-stack.<domain> is not yet published correctly.`           | Publish the TXT record exactly as shown, wait for the TTL, then **Recheck DNS**.                                                               |
| `<host> resolves to Cloudflare proxy address <ip>. Switch its record to DNS only …` | The record is proxied (orange cloud). Ark needs DNS-only A/AAAA records.                                                                       |
| `Address lookup failed for <host>. …`                                               | A or AAAA lookup failed. Check the authoritative DNS.                                                                                          |
| `Unexpected AAAA <host> → <ip>. Remove or correct it at the DNS provider …`         | An AAAA record Ark did not ask for. Let's Encrypt tries IPv6 first, so it would fail issuance. Remove it.                                      |
| `CAA at <name> blocks Let's Encrypt HTTP-01. …`                                     | Allow `letsencrypt.org` in the CAA `issue` records.                                                                                            |
| `CAA accounturi at <name> does not permit Ark's active Let's Encrypt account. …`    | Authorise Ark's ACME account in the CAA record, or relax the restriction.                                                                      |
| `CAA lookup at <name> failed. …`                                                    | Check the authoritative DNS and DNSSEC.                                                                                                        |
| `IPv6 withdrawal is pending for <host>. …`                                          | A prior AAAA must disappear first. Remove it (manual providers show **Remove at provider**) and wait for public DNS to confirm.                |
| `Review and publish the Cloudflare DNS plan for <host>, then recheck DNS.`          | Open **Review DNS** and **Publish reviewed DNS**; Cloudflare records must be published through a reviewed plan.                                |
| `The incoming mail MX record needs review and public DNS verification.`             | Publish the reviewed MX record and recheck.                                                                                                    |

For manual providers, automatic checks run every two minutes for 30 minutes after you open the provider guide or select **Recheck DNS**; after that, select **Recheck DNS** again. You can also queue a check with `POST /api/domains/:id/verify`. See [Domains and DNS](../features/domains-and-dns.md) and [the front-door guide, §8](../guides/front-door.md#8-dns).

### "Public DNS for `<host>` changed." or "DNS publishing or withdrawal is pending for `<host>`." before issuance

- **Cause:** `certificate.issue` re-checks DNS just before ordering. The records changed since verification, a Cloudflare record is not yet published, or an AAAA withdrawal is still pending.
- **Fix:** recheck DNS. The route returns to `awaiting_dns` and continues once the records resolve again.

### "Public certificate issuance is not configured. Set ARK_LEGO_BIN and ARK_ACME_EMAIL; …"

- **Cause:** the domain worker has no ACME email. The shipped Compose file sets `ARK_LEGO_BIN`, but `ARK_ACME_EMAIL` defaults to empty. Outside `ARK_CERTIFICATE_MODE=development` there is no self-signed fallback.
- **Fix:** set `ARK_ACME_EMAIL` in `.env`, recreate the domain worker and verify the domain again ([Public certificates](../operating.md#public-certificates)).

### Certificates stay untrusted, or the route waits in `issuing_certificate`

- **Symptom:** the endpoint shows `certificate_untrusted`, the certificate is `untrusted`, and a route's error reads `The certificate from letsencrypt-staging is not publicly trusted, so the edge will not serve it. …`
- **Cause:** the domain worker defaults to `ARK_ACME_STAGING=1`. Staging (and development `local-openssl`) certificates are recorded as untrusted and never served by the public edge.
- **Fix:** set `ARK_ACME_EMAIL` and `ARK_ACME_STAGING=0`, recreate the domain worker (`docker compose --env-file .env -f infra/platform/docker-compose.yml up -d domain-worker`), then verify the domain again to reissue. Changing the flag alone does not make existing certificates trusted.
- **Variant:** `Certificate issuance failed: … Verify the domain again to retry.` means the ACME order itself failed. Read the `certificate.issue` operation error, fix the cause and retry with `POST /api/domains/:id/verify`. See [Certificates](../features/certificates.md).

### `ArkCertificateExpiry` fires, or "Certificate for … expires soon"

- **Cause:** a managed certificate expires within 14 days. Nothing schedules renewal by itself.
- **Fix:** run domain verification (**Recheck**, or `POST /api/domains/:id/verify`). It renews ready endpoints whose certificate is missing, unusable or within 30 days of expiry. The Prometheus gauge also counts superseded certificate rows, so it can keep firing after a renewal; the in-app alert looks only at the newest certificate per endpoint ([ArkCertificateExpiry](../features/monitoring.md#arkcertificateexpiry)).

### The database endpoint still serves the old certificate

- **Symptom:** the renewed certificate is `awaiting_reload`, or the alert `PgBouncer reload failed: the renewed database certificate is not being served` (`pgbouncer-reload`) is open.
- **Cause:** PgBouncer picks up renewed files only on reload, and Ark marks the certificate as served only after `pgbouncer.reload` confirms the new fingerprint on the public listener.
- **Fix:** check the `pgbouncer.reload` operation's `pgbouncer-reload-failed` step, the database worker and `pgbouncer-public` logs, then retry the reload. The alert resolves on the next successful reload.

## Front door and edge

### A route stays in `awaiting_acl`

- **Symptom:** `last_error` reads `The edge cannot open TCP to <ip>:<port> (…). Check the tailnet grant for this port.`, or the target machine is missing from the observed generation.
- **Cause:** only a passing TCP probe from the edge node's namespace moves a route on. Netmap presence alone is not enough.
- **Fix:** merge the route's grant from **Front door ACL** (`GET /api/front/acl` or `GET /api/front/routes/:id/acl`) into the tailnet policy, check that the service listens on the target port, then wait for the next `edge.observe` (every 5 minutes) or start one with `POST /api/front/tailnet/observe`. See [the ACL snippet](../guides/front-door.md#7-the-tailnet-acl-snippet).

### A route is in `identity_mismatch`

- **Cause:** the entered target name now belongs to a different machine (a renamed or re-registered device).
- **Fix:** re-confirm the target with `PATCH /api/front/routes/:id` and an `exposure.public` step-up. The state sticks until you do.

### Every tailnet route is withdrawn, or routes show `observation_expired`

- **Symptom:** routes return 503 at the edge; their error reads `The edge node's tailnet observation expired; the route is withdrawn until it is renewed.`; `edge.observe` operations fail with `Edge observation failed; the lease was not renewed. …`
- **Cause:** the observation lease lasts 6 minutes from the start of the last complete read. When it expires, the watchdog withdraws every tailnet route within 5 seconds. Reads fail when tailscaled is unreachable or not logged in, when the edge node has not joined yet (a fresh host shows failed `edge.observe` runs until it is enrolled), or when the domain worker is down. Without `ARK_EDGE_WATCHDOG_TOKEN`, the watchdog cannot read the lease at all and keeps every tailnet route withdrawn.
- **Fix:** check `edge-ts` (`tailscale status`), the domain worker and `edge-watchdog`; enrol or re-enrol the edge node if needed; then run `POST /api/front/tailnet/observe`. Routes return after the first successful observation ([Edge observer and lease watchdog](../operating.md#edge-observer-and-lease-watchdog)).

### The edge stopped serving after `edge-ts` restarted

- **Cause:** `edge` and `edge-l4` join one specific `edge-ts` container's namespace. If `edge-ts` is restarted in place or recreated on its own, they keep running in the old, empty namespace.
- **Fix:** run `mise run edge:rejoin`. If `edge-ts` is stopped, it fails with a start-the-owner-first error; start `edge-ts` first. Signed maintenance and the installer run this step themselves.

### "Edge route withdrawal failed; …" or an `Edge watchdog: …` alert

- **Cause:** the alert key `edge-withdrawal` is raised when the watchdog reports `withdrawal_failed`, `proxy_stopped`, `stop_failed` or `policy_unavailable`, or when `edge.drain` cannot update Caddy and stops it. A stopped Caddy restarts through its launch guard, which uses the closed configuration (ACME, redirects and the admin site keep working; tailnet routes stay withdrawn) unless the watchdog authorises the full one.
- **Fix:** read `docker compose logs edge`, `edge-l4` and `edge-watchdog`. The launch guards log which configuration they chose. Each watchdog report queues `edge.apply` so the rendered files follow the current policy. See [HAProxy SNI router (edge-l4)](../operating.md#haproxy-sni-router-edge-l4) for inspecting HAProxy through its sockets.

### A ready, enabled route is not served

- **Cause:** a route whose stored options, bypass paths, rate limit or client CA fail validation is omitted rather than served without its controls.
- **Fix:** look for it under `omitted` in the latest `edge-apply` step and correct the route with `PATCH /api/front/routes/:id`. Enabling a route whose rate limit cannot be rendered is refused until the limit is set again.

### The edge answers 421 for a hostname

- **Cause:** Caddy returns 421 when the HTTP/1.1 `Host` or HTTP/2 authority differs from the TLS SNI of the connection, for example a client reusing one connection for several hostnames.
- **Fix:** this is intended. Check that the client requests the same hostname it connected to.

## Workers and operations

### `ArkWorkerHeartbeatStale` fires

- **Cause:** the worker named by the `identity` label has not called `POST /api/internal/heartbeat` for over 90 seconds. Usual reasons: the container is stopped or crash-looping; it cannot reach `http://api:3000`; or its token is rejected (its log shows `Worker heartbeat failed: 401`).
- **Also check:** the API maps a worker token to its identity only when the matching `ARK_*_WORKER_TOKEN` is set in the API's environment; a worker on the shared `ARK_INTERNAL_TOKEN` counts as `module`, so its identity stays stale. A single-slot worker (database, mail, agent) busy with a job longer than 90 seconds reports stale until the job finishes. With embedded workers in development, every identity is stale. See [Worker heartbeats](../features/monitoring.md#worker-heartbeats).
- **Fix:** restart or repair the worker; make sure the worker's `ARK_WORKER_TOKEN` and the API's `ARK_*_WORKER_TOKEN` hold the same installer-generated value.

### An operation stays `queued`

- **Cause:** nothing that may run it is polling, or it is fenced. A worker claims only kinds on its allowlist; `service.*` and `update.apply` run only in the Docker agent; `mail.*`, `mailbox.*` and `ses.*` are never claimed while mail is disabled; and an operation is not claimed while another running operation shares one of its targets.
- **Fix:** check that the worker for that kind is running and fresh, then look for a running operation on the same target. The worker for each kind is listed in [Operations and workers](operations-and-workers.md).

### "Previous worker lease expired; operation reclaimed."

- **Cause:** a running operation's lease heartbeat stopped for longer than its lease (90 seconds by default), usually because the worker died or lost the API. The operation is put back to `queued` and runs again.
- **Fix:** none needed if it then succeeds. If it keeps happening, look for worker restarts.

### A worker logs "needs_recovery: … completion failed after …"

- **Symptom:** a TypeScript worker logs `needs_recovery: worker completion failed after a mutation: …`, or the agent logs `needs_recovery: completion failed after <kind>: …`.
- **Cause:** the job made its change, but the worker could not report completion to the API. The operation row is not moved to `needs_recovery` by this path: it stays `running` until its lease expires, and is then reclaimed and run again.
- **Fix:** check the target's real state and the worker's connection to the API. Prometheus exports `ark_operations{status="needs_recovery"}` for the state itself; no rule alerts on it.

### `ArkOperationFailures` keeps firing after the problem is fixed

- **Cause:** the gauge counts every `failed` operation row, with no time window. Running the action again creates a new operation and leaves the failed one in place.
- **Fix:** review the failed operations and their errors; the rule reflects history, not only current failures ([ArkOperationFailures](../features/monitoring.md#arkoperationfailures)).

### A worker gets 403 "A valid worker job allowlist is required."

- **Cause:** the worker asked for job kinds outside its identity's allowlist, or for none. This points to a token wired to the wrong worker.
- **Fix:** give each worker its own token, as the shipped Compose file does.

## Public database access

### Connections to the pooler time out or are refused

- **Cause:** the pooler-wide source policy does not admit the client, the policy is not publishable, or the per-source limits drop it. `GET /api/databases/pooler-policy` and the databases view under "Public database port (5432)" show the status:

| Status                 | Meaning and fix                                                                                                                      |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `no_public_databases`  | No database is public, so PgBouncer is not routed on 5432. Make a database public.                                                   |
| `deny_all`             | The policy is empty. Save the pooler-wide CIDRs, or allow the internet with step-up.                                                 |
| `review_required`      | The saved policy differs from what the databases request, or they conflict. Review and save one common policy.                       |
| `unconfirmed_internet` | "Allow the internet" was not saved with an `exposure.public` confirmation. Save the policy again with step-up.                       |
| `invalid_policy`       | The saved policy cannot be rendered; the message says why.                                                                           |
| `fenced`               | `PgBouncer is closed at the edge (…) until a confirmed reload lifts the fence.` Fix the cause, then let a successful reload lift it. |
| `published`            | Routed. If clients still fail, check the source address against the policy and the drop counters.                                    |

- **Fix:** save the policy with `PUT /api/databases/pooler-policy` (owner, MFA, `exposure.public`). If `ArkDatabaseIngressDrops` is firing, the source exceeds the per-source limits; raise them with `PUT /api/settings/db-ingress` if the client is legitimate. See [Public database access](../features/public-database-access.md) and [PostgreSQL router (5432)](../operating.md#postgresql-router-5432).

### TLS or authentication errors from a database client

The [Vercel guide's troubleshooting table](../guides/vercel-database.md#10-troubleshooting) covers the client-side messages. In short: `certificate required` means no client certificate was sent; `unknown ca` means the client was revoked or its generation retired; `certificate has expired` means the successor was never delivered; `self-signed certificate` and similar mean the database hostname is not serving a trusted certificate yet; `SASL authentication failed` is a wrong password.

### "Revoked database client `<role>` may still have live PgBouncer sessions"

- **Cause:** `database.client_revoke` could not confirm that `KILL_CLIENT` left no sessions for the role (alert key `pgbouncer-revoke:<role>`).
- **Fix:** check the database worker and PgBouncer's admin socket (`SHOW CLIENTS`), then retry the revocation. The alert resolves once no sessions remain.

### Rollover and retirement alerts

- `ArkDatabaseClientRolloverWarning` and `ArkDatabaseClientRolloverCritical` mean a successor certificate is undelivered close to expiry: deliver and confirm it ([manual rollover](../guides/vercel-database.md#7-manual-rollover)).
- `ArkDatabaseClientRetirementFailed` means a retiring generation was not drained by `not_after` + 5 s: check containment at once, following [Certificate rollover](../operating.md#certificate-rollover).
- Vercel delivery alerts (`vercel-push:<client>`) that mention a mismatched certificate and key or an unsettled write need the steps in [Vercel certificate rollover recovery](../operating.md#vercel-certificate-rollover-recovery).

## Backups

### `ArkBackupsUnverified` fires

- **Cause:** at least one backup row lacks restore proof. An upload or a completed restore test is not proof on its own; a human must confirm that the restored copy booted and served its data. The gauge counts every backup row, old ones included.
- **Fix:** run a restore test (`POST /api/backups/restore-test`), check the restored copy, then record it with `POST /api/backups/:id/verify-restore` ([Backups](../features/backups.md)).

### "Backups healthy" is false, or `backup-*` alerts are open

The off-VPS alerts name the target or source; the full table is in [the backups guide](../guides/backups.md#health-and-alerts). Common cases:

- `backup-no-target` or `backup-no-target:tailnet_rest`: healthy backups need at least one S3-compatible target and one home (tailnet REST) target.
- `backup-source:<source>`: archiving is off, failing or the executor is unreachable. Without a cipher pass and an executor token of at least 24 characters, WAL archiving stays off.
- `backup-target-stale:<target>` or `backup-rpo:<target>:<source>`: exports to a destination have stopped; a failed export retries every five minutes while other destinations continue.
- `backup-tailnet:<target>`: transfers to the home target are suspended because `backup-ts`'s observation expired or the pinned machine changed.
- `backup-capacity:<source>`: WAL is accumulating on the VPS until every destination acknowledges it; fix the lagging destination before the disk fills.

## Mail

### Outbound mail stays `paused`

- **Cause:** outbound is `ready` only when SES reports production access with sending enabled, and the domain identity is verified with DKIM and MAIL FROM both at `SUCCESS`. Until then Ark keeps outbound paused; there is no direct-delivery fallback. Inbound mail does not depend on SES and can be `ready` while outbound is paused.
- **Fix:** complete the SES side (production access, DKIM and MAIL FROM records), then select **Reconcile SES** on the Email screen (`POST /api/ses/reconcile`). The `ses-reconcile` step shows what SES reported. See [Mail](../features/mail.md).

### Inbound or client status stays `pending`

- **Cause:** inbound needs a verified domain, a provisioned mailbox, a ready listener and an issued, unexpired mail certificate; client status needs the certificate and a mailbox.
- **Fix:** finish domain verification and certificate issuance, then select **Reconcile Stalwart** (`POST /api/mail/reconcile`).

### "Mail is disabled on this installation." (503)

- **Cause:** `ARK_MAIL_ENABLED=0`. Mail operations are unavailable, and queued mail jobs wait until mail is enabled again.
- **Fix:** if this installation should run Stalwart, set `ARK_MAIL_ENABLED=1` and rerun `mise run host:install` ([VPS hardening](../operating.md#vps-hardening)).

## Host

### `ArkHostRebootRequired` fires

- **Cause:** unattended upgrades installed an update that needs a reboot, and the flag persisted for five minutes.
- **Fix:** the host reboots automatically at `ARK_HOST_REBOOT_TIME` (default 04:00). If the alert survives the window, check the apt configuration that the hardening phase installed. See [Maintenance and upgrades](maintenance-and-upgrades.md).

### `ArkDatabaseIngressCountersStale` fires

- **Cause:** the `database-ingress` reconciler stopped writing `tmp/db-ingress/counters.json`, or the snapshot is unreadable.
- **Fix:** check `database-ingress` and its `allowlist.status`. Until it recovers, `ArkDatabaseIngressDrops` cannot detect drops.

## Related pages

- [Monitoring and alerts](../features/monitoring.md) for every metric and rule.
- [Operations and workers](operations-and-workers.md) for operation states and worker allowlists.
- [Recovery](recovery.md) for lockout, MFA reset and host loss.
- [Operating](../operating.md) for the full runbooks.
