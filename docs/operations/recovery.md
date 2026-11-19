# Recovery

This page covers getting back control when something has gone wrong: local lockout and bootstrap inspection, resetting an owner's MFA, losing the host, restoring from off-VPS backups, recovering withdrawn edge routes, stuck operations, and comparing an inventory before importing from another system.

## Keep recovery material off-host

Most recovery paths depend on material that must not live only on the VPS. Store these somewhere independent of it:

| Material                                                                           | Needed for                                           |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `ARK_ROOT_KEY` and `ARK_ROOT_KEY_ID` from `.env`                                   | Reading any sealed secret after a database restore   |
| `ARK_MFA_RECOVERY_TOKEN` from `.env`                                               | [Resetting an owner's MFA](#resetting-an-owners-mfa) |
| Each owner's MFA recovery codes (shown once at enrolment)                          | Signing in without the authenticator                 |
| `ARK_PLATFORM_PG_REPO_CIPHER_PASS` and `ARK_APP_PG_REPO_CIPHER_PASS`               | PostgreSQL point-in-time restore                     |
| Each backup target's restic repository password, and the home rest-server password | Reading the off-VPS repositories                     |
| A read-only key for the backup bucket                                              | Restoring without the writer credential              |
| The `ark-postgres` and `ark-app-postgres` image references for the running release | Restoring with matching PostgreSQL binaries          |

The installer generates the `.env` values. The backups guide lists the backup material in [Recovery material to keep off-host](../guides/backups.md#recovery-material-to-keep-off-host).

## Local lockout and bootstrap inspection

The raw API listener is published only on `127.0.0.1:3000` on the host. Whatever happens to public or tailnet administration, an operator with SSH access can reach it through a tunnel:

```sh
ssh -L 3000:127.0.0.1:3000 <user>@<host>
```

Open `http://localhost:3000` in your local browser. Keep that origin in `BETTER_AUTH_TRUSTED_ORIGINS` if you later change the admin URL. To use `http://127.0.0.1:3000` in the browser, add it explicitly and recreate the API service.

### The recover CLI

The recovery CLI (`server/src/cli.ts`) reads bootstrap state and users. Only `reset-setup` changes data.

| Command       | What it does                                                                                                                                                               |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `help`        | Lists the commands (the default).                                                                                                                                          |
| `status`      | Prints the `platform_setup` row, the user count, whether `ARK_SETUP_TOKEN` is configured, and a tunnel hint. Use the registered browser origin from the preceding section. |
| `owners`      | Lists every user's email and platform role.                                                                                                                                |
| `reset-setup` | Reopens setup and the domain wizard, and prints a suggested token. It refuses while any user exists.                                                                       |

On the production VPS, run from the repository root. The API container already has the internal database URL and the setup token. Production Compose leaves the database on an internal network, so host tasks using the development URL on loopback cannot connect.

```sh
docker compose --env-file .env -f infra/platform/docker-compose.yml exec api bun server/src/cli.ts status
docker compose --env-file .env -f infra/platform/docker-compose.yml exec api bun server/src/cli.ts owners
```

In local development with PostgreSQL listening on the host as configured in `.env`, use `mise run recover -- status` or `mise run recover -- owners`. Use the same environment-specific invocation for `reset-setup`.

Setup cannot be reopened while users exist. If the remaining owners are unusable, change roles through the UI or a reviewed SQL break-glass, as the CLI's refusal message says; do not delete users to reopen setup.

### Common lockout causes

- **Public administration unreachable.** Use the tunnel. The local listener does not depend on the edge, DNS or certificates.
- **Tailnet administration unreachable.** The tunnel still works. Check the `tailscale` and `tailnet-gateway` containers.
- **Rate-limited sign-in.** Sign-in and two-factor attempts are limited to five per minute per client address. Wait a minute.
- **Lost authenticator.** Sign in with a recovery code (tick **Use a recovery code** on the sign-in form). If no codes are left, reset MFA as below.

## Resetting an owner's MFA

The reset script (`scripts/recover-mfa.ts`) takes the owner's email, the confirmation `RESET:<email>`, and the value of `ARK_MFA_RECOVERY_TOKEN`. Replace the example email with the owner's email in lowercase.

On the production VPS, run from the repository root. The shell inside the API container expands the token using the container's environment.

```sh
docker compose --env-file .env -f infra/platform/docker-compose.yml exec api \
  sh -c 'exec bun scripts/recover-mfa.ts "$1" "RESET:$1" "$ARK_MFA_RECOVERY_TOKEN"' sh owner@example.com
```

For a local development database, read the token with Bun before passing it to the reset task.

```sh
mise run recover:mfa -- owner@example.com RESET:owner@example.com \
  "$(bun --env-file=.env -p 'process.env.ARK_MFA_RECOVERY_TOKEN ?? ""')"
```

The script refuses (and prints its usage) unless the confirmation matches the email exactly and the token matches `ARK_MFA_RECOVERY_TOKEN` in a constant-time comparison. It then, in one transaction under an advisory lock:

1. finds the account, which must have the `owner` role (any other account fails with `The requested account is not an owner.`);
2. deletes the account's two-factor secrets, step-up grants and sessions;
3. clears `two_factor_enabled` and `mfa_enrolled_at`;
4. writes an `mfa.recovery_reset` audit event with source `host-recovery`.

Sign in immediately afterwards and enrol MFA again; owner mutations stay blocked until enrolment completes.

> [!WARNING]
> Anyone with shell access to the host and the recovery token can reset an owner's MFA. Keep `ARK_MFA_RECOVERY_TOKEN` off-host and restrict host access accordingly.

## Host loss

`mise run recover-host` (`scripts/recover-host.ts`) prints the host-loss checklist and what the current environment is ready for. It exits with status 1 when `ARK_ROOT_KEY` or `DATABASE_URL` is missing.

```json
{
  "ready": { "rootKey": true, "databaseUrl": true, "authSecret": true, "setupToken": true },
  "checklist": ["…"],
  "restore": {
    "isolatedCompose": "infra/restore/docker-compose.yml",
    "execute": false,
    "warning": "Do not boot a duplicate Tailscale identity. Disable reconciliation, outbound mail, and public ingress until verification completes."
  }
}
```

The checklist (`hostLossChecklist` in `shared/src/install.ts`):

1. Restore `ARK_ROOT_KEY` and `ARK_ROOT_KEY_ID` from off-host storage before any database restore.
2. Bring up a clean host and unique Compose project names. Do not reuse the failed Tailscale node identity.
3. Restore the platform database, then application clusters, then mail/volume snapshots.
4. Disable reconciliation, outbound SES, and public ingress until ownership and credentials are verified.
5. Re-enroll Tailscale, verify private login, then enable public routes last.

### The isolated restore target

`infra/restore/docker-compose.yml` (project `ark-restore-isolated`) is a scratch PostgreSQL for inspecting restored data. It has no public ports, no Tailscale identity and no outbound mail: `restore-postgres` listens only on `127.0.0.1:55432`, uses its own volume and does not restart. Restore into it first and verify the data before anything touches the new production host.

### Rebuilding

Ark has no single command that rebuilds a host. In outline, following the checklist:

1. Provision a new VPS and follow [VPS hardening](../operating.md#vps-hardening) with fresh Tailscale keys. Never reuse the failed host's `tag:ark-vps`, `ark-edge` or backup node identities; remove the old devices in the Tailscale console.
2. Put the off-host `ARK_ROOT_KEY` and `ARK_ROOT_KEY_ID` in `.env` before the installer generates new ones. The installer keeps existing values.
3. Recover the platform database, then the application cluster, from the off-VPS backups (next section), verify them in an isolated container, and move the data into the new installation.
4. Keep public routes, outbound mail and SES paused until owners, credentials and DNS are verified. Enrol the edge node again ([Edge Tailscale node](../operating.md#edge-tailscale-node)) and enable public routes last.

## Restoring from off-VPS backups

PostgreSQL backups leave the VPS as restic snapshots of the encrypted pgBackRest repo2, to S3-compatible targets and to a home machine over the tailnet. Recovery runs on a separate machine and never needs the VPS, the root key, the Ark database or the local repository.

**From an S3-compatible target.** `scripts/offsite-restore.ts` takes the bucket, a read-only key, the restic password, the repo2 cipher pass, the cluster (`ARK_RESTORE_CLUSTER`), a target time (`ARK_RESTORE_TARGET_TIME`) and the matching PostgreSQL image (`ARK_RESTORE_IMAGE`). It picks the newest snapshot covering the target time (or `ARK_RESTORE_SNAPSHOT`), restores it into a scratch volume, runs a point-in-time `pgbackrest restore` into an empty PGDATA, and starts PostgreSQL with no network and archiving off. It fails loudly if the archived WAL does not reach the target time. Inspect the result with `psql`, then `pg_dump` what you need. Full invocation: [Off-VPS point-in-time restore](../guides/backups.md#off-vps-point-in-time-restore).

**From the home machine.** The recovery tool reads only S3 repositories, so a home REST recovery is manual: extract the snapshot with restic, restore with pgBackRest in a no-network container, then replay WAL with the stock entrypoint. Follow [Pruning and recovery from the home machine](../guides/backups.md#pruning-and-recovery-from-the-home-machine).

> [!IMPORTANT]
> A successful upload is not a verified restore. `mise run test:backups` proves full point-in-time recovery of both clusters from the bucket alone; run it after changing the backup configuration, and rehearse a real restore with your own material.

In the UI, `POST /api/backups/restore-test` runs file restore tests from an exact recorded snapshot. PostgreSQL restore tests refuse to run on the VPS because the worker has no live repo2; use the off-VPS tool for databases. See [Backups](../features/backups.md).

## Edge route withdrawal

The edge fails closed: when the edge watchdog cannot prove that a tailnet route is allowed, it withdraws that route from Caddy and HAProxy within five seconds and the route answers a fixed 503 or is not routed. Other routes, ACME, redirects and the admin site keep working. Withdrawal is expected in these cases:

| Cause                                                          | What you see                                                    | Recovery                                                                                                                                                         |
| -------------------------------------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `edge.observe` keeps failing, so the 6-minute lease expires    | Every tailnet route withdrawn; failed `edge.observe` operations | Fix the edge node (is `edge-ts` running and logged in?), then `POST /api/front/tailnet/observe`. Routes return after the next successful observation.            |
| The watchdog cannot read the lease for 5 seconds               | Every tailnet route withdrawn                                   | Check that `api` is up and `ARK_EDGE_WATCHDOG_TOKEN` is set for both `api` and `edge-watchdog`. Without the token every tailnet route stays withdrawn.           |
| A target machine left the tailnet or lost its grant            | The route is `awaiting_acl` with a reason in `last_error`       | Restore the device or merge its grant from **Front door ACL** (`GET /api/front/acl`), then observe again.                                                        |
| A target name now belongs to another machine                   | The route is `identity_mismatch`                                | Re-confirm the target with `PATCH /api/front/routes/:id` and an `exposure.public` step-up.                                                                       |
| `edge-ts` was restarted or replaced under `edge` and `edge-l4` | Nothing served at all through the edge                          | `mise run edge:rejoin`.                                                                                                                                          |
| The edge node identity is lost or must be replaced             | Every tailnet route withdrawn                                   | Remove the old device, remove the `ark_edge_ts_state` volume and re-enrol with a fresh one-off key ([Edge Tailscale node](../operating.md#edge-tailscale-node)). |

### When the watchdog stops a proxy

If a withdrawal cannot be applied and verified, the watchdog fences protected traffic, may stop Caddy (or, through the launch guard, HAProxy), and reports an event. The API audits it as `edge.watchdog.<event>`, queues `edge.apply` to re-render from the current policy, and for every event except `withdrawn` raises a critical alert, for example `Edge watchdog stopped caddy after a failed route withdrawal`. A failed `edge.drain` raises `Edge route withdrawal failed; …` under the same alert key.

Docker restarts a stopped proxy, and its launch guard starts it from the closed configuration until the watchdog answers `open`. To recover:

1. Read the alert and the logs:

   ```sh
   docker compose --env-file .env -f infra/platform/docker-compose.yml logs edge-watchdog edge edge-l4
   ```

2. Check that the queued `edge.apply` and `edge.l4_apply` succeeded on the **Activity** page.
3. Check `GET /api/front/tailnet` (owner): the latest generation, its lease and each route's status and whether it is served.
4. If the cause was transient, the routes come back on their own once the lease and the rendered files agree. Acknowledge the alert with `POST /api/alerts/:id/ack`.

The mechanics are described in [Edge observer and lease watchdog](../operating.md#edge-observer-and-lease-watchdog) and [HAProxy SNI router (edge-l4)](../operating.md#haproxy-sni-router-edge-l4).

### The backup node

Losing the backup node or letting its separate six-minute lease expire blocks home REST transfers and stops in-flight ones within five seconds. S3 exports and public routes are unaffected. Re-enrol `backup-ts` as described under the backup node in [Revocation](../operating.md#revocation).

## Stuck or failed operations

- **Running for too long.** Workers heartbeat their lease every 15 seconds. If a worker dies, its operation returns to `queued` after 90 seconds with `Previous worker lease expired; operation reclaimed.` and runs again.
- **Never claimed.** Check that the worker for its kind is running and its heartbeat is fresh (`ArkWorkerHeartbeatStale`). Mail kinds wait while mail is disabled. See the kind table in [Operations and workers](operations-and-workers.md).
- **Completion failed after a mutation.** The worker logs `needs_recovery: …`. The operation is reclaimed after its lease expires and runs again, so check that the repeated mutation is safe before acting by hand.
- **Failed.** Read `error` and the steps on **Activity**, fix the cause, and repeat the action; a new operation is created.

Some failure paths have their own runbooks: database client retirement failures and [Vercel certificate rollover recovery](../operating.md#vercel-certificate-rollover-recovery) under [Certificate rollover](../operating.md#certificate-rollover), and the troubleshooting guide in [the Vercel guide](../guides/vercel-database.md#10-troubleshooting).

## Comparing an import inventory

Ark can compare the inventory of an older system (Orkmail, PgStack or a Compose host) with its own before a migration. It never imports owners.

```sh
mise run import -- inventory.json
```

The file names its `source` and the resource names to compare:

```json
{
  "source": "pgstack",
  "domains": ["example.com"],
  "databases": ["storefront"],
  "services": ["web"]
}
```

`scripts/import.ts` reads Ark's domains, databases and services and prints, per resource type, the `conflicts` (names that already exist in Ark) and the `importable` names, with `ownersImported: false` and the note `Owners are never imported. Review conflicts, restore-test source backups, then cut over one low-risk resource.` It only reads; nothing is created. A missing or invalid `source` stops it with `Inventory must include source: orkmail | pgstack | compose`.

The same comparison is available to an owner with MFA as `POST /api/import/scan`, which queues `import.scan` on the backup worker and records the result in an `import-scan` step.

When cutting over, move one low-risk resource at a time. Stop the old system's reconcilers before transferring a live mail domain, so two systems never manage the same mailboxes.

Related pages: [Operations and workers](operations-and-workers.md), [Maintenance and upgrades](maintenance-and-upgrades.md), [Troubleshooting](troubleshooting.md), [Security model](../security/security-model.md).
