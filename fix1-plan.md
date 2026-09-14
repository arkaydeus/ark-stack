**Fix 1 — remediation implementation plan**

Prepared 13 September 2026 against commit `638ca9e`. This document plans fixes; it does not certify the current application for production. The product requirements remain those in [the implementation plan](docs/implementation-plan.md): public database access, guided custom-domain/DNS setup, generated credentials, public incoming mail, selectable public or tailnet-only administration, Better Auth, container operations, monitoring, updates and recoverable backups.

The current implementation contains useful UI, schemas and policy helpers, but several important workflows are incomplete or do not enforce the intended security boundaries. Fix those boundaries and verify real integrations before expanding the feature surface. Preserve functioning domain logic and UI components where possible; do not solve these problems by relabeling placeholders as completed features.

**1. Evidence and limits of the review**

Verification performed:

- All four TypeScript workspaces type-check.
- All 55 existing TypeScript tests pass against a newly created disposable PostgreSQL instance; Go tests also pass.
- Additional isolated checks reproduce the failures below. The temporary database/container was removed afterward. Existing services, real DNS, mail accounts, production data and cloud-provider resources were not modified.
- No hostile Compose document was deployed. The security finding is that the policy accepts definitions that grant forbidden access, including local-driver bind mounts and external control resources.
- The tests under `tests/browser` call the Hono application directly; they do not drive a browser through signup, MFA and onboarding. The UI title test can pass with a hardcoded fallback when a build is absent. Passing this suite is therefore insufficient release evidence.

| Finding                                                                                                                             | Evidence                                                                                                           | Work package |
| ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------ |
| Host-root bind mounts, control-network attachment and control-volume attachment pass the TypeScript Compose policy                  | Reproduced using three otherwise-valid named-volume/network documents                                              | F01          |
| First owner cannot complete setup: wizard requires MFA, while enrollment UI is behind the completed-wizard screen                   | Fresh owner signup returned 200; wizard returned 403; UI flow inspected                                            | F02          |
| An authenticated owner without MFA can create a project with a foreign Origin and `text/plain` JSON                                 | Reproduced at the Hono request boundary; an actual browser CSRF exploit was not exercised                          | F03          |
| Generic secret reveal has no resource scope check                                                                                   | Reproduced with an authenticated/MFA-assured operator fixture with no grants; unrelated canary secret returned 200 | F03          |
| Agent completion succeeds without the current claim token                                                                           | Reproduced against a running service operation with a stored claim token                                           | F05          |
| Domain with no DNS records becomes verified                                                                                         | Reproduced with an unpublished ownership token and an empty record set                                             | F06          |
| Generated runtime role cannot insert into a normal `serial` table; generated test DB migration role cannot create a table           | Both failures reproduced against PostgreSQL                                                                        | F09          |
| Retrying provisioning fails at `CREATE DATABASE` after previous creation                                                            | Reproduced; inspection also shows passwords are persisted only after external DDL finishes                         | F05/F09      |
| Docker deployment passes an unsupported flag to `compose up`                                                                        | Read-only dry run returned `unknown flag: --no-interpolate`                                                        | F01/F04      |
| Compose does not run the API/web/agent/module workers; worker entrypoints only log jobs                                             | Code/config inspection                                                                                             | F04          |
| Certificate fallback produces self-signed certificates and marks endpoints ready; renewal and challenge delivery are incomplete     | Code/config inspection                                                                                             | F07          |
| Admin mode change writes files but does not apply live gateway changes or rebuild Better Auth configuration                         | Code/config inspection                                                                                             | F08          |
| Public pooler mounts different files from those generated by the application; firewall rules use INPUT for forwarded Docker traffic | Code/config inspection                                                                                             | F09          |
| Mail suspension/device/alias operations do not consistently mutate the native mail service                                          | Code/config inspection                                                                                             | F11          |
| Restore commands are marked isolated without executing in the isolated target; mail backup copies the live store                    | Code/config inspection                                                                                             | F12          |
| Updates lack the promised pull, readiness, recovery and scheduling pipeline; monitoring lacks working scrape wiring                 | Code/config inspection                                                                                             | F13/F14      |

The review was interrupted to produce this fix plan. Findings based on inspection still need their proposed integration tests; absence of a listed issue is not evidence that every other path is correct. In particular, the full native Stalwart/SES behavior and internet-facing network topology have not been tested live.

**2. Delivery rules and order**

Treat F01–F12 as production blockers for the corresponding capability. Public administration requires F02/F03/F04/F05/F07/F08; public databases additionally require F06/F09/F10; production mail additionally requires F11/F12. Do not enable automatic updates until F13 passes. Existing development instances may remain usable with clearly identified development behavior.

Implement changes as reviewable pull requests, each with a regression test for the failure it fixes. Start each package by preserving a failing reproduction in the appropriate test suite. Use dedicated disposable databases, Docker daemons/VMs and provider test accounts; never let tests discover production `.env` values or process an existing operation queue.

Suggested sequence:

| Milestone                                       | Packages           | Usable outcome                                                            |
| ----------------------------------------------- | ------------------ | ------------------------------------------------------------------------- |
| A. Contain privilege and auth defects           | F01, F02, F03      | Safe policy boundary and complete authenticated onboarding shell          |
| B. Make the platform executable and recoverable | F04, F05           | Actual Compose deployment, independent workers and reliable jobs          |
| C. Complete domain and endpoint lifecycle       | F06, F07, F08      | Manual DNS to working HTTPS, both administration modes                    |
| D. Complete data services and recovery          | F09, F10, F11, F12 | Public database and mail access with working roles and proven restoration |
| E. Complete operations and release validation   | F13, F14           | Safe updates, useful monitoring and full release acceptance               |

Schema contracts and test fixtures for later packages can be prepared earlier. Do not ship a path with an unsafe executor merely because its frontend is complete. Budget these as substantial implementation work rather than cosmetic fixes; estimate individual PRs after the worker/agent and native mail contracts are settled.

**F01. Replace the permissive Compose checks with a complete agent-enforced contract**

Primary files: `shared/src/compose-policy.ts`, `agent/policy.go`, `agent/main.go`, `agent/docker.go`, `agent/journal.go`, `server/src/modules/docker.ts`, and service/adoption handlers in `server/src/app.ts`.

Problems: TypeScript checks selected service fields but does not validate top-level volume/network ownership or volume driver options. The Go validator searches substrings, so equivalent YAML/JSON syntax can bypass it. The agent validates `payload.compose` but executes `payload.file`; those need not contain the same document. Arbitrary container IDs and adoption requests are not independently checked against an agent-owned resource ledger.

Implementation:

1. Define a versioned workload specification and a default-deny allowlist for every accepted service, volume, network and top-level field. Use a real parser in Go. Set input/alias/depth/service limits; reject unknown fields, duplicate keys and unsupported features.
2. Deny external volumes/networks, caller-chosen global names, local-driver bind mounts, driver options/plugins, platform resources, device access, host namespaces and unapproved capabilities. Introduce approved database network attachments only as agent-resolved resource references, never arbitrary network names.
3. Cover alternative mount and port syntax, ranges, YAML flow mappings/JSON, anchors, `volumes_from`, logging driver options, lifecycle hooks, host aliases and environment/file interpolation. Inject required hardening/resource limits into the generated model rather than relying on a user to include them.
4. Have the agent generate and persist the exact canonical Compose document under an agent-owned directory. Bind approval to its hash. Stop accepting API-supplied executable file paths. Defend approved host file access against traversal, symlinks and races.
5. Maintain a durable ledger of platform-protected and workload-owned container/network/volume IDs. Check current engine identity before every mutation. Labels are supplementary evidence. Adoption must inspect actual existing resources and deny platform/unowned targets even if the submitted manifest is harmless.
6. Normalize and validate the final effective Compose model before execution. Use fixed arguments, a minimal environment, process deadlines, bounded output and redaction. Remove `--no-interpolate` from `compose up`; enforce interpolation rejection during validation instead. Keep this functional fix behind the security-policy fix.
7. Give only the normal agent the socket; use an explicitly separate maintenance executor for its own upgrade. Logs/discovery/stats must flow through the agent as well, not through a hidden API-side Docker fallback.

Acceptance: both validators reject the three reproduced payloads; they also reject alternative encodings and protected-resource adoption. API requests cannot substitute an unvalidated file or container ID. Agent inspection returns scoped, redacted results. A permitted application deploys on an isolated Linux test daemon, with the effective mounts/networks/capabilities asserted afterward. Restarting the agent preserves its ownership ledger.

The named-volume bypass is real Docker behavior: the local volume driver can bind a host directory through `driver_opts`. See [Docker's volume reference](https://docs.docker.com/reference/compose-file/volumes/).

**F02. Repair first-owner setup and complete Better Auth MFA enrollment**

Primary files: `web/src/App.tsx`, `web/src/pages/Auth.tsx`, `web/src/pages/Wizard.tsx`, `web/src/pages/Views.tsx`, `server/src/auth.ts`, `server/src/access.ts`, and setup handlers.

Problems: `App` redirects a signed-in first owner straight to Wizard until `wizardCompleted`, preventing access to Settings. Wizard requires MFA. Settings' enrollment button ignores the returned TOTP URI and recovery codes, and does not complete enrollment verification. Signup succeeding is therefore not proof the installation is usable.

Implementation:

1. Introduce an explicit setup state machine: owner creation → MFA enrollment → code verification → recovery-code acknowledgement → assured session → domain setup. Render enrollment independently of normal navigation and wizard completion.
2. Use Better Auth's TOTP enable response to display a QR/manual secret and recovery codes. Keep these values in short-lived component memory; do not put them in URLs, logs or browser persistence. Verify a code through the supported API and confirm the resulting session satisfies server-side MFA assurance.
3. Inspect the pinned Better Auth 1.7.1 integration and Drizzle field mapping for `mfaEnrolledAt`. Test real session serialization; do not rely only on hand-constructed objects. Record assurance only after verification and reject pre-enrollment sessions. Allow an explicit re-login if the installed version requires it.
4. Make interrupted enrollment resumable. Implement invalid-code, recovery-code, lost-session, expired-bootstrap and concurrent-owner-creation handling. The first owner must be able to complete everything without a pre-existing working mailbox.
5. Require a deliberate recovery/re-enrollment flow for MFA loss. Do not make disabling MFA an ordinary unprotected endpoint or leave the final owner permanently locked out.

Acceptance: a real browser starts from empty volumes and completes owner creation, MFA and domain setup. Invalid/unverified enrollment cannot authorize mutations. Recovery codes are displayed and work once; stale sessions fail privileged checks. Reloading during enrollment neither bypasses verification nor strands setup.

Better Auth documents `totpURI`, recovery codes and the enrollment verification flow in its [two-factor guide](https://better-auth.com/docs/plugins/2fa). Verify exact return shapes against the pinned release.

**F03. Enforce authorization, CSRF, secret scoping and audit consistently**

Primary files: `server/src/app.ts`, `server/src/access.ts`, `shared/src/authz.ts`, `server/src/schema.ts`, and database migrations.

Problems: custom application endpoints lack a consistent CSRF boundary; multiple mutations omit MFA. Generic secret reveal checks operator status but not resource ownership. Device revocation lacks mailbox/domain authorization. Backup targets and some global settings/actions are insufficiently scoped. One-time reveal uses read/check/update rather than atomic consumption. Recent step-up uses session `updatedAt`, which is not evidence of a recent credential challenge. Some state responses expose raw operation payloads/evidence or Compose previews.

Implementation:

1. Add centralized browser-request protection before custom mutations: exact configured origin, expected media type, bounded bodies and an explicit CSRF strategy. Separate token-authenticated internal APIs. Better Auth's own route protection does not automatically protect Hono application routes.
2. Define route policies in one reviewable matrix: capability, resource scope, MFA, recent step-up and confirmation requirements. Apply them to every mutation, including project creation, service lifecycle, settings, backups, aliases and device revocation.
3. Restrict platform-wide exposure/settings/maintenance/access administration to appropriate owner capabilities. Resolve resource IDs server-side. Resolve mail queue IDs to native recipients/scope before permission checks; do not authorize using a recipient asserted by the caller.
4. Give secrets explicit owning resource/project/domain and purpose. Prefer resource-specific reveal/rotate endpoints. The generic endpoint must resolve ownership and disallow broad provider/root secrets. Check scope on log, query, backup and operation evidence access too.
5. Atomically consume one-time credentials with a conditional update/delete in the same transaction as the audit record; only the winning request can obtain plaintext. Define the lost-response behavior as rotation. Apply no-store and remove UI plaintext on expiry/navigation/logout.
6. Implement an actual short-lived step-up grant issued after credential/MFA verification, bound to user, session and action/plan. Session refresh timestamps must not extend it. Invalidate grants when permissions or dependencies change.
7. Replace raw database row serialization with response DTOs. Redact Compose environment values, provider responses, operation payloads, error text, command output and audit diffs before persistence and transport.
8. Persist requested changes, audit and job/outbox atomically. Use a non-superuser API database role with migrations performed separately; enforce audit append-only access at the database permission layer.

Acceptance: table-driven tests exercise every route for anonymous, unassured, stale-step-up, ungranted operator, viewer and owner identities. Foreign/same-site sibling origins and inappropriate content types fail custom writes. Unrelated secret/device/backup/queue IDs are denied. Two concurrent reveals yield one success. Canary credentials never appear in inventory, previews, audit, exceptions or job streams. Include real Better Auth sessions as well as narrow authorization fixtures.

**F04. Deliver the actual Compose runtime and independent workers**

Primary files: `infra/platform/docker-compose.yml`, `infra/mail/docker-compose.yml`, `workers/src/*`, `server/src/index.ts`, `server/src/env.ts`, installer scripts, Dockerfiles to add, and deployment documentation.

Problems: the platform manifest starts data engines/proxies but has no API/web, agent or module-worker services. Worker entrypoints merely list queued jobs; the API coordinator executes provider/database/backup adapters. Embedded execution defaults on. The installer retains static `ark`/`ark_app` database superuser credentials. The host API uses a default network bind even though setup instructions describe a loopback tunnel. Public Stalwart and control services share the same bridge.

Implementation:

1. Add reproducible multi-stage images and Compose services for web/API, coordinator, database/mail/domain/backup workers and agent. Keep one frontend/API artifact if convenient, but run credentialed adapters in separate processes.
2. Replace `runWorker` logging with typed claim/execute/heartbeat/complete loops. Move adapter imports and provider/root/cluster credentials out of the browser-facing API runtime. Disable embedded execution in production; retain a conspicuous development-only mode if useful.
3. Give each worker its own identity and permitted job types/resources. Use authenticated internal transport and least-privilege database/API access. Remove direct API subprocesses for Docker, nftables, backups, certificate reloads and provider maintenance.
4. Add explicit admin/control/mail-management/database-management/workload networks and egress where needed. Public mail must not share unrestricted connectivity to platform PostgreSQL. Reserve and test CPU/memory/PID/disk budgets.
5. Generate independent platform/application/bootstrap credentials and enforce restrictive filesystem modes. Configure distinct migration/runtime/backup roles. Preserve existing customized secrets on upgrade and provide a rotation migration for deployments using known defaults.
6. Use loopback-only bootstrap and no raw public API port. In the container topology, only the selected gateway reaches browser API routes. Add non-root/read-only filesystems, dropped capabilities and no-new-privileges where supported, with documented narrow exceptions.
7. Align all generated paths and UID/GID permissions with the actual service mounts. Mount only per-service keys. Generate operational configuration in a state directory rather than modifying repository files at runtime.
8. Make the installer wait for health, apply versioned migrations safely, start the complete selected topology and report real readiness. Supply a matching teardown/recovery runbook that preserves data by default.

Acceptance: a clean Linux host runs the built product using the documented Compose/installer workflow without host Bun/Python/Go servers. API has no socket/provider/root/cluster-admin secrets. Killing the API leaves mail/database workloads running; workers resume when control access returns. Default DB passwords are absent. External scans cannot reach raw API/control data ports.

**F05. Make the operation engine durable, fenced and truthful**

Primary files: `server/src/coordinator.ts`, `server/src/app.ts` internal endpoints, `shared/src/operations.ts`, operation schemas/migrations, worker runtime and agent journal.

Problems: no full lease heartbeat/recovery protocol or resource exclusion is implemented. Completion allows omitted claim tokens. Agent jobs can be claimed before payload preparation; normal start/stop requests contain only a target ID while the agent expects `containerId`. Separate workers do not execute their jobs. Desired state, external changes, secret persistence and audit are not atomic/recoverable. Several no-op/planning paths finish as succeeded.

Implementation:

1. Define immutable typed job contracts and versions for each executor. Either resolve target IDs within the agent's ledger or provide a fully prepared authenticated specification; never race agent claims against API payload construction.
2. Atomically insert desired-state revision, operation, audit and outbox. Add safe uniqueness/idempotency constraints. Serialize conflicts by resource/project/provider as appropriate, not merely by one process-local timer.
3. Require nonempty current claim tokens and worker ownership on heartbeat/complete. Compare operation state and claim in the same conditional update. Return a conflict if no row was updated. Reject expired, replayed and wrong-worker completions.
4. Record leases, attempt IDs and per-step intent/result. Couple takeover to execution-side fencing/exclusion; a timed-out worker may still be running an external command. Do not automatically replay destructive operations with uncertain outcomes.
5. Store generated credentials and planned object identities before external provisioning. Observe external state after interruption and resume/reconcile compatible steps. Expose partial completion as `needs_recovery` when it cannot be safely determined.
6. Add `waiting_for_dns`, `waiting_for_provider`, `awaiting_configuration`, `planned`, `needs_recovery` or equivalent typed states. A plan file, HTTP 200 containing provider errors, or disabled execution cannot count as verified completion.
7. Check cancellation and current authorization at safe step boundaries. Preserve last-known good configuration and journals independently where platform self-maintenance may take down the API/database.
8. Add durable schedules for verification retries, certificate renewal, monitoring, backup checks and approved update policies. Include timezone/DST, missed-run handling, duplicate prevention and restart recovery.

Acceptance: missing/stale claims fail; two workers cannot mutate one resource concurrently; expired claims are recoverable without racing a still-running executor. Kill workers before/after every external mutation and verify safe resumption. Permissions revoked after queueing prevent execution. Failed audit/outbox writes cannot leave an accepted but untracked requested change. The UI never displays “succeeded” for an unexecuted plan.

**F06. Implement verified, resumable domain onboarding**

Primary files: wizard/domain handlers in `server/src/app.ts`, domain operations in `server/src/coordinator.ts`, `shared/src/dns-plan.ts`, `shared/src/hostnames.ts`, `shared/src/schemas.ts`, `web/src/pages/Wizard.tsx`, and Domains UI.

Problems: `/api/domains` creates no expected ownership record, and verification treats an empty record set as success. Wizard immediately queues database/mail provisioning and certificates alongside verification; failed verification does not block the following jobs. Endpoint state is changed in bulk rather than independently. Later successful verification does not reliably resume dependent mail/certificate work. Custom hostname fields exist in the API but are absent from the wizard; mail provisioning reconstructs `mail.<domain>` instead of using the selected endpoint.

Implementation:

1. Route wizard and subsequent domain creation through one transactional domain-plan service. Every claim requires a stored challenge tied to the installation/resource, plus expected records with explicit purposes and dependency groups. Unknown domains and missing ownership records fail verification.
2. Build a dependency graph: ownership → endpoint DNS → certificate → native configuration → external probe → ready. Allow safe private preparatory steps, but do not publish or mark a service ready before its required checks pass.
3. Verify database, mail and admin hostnames independently. Inbound mail must not wait for outbound SES approval or unrelated admin DNS. Trigger only newly unblocked jobs and retry waiting states with bounded backoff.
4. Add editable custom database/mail/admin hostnames, validated IPv4 and optional validated IPv6, first-service fields and accurate DNS-provider guidance. Use one canonical stored endpoint identity throughout provisioning, client settings and certificates.
5. Inspect existing DNS for CNAME conflicts and current MX/SPF/DMARC policies. Present a diff and migration consequences; never silently overwrite existing delivery policy. Manual DNS is a complete supported flow without an API token.
6. Validate ownership against authoritative records and selected resolvers, with TXT chunk handling, normalization, TTL/propagation status, CAA and AAAA checks. Protect any network probing against SSRF and address rebinding; restrict probes to approved addresses/ports.
7. Implement optional DNS-provider writes only after a reviewed diff. Verify provider success bodies, pagination/unique zone selection, record ownership and post-write observations. Publishing records must not require those same records to have already verified.
8. Make renaming, removal and reassignment explicit migrations with fresh proof, dependency checks and retention of underlying data. Do not delete data or republish routes because a transient DNS lookup fails.

Acceptance: an empty record set cannot verify a domain; false/missing proof fails; the full manual-DNS flow completes after records become correct without restarting the app. Wrong mail DNS does not prevent an otherwise-ready database. User-selected hostnames appear in the actual service certificates/settings. Restart and retry do not create duplicate databases, secrets or provider identities.

**F07. Replace certificate simulation with a working issuance/renewal/deployment lifecycle**

Primary files: `server/src/modules/certificates.ts`, `shared/src/acme.ts`, certificate operations/schedules, platform Compose, edge config and certificate volume definitions.

Problems: missing lego configuration silently creates a self-signed leaf, and issuance sets the endpoint ready without proving listener deployment. ACME staging is the default even for user-facing readiness. Lego's webroot is not coherently mounted into the edge. `certificate.renew` calls the same `run` argument builder and has no complete renewal scheduler. Certificate/key files are copied individually, shared broadly and not verified at the consuming service.

Implementation:

1. Require explicit production ACME configuration for public endpoints. Keep self-signed/staging certificates in a clearly isolated development mode; they must never satisfy public endpoint readiness. Fail into an actionable configuration state rather than silently substituting certificates.
2. Use a single defined challenge webroot mounted at matching paths into worker and edge, with host routing and permissions tested. Keep the challenge path available in tailnet-admin mode because database/mail certificates still need renewal.
3. Implement real issue and renew operations against the pinned lego version, with durable account/order state, due scheduling, issuer rate-limit backoff, and no repeated issuance while DNS is wrong. Add optional supported DNS-01 automation separately.
4. Issue per-endpoint credentials and store certificate/key pairs atomically as versioned material. Validate SANs, issuer chain, expiry and key/certificate match before promotion. Only the correct consumer receives each private key.
5. Perform a restricted native reload or agent-approved replacement and probe the externally presented certificate using the real protocol. Store issuance, deployment and externally verified readiness as separate events. Preserve the previous valid pair on failure.
6. Use the selected private `*.ts.net` certificate mechanism for Tailscale. Do not issue public ACME certificates for a private custom name without a working challenge plan.
7. Alert on impending expiry, repeated renewal/deployment failures and stale verification. Implement cleanup/retirement only after dependent endpoints are detached.

Acceptance: staging integration proves issuance and renewal with a real ACME test environment; a controlled production smoke test verifies a publicly trusted certificate. Incorrect DNS, blocked challenge traffic and expired certificates cannot produce “ready.” New PostgreSQL/SMTP/IMAP/HTTPS connections present the renewed certificate. Renewal works with the admin page tailnet-only and after worker restart.

**F08. Apply admin mode changes to the live topology and Better Auth origin**

Primary files: `shared/src/edge.ts`, `server/src/modules/providers.ts`, `changeMode`, `server/src/auth.ts`, `server/src/env.ts`, platform gateway/Serve definitions and Settings UI.

Problems: `writeEdge` writes files without validating/reloading the running gateway. Caddy has its admin API disabled and no alternate reload process is invoked. The API reads Better Auth origin configuration once at startup, so setting database `adminMode` does not switch authentication URLs/cookies. The Tailscale config points to `127.0.0.1:8080`, but no namespace-sharing gateway is deployed. Public Caddy forwards every API path rather than restricting browser routes. The raw API's bind can bypass the intended gateway policy.

Implementation:

1. Deliver the actual loopback gateway sharing the Tailscale namespace and a tested public edge path. Do not expose the API process directly. Mount the Serve configuration directory as a directory and verify changes/recreation with the pinned image.
2. Generate allowlisted browser routes at the public edge. Deny internal worker, metrics, recovery/setup-after-bootstrap and service-native administration paths. Reject unknown hosts and sanitize forwarded headers. Separate workload proxy connectivity from control access.
3. Make one validated active-origin configuration authoritative for Better Auth and browser links. Apply it through a controlled restart/reconfiguration, not untrusted Host inference. Preserve host-only cookies and exact trusted origins.
4. Implement a staged mode-change job: validate destination; prepare config/certificate; test candidate listener; switch routing and origin; revoke affected sessions; verify login; retire old ingress. Retain a local recovery path.
5. For public → tailnet, explicitly close existing public admin streams/connections and test both hostname and raw-IP bypasses. Never restore public exposure automatically after a private-path failure. For tailnet → public, refuse activation without verified DNS/certificate and a working final-origin login.
6. Do not restart or alter public database/mail endpoints when changing admin mode. Keep public ACME challenges available where required.

Acceptance: browser login and privileged operations work on the selected final origin after both transitions. The old public admin route is actually unreachable after switching private, including forged Host/forwarded headers. Internal worker endpoints are not publicly routed. Existing database/mail connections remain unaffected. Gateway/sidecar replacement and failed transitions have exercised recovery procedures.

**F09. Fix PostgreSQL roles, public listener wiring and network policies**

Primary files: `shared/src/provision-sql.ts`, `server/src/modules/database.ts`, PgBouncer operations/provider helpers, `shared/src/pgbouncer.ts`, `shared/src/cidr.ts`, `infra/database/*`, platform Compose and database routes/UI.

Problems: default grants omit sequence privileges, and test database creation does not apply the primary database's schema/extension setup. Passwords are generated before execution but only saved after all DDL completes. Provisioning does not use a complete per-cluster connection model. The generated pooler config/userlist goes to `tmp/pgbouncer`, while Compose mounts `infra/database`; generated certificates are under hostname directories while pooler expects root files. Backend TLS verification is absent. Source CIDRs are shown per database but unioned across the host, including private databases. Generated nftables rules target INPUT rather than the forwarded path used by published containers.

Implementation:

1. Fix schema/default privileges for tables and sequences for every permitted object-creating role. Apply explicit function execution policy and test SECURITY DEFINER boundaries. Use a non-login owner unless a specific administrative use requires otherwise.
2. Provision test databases completely, including schema ownership/grants, extension selection and independent test credentials. Verify generated migration/runtime/read-only/test credentials using real connections before marking ready.
3. Use the F05 provisioning journal: persist encrypted intended passwords first; identify compatible pre-existing databases/roles; resume missing steps without generating a different password on every retry. Add an existing-installation repair operation instead of relying on init-only SQL.
4. Resolve cluster connection details from the managed cluster record and protected secret references. Do not route every cluster to one ambient `DATABASE_APP_URL`. Keep platform resources outside application management.
5. Align pooler config/userlist/certificate paths and permissions with the running Compose service. Add the public listener only after validated configuration, certificate and network policy are installed. Use a separate private pooler/management path with no public console credentials.
6. Generate explicit mappings and native authentication/authorization rules so public clients cannot select private databases or privileged roles. Remove mappings and terminate applicable existing public sessions when exposure is revoked.
7. Require client TLS/SCRAM, verified TLS to PostgreSQL, and verified client examples. Preserve TLS options when constructing direct/query connections; the current URL decomposition drops them. Test trust failures, not just successful encryption.
8. Implement source policy at endpoint scope initially, matching the product plan. Do not union per-database rules and claim they apply separately. Private database records must not restrict or widen unrelated public endpoints.
9. Apply the firewall in the actual Docker forwarding path for the selected iptables/nftables backend. Detect unsupported host setups and fail closed for restricted endpoints. Apply changes atomically and verify from allowed and denied external IPv4/IPv6 clients. Do not substitute an application-side CIDR checker for network enforcement.
10. Add public/private changes, role inventory and explicit credential handoff/rotation UI. Mark “ready” only after external pooler login and basic application access succeed.

Acceptance: migrate a `serial`/sequence-backed table and insert/read using the runtime role; the runtime role cannot perform DDL or cross-project access. Test DB credentials can perform their intended workflow. Interrupted provisioning resumes with matching credentials. Public login uses the selected hostname and verifies TLS; private databases and admin roles are denied. CIDR changes affect real external connections as displayed. Existing installed databases receive corrected grants safely.

**F10. Bound SQL execution and repair database workspace isolation**

Primary files: `server/src/modules/database.ts`, `shared/src/sql-guard.ts`, SQL/schema routes and `DatabasesView` in `web/src/pages/Views.tsx`.

Problems: query code retrieves all rows and only then slices to 200, allowing large responses to exhaust API memory. Per-request client instances provide no aggregate concurrency budget or cancellation endpoint. Frontend sends the first database ID as `workspaceId` regardless of selection and puts all results/schema/credentials into one shared output state. UI wording claims isolation that is not implemented.

Implementation:

1. Execute SQL in the database worker using server-controlled limits: statement/lock/transaction/connect timeouts, maximum concurrent queries per user/cluster, maximum rows and bytes, and bounded fetch/cursor/stream behavior. Do not rely solely on a SQL parser or elapsed timeout.
2. Use least-privilege native roles and read-only transactions for browsing. Enforce extension/function and write permissions independently of lexical classification. Validate query/read modes on every request.
3. Add a query execution ID and explicit cancel operation bound to actor/database. Cancel safely and close connections on disconnect, timeout and worker failure. Avoid logging SQL literals or result data by default.
4. Keep a workspace map keyed by actual database ID and role. Each execution captures an immutable SQL snapshot, workspace ID and request generation. Late schema/query responses update only their originating workspace.
5. Separate schema browsing, query results and one-time credentials into distinct UI state and components. Display the executed database/role next to results, preserve drafts on navigation, and expose limit/truncation/cancellation state honestly.

Acceptance: a huge `generate_series`/large-text query is bounded by measured memory, rows and bytes; timeouts/cancellation leave no active backend query. Switching databases during a query cannot overwrite the newly selected workspace. Multiple concurrent requests respect server limits. Successful generated-role use is tested through both pooled and direct supported paths.

**F11. Complete native Stalwart lifecycle and SES/DNS reconciliation**

Primary files: `infra/mail/*`, `shared/src/stalwart.ts`, `shared/src/mail-state.ts`, `server/src/modules/mail.ts`, `server/src/modules/providers.ts`, queue helpers, mail/device/alias handlers and mail workers.

Problems: the mail Compose file references the custom Orkmail image but does not supply that image's recovery environment or expected configuration/data paths. The upsert plan omits aliases and does not translate suspended mailboxes into native access restriction; omitted purged entries are not native deletion. Device creation/revocation changes local records only. A successful `/jmap` query is counted as applying configuration even without CLI execution, and JMAP method errors can exist inside HTTP 200. Native IDs are fabricated. The SES flow does not correctly establish readiness, propagate returned DKIM records or connect restricted SMTP credentials to the mail engine.

Implementation:

1. Choose a supported, pinned Stalwart distribution/configuration contract. Either correctly build and adapt the original image/bootstrap or replace it with an owned compatible image; do not depend on an unbuilt local image. Align data/config/certificate paths, users, health checks and recovery credentials.
2. Implement a version-tested adapter for domain/account/alias/settings/device/queue/lifecycle operations. Parse native method results and IDs. A status/query call is not a write; partial application must fail or enter recovery with evidence.
3. Apply mailbox suspension and device revocation to native access immediately. Implement retained deletion, explicit restore and permanent purge with dependency previews, recent step-up, observed completion and reserved addresses. Removing an item from an upsert plan must never count as deleting it.
4. Reconcile aliases immediately after create/update/delete, with cross-type collisions, loops and external-forward restrictions. Resolve queue ownership from the native item before mutation. Use actual native IDs including domain context.
5. Propagate the user's selected mail hostname and per-service certificates into actual SMTP/IMAP listeners. Configure submission TLS/authentication and implicit IMAPS explicitly; comments in configuration are not enforcement. Verify unauthorized relay denial against the running pinned version.
6. Make SES reconciliation idempotent and check provider success/error bodies, account production/quota status, domain verification and relay test results separately. Fetch actual DKIM tokens and MAIL FROM records into the DNS plan. Avoid using truthiness of response objects or presence of AWS keys as readiness.
7. Bootstrap restricted provider/SMTP credentials, persist and deploy them only to the required worker/mail secret mount, and remove broad bootstrap credentials. Keep outbound paused until verified; do not silently fall back to direct delivery. Receiving must start independently of SES.
8. Write generated credential-bearing native plans with restrictive permissions and controlled retention, or pass secrets directly through a protected channel. Never return these plans as general operation evidence.

Acceptance: on a disposable real Stalwart instance, create a mailbox and deliver/read a message; create an alias and verify delivery; suspend and observe denied login/submission; revoke a device and observe rejection; recover retained mail; purge a disposable mailbox and verify native completion. Inbound works with SES unavailable. Controlled SES tests prove actual DKIM/MAIL FROM and relay behavior. No open relay or public native admin endpoint is present.

**F12. Make backups consistent and restore proof meaningful**

Primary files: `shared/src/backup-plan.ts`, `server/src/modules/backups.ts`, backup/restore operations, `infra/restore/docker-compose.yml`, storage config to add and recovery scripts.

Problems: the restore planner returns `isolated: true` but executes pgBackRest with the normal stanza/config and no isolated data path. It never starts or connects to the supplied isolated Compose target. Successful subprocess exit is immediately labeled `restore_verified`; no database/mail assertions are run. Selected backup IDs are not bound to the native snapshot restored (`latest` may be used). Mail backup directly reads the changing live store. Hashing command output is not an archive checksum or native snapshot ID.

Implementation:

1. Model backup sources, repositories, native backup IDs, manifests, encryption keys, retention and consistency recipes. Resolve these from authorized records; do not treat user-supplied target strings as interchangeable stanza/repository/filesystem paths.
2. Configure pgBackRest base backups/WAL archiving for each real cluster, plus logical export/grant recovery where required. Test the backup/restore tooling and PostgreSQL versions together. Verify recovery keys independently of the database being backed up.
3. For mail and persistent volumes, implement a supported online consistent snapshot or an explicit stop/quiesce/copy/resume job with failure-safe resume. Never make a live directory copy count as a proven consistent store.
4. Launch restore verification in a dedicated isolated runner/project with fresh volumes, unique identity, blocked outbound effects and an explicit alternate data path/config. Do not invoke restore against the production stanza's default data directory. Bind the exact requested backup ID and recovery target into the approved operation.
5. Boot restored services privately and verify database roles/grants/application queries, representative mail contents and configuration/secret integrity. Record actual archive identity, checksums, tested service versions, validation results and elapsed recovery time.
6. Keep planned, uploaded, integrity-checked and restore-tested states separate. A zero exit code from extraction is not restore proof. A restore test for one resource cannot mark another backup verified.
7. Add schedule/retention handling with bounded staging space, concurrency locks, storage failure alerts and explicit pruning credentials. Fail safely if required backup configuration is absent. Keep previous recovery points during fixes/migration.
8. Replace the checklist-only host recovery experience with an executable, stepwise recovery workflow plus a documented manual fallback. Ensure restored workers cannot replay stale destructive/provider jobs before reconciliation review.

Acceptance: the restore runner demonstrably writes only to new isolated volumes; sentinel data in the source remains unchanged. Exact backup selection is verified. Corrupt/incomplete archives and incorrect credentials fail proof. A full fresh-host drill restores platform, application data and actual mail, with external writes disabled until cutover. Record measured recovery objectives instead of claiming untested targets.

**F13. Complete updates, rollback and platform maintenance**

Primary files: registry/update helpers, update operations, agent deployment code, `shared/src/maintenance.ts`, `scripts/maintain.ts`, release manifests and Updates UI.

Problems: discovery performs a bare registry HEAD with incomplete authentication/media-type/error handling. Deploy uses `--pull never` without a preceding pull. Current digest inspection reads image-only metadata from a container and omits the deployment file/project context required by other Compose operations. Updates overwrite desired configuration before observing success and have no complete health/rollback path. Stateful classification relies on names. Maintenance validates a self-computed image-list hash but does not bind the executed Compose file to that list or trusted publisher.

Implementation:

1. Implement registry authentication challenges, repository/architecture handling, manifest/index types, explicit failure states, rate limits and caching. Store immutable candidate digests plus the allowed update channel and provenance evidence.
2. Resolve and pull the exact approved image before deployment; compare the actual running image ID/digest afterward. Use the agent ledger/canonical manifest for all Compose operations. Do not treat unavailable digest evidence as successful verification.
3. Record immutable deployment revisions and secret-version references before mutation. Approvals bind to resource revision, exact digest, exposure/data changes and health/recovery recipe. Revalidate approval and permissions when execution begins.
4. Determine statefulness from managed data and adapter metadata, not display names. Require tested recovery points and release-specific migration handling for persistent services. Preserve previous manifests and images until stabilization succeeds.
5. Deploy under a resource lock, check readiness plus application smoke tests, observe a stabilization period, then mark verified. Execute an approved rollback only when compatible with stored data; otherwise provide forward recovery/restore.
6. Implement scheduled detection and opt-in automation only for explicitly eligible stateless services after manual deployment/recovery tests. Do not silently interpret an `auto_stateless` field as completed automation.
7. Bind platform maintenance to a trusted signed release containing the exact normalized Compose manifest, images and migration requirements. Verify trust separately from a checksum. Use an independent durable runner capable of updating the agent/API safely; never run an unrelated caller-supplied Compose file after approving a different image list.

Acceptance: fresh-host deployment pulls and runs the approved digest. Registry authorization failure is visible. An unhealthy update restores a compatible prior stateless revision; stateful incompatibility blocks automatic rollback. Renaming a database service cannot make it eligible for stateless automation. Changing the approved maintenance manifest/image invalidates verification. Interrupted self-update recovers through the journal/local procedure.

**F14. Finish monitoring, frontend truthfulness and release validation**

Primary files: `infra/monitoring/*`, metrics/alerts handlers, agent observation transport, `web/src/App.tsx`, `web/src/pages/*`, test directories, CI and operational/security documentation.

Problems: Prometheus defaults to `/metrics`, but no compatible protected metrics endpoint is wired; `/api/metrics` returns session-protected JSON instead. Host/service observations and notification behavior are limited. UI controls frequently imply completion that is only a local record change. Real browser workflows, external protocol tests and recovery failure tests are absent. Security checkboxes currently overstate verified implementation.

Implementation:

1. Expose a private Prometheus-format endpoint or exporter with service authentication; wire the correct network target/path and credentials. Keep browser metrics queries scoped through the API. Add agent events plus periodic reconciliation, with explicit stale/unknown status.
2. Add actionable database/pool/mail queue/certificate/backup/host/disk/agent alerts. Implement resolved states, acknowledgements, silences and notification retries. Use an independent off-host heartbeat receiver to detect complete host loss. A static reminder alert is not an external heartbeat implementation.
3. Route logs/stats through scoped agent requests with bounded live streaming/history, redaction, escaping, rate limits and reconnect behavior. Test permission revocation during a stream. Show unavailable historical logs honestly.
4. Make every UI action follow queued → running/waiting → verified/failed/recovery state. Replace misleading ready/success labels and dead-end controls. Add error handling and pending guards to all actions. Capture form elements/data before asynchronous work; do not access React's `event.currentTarget` after awaiting submission.
5. Add actual browser automation for first owner/MFA, domain setup, final-origin login, role restrictions, service deployment, credential handoff, SQL workspace switching and mode transitions. Remove hardcoded-success fallbacks from tests.
6. Add isolated integration suites for actual Docker, PostgreSQL, Stalwart, ACME and recovery. Keep provider mocks for deterministic unit tests but add controlled opt-in provider acceptance with documented prerequisites. Tests must refuse production endpoints/queues and use unique disposable resources.
7. CI runs formatting/lint/typecheck, unit and policy tests, migrations from empty and previous schemas, native integration tests and frontend build/browser tests. Add scheduled Linux deployment/restore/failure drills, dependency/image/secret scanning and release artifact verification.
8. Rewrite `README.md`, `docs/architecture.md`, `docs/operating.md` and `docs/security-review.md` around observed behavior. A checkbox requires a linked test/run artifact, not a comment or helper name. Separate implementation status from deployment acceptance and limitations.

Acceptance: Prometheus successfully scrapes the actual deployment and generates a controlled failure alert; stopping the host triggers the independent heartbeat alarm. Browser flows run against real built assets. Test failures cannot be converted to success through missing build/provider/restore fallbacks. Documentation accurately identifies any remaining unsupported feature.

**3. Schema and upgrade work across packages**

Use additive migrations first, preserving current installations and their secrets. Add explicit worker identities/capabilities, step-up grants, scoped secret ownership, job claims/steps/resource locks, domain dependencies, endpoint/certificate deployment state, agent resource bindings, database connection references, backup manifests and deployment revisions as needed. Keep raw provider credentials out of browser-visible records.

Backfill existing records as unverified where reliable evidence is absent. Do not infer “ready” from previous status strings, invent native resource IDs, or assign unowned secrets/resources to a random user. Provide an owner-visible repair/adoption queue. Existing databases need grant repair and credential reconciliation; existing endpoints need real DNS/certificate/listener verification; prior restore proof needs revalidation. Preserve data while correcting metadata.

Before upgrading, back up the platform database/keys and capture existing live state. Stop obsolete workers so old and new executors cannot race. Deploy a compatible API/worker/agent release set, migrate, reconcile observations, then enable verified mutation paths. Rollback must account for schema/data compatibility, not just application image tags.

**4. Final end-to-end release gate**

Run this on a fresh disposable Linux host, then repeat the upgrade path from a representative existing installation:

1. Install using the documented workflow; confirm the complete Compose topology, generated credentials and private control boundaries.
2. Create the owner, enroll/verify MFA and retain recovery codes through the actual browser UI.
3. Choose custom database/mail/admin names, manually publish the displayed DNS records, and watch each endpoint advance only when its prerequisites pass.
4. Log into public administration at its final trusted HTTPS origin. Confirm non-browser internal paths and raw API ports are unreachable externally.
5. Create a database; use generated runtime credentials from an external host to insert into a sequence-backed table over verified TLS. Confirm private/privileged access and disallowed source addresses fail.
6. Deliver incoming mail from an independent sender, read through IMAPS, test submission/SES when configured, and verify alias, suspension and device revocation behavior.
7. Deploy a pinned stateless workload through the agent, inspect logs/stats, restart it and reject every forbidden mount/network/adoption fixture.
8. Switch administration to tailnet-only. Confirm the public admin route and existing public admin streams close while public database and mail access continue. Verify private login and local recovery.
9. Exercise ACME renewal, kill/restart workers during operations, and demonstrate safe resumption without duplicate mutations or mismatched secrets.
10. Restore exact database and mail backups into isolated targets; run data/access assertions and confirm source data and external providers were untouched.
11. Exercise a failed stateless update and safe recovery, and prove that an unsafe stateful update/rollback is blocked.
12. Trigger monitoring/notification/host-heartbeat failures and verify actionable alerts. Confirm no canary secrets leak in API payloads, UI previews, logs, manifests or audit output.

Attach the test results and measured recovery times to the release record. Fix 1 is complete when the relevant work-package acceptance criteria and this release gate pass, and no production-facing capability is silently implemented as a plan-only or success-shaped no-op.
