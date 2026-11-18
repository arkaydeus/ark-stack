# Code review — Ark Stack control plane, agent, and workspace tooling

- Reviewer: Claude (Fable 5.1), automated commit-and-review workflow
- Date: 2026-09-15
- Branch: `commit-code-review-625378d34475-r1`
- Head: `5159429b30f84f3bb5511eb2847e3bb2d61d9b53`
- Base: `2ab5494402b6a3fce3cedbc99611572c3b44ee69`

## Review Scope

- Target branch: main
- Base ref: `main...HEAD`. Base `2ab5494402b6a3fce3cedbc99611572c3b44ee69` (Initial commit), head `5159429b30f84f3bb5511eb2847e3bb2d61d9b53`. Note: `origin/main` already points at the head commit, so `origin/main...HEAD` is empty; the review covers the full PR #1 content relative to the local `main`.
- Commit created: none (automated review)
- Files reviewed:
  - `server/src/app.ts`, `auth.ts`, `access.ts`, `env.ts`, `index.ts`, `cli.ts`, `db.ts`, `migrate.ts`, `schema.ts`, `coordinator.ts`, `modules/*.ts` and their tests
  - `workers/src/*.ts`
  - `shared/src/*.ts` and tests, `scripts/*.ts`, `templates/*.yml`, `tests/**`
  - `agent/*.go`, `agent/Dockerfile`, `agent/go.mod`
  - `web/src/**`, `web/vite.config.ts`, `web/index.html`, `e2e/onboarding.spec.ts`
  - `Dockerfile`, `infra/**`, `.github/workflows/ci.yml`, `mise.toml`, `.env.example`, `.gitignore`, `server/drizzle/*.sql`
- Files skipped:
  - `bun.lock`, `agent/go.sum` (lockfiles)
  - `docs/*.md`, `README.md`, `fix1-plan.md` (documentation, used only as context)
  - `web/src/components/ui/*.tsx`, `web/src/styles.css`, `.oxfmtrc.json`, `.oxlintrc.json`, `web/components.json` (generated/vendored UI primitives and formatter config)
- Files left uncommitted: none (working tree clean at start and end)
- Commands run:
  - `bun install --frozen-lockfile` — PASS (245 packages)
  - `bunx oxfmt --check .` — PASS (142 files)
  - `bunx oxlint . --deny-warnings` — PASS
  - `bunx tsc --noEmit -p shared|server|web|workers/tsconfig.json` — PASS (0 errors each)
  - `bun test shared server workers tests` without database — FAIL (expected: 5 files abort at module load on missing `DATABASE_URL`)
  - `bun run --cwd server db:migrate` against disposable `postgres:17` — PASS (12 migrations)
  - `bun test shared server workers tests` with database — PASS (81 pass, 0 fail, 20 files)
  - `go test -count=1 ./...` in `agent/` — PASS
  - `go vet ./...` in `agent/` — PASS
  - `bun run --cwd web build` — PASS
  - `bun scripts/test-edge-config.ts` — PASS
  - `docker compose ... config --quiet` for platform, platform+dev, mail, monitoring — PASS
  - Ad-hoc probes (sign-up path variants, compose-policy inputs, `postgres:17` with `--cap-drop ALL`) — see Issues
- Commands not run:
  - `bun scripts/test-e2e.ts` (Playwright onboarding) — requires browser install and a full stack; out of scope for this pass
  - `bun scripts/test-stalwart-integration.ts`, `bun scripts/test-upgrade-migrations.ts` — container-heavy integration checks, not needed for the findings below
  - `ARK_DOCKER_INTEGRATION=1 go test` — Docker-mutating integration test
- Limitations:
  - No end-to-end boot of the production compose stack was performed; two deployment findings are based on code plus targeted container probes.
  - Web UI findings are from static reading and server contract comparison, not browser execution.

## Risk Profile

- Change type: feature, infra, security, migration, ui
- Risk areas: auth, authorization, data-loss, external-io, database, concurrency, background-jobs, deployment, supply-chain
- Overall risk: high
- Reasoning: This is a new control plane that provisions databases, DNS, certificates, mail, and Docker workloads with a socket-privileged agent. The core operation pipeline has state-machine bugs that break multi-worker production, the agent can be pointed at the platform's own compose project, and the production compose topology cannot boot as written.

## Issues

### 1. [P1][conf:88][concurrency]

#### Backup worker re-executes delegated `update.apply` every poll cycle

- File: server/src/app.ts:200
- Symbol: workerPrefixes / coordinator.applyUpdate
- Description: The backup worker's allowlist includes the `update.` prefix, so it claims `update.apply`. `applyUpdate` inserts a deployment revision, rotates `desiredRevision`, then throws `DelegateToAgent` and requeues the same row with the compose payload. The requeued row is still claimable by the backup worker, which repeats the insert and rotation on every cycle it wins against the agent.
- Evidence: `backup: ["backup.", "update.", "import."]` and `agent: ["service.", "update.apply"]` at `app.ts:197-202`; `claimQueued` only applies the payload guard when `agentOwned` is true (`coordinator.ts:280-287`); the embedded-mode guard at `coordinator.ts:357` checks `payload.file`, a key the delegation payload never sets (it sets `compose`, `composeHash`, `project`).
- Suggestion: Remove `update.` from the backup worker allowlist (grant `update.detect` explicitly), and in `applyUpdate` short-circuit when `payload.composeHash` is already present. Fix the `processQueued` guard to check `composeHash`.
- Verification: Enqueue `update.apply`, claim with backup-worker prefixes twice; assert exactly one `deployment_revisions` row and that the second claim returns nothing.

### 2. [P1][conf:88][correctness]

#### Operator-initiated domain verification always fails at the `edge.apply` follow-up

- File: server/src/coordinator.ts:660
- Symbol: issueCertificate
- Description: `domain.verify` -> `certificate.issue` -> `edge.apply` propagates the operator's `actorId` onto a `platform`-targeted operation. `runOperation` calls `assertExecutionAuthorized` on every operation, which rejects non-owners for the `platform` target. The endpoint stays at `testing`, the Caddy route is never applied, and a failed-operation alert fires.
- Evidence: `await enqueue({ kind: "edge.apply", actorId: operation.actorId ?? undefined, targetIds: ["platform"] })` (`coordinator.ts:660`); `if (targetId === "platform") throw new Error("Only owners may execute platform-wide operations.")` (`coordinator.ts:443`); `/api/domains/:id/verify` requires only operator (`app.ts:925-928`).
- Suggestion: Enqueue system follow-ups (`edge.apply`, `pgbouncer.reload`) without `actorId`, or mark them as system-derived so the platform check is skipped.
- Verification: Run `certificate.issue` with an operator actor, process the resulting `edge.apply`, assert it succeeds.

### 3. [P1][conf:85][security]

#### A project slug of `platform` makes the agent run `docker compose up` against the control plane

- File: agent/main.go:178
- Symbol: execute / composeUp
- Description: Project names are derived as `ark-${slug}` and the slug regex allows `platform`, `mail`, and `monitoring`. The agent passes the payload project name straight to `docker compose -p <project> up -d` with no validation. A service named `api`, `postgres`, or `edge` deployed into slug `platform` is recreated by Compose inside the real `ark-platform` project, replacing the platform container with the operator's image. The only guard runs after `compose up` has already mutated the host.
- Evidence: slug regex `/^[a-z][a-z0-9-]{0,40}$/` (`shared/src/schemas.ts:92`), no reserved-slug check at `app.ts:952-961`; `ark-${project?.slug ?? "workload"}` (`coordinator.ts:997`, `app.ts:1182`); `exec.CommandContext(ctx, "docker", "compose", "-f", file, "-p", project, "up", ...)` (`agent/docker.go:487`); `name: ark-platform` (`infra/platform/docker-compose.yml:1`).
- Suggestion: Reserve `platform`, `mail`, `monitoring`, `restore` slugs server-side, and have the agent reject project names matching `ark-platform`, `ark-mail`, `ark-monitoring` before any Docker call. Pre-flight: refuse if containers already exist under that project that are not in this workload's ledger.
- Verification: Unit test `execute` with `project: "ark-platform"` and assert rejection before Docker is invoked.

### 4. [P1][conf:85][security]

#### Wizard can be re-run by any operator, bypassing owner and step-up controls on admin exposure

- File: server/src/app.ts:729
- Symbol: POST /api/wizard
- Description: The wizard has no `wizardCompleted` guard and requires only operator plus MFA. It rewrites `adminMode`, `baseDomain`, `adminHostname`, and `authOrigin`, and creates a public admin endpoint. The same `adminMode` change through `/api/settings/mode` requires owner plus an `exposure.public` step-up, and `PUT /api/settings` requires owner.
- Evidence: `requireOperator(access); requireMfa(session);` with no setup check (`app.ts:732-733`); owner check and `requirePrivileged(..., "exposure.public", ...)` at `app.ts:2069-2076`; owner check at `app.ts:2090`.
- Suggestion: Require owner, reject when `platform_setup.wizard_completed` is already true, and require the `exposure.public` step-up when `adminMode` is `public`.
- Verification: As an operator after wizard completion, POST `/api/wizard` with `adminMode: "public"`; expect 403.

### 5. [P1][conf:85][security]

#### Maintenance token check fails open when `ARK_MAINTENANCE_TOKEN` is unset

- File: server/src/app.ts:1704
- Symbol: POST /api/platform/maintain
- Description: When the env var is empty the comparison target becomes the literal string `missing`, so the header `x-maintenance-token: missing` satisfies the second factor. `env.ts` does not require the variable for the API role.
- Evidence: `secureEqual(c.req.header("x-maintenance-token") ?? "", env.maintenanceToken || "missing")`; `maintenanceToken: process.env.ARK_MAINTENANCE_TOKEN ?? ""` (`env.ts:33`).
- Suggestion: Throw 503 when `env.maintenanceToken` is empty, or make it `required()` for the API runtime.
- Verification: Start the API without the variable, call the route with header `missing`; expect rejection.

### 6. [P1][conf:90][security]

#### Long-form `published` port ranges bypass the reserved-port policy

- File: shared/src/compose-policy.ts:412
- Symbol: extractPorts
- Description: The range check only runs for string port entries. For object entries `Number("80-81")` is `NaN` and is silently dropped, so a range covering 25, 80, 443, or 5432 validates with `ports: []`.
- Evidence: Probe `ports: [{target: 80, published: "80-81"}]` returned `{"ok":true,"ports":[]}` while the short form `"80-81:80"` was rejected with "Port ranges and ambiguous publish syntax are not allowed."
- Suggestion: In the object branch return `[Number.NaN]` when `published` is not a finite integer or contains `-`, so it hits the existing violation.
- Verification: Add the long-form range case to `compose-policy.test.ts` and assert `ok === false`.

### 7. [P1][conf:85][deployment]

#### `api` container is `read_only` but service registration writes compose files under the image filesystem

- File: infra/platform/docker-compose.yml:11
- Symbol: x-app anchor / docker.composeDir
- Description: The `api` service has no `ARK_COMPOSE_DIR`, so `writeApprovedCompose` falls back to `/app/tmp/compose/<id>` on a read-only root with only `/tmp` as tmpfs. The `services` row is inserted before the write, so every `POST /api/services` in the production stack leaves an orphaned `registered` row and returns a 500.
- Evidence: `read_only: true` (`docker-compose.yml:11`); no `ARK_COMPOSE_DIR` anywhere in the compose file; `join(process.cwd(), "tmp", "compose", serviceId)` (`server/src/modules/docker.ts:19`); `db.insert(services)` precedes `writeApprovedCompose` (`app.ts:1160-1171`); `WORKDIR /app` in `Dockerfile`.
- Suggestion: Set `ARK_COMPOSE_DIR=/tmp/ark-compose` (or a named volume) on `api`, and write the file before the insert or wrap both in a transaction.
- Verification: Boot the stack and register a service; expect success and no orphan rows.

### 8. [P1][conf:90][deployment]

#### `postgres` and `app-postgres` cannot start with `cap_drop: [ALL]` and no `user:`

- File: infra/platform/docker-compose.yml:34
- Symbol: services.postgres / services.app-postgres
- Description: The official entrypoints run as root and drop to `postgres` with `gosu`, which needs `CAP_SETUID`/`CAP_SETGID` and `CAP_CHOWN`. With the bounding set emptied the container exits immediately. CI only runs `compose config`, so this is never exercised.
- Evidence: Running `postgres:17` with `--cap-drop ALL --security-opt no-new-privileges:true` exited with status 1 and logged `chmod: changing permissions of '/var/lib/postgresql/data': Operation not permitted` and `error: failed switching to 'postgres': operation not permitted`.
- Suggestion: Add `cap_add: [CHOWN, SETUID, SETGID, DAC_OVERRIDE, FOWNER]`, or run as `user: postgres` with a pre-owned volume. Add a CI step that boots `postgres` with `--wait`.
- Verification: `docker compose -f infra/platform/docker-compose.yml up --wait postgres` succeeds.

### 9. [P1][conf:80][correctness]

#### Agent ledger assumes one workload per Compose project, but the server shares one project per slug

- File: agent/ledger.go:63
- Symbol: recordWorkload
- Description: `recordWorkload` scans every container labelled with the project and fails if any service name is absent from this workload's compose. The server uses `ark-<slug>` for all services in a project, so the second service deployed into any project fails post-up, the new containers are never ledgered, and later start/stop/logs operations fail with "no currently owned container matches". Removing a service between revisions triggers the same failure because orphans are kept.
- Evidence: `if item.Labels["com.docker.compose.project"] == project { ... composeServiceImage(compose, serviceName); if err != nil { return err } }` (`ledger.go:69-74`); `COMPOSE_IGNORE_ORPHANS=1` (`docker.go:491`); no rollback after `composeUp` (`main.go:197-200`).
- Suggestion: Use a per-service project name, or scope the scan to the services declared in this compose and clean up on post-up validation failure.
- Verification: Deploy two services with different names into one project on the integration daemon; the second must succeed.

### 10. [P1][conf:85][correctness]

#### Empty allowlist generates a self-deleting nft script that the host scripts then reject

- File: shared/src/cidr.ts:106
- Historical symbols: `nftAllowlist` and `applyNft`. FD-15 uses `renderDbIngress` and `applyPolicy` in `scripts/database-ingress.ts`.
- Description: With no CIDRs the generated file creates then deletes the table. Both host-side scripts run `nft list table inet ark_db_ingress` afterwards, which fails, so they record `applied=false` and stop the listener. The documented "any authenticated client" mode can never expose the port through the ingress container.
- Evidence: `table inet ark_db_ingress\ndelete table inet ark_db_ingress` (`cidr.ts:107`); `if (!listed.includes("ark_db")) throw new Error("nft readback did not show ark_db_ingress")` (`scripts/database-ingress.ts:44`); the server-side `applyDatabaseAllowlist` special-cases `!cidrs.length` but the scripts do not.
- Suggestion: Emit a real table with an accept-only chain for the empty case, or have both scripts treat "table absent" as the expected state when the file carries an open-mode marker.
- Verification now covered by `mise run test:db-ingress`, which checks the 5432 policy acknowledgement and both network paths. HAProxy owns the public listener.

### 11. [P1][conf:85][correctness]

#### Cloudflare mutation chooser overwrites a single unrelated record of the same type and name

- File: shared/src/cloudflare.ts:32
- Symbol: chooseCloudflareMutation
- Description: When exactly one record exists with different content, the function returns `update` for that record regardless of what it is. Writing an apex SPF TXT replaces an existing `google-site-verification` TXT; writing MX replaces the incumbent provider's MX.
- Evidence: Probe with existing `[{id:"1", content:"google-site-verification=xyz"}]` and an SPF write returned `{"action":"update","id":"1"}`. Caller fetches existing records by type and name only (`server/src/modules/providers.ts:108-113`).
- Suggestion: Only `update` when the existing content is recognisably the same kind (`v=spf1`, `v=DMARC1`, the `_ark-stack` token); otherwise `create` for TXT or fail with "resolve manually" for MX/A/AAAA/CNAME.
- Verification: Unit test with one unrelated TXT asserting the action is not `update`.

### 12. [P2][conf:95][correctness]

#### All shipped compose templates are rejected by the compose policy

- File: templates/http-app.yml:11
- Symbol: ""
- Description: Each template uses a `deploy:` block, which is not in the service key allowlist. Users starting from the "reviewed" templates fail validation immediately.
- Evidence: `validateComposeSource` on all three templates returned `Unsupported field "deploy" is rejected.`
- Suggestion: Remove `deploy:` (limits are injected by canonicalisation) and add a test that iterates `templates/*.yml` through the validator.
- Verification: The new test passes.

### 13. [P2][conf:78][correctness]

#### Failed agent deploy leaves the service claiming the new image digest

- File: server/src/coordinator.ts:1084
- Symbol: applyUpdate / finalizeAgentCompletion
- Description: `applyUpdate` writes the candidate `compose` and `imageDigest` onto the service before delegating. On agent failure only `status` is set to `failed`, so update detection reports the unapproved digest as current and a later `service.deploy` uses the pinned candidate compose.
- Evidence: `.set({ compose: nextCompose, imageDigest: digest, desiredRevision, status: "updating" })` before `throw new DelegateToAgent(...)`; failure branch at `coordinator.ts:463-476` sets status only.
- Suggestion: Keep the desired digest on the revision row until success; restore prior `compose`/`imageDigest` on failure.
- Verification: Run `applyUpdate` then `finalizeAgentCompletion(op, false)`; assert `imageDigest` equals the pre-update value.

### 14. [P2][conf:85][correctness]

#### Certificate expiry and backup-stale alerts become permanent

- File: server/src/modules/alerts.ts:80
- Symbol: evaluateAlerts
- Description: Renewals insert new `certificates` rows and never supersede old ones, so every superseded row raises a critical alert forever. The backup-stale filter flags any row older than 36 hours regardless of newer backups for the same target.
- Evidence: No `delete(certificates)` or status update in `issueCertificate` (`coordinator.ts:644-654`); alerts iterate all rows (`alerts.ts:80-106`).
- Suggestion: Mark prior certificate rows superseded on issue and evaluate only the newest row per endpoint; compute backup freshness per `(kind, targetId)`.
- Verification: Insert an old and a new cert row for one endpoint, run `evaluateAlerts`, assert no critical alert.

### 15. [P2][conf:75][correctness]

#### Stateful `update.apply` is unreachable because nothing sets `restore_verified`

- File: server/src/coordinator.ts:1068
- Symbol: applyUpdate / restoreBackup
- Description: The stateful gate requires a backup with `restoreVerified` and status `restore_verified`, but `restoreBackup` writes `integrity_ok` directly and no code path sets `restoreVerified`.
- Evidence: `backup.restoreVerified && backup.status === "restore_verified"` (`coordinator.ts:1069`); grep of `server/` finds no writer of `restoreVerified: true`.
- Suggestion: Transition to `restore_verified` via `nextBackupStatus` when the restore run validates, and add a test proving the gate can be satisfied.
- Verification: Test that a verified restore allows a stateful update.

### 16. [P2][conf:80][concurrency]

#### `claimQueued` target-overlap exclusion and `enqueue` dedupe are check-then-act across transactions

- File: server/src/coordinator.ts:275
- Symbol: claimQueued / enqueue
- Description: The `NOT EXISTS (... status = 'running')` predicate is evaluated per claimer snapshot, so two workers can concurrently claim two queued rows sharing a target. `enqueue` mints a random idempotency suffix once a prior terminal operation exists, so concurrent callers create duplicates.
- Evidence: `FOR UPDATE SKIP LOCKED` locks only the selected row (`coordinator.ts:299`); `const idempotencyKey = related.length ? ${base}:${createId("idem")} : base;` (`coordinator.ts:230`).
- Suggestion: Take `pg_advisory_xact_lock(hashtext(target))` inside the claim transaction; wrap enqueue lookup plus insert in a transaction with an advisory lock on the base key.
- Verification: Concurrent claim and enqueue tests asserting a single winner.

### 17. [P2][conf:85][concurrency]

#### Embedded coordinator never heartbeats, so long operations get reclaimed mid-run

- File: server/src/coordinator.ts:348
- Symbol: processQueued
- Description: The embedded runner claims with a 90-second lease and awaits `runOperation` without heartbeating. Any concurrent `claimQueued` call resets the row to `queued`, and operations that exceed 90 seconds (ACME, restore, deploy) are re-executed while the original completes and then fails as stale. Development mode only.
- Evidence: No `heartbeatClaim` call in `processQueued`; the remote runtime does heartbeat every 15 seconds (`workers/src/runtime.ts:62`).
- Suggestion: Heartbeat on an interval during `runOperation`, matching the worker runtime.
- Verification: Test with a long fake operation and a concurrent reclaim.

### 18. [P2][conf:80][security]

#### `/api/step-up` password verification has no rate limit

- File: server/src/app.ts:846
- Symbol: POST /api/step-up
- Description: `auth.api.verifyPassword` is called server-side, so Better Auth's rate limiter that wraps `auth.handler` does not apply. A stolen post-MFA session cookie can brute-force the password to mint step-up grants for secret reveal and credential rotation.
- Evidence: No attempt counter or throttle around the call at `app.ts:846-873`; `rateLimit` in `auth.ts` only covers `/api/auth/*` requests.
- Suggestion: Add a per-session failed-attempt counter with lockout and audit failures.
- Verification: Loop wrong passwords; expect 429 or lockout.

### 19. [P2][conf:90][error-handling]

#### Validation errors thrown as plain `Error` surface as generic 500s

- File: server/src/app.ts:120
- Symbol: app.onError
- Description: `normalizeHostname`, `assertExternalForwarding`, `assertAliasGraph`, `classifySql`, `assertCidrs`, `buildDomainPlan`, and Better Auth's `APIError` (wrong step-up password) are neither `HTTPException` nor `ZodError`, so users get "The request could not be completed." with the reason only in server logs.
- Evidence: `onError` handles only `HTTPException` and `ZodError`; callers at `app.ts:896, 1025, 1039, 1383, 1566, 873`.
- Suggestion: Map `APIError.status` and a shared `ValidationError` class to 4xx in `onError`.
- Verification: POST `/api/aliases` with an alias loop; expect 422 with a message.

### 20. [P2][conf:85][correctness]

#### Single-use step-up grants are consumed before target validation

- File: server/src/app.ts:1531
- Symbol: requirePrivileged call sites
- Description: `requirePrivileged` consumes the grant first; a subsequent 404, 403, or 422 burns the grant and forces full re-authentication. In `/api/mailboxes/:id/credential` the `credentialAvailable` check precedes `requireDomain`, so a 409-vs-403 difference reveals whether a foreign mailbox has an unrevealed credential.
- Evidence: Ordering at `app.ts:1105, 1373, 1556, 1643, 1716, 1808, 1820`.
- Suggestion: Load the resource and run scope checks and pure validators first, then consume the grant.
- Verification: Create a grant, hit a route with a bad target, then retry with a good one; the grant must still be valid.

### 21. [P2][conf:80][privacy]

#### Operators see the whole mail queue regardless of domain grants

- File: server/src/app.ts:1591
- Symbol: GET /api/mail/queue
- Description: The read route requires only operator, while the mutation route is domain-scoped. Senders and recipients across all tenants are exposed.
- Evidence: `requireOperator(c.get("access")); const items = (await listMailQueue()).map(redactQueueItem);`
- Suggestion: Filter items to domains the caller can view.
- Verification: Operator with empty `domainIds` receives an empty list.

### 22. [P2][conf:90][observability]

#### Privileged mutations are not audited

- File: server/src/app.ts:1565
- Symbol: ""
- Description: `PUT /api/databases/:id/cidrs`, restore-test, platform maintain, updates apply, settings mode, `PUT /api/settings`, mailbox and alias creation, service create/adopt, device creation, queue mutations, and alert acknowledgement write no `audit()` row. Only the step-up mint is recorded, not the action it authorised.
- Evidence: No `audit(` call in those handlers.
- Suggestion: Add `audit(...)` with the operation id after each enqueue or write.
- Verification: Perform each action and assert an `audit_events` row.

### 23. [P2][conf:85][correctness]

#### Agent post-up protected-network check uses substrings and contradicts pre-flight rules

- File: agent/docker.go:325
- Symbol: validateAdoptableInspection
- Description: Pre-flight matches network names by prefix, but post-up inspection rejects any attached network containing `control`, `monitoring`, `database-management`, `mail-management`, or `ark-platform`. A slug like `control-room` passes validation, `compose up` runs, then ledgering fails and containers are left unmanaged.
- Evidence: `if strings.Contains(normalized, fragment)` (`docker.go:331`) versus prefix matching in `policy.go:216-224`.
- Suggestion: Match on exact platform project labels and keep pre-flight and post-up rules identical.
- Verification: `validateAdoptableInspection` with network `ark-monitoring-dash_default` must pass.

### 24. [P2][conf:85][correctness]

#### Agent refuses tag-pinned images that the server policy accepts

- File: agent/docker.go:514
- Symbol: pullImage
- Description: The server allows tag-pinned images (only bare `latest` is rejected) and passes them in `images`, but the agent only pulls `@sha256:` references and runs `up --pull never`. Such composes can never deploy on a fresh host.
- Evidence: `only immutable image digests may be pulled` check at `docker.go:514-517`; `compose-policy.ts:337-344` accepts tags.
- Suggestion: Resolve tag to digest server-side before enqueue, or let the agent pull non-`latest` tags.
- Verification: Deploy `nginx:1.27.3` end to end.

### 25. [P2][conf:80][correctness]

#### Docker client hard 20-second timeout breaks stop/restart for services with longer grace periods

- File: agent/docker.go:24
- Symbol: dockerHTTP / mutateContainer
- Description: `stop_grace_period` is an allowed field, but stop and restart calls block for the container's timeout while the client times out at 20 seconds, so the operation is reported failed although the stop proceeds.
- Evidence: `Timeout: 20 * time.Second` on the client; no `?t=` on the stop call.
- Suggestion: Derive the per-call timeout from the container's `StopTimeout` plus margin.
- Verification: Deploy with `stop_grace_period: 45s` and issue `service.stop`.

### 26. [P2][conf:80][error-handling]

#### A new `http.Transport` per Docker call leaks connections and goroutines

- File: agent/docker.go:21
- Symbol: dockerHTTP
- Description: Each call builds and discards a transport whose idle keep-alive connection is never closed, pinning one socket and two goroutines per call for the process lifetime. Logs and stats polling make this unbounded.
- Evidence: `Transport: &http.Transport{...}` constructed inside the per-call helper.
- Suggestion: Build the client once, or set `DisableKeepAlives: true`.
- Verification: Loop `containerStats` and watch the FD count.

### 27. [P2][conf:75][security]

#### Adoption path does not reject `container:` namespace modes

- File: agent/docker.go:274
- Symbol: validateAdoptableInspection
- Description: Only literal `host` modes are rejected. `NetworkMode: "container:<id>"` yields empty `Networks`, bypassing the protected-network check, and `PidMode`/`IpcMode` `container:` are unchecked. The authored-compose policy rejects these, so adoption is weaker.
- Evidence: `docker.go:274-275, 297-301`; `compose-policy.ts:195` rejects `service:|container:`.
- Suggestion: Allow only `""`, `default`, `bridge`, `none`, `private`, or a named compose network, and require non-empty `Networks`.
- Verification: Add the `container:abc` case to `docker_test.go`.

### 28. [P2][conf:75][error-handling]

#### Ledger and compose writes skip fsync, and a truncated ledger has no recovery path

- File: agent/ledger.go:55
- Symbol: saveLedger / materializeCompose
- Description: Write-then-rename without `Sync()` can leave an empty ledger after power loss; `loadLedger` then fails on parse and every owned-container operation fails until manual repair.
- Evidence: No `f.Sync()` in either path; parse error returned at `ledger.go:37-39`.
- Suggestion: fsync file and directory, keep a `.bak`, and fall back to it on parse failure.
- Verification: Truncate the ledger and observe recovery.

### 29. [P2][conf:95][testing]

#### Agent policy tests never reach the rules they claim to test

- File: agent/policy_test.go:5
- Symbol: TestRejectsDockerSocketAndPrivileged / TestRejectsReservedPort
- Description: `validateSandbox` runs first and the fixtures omit the canonical sandbox block, so they fail on "canonical read_only=true is required" before the port or mount rule executes. Removing `validatePorts` would not fail CI.
- Evidence: Ordering in `policy.go:96-102`; fixtures lack `read_only`/`tmpfs`.
- Suggestion: Build fixtures from a canonical base and assert on the specific error message.
- Verification: Temporarily stub `validatePorts` to return nil; the tests must fail.

### 30. [P2][conf:90][correctness]

#### CLI children ignore `DOCKER_SOCKET` while the HTTP client honours it

- File: agent/docker.go:503
- Symbol: dockerCommandEnv
- Description: `docker pull` and `docker compose` get a scrubbed env without `DOCKER_HOST`, so a non-default socket makes API and CLI calls hit different daemons.
- Evidence: `DOCKER_SOCKET` read at `docker.go:22`; not forwarded in `dockerCommandEnv`.
- Suggestion: Append `DOCKER_HOST=unix://<sock>`.
- Verification: Run with a custom socket path.

### 31. [P2][conf:78][security]

#### `type: image` volume mounts bypass the image allowlist

- File: shared/src/compose-policy.ts:366
- Symbol: hasForbiddenMount
- Description: Only `type: bind` is denied and `mountSource` returns null for non-volume types, so `type: image` (Compose 2.35+) mounts an arbitrary image's filesystem without passing `isAllowedImage` or digest pinning.
- Evidence: Probe with `volumes: [{type: image, source: evil.example/x:1, target: /data}]` returned `ok: true`.
- Suggestion: Allowlist mount types to `volume` and `tmpfs`.
- Verification: Unit tests for `image`, `cluster`, `npipe` rejected.

### 32. [P2][conf:90][correctness]

#### `parseIpv6` mangles embedded-IPv4 forms and `parseCidr` accepts malformed IPv6

- File: shared/src/cidr.ts:27
- Symbol: parseIpv6 / parseCidr
- Description: `::ffff:1.2.3.4` loses the `ffff` group and `64:ff9b::1.2.3.4` returns null. Separately, `::::/64` validates and is rendered into the nft file, which `nft -f` rejects, closing the public listener for every legitimate CIDR.
- Evidence: Probe returned bytes `0..0,1,2,3,4` for `::ffff:1.2.3.4`, `null` for the NAT64 form, and `{"ok":true,"cidr":"::::/64"}` for the malformed CIDR.
- Suggestion: Parse `${prefix}:0:0` without stripping; require `parseIpv6(addr) !== null` in `parseCidr`.
- Verification: Unit tests for the three forms and `assertCidrs(["::::/64"])` throwing.

### 33. [P2][conf:80][privacy]

#### `redactValue` does not match snake-case keys or URL-embedded credentials

- File: shared/src/redact.ts:17
- Symbol: redactValue
- Description: Key normalisation strips only `-`, so `DATABASE_URL`, `SMTP_PASSWORD`, and `AWS_SECRET_ACCESS_KEY` pass through, and `scheme://user:pass@host` strings are not caught. This function guards worker evidence and audit detail.
- Evidence: Probe output `{"DATABASE_URL":"postgres://u:hunter2@h/db","SMTP_PASSWORD":"hunter2","smtpPassword":"<redacted>"}`.
- Suggestion: Normalise `_`, match on substrings, and add a URL-credential regex.
- Verification: Add `redact.test.ts` covering these cases.

### 34. [P2][conf:85][security]

#### Installer writes `.env` with all platform secrets world-readable

- File: scripts/install.ts:26
- Symbol: ""
- Description: `Bun.write` uses the default mode 0644. The metrics token file is chmod'd to 0600 but `.env` is not.
- Evidence: `await Bun.write(envPath, ...)` with no chmod; `chmod(..., 0o600)` only at line 96.
- Suggestion: `chmod(envPath, 0o600)` after writing.
- Verification: `stat` shows 0600 after install.

### 35. [P2][conf:90][correctness]

#### `validateMaintenanceBundle` reports `rollbackSafe: true` for stateful images

- File: shared/src/maintenance.ts:37
- Symbol: validateMaintenanceBundle
- Description: `rollbackSafe` checks the full image reference against a set of bare component names, so it never matches, while stateful detection three lines earlier uses `includes`. The two disagree and the value is persisted.
- Evidence: A `postgres:16@sha256:...` bundle with `allowStateful: true` yields `rollbackSafe: true`.
- Suggestion: `rollbackSafe: stateful.length === 0`.
- Verification: Unit test with a stateful image.

### 36. [P2][conf:90][correctness]

#### `literal()` dollar-quote guard misses a trailing `$ark`

- File: shared/src/provision-sql.ts:82
- Symbol: literal
- Description: A value ending in `$ark` produces `$ark$...$ark$ark$`, closing the literal early and causing a syntax error. The password alphabet includes `$`, so this is reachable.
- Evidence: `value.includes("$ark$")` only.
- Suggestion: Also reject `value.endsWith("$ark")`, or drop `$` from the alphabet.
- Verification: `literal("abc$ark")` throws.

### 37. [P2][conf:78][error-handling]

#### Ingress reconcile loop drops overlapping events, self-triggers, and crashes on bind errors

- File: scripts/database-ingress.ts:62
- Symbol: reconcile
- Description: A boolean `reconciling` flag discards events during an in-flight pass (the server writes `allowlist.nft` then `expose` back to back), the status file is written into the watched directory, and `server.listen` has no error handler so `EADDRINUSE` is uncaught.
- Evidence: `if (reconciling) return;`; `writeStatus` into the same dir; no `server.on("error")`.
- Suggestion: Use a dirty flag that re-runs once, ignore `allowlist.status` events, and attach an error handler.
- Verification: Write both files rapidly and assert the final listener state.

### 38. [P2][conf:90][error-handling]

#### Every button-driven mutation in the UI swallows errors

- File: web/src/pages/Views.tsx:318
- Symbol: ""
- Description: Twenty-plus handlers use `void api(...).then(reload)` with no catch. Step-up-gated routes return 403 without a grant and the UI shows nothing.
- Evidence: Pattern at lines 77, 90, 138, 148, 318, 545, 563, 608, 654, 667, 794, 803, 909, 917, 943, 970, 1089.
- Suggestion: Route through a shared helper that sets an error state.
- Verification: Click "Rotate runtime" without a step-up and see an error message.

### 39. [P2][conf:95][correctness]

#### "Isolated restore test" button always fails validation

- File: web/src/pages/Views.tsx:917
- Symbol: ""
- Description: The UI posts `{kind, targetId}` but the server requires `backupId` and a `restore.overwrite` step-up, so the request is a guaranteed 422 and silent.
- Evidence: Server schema `backupId: z.string().min(1)` at `app.ts:1863-1868`.
- Suggestion: Render the button per backup row and send `backupId`.
- Verification: Network tab shows success after the fix.

### 40. [P2][conf:80][security]

#### Caddy admin API bound on all interfaces and reachable from the `api` and `tailscale` containers

- File: infra/platform/Caddyfile:2
- Symbol: ""
- Description: Both the static and generated Caddyfiles enable the unauthenticated admin API on `0.0.0.0:2019`, and `edge` shares the `admin` network with `api`, `tailscale`, and `tailnet-gateway`. Any SSRF or RCE in the API process can rewrite public routing.
- Evidence: `admin 0.0.0.0:2019` (`Caddyfile:2`, `shared/src/edge.ts:39`); `api` on `[control, admin, monitoring]` (`docker-compose.yml:95`).
- Suggestion: Add `origins`/`enforce_origin`, or isolate reload traffic on a network only `edge` and `domain-worker` join.
- Verification: `fetch('http://edge:2019/config/')` from `api` is refused.

### 41. [P2][conf:85][maintainability]

#### Dev default `ARK_EDGE_DIR` overwrites the tracked Caddyfile

- File: .env.example:48
- Symbol: ""
- Description: `ARK_EDGE_DIR=./infra/platform` plus `writeEdge` swap files means completing the wizard locally rewrites the checked-in `Caddyfile` and `serve.json`, and `.next` files are not gitignored.
- Evidence: `writeEdge` at `server/src/modules/providers.ts:525-540`.
- Suggestion: Default to `./tmp/edge` and gitignore `infra/platform/*.next`.
- Verification: Run the wizard locally; `git status` stays clean.

### 42. [P2][conf:75][deployment]

#### Host bind-mount ownership depends on the installer's uid

- File: scripts/install.ts:27
- Symbol: ""
- Description: The installer creates `tmp/certs`, `tmp/edge`, `tmp/pgbouncer`, `tmp/mail-state`, and `tmp/backups` without chown, while workers run as uid 1000 with no `DAC_OVERRIDE`. Running the installer as root or any other uid leaves workers unable to write.
- Evidence: `USER bun` in `Dockerfile`; `cap_drop: [ALL]` in the app anchor; no chown in `install.ts`.
- Suggestion: chown to 1000:1000 in the installer or use named volumes.
- Verification: `sudo mise run host:install` then check worker logs for EACCES.

### 43. [P2][conf:80][correctness]

#### `/api/secrets/:id/reveal` is unreachable through both edges

- File: infra/platform/TailnetCaddyfile:9
- Symbol: ""
- Description: The `@browserApi` allowlist in both Caddy configs omits `/api/secrets/*`, so Caddy returns 404 for the session-authenticated reveal route.
- Evidence: Matcher list in `TailnetCaddyfile:9` and `shared/src/edge.ts:25`; route at `app.ts:1716`.
- Suggestion: Add `/api/secrets/*` to both matchers, or remove the route if it is not browser-facing.
- Verification: Request through Caddy returns 401 from the API rather than 404.

### 44. [P2][conf:90][security]

#### `generatePassword` has modulo bias

- File: shared/src/crypto.ts:33
- Symbol: generatePassword
- Description: The alphabet has 65 symbols and `byte % 65` makes the first 61 symbols about a third more likely. Entropy loss is small but the fix is trivial.
- Evidence: Alphabet length 65 with `% alphabet.length`.
- Suggestion: Use a 64-symbol alphabet with `& 63`, or rejection sampling.
- Verification: Unit test asserting alphabet length divides 256.

## Investigated and not upheld

One candidate finding was raised during review and refuted by direct testing, recorded here so it is not re-raised:

- **Setup-token bypass on `POST /api/auth/sign-up/email` via a trailing slash.** The claim was that `rou3` strips a trailing slash so `/api/auth/sign-up/email/` would skip the gated Hono route and reach Better Auth's handler through the `app.all("/api/auth/*")` catch-all. Probed against a disposable Postgres with nine path variants (`.../email/`, `//sign-up/email`, `/sign-up//email`, `/sign-up/%65mail`, `/SIGN-UP/email`, `/email%2F`, `/email/.`, `/email;x`, `/email?x=1`), both before and after bootstrap closes. Every variant returned 403 or 404 with no `set-cookie`, and no extra `user` row was created. The gate holds.

## Test Coverage Gaps

- File: server/src/coordinator.test.ts — no coverage of the `DelegateToAgent` requeue path, module-worker re-claim of delegated jobs, `assertExecutionAuthorized` for operator actors on platform follow-ups, concurrent claims with overlapping targets, enqueue dedupe with a prior terminal operation, or `finalizeAgentCompletion` failure state.
- File: server/src/app.ts — no tests for the session/MFA middleware, Origin CSRF checks, `/api/step-up` wrong-password path, `/api/wizard` re-run authorization, `/api/state` tenant filtering, one-time secret reveal races, worker kind allowlist per identity, or `/api/platform/maintain` with an unset token.
- File: server/src/modules/database.ts, providers.ts, certificates.ts, mail.ts, queue.ts — workspace query limits, allowlist and pgbouncer writers, edge writer, Cloudflare publish, digest resolution, and certificate issuance are untested.
- File: shared/src/compose-policy.ts — long-form port objects, non-bind mount types, and shipped templates are not exercised.
- File: shared/src/cidr.ts, redact.ts, crypto.ts, hash.ts, id.ts, hostnames.ts, provision-sql.ts, maintenance.ts — no tests for embedded-IPv4 parsing, invalid v6 CIDR rejection, empty-allowlist semantics, redaction of snake-case keys and URLs, AES-GCM tamper detection, `secureEqual` length mismatch, hostname normalisation, `literal()` boundaries, or `rollbackSafe`.
- File: agent/policy_test.go, docker_test.go — port and mount rules are shadowed by sandbox validation; long-form ports, IPv6 and UDP ports, `container:` namespace modes, ledger corruption handling, and heartbeat cancellation are untested without the opt-in integration run.
- File: workers/src/runtime.test.ts — no test that a failed heartbeat blocks a `succeeded` completion or covers the delegation return path.
- File: infra/platform/docker-compose.yml — CI never boots any service, so the `read_only` compose-dir failure and Postgres capability failure are invisible to `compose config`.
- File: web/src — no component tests; no e2e coverage of step-up-gated buttons or the restore-test payload.

## Test Results

- `bun install --frozen-lockfile` — pass.
- `bunx oxfmt --check .` — pass, 142 files.
- `bunx oxlint . --deny-warnings` — pass.
- `bunx tsc --noEmit` for shared, server, web, workers — pass, 0 errors each.
- `bun test shared server workers tests` without a database — 57 pass, 5 fail. All five failures are the same module-load error from `server/src/db.ts:9`: `DATABASE_URL is required. Ark Stack runs against PostgreSQL.` in `server/src/access.test.ts`, `server/src/app-boundary.test.ts`, `server/src/coordinator.test.ts`, `server/src/modules/alerts.test.ts`, and `tests/browser/flows.test.ts`. This matches CI, which provides a Postgres service.
- `bun run --cwd server db:migrate` against disposable `postgres:17` — pass, 12 migrations applied.
- `bun test shared server workers tests` with database — 81 pass, 0 fail, 320 assertions, 20 files. No skipped or todo tests reported.
- `go test -count=1 ./...` in `agent/` — pass. `go vet ./...` — clean.
- `bun run --cwd web build` — pass.
- `bun scripts/test-edge-config.ts` — pass.
- `docker compose config --quiet` for all four compose combinations — pass.
- Not run: Playwright e2e, Stalwart integration, upgrade-migration, and Docker-integration agent tests.

## Verdict

- Ready: no
- Reasoning: Automated checks pass, but the production operation pipeline, agent project isolation, and compose topology have confirmed defects that break multi-worker deployment and allow an operator to target the control plane's own containers. Fix the P1 items and add the missing coordinator and compose-boot coverage before merging further work on top.
