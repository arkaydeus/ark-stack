**Ark Stack — implementation plan**

Prepared 13 September 2026. Status: proposed architecture and delivery plan; no application has been implemented or deployed.

Build a single-host infrastructure control plane with one React administration interface, PostgreSQL management, Stalwart email management, and Docker Compose service operations. Use Orkmail's desired-state and worker architecture as the starting point, port PgStack's database workflows, and introduce a narrowly scoped Docker agent. Provide guided custom-domain setup, automatic credentials and certificate lifecycle management, public database and incoming mail access, and selectable public or tailnet-only administration. Use Better Auth in both administration modes.

**1. Scope and working assumptions**

The first production target is one Linux VPS, operated by trusted administrators. All runtime components are delivered as Docker Compose services. The product manages multiple application projects on that host; it does not promise high availability or isolation suitable for running hostile customer code. A compromised host or Docker daemon can affect the entire installation. Strong isolation between untrusted workloads requires separate hosts or VMs.

Recommended defaults:

| Decision           | Initial choice                                                                                                                         |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Administration     | Choose public custom-domain HTTPS or tailnet-only HTTPS during setup; Better Auth login and mandatory administrator MFA in either mode |
| Domain setup       | Enter domain/hostnames, follow generated DNS guidance, then let the application verify and provision the selected services             |
| PostgreSQL         | Separate platform and application clusters; application PostgreSQL with optional pgvector and PgBouncer                                |
| Email              | Stalwart for receiving/storage/client access, Amazon SES for outbound relay; manual DNS or Cloudflare automation                       |
| Container services | Prebuilt images, approved templates, and a supported subset of Compose                                                                 |
| Updates            | Detect automatically; approve and schedule by default; optional automation for selected stateless services                             |
| Database exposure  | Public TLS database endpoints are a first-release feature; select public or private per database, independently of admin exposure      |
| Backups            | Encrypted off-site storage, application-consistent capture, and regular isolated restore tests                                         |
| Availability       | Workloads continue running when the administration app is unavailable; maintenance may interrupt individual services                   |

Defer multi-host scheduling, arbitrary source-code builds, a plugin execution system, self-service customer signup/billing, a new webmail client, automatic database major upgrades, and arbitrary root terminals. Public administrator access and public database endpoints are in scope from the first release. These deferred features can expand the product later without blocking the requested core capabilities.

**2. What to take from the existing repositories**

I inspected the READMEs, Compose manifests, security and operational documents, package manifests, and relevant provisioning, API, worker, and backup code. This is an architecture review of the checked-out files, not a live deployment audit.

| Source                    | Reuse or adapt                                                                                                          | Change in the new product                                                                        |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Orkmail control plane     | React/Vite/Tailwind UI, Hono API, Better Auth, Drizzle/PostgreSQL, role-scoped administration                           | One platform identity and navigation model across all modules                                    |
| Orkmail job processing    | Transactional desired state, audit and job creation; claim tokens, heartbeats, native object IDs, lifecycle protections | Shared operation engine with resource locks and module-specific adapters                         |
| Orkmail email             | Domains, aliases, mailboxes, device credentials, sending restrictions, SES/DNS reconciliation                           | Remove installation-specific names and provide guided integration setup                          |
| Orkmail secret boundaries | Different credentials for mail and maintenance workers; separate SMTP secrets                                           | Extend this separation to database, Docker and backup operations                                 |
| PgStack provisioning      | Runtime/migration role separation, optional test databases and pgvector, pooler configuration                           | Typed, recoverable provisioning operations instead of web-triggered shell scripts writing `.env` |
| PgStack database UI       | Database-scoped workspaces, schema browsing, explicit connection and query context                                      | Bounded SQL worker, scoped credentials, durable operations                                       |
| PgStack restart helper    | Operations must survive the web process restarting                                                                      | Independent agent journal and dedicated platform maintenance runner                              |

Concrete improvements to carry forward:

- PgStack's web container mounts both the Docker socket and the writable repository. Move these capabilities out of the web/API process.
- PgStack documents plaintext credentials in normal API inventory responses. Return redacted inventory and use explicit secret-access operations instead.
- PgStack uses encryption without certificate verification for some internal database connections. Introduce managed CA trust and verified database connections.
- PgStack publishes CloudBeaver and PgBouncer publicly and uses several floating image tags. Replace this with explicitly managed public database endpoints, a selectable administration exposure policy and version-plus-digest release records.
- A Docker network named `internal` is not necessarily configured with `internal: true`; network names are not security guarantees. Joining Tailscale to a bridge also does not automatically publish other containers' database ports.
- Orkmail's release notes explicitly identify live RocksDB copying and the absence of a fully isolated restore runner as unfinished work. Close that gap before importing production mail.
- Preserve the useful distinction in both projects between implemented features, planned features, and checks that still require a real deployment.

Local evidence: [Orkmail README](/Users/arkaydeus/project/infra/orkmail-stack/README.md), [Orkmail security](/Users/arkaydeus/project/infra/orkmail-stack/docs/security.md), [Orkmail release limitations](/Users/arkaydeus/project/infra/orkmail-stack/docs/web-portal-release.md), [PgStack Compose](/Users/arkaydeus/project/infra/pgstack1/docker-compose.yml), [PgStack README](/Users/arkaydeus/project/infra/pgstack1/README.md), and [PgStack improvement plan](/Users/arkaydeus/project/infra/pgstack1/docs/plans/2026-09-07-database-control-plane-improvements.md).

**3. Runtime architecture**

```text
Administrator: choose one normal access mode
     | public admin.example.com       | private node.tailnet.ts.net
     v                                v
Public HTTPS gateway          Tailscale Serve + loopback gateway
     | enabled in public mode         | enabled in tailnet mode
     +----------------+---------------+
                      |
                      v
Web assets + authenticated API ----> platform PostgreSQL
          |                              |
          |                       durable jobs + audit
          v                              |
Authenticated internal worker API <------+
     |              |               |                |
 DB worker      Mail worker     Docker agent     Backup worker
     |              |               |                |
 App Postgres   Stalwart/SES     Docker Engine    Off-site storage
 + PgBouncer    + DNS APIs           |
                              Managed Compose projects

Public mail clients --> mail protocol listeners --> Stalwart
Public SQL clients --> db.example.com:5432 --> public PgBouncer --> app PostgreSQL
Public web traffic --> optional application gateway --> selected workloads
DNS/certificate worker --> DNS verification + ACME --> scoped service certificates
```

Use three deployment boundaries: a platform Compose project, separate managed database/mail projects, and one Compose project per application. One installer orchestrates them. Avoid a single global restart or removal command affecting every workload.

The platform project contains the web/API container, a dedicated platform PostgreSQL instance, the operation coordinator, a public edge/challenge gateway, and a DNS/certificate worker. The Tailscale sidecar and loopback gateway are enabled for tailnet administration; public mode does not require a Tailscale account. Domain workers and the Docker agent run in separately configured services. A private monitoring service stores metrics. Heavy log indexing and advanced dashboards are optional.

The API is a modular TypeScript application, not a collection of independently deployed domain microservices. Workers are separate processes because their privileges and failure modes differ. The control database stores identities, configuration, operation state and audit history; it does not share a cluster with application databases. Managing or restoring an application cluster must not remove the job queue needed to complete that operation.

**4. Technology and code organization**

| Layer                    | Recommendation and reason                                                                                                                      |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend                 | React + TypeScript + Vite, Tailwind CSS 4, owned shadcn/ui components; matches both inspirations                                               |
| API                      | Node.js supported LTS + Hono + Zod; continue Orkmail's patterns                                                                                |
| Authentication           | Better Auth with PostgreSQL persistence, React integration, email/password, TOTP and recovery codes; application-enforced resource permissions |
| Domains and certificates | Dedicated DNS/certificate worker using a pinned lego ACME client; public edge serves its HTTP-01 challenges and loads its certificates         |
| Persistence              | PostgreSQL + Drizzle migrations; separate runtime and migration credentials                                                                    |
| Jobs                     | PostgreSQL-backed durable queue and outbox; avoid a Redis dependency initially                                                                 |
| Database worker          | TypeScript worker using direct PostgreSQL connections and bounded subprocesses for approved backup tools                                       |
| Mail worker              | Initially adapt the existing Python reconcilers behind a versioned internal API; avoid rewriting working provider logic at the same time       |
| Docker agent             | Small Go service with a typed protocol, Docker API integration, and a bundled, pinned Compose executable                                       |
| Metrics                  | Prometheus with fixed, bounded queries exposed through the application API                                                                     |
| Backups                  | pgBackRest for PostgreSQL physical backups/WAL; Restic for consistent mail snapshots, configuration and general file data                      |

The Go agent introduces another language, but keeps the most privileged component small and independent of the web dependency tree. This is a maintainability choice, not a claim that the language removes the Docker privilege risk. Pin exact compatible versions during the foundation phase; versions in the inspiration repositories are evidence of their current setup, not an instruction to copy them blindly.

The React/Vite/Tailwind combination and local component model are supported by the current [shadcn/ui Vite guide](https://ui.shadcn.com/docs/installation/vite). Review upstream component changes as owned source changes.

Suggested layout:

```text
web/                     React administration application
server/                  API, auth, authorization, operations, migrations
workers/database/        Provisioning and SQL execution
workers/mail/            Adapted Stalwart, SES and DNS reconciliation
workers/backup/          Backup scheduling and restore verification
workers/domains/         Domain verification, ACME issuance/renewal and certificate delivery
agent/                   Docker operations, policy, local recovery journal
shared/                  API schemas and generated client contracts
infra/platform/          Core Compose, public edge, Tailscale and admin gateways
infra/database/          PostgreSQL/PgBouncer templates and certificates
infra/mail/              Stalwart templates and public listener configuration
infra/monitoring/        Metrics and alert configuration
templates/               Reviewed application service definitions
tests/integration/       Disposable service and failure tests
tests/security/          Authorization and deployment-boundary tests
docs/                    Architecture decisions and operating runbooks
```

**5. Administration exposure, domain onboarding and network boundaries**

The setup wizard offers two administration modes. Public mode serves the dashboard at a verified custom hostname such as `https://admin.example.com` through the public edge. Tailnet-only mode serves it through Tailscale and installs no public admin route. Both require Better Auth and administrator MFA. This choice never determines whether databases or mail are public: those endpoints have independent policies.

In tailnet-only mode, run Tailscale in userspace mode. Only a minimal gateway shares `network_mode: service:tailscale`, listening on `127.0.0.1:8080`. Tailscale Serve proxies HTTPS to that gateway; the gateway forwards to the internal web/API service. Neither service publishes a host administration port. Keeping the API outside the shared namespace reduces the number of services that must be recreated when Tailscale is replaced.

Configure persistent Tailscale state, a stable node name, a dedicated tag such as `tag:ark-stack-admin`, and an explicit tailnet grant for the administrator group to TCP 443. Review the effective policy for broader existing grants: adding a narrow rule does not undo an existing allow-all rule. Enable tailnet HTTPS/MagicDNS, provision a scoped enrollment credential, and remove the bootstrap credential after enrollment when using persistent node state.

Use `TS_USERSPACE=true`, a mounted Serve configuration directory, and `TS_SERVE_CONFIG`. Do not grant Funnel capability to this node; assert that no public Funnel listener is enabled. No subnet routes, exit-node function, TUN device or kernel-networking capabilities are needed for the proposed HTTP proxy design. Validate the exact pinned image in the deployment test. These configuration mechanisms are documented in [Tailscale Docker parameters](https://tailscale.com/docs/features/containers/docker/docker-params); Serve's private access and HTTPS behavior are described in [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve).

Public mode publishes only the dashboard and its browser API, including Better Auth endpoints, at the configured hostname. Enforce TLS, edge request limits and application rate limits; reject unknown Host values and strip client-supplied forwarding/identity headers. Internal worker routes, metrics, service-native management endpoints and health details are excluded. Disable any public setup route after initialization. Provide a local CLI/SSH recovery path for both modes.

Keep application authentication mandatory even for permitted tailnet users. Tailscale identity may enrich audit data, but is not the sole authorization check. Trust forwarded headers only from the configured gateway; use one exact canonical HTTPS origin per active administration mode for cookies, redirects and CSRF checks. Internal worker routes require independent service credentials and are not forwarded by either admin gateway.

Changing mode is a durable operation: verify the destination DNS/certificate or tailnet connectivity, prepare the gateway, switch the canonical auth origin and route policy, revoke sessions as needed, and verify the new login path. A transition into tailnet-only mode removes the public route and closes existing public admin connections; verification includes public Host-header and direct-IP bypass attempts. Never silently republish the dashboard if private access later fails. Use the local recovery path to resolve lockout. Mode changes do not restart database or mail services.

For tailnet-only mode, use the Tailscale-provided `*.ts.net` name by default. A chosen private custom admin name is an advanced supported configuration using split DNS to the Tailscale address, an in-namespace HTTPS gateway and a separately managed certificate. Tailscale Serve's managed certificate is not a certificate for an arbitrary custom domain. Automatic renewal for a private custom name requires DNS-01 automation or an explicitly configured public challenge-only endpoint; neither exposes the admin application.

**5a. Guided domain setup**

The normal experience is: enter domain details, copy the generated DNS records into the DNS provider, wait for verification, and receive working service endpoints and generated credentials. DNS API credentials are optional. No manual `.env` editing, password generation, certificate copying, or Compose editing should be part of routine onboarding.

The installer handles the prerequisite host setup once: Docker, host addressing, platform secrets and a protected initial access path. It prints a local one-time setup URL/token for an SSH tunnel or enables a provisioned tailnet setup route. The user creates the owner and enrolls MFA before the wizard can publish the admin application. Do not require an existing HTTPS custom domain or a working local mailbox to begin setup. If onboarding moves from a local setup origin to HTTPS, close the setup session and establish a fresh session at the final origin.

The wizard collects the base domain, DNS provider (including manual/other), server address confirmation, selected services, and hostnames. Suggest `db.example.com`, `mail.example.com` and, for public administration, `admin.example.com`, but allow different verified names and additional mail domains. Ask for a first database/application name and optional first mailbox; generate their independent credentials automatically. Keep owner authentication separate from generated database/mailbox credentials.

An example record plan, rendered with the actual entered names and detected/confirmed addresses:

| Record    | Name                                        | Value shown by the application                      | When needed                    |
| --------- | ------------------------------------------- | --------------------------------------------------- | ------------------------------ |
| TXT       | `_ark-stack.example.com`                    | Installation-bound random domain-ownership token    | Initial ownership verification |
| A         | `db.example.com`                            | VPS public IPv4                                     | Public database endpoint       |
| A         | `mail.example.com`                          | VPS public IPv4                                     | Incoming/client mail endpoint  |
| A         | `admin.example.com`                         | VPS public IPv4                                     | Public admin mode              |
| MX        | `example.com`                               | Priority 10, `mail.example.com`                     | Incoming mail for the domain   |
| TXT/CNAME | Provider-generated DKIM and MAIL FROM names | Exact generated/provider-returned values            | Outbound authentication        |
| TXT       | SPF owner and `_dmarc.example.com`          | Proposed records merged with existing sender policy | Outbound sender policy         |

Offer AAAA records only when IPv6 routing, listeners, firewalling and external probes work. Explain DNS-only records for database/mail hostnames; ordinary HTTP CDN proxying does not transport these protocols. MX targets use a hostname with address records, not an IP or a CNAME target. Show the provider's relative-name form, full hostname, type, value, priority, TTL guidance and copy controls. One domain normally needs several records, not just one.

Before recommending edits, inspect existing MX/SPF/DMARC/DKIM and CNAME conflicts. Show a migration warning for existing mail routing and preserve unrelated senders/records. Never create multiple SPF policies at the same owner or replace the existing MX set without a reviewed cutover. A manual edit remains the user's DNS-provider action; optional DNS automation applies only the reviewed diff with a scoped token.

Verify the ownership TXT, address records, authoritative DNS and selected recursive resolvers. Check stale/unreachable AAAA, CAA restrictions, proxying, DNS errors and propagation with actionable messages. Normalize IDNs and reject malformed names, control characters, suffix-confusion and duplicate claims. DNS/protocol probes must have SSRF controls, fixed approved ports, checked resolved addresses and no arbitrary URL fetch capability; private-address probes require the explicit tailnet workflow.

Track each endpoint separately through `draft → awaiting_dns → verified → issuing_certificate → provisioning → testing → ready`, with retryable waiting/error states. Queue idempotent steps with backoff and retain progress across refreshes/restarts. Do not repeatedly call the certificate authority while DNS is still invalid. An inbound mailbox can become ready while outbound SES approval is pending; database readiness is independent of both.

After verification, automatically issue certificates, configure listeners/pooler/mail domains, create the requested database/roles/mailbox, generate and store scoped secrets, enable the approved exposure, and test the result. Show public database connection strings with hostname verification, mailbox client settings, certificate/renewal state and a one-time credential handoff. Later databases using an existing cluster endpoint need no new DNS record. Mail domains can reuse the existing `mail.example.com` MX target.

Treat hostname changes as migrations: verify the replacement, issue its certificate, present updated connection settings and coordinate the cutover before retiring the old route. Periodically detect DNS drift and expiration; transient DNS failures generate degraded status rather than deleting data. On explicit domain removal, check dependent endpoints, revoke claims and stop certificate renewal/routes that are no longer used. Reassignment requires fresh ownership proof. Keep mail/database data retention separate from domain routing, and never delete external DNS records unless their managed ownership and intended removal are verified.

The user supplies domain control and any chosen provider credentials; the application cannot obtain registrar control, remove a cloud-provider port block, set provider-owned reverse DNS without an API, or grant itself SES production access. Detect these conditions and show provider-specific guidance/status in the wizard. Incoming mail does not depend on SES: provision it as soon as its own domain, mailbox, listener and certificate checks pass.

**5b. Automatic certificate lifecycle**

Use a dedicated certificate worker and one public edge owner for ports 80/443. For manually managed DNS, use ACME HTTP-01 after the hostname points at the server: the edge serves only generated challenge files on port 80, while the worker issues and renews without further user DNS edits. HTTP validation can obtain a certificate for a database or mail hostname even though its main protocol is not HTTP. Keep the challenge route available for renewal; return a fixed response for unrelated requests to non-web hostnames. HTTP-01 requires public port 80 and does not issue wildcard certificates. If that is unavailable, offer scoped DNS-provider automation or challenge delegation; repeated manual TXT edits are not an automatic-renewal solution. See [Let's Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/).

Use a pinned lego client with persistent protected ACME account state, staging-CA tests, renewal-window scheduling, retry backoff and failure alerts. The client supports HTTP webroot and DNS-provider challenge mechanisms; see [lego's operating guidance](https://github.com/go-acme/lego/blob/main/docs/content/advanced/tips.md). Persist certificate records including endpoint, names, issuer, fingerprint, expiry and last verified deployment. Avoid reliance on a reverse proxy's private certificate-cache directory layout.

Issue separate key/certificate material for the public admin hostname, database endpoint and mail endpoint where practical. The worker publishes atomic versioned files into per-service certificate volumes; consuming services get read-only access only to their own key material. Give neither the edge nor the worker the Docker socket. Use restricted reload operations through the agent or service-native APIs, retain the last valid material on issuance failure, and verify the presented chain/hostname after renewal. Test the pinned service's behavior for changed files, new connections and any required reconnection; do not assume a reload succeeded solely because the command returned success. Never silently downgrade TLS because renewal failed.

The public HTTPS edge loads the issued admin/application certificates. PgBouncer terminates PostgreSQL TLS itself, and Stalwart terminates SMTP/IMAP TLS; an ordinary HTTP reverse proxy does not terminate those protocols. Tailscale manages the private `*.ts.net` certificate independently. Certificate issuance/renewal is a platform capability with its own audit/status views, not a manual task for each module.

| Network boundary    | Allowed participants and traffic                                                                                                              |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Admin transit       | Selected public gateway or Tailscale gateway to browser-facing web/API routes only                                                            |
| Control             | API to platform PostgreSQL; authenticated worker communication through explicitly attached networks                                           |
| Database management | Database worker to direct application PostgreSQL/PgBouncer administration endpoints                                                           |
| Application data    | Approved workload project to its pooler endpoint; workload networks remain separate                                                           |
| Mail management     | Mail worker to private Stalwart management endpoint                                                                                           |
| Public ingress      | Explicit database pooler listener, mail protocols, ACME challenges, approved application routes, and admin browser routes only in public mode |
| Observability       | Selected exporters/agent to metrics collector; collector has no deployment credential                                                         |

Use actual internal networks where egress is unnecessary. For workers requiring AWS, DNS, registries or backup storage, provide deliberate egress and document it. Compose networks alone do not enforce fine-grained directional or destination-based firewall policy; supplement host/provider controls where required.

Externally reachable services for the standard public database/mail setup: PostgreSQL-compatible TLS endpoint on host TCP 5432 mapped to the public PgBouncer container, SMTP 25, submission 587 with mandatory TLS/authentication, IMAPS 993, and port 80 for ACME challenges. Enable public 443 routes for public administration and selected web applications. Enable 465 only if needed. SMTP 25 accepts incoming server-to-server delivery for local recipients without user authentication and offers STARTTLS; require authenticated TLS on submission and prohibit unauthorized relaying. JMAP/webmail HTTPS is optional; native Stalwart administrative routes remain private. The dedicated edge owns public 80/443, avoiding the port conflict between the two inspiration stacks.

The direct application PostgreSQL backend, platform PostgreSQL, internal pooler, Docker API, metrics and worker endpoints have no public host bindings. Public database traffic uses a separately configured public pooler with explicit database/user admission. Add private database tailnet access using a separately configured TCP gateway/sidecar with separate grants; the admin HTTP sidecar does not implicitly expose PostgreSQL.

Validate from outside the VPS over IPv4 and IPv6. Docker's published-port handling can bypass expected UFW filtering, so deployment verification must inspect Docker-aware firewall rules and actual connectivity, as explained in [Docker's firewall documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

**6. Docker agent security contract**

Normal operation gives only the Docker agent the host Docker socket. Treat this service as host-privileged even if its container runs with reduced capabilities. A socket mounted read-only still accepts mutating API requests; a generic socket proxy with container-creation permission also remains a substantial privilege boundary. Docker describes the daemon's ability to mount host filesystems in its [Engine security documentation](https://docs.docker.com/engine/security/).

The agent consumes authenticated, typed jobs. The browser never submits raw Docker API requests, shell command strings, arbitrary host paths, or unrestricted Compose command-line arguments. The agent independently validates every operation against a host-installed policy and ownership ledger that routine API operations cannot relax.

Initial approved actions: inventory, bounded logs/statistics, inspect a registered resource, start/stop/restart a registered service, deploy an approved project revision, remove explicitly selected resources, and update to an approved image digest. Docker observations must omit environment variables, registry credentials and secret-bearing labels before leaving the agent.

For service definitions:

- Accept a documented subset of Compose. Parse safely, limit input size/complexity, normalize, validate, then generate the final manifest. Reject unsupported fields instead of silently ignoring them.
- Reject privileged mode, Docker sockets, devices, host PID/IPC/network modes, arbitrary added capabilities, external volume drivers, arbitrary bind mounts and access to platform networks.
- Disable raw `build`, remote includes, inherited Compose files, host environment interpolation, arbitrary env files, lifecycle hooks and unreviewed volume driver options. Introduce any future support deliberately with tests.
- Use agent-owned project directories and named volumes. If approved file mounts are needed, canonicalize paths and defend against traversal, symlinks and time-of-check/time-of-use substitutions. Reject project-controlled escape paths.
- Enforce resource limits, port reservations, allowed registries/images, known secret references and fixed network ownership. A service command inside an approved image is distinct from a host-side deployment hook.
- Use immutable resource IDs plus the agent ledger; labels alone do not prove authorization. Recheck target identity before mutations and serialize operations against the same resource.
- Run Compose with a fixed argument vector, controlled environment, explicit project/files, timeouts and bounded output. Avoid shell interpolation. Validate the final normalized model too.

Authentication uses independent, rotatable worker identities and encrypted internal transport where it crosses bridges. Use short-lived claims, timestamps/nonces and operation IDs against replay. The agent makes outbound authenticated calls for work; it exposes no public management listener. Log streams use the same authenticated transport and bounded multiplexing.

Separate platform-maintenance jobs from ordinary workload jobs. A protected, short-lived maintenance runner may also need Docker access to update the agent itself. It accepts only a locally approved platform release bundle and retains a host-visible recovery journal. Document this as an explicit exception to the one-agent socket rule. The full privileged path requires security review; moving the socket out of the API limits exposure but does not make an API compromise harmless.

**7. Identity, secrets and audit**

Better Auth is the selected authentication system for both public and tailnet modes. Use its React client with the Hono API, Drizzle/PostgreSQL persistence, email/password sessions and two-factor plugin for TOTP/recovery codes. Resource-level authorization remains enforced by the application and workers. Better Auth sessions do not authenticate PostgreSQL or SMTP/IMAP clients; those use independently generated native credentials. Implement the library integration against the pinned release and verify MFA enrollment, login and recovery behavior using the [Better Auth two-factor documentation](https://better-auth.com/docs/plugins/2fa).

Set Better Auth's explicit `baseURL` and exact `trustedOrigins` from the active verified admin endpoint. Keep cookies host-only and secure on the final HTTPS endpoint; do not use wildcard trusted origins, shared parent-domain cookies or client-controlled Host headers to derive authentication URLs. Retain built-in CSRF protections and trust forwarded headers only behind the configured sanitizing gateway. See [Better Auth security guidance](https://better-auth.com/docs/reference/security). Use local bootstrap credentials/recovery codes before outbound email works; a password-reset email must not be the only way to recover the system that sends it.

Start with platform owner, scoped operator and viewer roles, with project/database/domain grants. Add delegated mail administration using the existing Orkmail model. Enforce permissions in API handlers, worker job creation, log/metric queries and sensitive resource lookups. A viewer of metadata does not automatically get database rows, SQL text, logs, mail contents or secret access.

Bootstrap with an expiring, single-use local setup token and an atomic first-administrator transaction. Close signup after bootstrap. Require MFA before administrator mutations; support recovery codes and session revocation. Protect the last active owner. Access changes invalidate affected sessions and pending privileged approvals. A hostname or node-identity change requires a deliberate recovery procedure because it affects trusted origins and potentially passkey relying-party identity.

Require recent step-up authentication for role grants, secret reveal, permanent deletion, restoration over existing data, public exposure, credential rotation and platform updates. Confirmation previews show affected resources, data-retention consequences and downtime; bind them to actor, exact revision, expiration and single use. Revalidate authorization and dependencies when execution begins.

Use Secure/HttpOnly cookies, deliberate SameSite settings, exact-origin CSRF checks, login/setup/recovery rate limits, a restrictive CSP, and no-store responses for sensitive information. Reauthorize long-lived streams and close them when access is revoked.

Store dynamic secrets using authenticated encryption with key IDs and a root key mounted outside the control database. Mount only each worker's necessary decryption capability/secrets; the API must not automatically receive provider or database superuser credentials. Prefer worker-side encryption for operational secrets and a separate protected reveal capability. Keep bootstrap, session, worker, SMTP, DNS, provider, registry and backup credentials independent.

Use file-based runtime secret delivery where images support it. Compose secrets provide per-service file mounts, not an encrypted host vault; root ownership, filesystem permissions, disk protection and off-host key recovery still matter. See [Docker Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/). Environment injection is an explicit compatibility exception for images requiring it, with redaction from inventory, logs and exported manifests.

New human credentials are retrievable once and then require rotation if lost; ordinary inventory returns only metadata. Managed service credentials may need encrypted retention so the platform can redeploy or rotate them. Show secret references and rotation dates, not values. Include staged rotation with overlap where the target supports it, and explicit interruption where it does not.

Audit actor, target, action, redacted diff, approval, effective role, operation ID and outcome. The runtime role cannot alter or delete audit records. Forward audit events to separate storage for stronger tamper evidence; a local append-only table cannot resist a host or database superuser. Do not record passwords, email bodies, raw authorization headers or unrestricted SQL literals.

**8. Shared operations and resource model**

All long-running changes use the same flow: validate and authorize, create a preview, accept approval when required, commit desired state/audit/outbox in one transaction, queue work, execute with a resource lock, verify observed state, and publish the outcome.

Core records include users/sessions/grants; projects; resources and external IDs; resource revisions; service definitions and deployment revisions; database clusters/databases/roles; mail domains/mailboxes/aliases; domain claims and expected/observed DNS records; endpoints and exposure policies; certificate orders/renewals/deployments; encrypted secret references; operations/steps/claims; backups/restore tests; update policies; observations/alerts; and audit events. Domain ownership, DNS readiness, certificate readiness and actual service readiness are distinct recorded facts.

Each managed resource tracks desired revision, observed revision, owner, protected status and observation timestamp. Each operation tracks idempotency key, actor, approved plan hash, target IDs, claim/fencing token, heartbeat, attempts, per-step journal, verification evidence and redacted error. Use database constraints to prevent duplicate operations and overlapping destructive work.

Operation states: queued, waiting for approval, running, waiting for an external condition, succeeded, failed, cancelled, and needs recovery. Unknown/stale observations are not healthy states. DNS propagation can remain pending without treating it as a broken deployment.

PostgreSQL DDL, Docker and external provider calls do not share a transaction. Record intent before each external mutation, then record the observed result. Retry idempotent steps with backoff; inspect uncertain outcomes before replaying destructive steps. Use leases plus execution-side exclusion/fencing: lease expiry alone must not let a replacement worker race an old worker still performing external actions. Cancellation is cooperative at safe boundaries and never means data has been rolled back.

Workers periodically reconcile observations without silently overwriting operator drift. Manual recovery changes require refresh/adoption before normal reconciliation resumes. If the API/control database is down, existing mail, databases and containers continue; mutation processing stops safely. The Docker agent's local durable journal preserves progress needed to recover platform maintenance without the API.

**9. PostgreSQL management**

Deliver one managed application cluster first, with a model allowing additional clusters later. Its public endpoint uses the hostname entered in the setup wizard, such as `db.example.com:5432`. Keep its release lifecycle independent of the platform cluster. Evaluate a supported PostgreSQL major with compatible pgvector, PgBouncer and backup tooling during the foundation phase; do not automatically upgrade an imported PostgreSQL 17 data directory to 18.

Initial administration:

- Cluster health, version, connections, storage, pool saturation and backup freshness.
- Create a database with migration and runtime credentials, optional read-only/reporting roles, optional separate test database, and allowlisted extensions.
- Inspect live databases, schemas, tables, indexes, sizes, roles and grants. Distinguish observed roles from credentials the platform actually holds.
- Rotate/revoke credentials, set connection limits and review dependencies before deletion. Database deletion requires a recovery point and explicit confirmation; it is not ordinary reconciliation.
- Provide public pooled runtime, internal pooled runtime and private direct migration connection profiles. Public database access is part of guided provisioning. Offer network policy choices of authenticated public access from any address or specified IPv4/IPv6 source CIDRs; both retain required TLS and scoped database credentials. Tailnet profiles appear when the private database gateway is enabled.
- Provide a native schema/table browser and bounded SQL workspace, so CloudBeaver is optional rather than the primary administration interface.

Implement provisioning as resumable steps: reserve safe names and choose the verified endpoint, generate/encrypt secrets, create the database, create roles, set ownership/grants, install approved extensions, configure private/public pooler mappings according to exposure policy, verify the endpoint certificate, test each credential and record the outcome. PostgreSQL identifier limits apply after adding suffixes such as `_runtime`; validate the final identifiers and quote them safely. Value parameters do not substitute for identifiers.

Expose public database traffic through a dedicated PgBouncer instance, separate from the private pooler. Maintain explicit public database mappings and database/role admission rules; private databases and platform resources must not be selectable by simply changing the requested database name. Verify both requested database and effective backend identity. Deny privileged, monitoring, backup and bootstrap identities on the public listener; expose no PgBouncer administration/stats credentials there. Use a protected private management path for configuration reloads. Set pool/connection/login limits, timeouts and abuse monitoring so public connection attempts cannot exhaust the backend.

Require client TLS and SCRAM authentication. Since the front door's FD-16, public clients must also present a certificate from one of Ark's private database-client CAs (`client_tls_sslmode=verify-full`, TLS 1.3 only; see `docs/design/front-door.md` §3.10.2). Issue a publicly trusted certificate for the selected database hostname, verify the backend CA/hostname, and generate client examples using `sslmode=verify-full` with the correct trust configuration. Distinguish requiring TLS on the server from clients verifying the server hostname. PgBouncer's TLS and authentication settings are described in its [configuration reference](https://www.pgbouncer.org/config.html).

The completion screen supplies the generated database name, username, port, TLS/trust instructions and a one-time password/connection string, for example `postgresql://orders_runtime:<generated-password>@db.example.com:5432/orders?sslmode=verify-full`. Encode connection-string values safely. The console can rotate a lost credential or inject a retained encrypted credential into an authorized managed application. No platform superuser password appears in connection examples.

A hostname is an address and certificate identity, not a database authorization boundary. Multiple databases on the first cluster share its endpoint and are selected by database name and scoped credentials. DNS aliases pointing at the same IP/port do not route to distinct clusters, and PostgreSQL is not HTTP virtual-host routing. If later clusters need separate public endpoints on the same IP, allocate explicit ports or a separately reviewed PostgreSQL-aware routing design. Custom aliases must be verified and covered by the presented certificate before being advertised.

Provide an optional public session-pooling endpoint, for example port 5433, for approved migration roles/tools that require session semantics; verify its supported feature set. Privileged/unsupported maintenance remains private direct access. Keep source allowlists endpoint-wide initially: per-database source rules require database-aware admission that sees the true client address, not a misleading per-row UI switch. Ensure the selected Docker networking mode preserves usable source addresses and test IPv4/IPv6 restrictions externally. Making a database private removes its public mapping/admission and terminates its existing public sessions without interrupting private workloads.

Revoke inappropriate `PUBLIC` database/schema access and function privileges. Use separate owner/migration/runtime/read-only roles, set default privileges for the actual object-creating roles, and test access across two projects. Keep pooler authentication functions in a protected schema with a fixed search path and tightly restricted execution. Review SECURITY DEFINER ownership and every route to password-verifier access. Scope PgBouncer user mappings and limits; do not expose all cluster databases through an unexamined wildcard.

Require SCRAM authentication and verified TLS on pooler and direct administrative connections. Maintain certificate issuance, trusted CA distribution, renewal alerts and tested reload operations. A narrowly scoped pooler reload capability replaces giving a certificate sidecar the Docker socket. Bootstrap-only cluster privilege and vetted extension installation remain isolated worker capabilities; routine inventory and SQL execution use lesser credentials.

For SQL execution, always display the selected database and effective role next to Run. Bind each request and result to an immutable database/workspace ID. Start read-only by default; a SQL parser warning is not authorization. Enforce database privileges, read-only transaction policy, safe function access, statement/lock/idle timeouts, bounded rows and bytes, streaming/cursors, concurrency limits and cancel/connection cleanup. Do not fetch an unlimited result and truncate it in the browser. Arbitrary functions and foreign data access require review because apparently read-only SQL may have side effects.

Write SQL requires explicit scoped access and recent authentication; never use a shared superuser connection. Audit execution metadata and a query fingerprint, with raw query history off by default. Test changing databases while a query is running so a late result cannot appear under the wrong database. Provide direct connections for migrations requiring session semantics and verify supported driver behavior through the pooler.

**10. Email management**

Retain Stalwart as the email engine and adapt Orkmail's reconciliation. Build the management experience into the shared React application. Start with manual DNS plus a Cloudflare adapter and SES relay; hide provider-specific behavior behind explicit interfaces so additional providers can be added later.

| Workflow          | Required behavior                                                                                                           |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Domain onboarding | Show required MX, SPF, DKIM, DMARC and custom MAIL FROM records; compare observed DNS; retain pending status until verified |
| Mailboxes         | Create, quota, owner, suspend/resume, password/device rotation, retained deletion, recovery and permanent purge             |
| Aliases           | Collision and loop checks, multiple recipients, explicit control over external forwarding                                   |
| Delivery          | Queue age, retry/defer/bounce details, pause sending, bounded retry/delete operations with scope checks                     |
| Client access     | IMAP/submission settings and one-time device credentials; keep portal and mailbox passwords separate                        |
| Abuse/reputation  | Auth failures, sender restrictions, mailbox/domain/global limits, SES quota and bounce/complaint observations               |
| Operations        | DNS/SES status, certificate expiry, reconciliation progress, storage usage and verified backup state                        |

Use restricted provisioning credentials after a one-time privileged SES bootstrap. Scope DNS tokens to intended zones. Separate outbound SMTP credentials from AWS API and DNS credentials. The public mail container must not receive broad provider keys, Docker access, the control database credential, or the root secret key.

Handle mailbox suspension locally before waiting on external providers. Preserve explicit native IDs, reserved purged addresses and deletion retention. A missing desired-state row never implicitly purges mail. Restrict retry and delete operations on the queue; suppress message bodies and sensitive header details unless a separately authorized workflow needs them.

Incoming-mail prerequisites include a suitable static address, domain control, correct address/MX records, provider permission for inbound TCP 25, provisioned local recipients, appropriate TLS and tested external delivery. Show reverse-DNS/provider guidance separately. SES production access/quota and sender-authentication records gate outbound SES readiness, not receiving mail. Integrate authenticated bounce/complaint events or documented polling; if a provider requires a public webhook, terminate it at a separate narrowly scoped ingress, not the admin API. Configure alerts through an independent outbound channel so mail failure can still be reported.

Adapt Orkmail's startup dependencies so Stalwart receiving/local account provisioning can start without successful SES bootstrap. Keep outbound sending paused until relay credentials and provider readiness are verified; never fall back to unintended direct outbound delivery. Expose separate receiving, client-access and sending statuses in the UI.

Test inbound delivery from an independent provider, outbound delivery through SES, IMAP access, submission TLS, suspension, password revocation and open-relay rejection. Native management/JMAP route separation and capabilities must be verified against the pinned Stalwart release and license. Do not assume features in a different documentation version are available. Keep webmail optional; the first release administers email without implementing a mail reader.

**11. Container service administration**

Provide projects containing one or more Compose services. The first templates should cover a stateless HTTP application, a background worker, and a persistent service with an explicit backup strategy. A workload can request an attached managed database: the platform creates scoped credentials and injects a secret reference without placing the platform database credential in the workload.

The creation flow asks for an approved image, command if required, ports/exposure, environment/secret references, volumes, resources, health check and update policy. Render a readable plan showing image digest, reachable endpoints, mounts, resource budget and persistent-data consequences before deployment.

Service detail includes status/health, restart count, exit/OOM events, CPU/memory/network/block I/O, logs, configuration revision, image provenance, update availability, backup coverage and operation history. Actions include deploy, start, stop, restart, scale where supported, update, revert a compatible deployment revision, and remove. Removal retains volumes by default; deletion of data is a separate dependency-checked action. Do not expose a global volume prune action.

Preserve each applied manifest, image digest, configuration hash and secret version reference. Do not store plaintext secret snapshots. Show drift from manual Docker changes and choose explicitly whether to adopt it or reapply desired configuration.

Existing containers are initially discovered as unmanaged metadata. Adoption requires an administrator to associate the exact project, inspect effective configuration, verify volume/network ownership and approve a safe supported manifest. Unknown or unsupported Compose constructs remain read-only. Never automatically restart or rewrite an existing service just because it appears in inventory.

For public HTTP services, generate explicit routes in a dedicated reverse proxy without giving that proxy the Docker socket. Validate hostnames and upstream membership; do not accept arbitrary proxy destinations that could reach control services or cloud metadata. Non-HTTP public ports require an owner-approved exposure plan and conflict checks.

**12. Monitoring, logs and alerts**

Use agent Docker events plus periodic reconciliation: events alone can be missed across reconnects. Combine container state, health checks and appropriate application probes. Report stale telemetry as unknown, including the time of last successful observation.

Prometheus stores short-term metric history; the React UI requests authorized fixed queries through the API. Start with approximately 15–30 second sampling and 14 days of retention, then tune against real disk/cardinality measurements. Reserve resources for mail, databases and control services so a noisy workload cannot consume the host. Keep exporters unprivileged where possible; add audited read-only host/cgroup mounts only for metrics that need them, not a blanket privileged monitoring container.

Stream live Docker stdout/stderr with timestamps, source, search/filter, pause/resume and bounded downloads. Authorize every resource and stream; cap rate, retained lines, bytes and concurrent followers. Escape untrusted text and terminal control sequences, redact known secrets before transport, and never render log content as HTML. Redaction is best effort, so scoped log access remains essential. Configure Docker log rotation at installation; show when older rotated logs are unavailable. Add centralized retained/searchable logs later behind a resource-budgeted profile.

Initial alerts: unhealthy/restarting/OOM services, missing agent heartbeat, host disk and inode pressure, database/pool exhaustion, WAL archival delay, mail queue age, certificate expiry, failed/stale backup, stale restore proof, and failed deployment. Include deduplication, acknowledgement, maintenance silences, escalation and a working notification test. Keep a heartbeat receiver or external probe outside this VPS: on-host monitoring alone cannot report complete host failure.

Use a notification provider independent of this mail server. Host kernel/security updates and reboots are a separate maintenance workflow; container image updates do not patch the host.

**13. Safe update management**

Use an update detector and the shared deployment engine. Store the running digest, approved candidate digest, registry/repository, architecture, release metadata and scan result. Registry queries require authentication/rate-limit handling and cached results; tags with no semantic version cannot reliably be classified as patch/minor/major. Resolve mutable tags to immutable digests before approval.

Proposed pipeline:

1. Detect a candidate within the service's allowed channel and surface its provenance and available release notes.
2. Evaluate security findings, compatibility rules, resource/disk headroom and maintenance constraints. Verify publisher signatures/provenance when available; require verification for our own releases and show when third-party verification is unavailable.
3. Capture the exact current configuration and verify a suitable recovery point for persistent data. A stale or untested backup can block a stateful update.
4. Record approval against the candidate digest and plan, then pull that exact image.
5. Apply the generated Compose revision under a project lock; run only reviewed health/migration hooks.
6. Observe container readiness and an application smoke test for a stabilization period. Restarting successfully is not sufficient evidence.
7. Mark the deployment verified, or run a permitted recovery path and report its actual result.

Default every service to notify-and-approve. Allow scheduled patch updates for explicitly selected stateless workloads after a successful manual deployment/rollback rehearsal. Stateful applications, PostgreSQL, Stalwart, the agent and the control plane require reviewed release-specific plans. Never equate switching to an old image with reverting database migrations or stored mail formats.

Use blue/green replacement only where routing, resource capacity and the application's state model support it. Compose on a single host does not provide a general zero-downtime upgrade guarantee. Single-writer databases and mail stores use a controlled interruption or a separately designed migration.

For the platform, use an independent maintenance runner, a durable local journal and backward-compatible expand/contract schema migrations. Update the API/workers as a compatible release set, observe recovery, and only then clean up old artifacts. Recreating the Tailscale namespace owner must trigger recreation/recovery of its gateway dependent. If a schema change makes rollback unsafe, block automatic rollback and present a tested forward-fix or restore procedure.

**14. Backup and disaster recovery**

Back up four distinct asset classes: the platform database and its recovery keys/configuration; application PostgreSQL clusters; Stalwart's message/configuration stores; and managed service volumes requiring persistence. A service with no tested backup strategy is visibly marked unprotected.

PostgreSQL needs both portability and recovery coverage. Use logical database exports plus role/ownership/grant information for selective moves. Add physical base backups and continuous WAL archival with pgBackRest for point-in-time recovery. `pg_dump` alone is not a PITR solution, as documented in [PostgreSQL continuous archiving](https://www.postgresql.org/docs/current/continuous-archiving.html). Define and test the backup repository, retention, archiving and restore workflow against the [pgBackRest user guide](https://pgbackrest.org/user-guide.html).

For mail, verify a supported consistent native backup mechanism for the selected Stalwart release and store. The CLI configuration snapshot is useful for reconciliation state but must not be treated as a complete mail-store backup; see [Stalwart state export](https://www.stalw.art/docs/management/cli/snapshot/). If a proven online backup is unavailable, explicitly quiesce/stop the writer, capture a consistent snapshot or copy while stopped, resume service and upload that immutable capture. State the associated interruption. Do not copy changing RocksDB files and label the result verified.

For application volumes, require a reviewed native dump or quiesce/snapshot recipe. Do not run arbitrary user-supplied host backup commands. The Docker agent may perform narrowly scoped stop/start work, while backup workers receive only the necessary data mounts and storage credentials.

Use encrypted off-site object storage with protected retention. Test backend-specific versioning/immutability support; do not assume Restic is append-only or that object locking works with every pruning setup. Separate backup writes from retention deletion where the storage design supports it. Monitor upload failures, repository locks, free staging space and backup age.

Each backup manifest records service versions/digests, data format versions, schema/configuration revision, secret key IDs, checksums and completion evidence. Store required encryption/recovery keys outside both the VPS and the backup repository, with a documented recovery mechanism. A successful upload, an integrity check and a successful restore are three separate statuses in the UI.

Proposed recovery targets, to be proven with representative data:

| Data                                                        | Target data-loss window   | Target recovery time                        |
| ----------------------------------------------------------- | ------------------------- | ------------------------------------------- |
| Platform + application PostgreSQL with healthy WAL archival | At most 15 minutes        | 1–2 hours for an agreed reference data size |
| Mail and supported file volumes                             | At most 6 hours initially | 2–4 hours for an agreed reference data size |

These are acceptance targets, not guarantees. Storage size, bandwidth, host replacement and DNS changes affect recovery. Alert on the actual latest recoverable time and measure restore duration in drills.

Restore into a new isolated environment first. Disable reconciliation, outbound email, provider writes and public ingress; do not boot a duplicate live Tailscale identity. Verify database ownership, application credentials, mail content and operational state before any cutover. For PITR, restore the cluster separately and recover individual databases from it when appropriate. Never silently rewind a shared production cluster to restore one application.

The host-loss runbook provisions a clean host, restores keys/platform state, restores managed data, reconciles native resource IDs and approved configuration, re-enrolls/revokes Tailscale nodes deliberately, verifies private access, then enables public traffic. SMTP delivery already acknowledged by a failed host may be lost up to the recovery point; backup frequency is not high availability.

**15. Integrated frontend experience**

Build one application shell with Overview, Domains & Endpoints, Projects, Databases, Email, Services, Activity, Backups, Updates and Settings. Setup begins with the guided domain/exposure wizard in section 5a. Domains & Endpoints shows record-by-record DNS guidance, verification progress, certificates/renewals and the independent public/private policy of each endpoint. Apply one project/domain scope model, one command/search experience, and consistent breadcrumb/context handling. A cross-module project page connects a deployed service with its database, secrets, routes, alerts and backup policy.

Use shadcn tables, dialogs, sheets, tabs, forms and status elements with shared Tailwind tokens. Favor accessible, dense operational views with responsive detail panels. Keyboard navigation, visible focus, screen-reader labels, non-color status text and light/dark modes are baseline requirements.

Every resource view separates desired configuration from observed health and displays data freshness. Every mutation shows validation, a concrete preview when appropriate, durable progress and an outcome that survives navigation/reload. Global Activity provides step history and explains recoverable partial failures. Do not show a successful toast merely because work was queued.

Specialized interactions: one-time credential reveal with no-store responses; SQL tabs bound to database/role; live logs with follow/pause and bounded history; deployment diffs showing exposure and volume effects; DNS onboarding showing expected and actual records; and restore screens clearly identifying source backup and destination.

Do not iframe the existing PgStack and Orkmail portals or expose service-native admin panels as the integrated experience. Optional advanced tools can be separate private links with their own authentication and scope. Mailbox self-service for users outside the tailnet, if later required, is a separate frontend/API exposure boundary.

**16. Delivery phases and release gates**

Estimates below are engineering effort for one experienced full-time engineer familiar with the existing code. They include implementation and ordinary validation, but not waiting for DNS/SES/provider access, external security review, or an extensive UI redesign. Reuse should save time; security and recovery work remain substantial. The total planning range is approximately 20–29 engineer-weeks, including guided domain/certificate automation and both administration modes, with a useful alpha earlier.

| Phase                              | Effort    | Deliverables                                                                                                                                                                          | Exit gate                                                                                                                                            |
| ---------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0. Design and compatibility spikes | 1–2 weeks | Threat model, version/license matrix, network/agent contracts, public/tailnet prototypes, manual-DNS ACME renewal experiment, consistent mail backup experiment, reference sizing     | Both access boundaries demonstrated; certificate/mail recovery methods chosen; no unresolved critical privilege path                                 |
| 1. Secure platform foundation      | 3–5 weeks | Compose installer, protected bootstrap, platform DB, Better Auth/MFA/RBAC, public/tailnet selection, domain wizard, DNS/certificate worker, UI shell, audit, operations, recovery CLI | Fresh install works with manually edited DNS; issuance/renewal and mode transitions pass; unauthorized access fails; jobs survive restarts           |
| 2. Container management alpha      | 3–4 weeks | Agent policy, discovery/adoption, approved templates, lifecycle actions, bounded logs/stats, service alerts                                                                           | Two isolated projects run; malicious Compose cases rejected; interrupted deployment reconciles safely                                                |
| 3. PostgreSQL module               | 4–5 weeks | Public hostname/pooler, generated credentials, per-database exposure, source policies, role model, verified TLS, schema browser, bounded SQL, rotation, backups                       | External verified-TLS login works; private resources/privileged roles denied publicly; interrupted provisioning repairable; restore preserves grants |
| 4. Email module                    | 3–4 weeks | Adapted Orkmail workers, shared DNS/certificate onboarding, generated mailbox credentials, integrated domain/mailbox/alias UI, SES setup, lifecycle and queue controls                | Inbound readiness independent of SES; external delivery, suspension/revocation and open-relay tests pass; consistent backup restores real messages   |
| 5. Updates and complete recovery   | 3–4 weeks | Digest-based update plans, schedules, stateless automation, platform maintenance runner, restore UI/drills, external heartbeat                                                        | Failed updates recover; unsafe stateful rollback is blocked; replacement-host restore works                                                          |
| 6. Production hardening            | 3–5 weeks | Security review, failure/load testing, alert tuning, supply-chain checks, documentation, pilot migration                                                                              | Full acceptance suite and measured recovery objectives pass; no critical unresolved security issue                                                   |

An alpha after phases 1–2 manages low-risk containers with the selected administration mode. Public administration still requires its exposure/security gate before publication. Existing production databases and mail remain on their current stacks until the corresponding module and recovery gates pass. Basic backups, logs and alerts are built alongside each module; phase 5 unifies and exercises them rather than introducing protection only at the end.

For phase 0, provision a disposable Linux test host and a test tailnet identity, domain, mailbox and object-storage repository. Verify firewall behavior, Tailscale/gateway replacement, Compose policy enforcement and mail snapshot consistency before polishing large feature surfaces. These experiments settle the highest-cost architectural uncertainties.

**17. Verification and migration**

Use unit tests for authorization/policy decisions and operation transitions; disposable Docker integration tests for actual behavior; browser tests for high-risk workflows; and an isolated Linux deployment for host/network/recovery gates. Do not run destructive Docker tests against a developer's or production daemon.

| Test category            | Required examples                                                                                                                                                                                                                                                                                                        |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Network security         | Tailnet-only admin unreachable publicly even with forged Host/forwarded headers; public mode exposes only browser routes; public DB/mail work in both admin modes; backend DB/metrics/workers remain private; IPv4/IPv6 policy checks; Funnel disabled                                                                   |
| Domain/certificate setup | Manual DNS flow without API token; ownership proof; conflicting existing records; delayed propagation; bad AAAA/CAA; restart mid-onboarding; ACME staging issuance/renewal/reload; expired/failed orders; SSRF protection; endpoint rename and abandoned-domain cleanup                                                  |
| Privilege boundary       | Reject Docker socket mounts, host namespaces, devices, path/symlink escapes, malicious includes/hooks, secret exfiltration attempts and access to protected platform projects                                                                                                                                            |
| Application security     | Cross-project/domain IDOR, CSRF, session/MFA bypass, bootstrap race, stale/single-use previews, worker replay and revoked stream access                                                                                                                                                                                  |
| Secrets                  | Routine APIs, image metadata, manifests, process output and logs do not return seeded canary secrets; recovery with external keys works                                                                                                                                                                                  |
| Database                 | External login with generated credentials and hostname verification; reject plaintext/incorrect passwords/private databases/admin console; CIDR enforcement; revoke existing public sessions; runtime DDL/cross-database denial; function/default privilege checks; interrupted creation; bounded result/cancel behavior |
| Email                    | Real send/receive, no open relay, sender controls, alias loops, suspend/recover/purge, revoked devices, provider failure and consistent restore                                                                                                                                                                          |
| Operations               | Lost heartbeat with old worker still alive, duplicate job submission, daemon outage, API restart, disk full, expired registry credentials, unhealthy candidate and agent update interruption                                                                                                                             |
| User interface           | Wrong-database late response prevention, reliable reconnect, inaccessible-action explanations, keyboard/focus behavior, log escaping                                                                                                                                                                                     |
| Recovery                 | New-host platform/database/mail restore, correct roles/secrets, no unintended external writes, no duplicate tailnet identity, measured data-loss window and duration                                                                                                                                                     |

CI should build/type-check/lint, run focused unit and integration suites, validate Compose/config policy, scan dependencies/images/secrets, and publish versioned release artifacts with SBOMs and signatures. Run heavier restore and deployment drills on scheduled isolated infrastructure and before stateful upgrade releases. Validate failure evidence rather than treating a skipped integration test as a pass.

Migration is optional adoption, not an automatic merge of the existing deployments:

1. Install the new control plane beside the existing stacks, using unique Compose project names, volumes and private endpoints. Verify ports and host capacity.
2. Import resource metadata read-only and compare database, mail and Compose inventories. Detect naming conflicts and unsupported definitions. Do not import legacy users as platform owners automatically.
3. Create and restore-test source backups. For PostgreSQL, choose a same-major adoption or an explicit dump/restore/upgrade procedure; validate extensions, locale/collation, ownership and grants.
4. For mail, stop the old reconcilers before ownership transfer. Preserve native IDs, message data, retained deletions, aliases, device state and provider identity bindings. Never allow two control planes to reconcile the same account simultaneously.
5. Import or rotate secrets through a protected one-time process. Preserve source encryption keys until all required records are re-encrypted and verified. Re-enroll platform administrators with MFA; invalidate transferred sessions deliberately.
6. Cut over one low-risk application first, then one test mail domain. Verify actual runtime database access, mail delivery, backups, alerts and rollback/recovery procedures.
7. Transfer remaining resources in maintenance windows. Keep the old stack and recovery artifacts intact until the new installation passes its retention and recovery gates. Returning to an old writer after new writes requires data reconciliation, not just switching an image or DNS record.

**18. Decisions to confirm at implementation kickoff**

Confirmed requirements are public database access with custom hostnames and generated credentials, guided user-managed DNS followed by automatic provisioning, public incoming mail, selectable public or tailnet-only administration, and Better Auth. Record final choices for the target Linux distribution and host capacity; expected database/mail sizes; whether SES/Cloudflare/Hetzner remain preferred providers; the initial domain/hostnames and admin mode; whether a public mailbox self-service web portal is also needed beyond standard mail clients; required uptime and recovery objectives; and which stateless services may update automatically.

Start capacity testing around a 4-vCPU, 8–16 GB RAM host with SSD storage and off-site backups. This is a sizing hypothesis, not a measured minimum. Benchmark the chosen mail filtering, PostgreSQL workload, metric retention, backup staging and concurrent services; alert well before disk exhaustion and cap aggregate workload resources. A smaller footprint can reduce optional monitoring features, but should not combine the control and application database trust boundaries just to reduce container count.

The first concrete implementation milestone is a Better Auth dashboard with protected bootstrap, public/tailnet exposure selection and a working domain/DNS/certificate wizard. It must also observe and restart one registered test service through the policy-enforcing agent, with durable audit/job history and an exercised failure-recovery path. The next end-to-end milestones provision a public database with generated credentials and a receiving mailbox from the same guided domain setup.
