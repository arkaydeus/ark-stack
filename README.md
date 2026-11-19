# Ark Stack

Ark Stack is a self-hosted control plane for a single Linux VPS. One administration UI, with mandatory MFA for administrators, manages:

- **domains and certificates**: a wizard plans the DNS records, verifies them publicly and only then requests Let's Encrypt certificates;
- **PostgreSQL**: application databases, the SQL workspace and public database access through a client-certificate pooler;
- **mail**: a Stalwart mail server with mailboxes, aliases and an SES relay for outbound mail;
- **services**: Docker Compose workloads, run only through a small Go agent that enforces a default-deny policy;
- **the front door**: selected services on your Tailscale tailnet, published on your own public domains without revealing their tailnet addresses. Public DNS points only at the VPS, and the edge forwards each route to the tailnet machine it is pinned to.

Workers and the agent carry out every change and report evidence, so a domain, certificate, database or backup is shown as ready only after the work behind it has been checked. Public administration and public database endpoints are independent, and tailnet-only admin mode publishes no public dashboard route. [Overview](docs/introduction/overview.md) explains the product in more detail.

The code is TypeScript (Bun, Hono, React and Drizzle) on PostgreSQL, plus the Go agent. Tooling is **mise**, **bun** and **oxc**.

## Getting started

Choose one path:

- **[Try it locally](#try-it-locally)**: run the API, the admin UI and the databases on your workstation, for development or a look around. No domain, VPS or tailnet is needed.
- **[Install on a VPS](#install-on-a-vps)**: a hardened production install on Ubuntu, with the front door serving your first domain over public HTTPS.

### Try it locally

You need:

- [mise](https://mise.jdx.dev), which installs the pinned Bun and Go versions from `mise.toml`;
- Docker with Compose v2, for the PostgreSQL containers and most integration tests;
- OpenSSL on the `PATH`;
- free local ports 3000 (API) and 5173 (UI), and 5433 and 5434 for the databases.

**1. Install the toolchain and create `.env`.** From the repository root:

```sh
mise trust
mise run setup
cp .env.example .env
ARK_INSTALL_SKIP_DOCKER=1 ARK_INSTALL_NONINTERACTIVE=1 mise run host:install
```

The API refuses to start while any generated secret in `.env` is empty or an example value. The last command fills those secrets with random values without touching Docker, keeps every other value, and prints the setup token. It is safe to run again.

**2. Point the database URLs at the generated passwords.** The installer does not rewrite `DATABASE_URL` and `DATABASE_APP_URL`, which still carry the example passwords:

```sh
api=$(grep '^ARK_API_DB_PASSWORD=' .env | cut -d= -f2)
app=$(grep '^ARK_APP_DB_PASSWORD=' .env | cut -d= -f2)
# Edit .env so that:
#   DATABASE_URL=postgres://ark_runtime:$api@127.0.0.1:5433/ark_platform
#   DATABASE_APP_URL=postgres://ark_cluster_admin:$app@127.0.0.1:5434/postgres
```

**3. Start the databases and apply the migrations.** Export `.env` so Compose sees it, start both clusters, then migrate as the schema owner `ark_migration` (the runtime role in `DATABASE_URL` cannot create tables):

```sh
set -a; . ./.env; set +a
mise run db:up
DATABASE_URL="postgres://ark_migration:$ARK_CONTROL_DB_PASSWORD@127.0.0.1:5433/ark_platform" \
  bun run --cwd server db:migrate
```

If ports 5433 and 5434 do not answer (some Docker versions, such as Docker Desktop with Engine 29, publish no ports for these containers), stop them with `mise run db:down` and use [a throwaway database](docs/getting-started/local-development.md#alternative-a-throwaway-database) instead.

**4. Run the stack.**

```sh
mise run dev
```

This starts the API with embedded workers on port 3000 and the Vite UI on port 5173. Open <http://localhost:5173> (use `localhost`, not `127.0.0.1`: only registered hosts are answered).

**5. Create the owner, enrol MFA and run the domain wizard.**

1. On **Create the owner**, enter a name, email, a password of at least 12 characters, and the **Setup token**: `ARK_SETUP_TOKEN` from `.env`, also printed by the installer. Select **Create administrator**. Setup closes after the first owner exists.
2. On **Secure the owner account**, confirm your password, add the TOTP secret to an authenticator app, save the recovery codes outside the browser, and enter a six-digit code.
3. Complete the domain wizard: choose the admin mode, enter a base domain and public IPv4 address, choose the DNS provider and the first services, then select **Generate DNS plan and continue**.

Locally, DNS checks are stubbed and certificates are self-signed, so endpoints end in `certificate_untrusted`, and mail, Cloudflare and Docker operations wait for providers that are not running. That is expected. [Local development](docs/getting-started/local-development.md) has the full walkthrough and [common problems](docs/getting-started/local-development.md#common-problems); [First run and domain wizard](docs/getting-started/first-run.md) describes every screen.

### Install on a VPS

You need:

- an Ubuntu VPS with a public IPv4 address (IPv6 optional), a provider firewall you control, and working console or rescue access;
- Docker Engine with the Compose v2 plugin, installed beforehand (the installer does not install Docker);
- `git`, OpenSSL and mise available to root, with this repository checked out on the VPS and `mise trust` and `mise install` run in it;
- a Tailscale tailnet where you can edit the policy file and create auth keys, the Tailscale Ubuntu package source configured on the VPS, and an untagged owner device for SSH;
- a domain whose DNS you control, at Cloudflare (reviewed automatic publishing) or any other provider such as Namecheap (manual records);
- an email address for the Let's Encrypt account.

[Production install](docs/getting-started/production-install.md) is the complete procedure. The steps, in order:

1. **[Plan the tailnet tags and keys.](docs/getting-started/production-install.md#plan-the-tailscale-identities)** In the tailnet policy file, declare `tag:ark-vps` and `tag:ark-edge` in `tagOwners`, add an owner-only grant for TCP 22 to `tag:ark-vps` with a Tailscale SSH rule in `check` mode, and give `tag:ark-edge` no grants yet. Create each auth key only when you need it: not reusable, not ephemeral, pre-approved, a single tag, a 1-day expiry. Revoke it once its node has joined.

2. **[Enrol the host](docs/getting-started/production-install.md#enrol-the-host)** with a `tag:ark-vps` key, then delete the key file and revoke the key:

   ```sh
   sudo install -m 600 /dev/null /root/ark-vps-authkey   # then paste the key into this file
   sudo TS_VPS_AUTHKEY_FILE=/root/ark-vps-authkey mise run host:install --enroll-vps
   ```

   From your owner device, open `tailscale ssh <user>@<vps-magicdns-name>` and keep that session open for the rest of the install.

3. **[Harden the host and install.](docs/getting-started/production-install.md#harden-the-host-and-install)** Let the installer create `.env`; do not start from a copy of `.env.example` in production. It generates every secret, installs the host firewall and unattended upgrades, builds the images and starts the platform, then prints the setup URL and token. [Decide the install-time settings](docs/getting-started/production-install.md#decide-the-install-time-settings) first, such as `ARK_MAIL_ENABLED=0` to install without mail.

   ```sh
   sudo mise run host:install --harden-vps
   curl -fsS http://127.0.0.1:3000/api/health
   ```

4. **[Close public SSH.](docs/getting-started/production-install.md#close-public-ssh)** After confirming a new Tailscale SSH session works, remove public TCP 22 at the provider and stop or rebind Ubuntu's public OpenSSH listener.

5. **[Set the provider firewall and audit it.](docs/getting-started/production-install.md#provider-firewall-and-audit)** Apply the generated `providerRules` at your provider, run the local audit, then scan from another machine with Nmap:

   ```sh
   sudo mise run host:audit --inventory > ark-host-inventory.json
   sudo mise run host:audit
   sudo mise run host:audit --external ark-host-inventory.json <public-ipv4> <public-ipv6>
   ```

6. **[Enrol the edge node.](docs/getting-started/production-install.md#enrol-the-edge-node)** Give the installer a one-off `tag:ark-edge` key when it asks, or set `TS_EDGE_AUTHKEY` in `.env`, then start the node and rejoin its dependents:

   ```sh
   docker compose --env-file .env -f infra/platform/docker-compose.yml up -d edge-ts edge edge-l4
   mise run edge:rejoin
   ```

   Check that the node is tagged `["tag:ark-edge"]`, empty `TS_EDGE_AUTHKEY` and revoke the key, and allow UDP 41642 at the provider for direct WireGuard paths.

7. **[Set the admin origin and ACME.](docs/getting-started/production-install.md#set-the-admin-origin-and-acme)** In `.env`, set `BETTER_AUTH_URL=https://admin.<domain>` and add that origin to `BETTER_AUTH_TRUSTED_ORIGINS`, keeping `http://localhost:3000` there while you still sign in through the tunnel. Set `ARK_ACME_EMAIL` and `ARK_ACME_STAGING=0` for publicly trusted certificates. Then recreate the services that read them:

   ```sh
   docker compose --env-file .env -f infra/platform/docker-compose.yml up -d api domain-worker
   ```

8. **[Create the first owner, enrol MFA and run the domain wizard.](docs/getting-started/production-install.md#first-login-and-the-domain-wizard)** The API listens only on `127.0.0.1:3000` on the VPS, so open a tunnel over the tailnet and browse to `http://localhost:3000`:

   ```sh
   ssh -L 3000:127.0.0.1:3000 <user>@<vps-magicdns-name>
   ```

   Create the owner with `ARK_SETUP_TOKEN`, enrol TOTP MFA, then run the wizard with **Public HTTPS**, your base domain, the VPS's public IPv4 (and IPv6, if it has one) and your DNS provider. [First run and domain wizard](docs/getting-started/first-run.md) walks through each screen and the records it plans.

9. **[Go public over HTTPS.](docs/getting-started/production-install.md#going-public)** Create the planned DNS records at your provider, or review and publish the Cloudflare diff, and select **Recheck DNS** until the endpoints leave `awaiting_dns`. The domain worker then issues the certificates, and once the admin certificate is `issued` the edge serves `https://admin.<domain>`. Keep the tunnel until you have signed in there.

Afterwards, copy the recovery material (`ARK_ROOT_KEY`, `ARK_ROOT_KEY_ID`, `ARK_MFA_RECOVERY_TOKEN`, the pgBackRest cipher passes and every backup target's restic password) off the host, as [After the install](docs/getting-started/production-install.md#after-the-install) describes. Re-running the installer is safe: it keeps every existing secret.

## Next steps

- **Add a domain.** The wizard creates the first domain, its records and its endpoints. With Cloudflare, Ark computes a diff of DNS-only records that you review and then publish. With Namecheap or any other provider, Ark shows the exact rows to create, including the apex (`@`) and `www`, and rechecks public DNS for you. AAAA records are added only after the IPv6 preflight passes. See [Domains and DNS](docs/features/domains-and-dns.md) and the [front-door DNS steps](docs/guides/front-door.md#8-dns), which include Namecheap.
- **Expose a tailnet service through the front door.** Publish a service running on any tailnet machine as an HTTP route (WebSockets included), either public or behind the Ark login with TOTP; as a TLS-TCP route routed by SNI; or as a raw TCP route on ports 20000–20049. Each route waits for its tailnet grant, DNS and certificate before you enable it. See the [front-door guide](docs/guides/front-door.md).
- **Give a Vercel app database access.** Open the public pooler and issue a client certificate from the app environment's own private CA. Each connection then needs TLS 1.3, that certificate and SCRAM, with alerts before the 90-day rollover. See [Guide: database access from Vercel](docs/guides/vercel-database.md) and [Public database access](docs/features/public-database-access.md).
- **Set up backups.** Copy both PostgreSQL clusters, mail and reviewed volumes off the VPS to an [S3-compatible bucket](docs/guides/backups.md#setting-up-the-s3-compatible-target) (AWS S3, Backblaze B2 or Cloudflare R2) and to an append-only `rest-server` on a [home machine over the tailnet](docs/guides/backups.md#home-machine-over-the-tailnet-fd-30), then set `ARK_BACKUP_EXECUTE=1`. See [Guide: off-VPS backups](docs/guides/backups.md).

Mail, application databases, services, monitoring and upgrades each have their own page in the [documentation](docs/index.md).

## For developers

### Key commands

| Command                      | Purpose                                                 |
| ---------------------------- | ------------------------------------------------------- |
| `mise run dev`               | API with embedded workers and the Vite UI               |
| `mise run check`             | format check, lint, typecheck and unit tests            |
| `mise run test`              | Bun unit tests (needs `.env` and a migrated database)   |
| `mise run test:db`           | DB-backed tests on a throwaway PostgreSQL (Docker only) |
| `mise run test:agent`        | Go agent policy tests                                   |
| `mise run test:e2e`          | real-browser owner, MFA and wizard flow                 |
| `mise run test:edge`         | Caddy, HAProxy, observer and edge harnesses (Docker)    |
| `mise run docs:check`        | check links, paths, tasks, endpoints and ports in docs  |
| `mise run docs:serve`        | browse the documentation site locally                   |
| `mise run db:studio`         | Drizzle Studio                                          |
| `mise run recover -- status` | development bootstrap and lockout inspection            |

Every task, with what it runs and needs, is in [Commands](docs/reference/commands.md). [Testing](docs/development/testing.md) explains each suite, including how `mise run test:db` manages its throwaway database and the PgBouncer harness. Image publishing to GHCR is in [Publishing first-party images](docs/operations/maintenance-and-upgrades.md#publishing-first-party-images). For production lockouts and MFA resets, follow the [recovery runbook](docs/operations/recovery.md).

### Layout

```
web/        React administration UI
server/     Hono API, Better Auth, Drizzle, operations coordinator
shared/     Policy, DNS planning, authz, and schemas
workers/    Database, mail, backup, and domain worker entrypoints
agent/      Go Docker agent and local recovery journal
infra/      Platform Compose, database, mail, and monitoring
templates/  Reviewed application service definitions
scripts/    Installer, audit, maintenance and recovery CLIs, docs tooling, test harnesses
docs/       Documentation site, runbooks, guides and design history
```

[Repository and conventions](docs/development/repository.md) describes each directory.

### Documentation

The full documentation starts at [docs/index.md](docs/index.md): an introduction, installation, every feature, operations, security and reference pages, organised by the sidebar in [docs/nav.json](docs/nav.json). Browse it as a site with `mise run docs:serve` (http://127.0.0.1:4321/), build it with `mise run docs:build` (static HTML in `dist/docs`) and check it with `mise run docs:check`.

Frequently used pages: [architecture](docs/architecture.md), [operating runbooks](docs/operating.md), [security review](docs/security-review.md), and the guides for the [front door](docs/guides/front-door.md), [database access from Vercel](docs/guides/vercel-database.md) and [off-VPS backups](docs/guides/backups.md). The front-door design and its as-built summary are in [docs/design/front-door.md](docs/design/front-door.md).

Local and live-integration evidence is recorded in [`docs/fix1-verification.md`](docs/fix1-verification.md). Public DNS, ACME, external CIDR, SES, off-host receiver, and fresh-host restore checks are deployment acceptance gates rather than unit-test substitutes.
