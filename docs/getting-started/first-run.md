# First run and domain wizard

This page walks through the first session on a new installation: opening the setup page, creating the owner with the setup token, enrolling MFA, every field of the domain wizard and what it creates, the DNS records to publish, certificate issuance and the endpoint states you will see until everything is served.

## Before you begin

You need a finished install ([Production install](production-install.md) or [Local development](local-development.md)) and two things from the host:

- **The setup token.** `ARK_SETUP_TOKEN` in the installation's `.env`. The installer prints it at the end of every run, with the setup URL.
- **A registered address.** The API answers only hosts named in `BETTER_AUTH_URL` and `BETTER_AUTH_TRUSTED_ORIGINS`; any other host gets HTTP `421` and `{"error":"This host is not a registered Ark origin."}`.

On a VPS, the raw API listens only on `127.0.0.1:3000`. Open an SSH tunnel over the tailnet and browse to a registered host, for example:

```sh
ssh -L 3000:127.0.0.1:3000 <user>@<vps-magicdns-name>
# then open http://localhost:3000
```

With the default settings `http://localhost:3000` is registered and `http://127.0.0.1:3000` is not. Locally, use `http://localhost:5173`.

The UI decides what to show from your state: the sign-in or owner-creation page without a session, the MFA screens until your session has MFA assurance, the domain wizard until it has been completed, and the full interface after that.

## Create the owner

While no user exists, the sign-in page is titled **Create the owner** and explains that "This single-use bootstrap closes after the first administrator exists."

1. Enter **Name**, **Email** and **Password** (at least 12 characters).
2. Enter the **Setup token**.
3. Select **Create administrator**.

Behind the button, the UI calls `POST /api/auth/sign-up/email` with the token in the `x-setup-token` header. The API takes an advisory lock, compares the token in constant time, and only then lets Better Auth create the account. On success it grants the new user the `owner` role in `platform_access`, marks setup complete and records when bootstrap closed. The browser is signed in and the page reloads.

Setup is single-use:

- A second attempt, or a wrong token, is refused with `Administrator setup is closed or the token is invalid.`
- If users exist but setup was never marked complete (for example after an interrupted bootstrap), the API grants the existing users the owner role, closes setup and answers `Setup is already complete. Sign in with the existing administrator.`
- `GET /api/setup/status` reports `required` (no owner yet) and `wizardRequired` (owner exists, wizard not done).

The token is not used again. The [recovery CLI](../operations/recovery.md#the-recover-cli) can reopen setup only when no users exist.

## Enrol MFA

Before any domain setup or administrative change, the UI shows **Secure the owner account**: "MFA enrollment is required before domain setup or any administrative mutation."

1. **Confirm your password** and select **Create TOTP enrollment**. Better Auth creates a TOTP secret (issuer "Ark Stack") and a set of recovery codes.
2. Add the **manual secret** to your authenticator app. It is shown as text, exists only in the page's memory and is not shown again.
3. Save the **recovery codes** outside the browser. Each works once in place of a TOTP code.
4. Enter the **Six-digit verification code** and select **Verify TOTP**.
5. Tick **I saved the recovery codes outside this browser.** and select **Continue to domain setup**.

On successful verification the API records the enrolment time as the creation time of your current session, so this session gains MFA assurance immediately ("TOTP is verified and the session was rotated to MFA assurance"). Any session created before enrolment does not: if you see **Refresh your assured session**, select **Return to sign in** and sign in again.

From now on, signing in asks for email and password, then **Verify your sign-in** with a TOTP code, or a recovery code with **Use a recovery code** ticked. Sign-in and two-factor attempts are limited to five per minute per client address. If every factor is lost, see [Recovery](../operations/recovery.md).

## The domain wizard

The wizard is titled "Choose how this host is reached, then publish DNS." It runs once: after it completes, the same values are changed from **Settings** and **Domains & Endpoints**, and a second submission is refused with `First-run setup is already complete. Change these settings from Settings instead.` Only an owner with MFA assurance can submit it.

### Administration exposure

"Both modes use Better Auth and mandatory administrator MFA." The admin mode never decides whether databases or mail are public; those stay independent.

| Field                               | Required | Default if empty | Meaning                                                                                                                                                  |
| ----------------------------------- | -------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Public HTTPS** / **Tailnet only** | yes      | Public HTTPS     | Public: serve the admin UI at the admin hostname through the public edge. Tailnet only: no public admin route; Tailscale Serve to a loopback gateway.    |
| **Base domain**                     | yes      |                  | The zone you control, for example `example.com`.                                                                                                         |
| **Public IPv4**                     | yes      |                  | The VPS's public IPv4 address. Every A record points here.                                                                                               |
| **Public IPv6 (optional)**          | no       |                  | The VPS's global IPv6 address. Starts the IPv6 preflight; AAAA records wait until it passes.                                                             |
| **Admin hostname (optional)**       | no       | `admin.<domain>` | Used only in public mode.                                                                                                                                |
| **Database hostname (optional)**    | no       | `db.<domain>`    | The public pooler hostname, used when **Public database endpoint** is ticked.                                                                            |
| **Mail hostname (optional)**        | no       | `mail.<domain>`  | The mail server hostname, used when **Incoming mail** is ticked.                                                                                         |
| **DNS provider**                    | yes      | Manual / other   | **Manual / other**: Ark shows the records and you create them. **Cloudflare (publish after review)**: Ark computes a diff for you to review and publish. |

Hostnames must be valid DNS names; the IPv4 address must be a dotted quad.

### First services

"Credentials are generated automatically and shown once."

| Field                        | Default | Meaning                                                                                                                                      |
| ---------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Public database endpoint** | ticked  | Creates the database endpoint and the application cluster record.                                                                            |
| **Incoming mail**            | ticked  | Creates the mail endpoint and mail domain. Refused with `Mail is disabled on this installation.` when `ARK_MAIL_ENABLED=0`; untick it there. |
| **First database name**      | empty   | Optional. A lowercase name starting with a letter, up to 41 characters of `a-z`, `0-9` and `_`, for example `orders`.                        |
| **First mailbox local part** | empty   | Optional. The part before `@`, for example `hello`.                                                                                          |

Select **Generate DNS plan and continue**.

### What the wizard creates

`POST /api/wizard` records desired state in one request and returns the domain ID, the planned records and the verification operation:

- **Domain claim** for the base domain, with a fresh ownership token `ark-own-…`, status `awaiting_dns`, the chosen DNS provider and the MAIL FROM name `bounce.<domain>`. You are granted access to it.
- **DNS records**, planned as below.
- **Endpoints**, each `public` and `awaiting_dns`: `database` (if ticked), `mail` (if ticked), and `admin` (public mode only).
- **Database cluster** record named `application` in `provisioning`, and the first database (if named) in `queued`, exposure `public`.
- **Mail domain** with inbound `pending` and outbound `paused`, and the first mailbox (if named).
- **Platform settings**: admin mode, base domain, admin hostname (public mode), public addresses, IPv6 status `unchecked`, DNS provider, and `BETTER_AUTH_URL` as the current admin origin.
- **Operations**: `domain.ipv6_preflight` if you gave an IPv6 address, and `domain.verify` for the domain unless the provider is Cloudflare (which waits for you to publish first). An audit event `wizard.complete` records the admin mode.

Nothing is published or issued by the wizard itself.

## DNS records

The plan comes from `buildDomainPlan` in `shared/src/dns-plan.ts`. With every option enabled and `example.com`:

| Type | Name                     | Value                                            | TTL | Required | Purpose                                           |
| ---- | ------------------------ | ------------------------------------------------ | --- | -------- | ------------------------------------------------- |
| TXT  | `_ark-stack.example.com` | `ark-own-…` (the ownership token)                | 60  | yes      | Installation-bound domain ownership proof         |
| A    | `db.example.com`         | the public IPv4                                  | 300 | yes      | Public database endpoint                          |
| A    | `mail.example.com`       | the public IPv4                                  | 300 | yes      | Incoming and client mail endpoint                 |
| MX   | `example.com` (`@`)      | `mail.example.com`, priority 10                  | 300 | yes      | Incoming mail for the domain                      |
| TXT  | `example.com` (`@`)      | `v=spf1 include:amazonses.com -all`              | 300 | yes      | Outbound sender policy                            |
| TXT  | `_dmarc.example.com`     | `v=DMARC1; p=none; rua=mailto:dmarc@example.com` | 300 | yes      | DMARC reporting policy                            |
| A    | `admin.example.com`      | the public IPv4                                  | 300 | yes      | Public administration hostname (public mode only) |

AAAA records (TTL 300, not required) are added for the same hostnames only once the IPv6 preflight has passed and the domain's IPv6 switch is on. A new install starts with the preflight `unchecked`, so the first plan has no AAAA records.

If the domain already has an SPF record, merge `include:amazonses.com` into it: a name must never have two SPF records. If it already receives mail elsewhere, review the existing MX records before replacing them. The wizard plans no SES identity or DKIM records; outbound mail and its SES requirements are covered in [Mail](../features/mail.md).

## Publish and verify DNS

Open **Domains & Endpoints**. Each domain card shows its status and its records, each with its own status (`pending`, `verified` or `error`). Select **Review DNS** to open the review panel. It states whether IPv6 is being published ("Publishing A only. IPv6 is disabled or its preflight has not passed." on a new install), lists the records, and offers provider guides.

**Manual and other providers.** Create the records at your provider exactly as shown, turn off any proxy or CDN for those names, remove conflicting A, AAAA or CNAME records, and check that no CAA record excludes Let's Encrypt. Opening the review starts a 30-minute window in which Ark rechecks public DNS every two minutes; **Recheck DNS** queues `domain.verify` immediately and restarts the window. Rows marked for removal stay pending until a public lookup confirms they are gone.

**Cloudflare.** The domain worker needs a Cloudflare token (`DNS_API_TOKEN`) scoped to Zone / DNS / Edit and Zone / Zone / Read for the zone. The review lists `keep`, `update`, `create`, `delete` and `blocked` actions with the current and new values. Records are always DNS-only, never proxied, and Ark refuses ambiguous same-name edits. Resolve blockers at Cloudflare, then select **Publish reviewed DNS**. That sends `POST /api/domains/:id/publish` with the review's plan hash and returns `202` with an operation ID; the panel follows it until it finishes, and publishing queues `domain.verify`. Publishing needs an owner or operator with MFA assurance.

The [front-door guide's DNS section](../guides/front-door.md#8-dns) has step-by-step provider instructions, including Namecheap.

### What verification checks

`domain.verify` runs in the domain worker. It reads public DNS for every planned record and, for each endpoint, blocks progress when:

- a required record is missing or has another value;
- the hostname resolves to a Cloudflare proxy address ("Switch its record to DNS only");
- an unexpected AAAA record is present (Let's Encrypt tries IPv6 first);
- a CAA record excludes Let's Encrypt;
- on Cloudflare, a required record has not been published from a reviewed plan.

The domain becomes `verified` once the ownership TXT record is observed. Each endpoint becomes `verified` when its own records pass; otherwise the first blocking error is stored on the domain and shown at the top of the review panel. A verified endpoint immediately gets a `certificate.issue` operation. Verification also starts the work that depends on DNS: once the database endpoint is verified, the first database is provisioned (`database.provision`); once the mail endpoint is verified and mail is enabled, mailboxes are provisioned in Stalwart (`mail.provision`). DNS is re-checked on a schedule afterwards, so drift is noticed.

## Certificates

`certificate.issue` runs in the domain worker:

1. It re-reads public DNS and CAA for the hostname, in case anything changed since verification, and stops with an explanation if so.
2. It runs lego with the HTTP-01 challenge. Let's Encrypt fetches `/.well-known/acme-challenge/<token>` over TCP 80, which the edge Caddy serves from the ACME webroot.
3. It stores the certificate metadata (issuer, fingerprint, expiry) and queues `edge.apply`.

The outcome depends on configuration:

| Configuration                                        | Certificate status                                                              | Endpoint status         | Served by the edge |
| ---------------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------- | ------------------ |
| `ARK_ACME_EMAIL` set, `ARK_ACME_STAGING=0`           | `issued`                                                                        | `testing`               | yes                |
| `ARK_ACME_EMAIL` set, `ARK_ACME_STAGING=1` (default) | `untrusted`                                                                     | `certificate_untrusted` | no                 |
| `ARK_CERTIFICATE_MODE=development`, no lego          | `untrusted` (self-signed, 30 days)                                              | `certificate_untrusted` | no                 |
| None of the above                                    | none: the operation fails with "Public certificate issuance is not configured." | `verified`              | no                 |

The database endpoint's certificate is served by PgBouncer, not Caddy, so it is first `awaiting_reload`: a `pgbouncer.reload` operation reloads PgBouncer and confirms the new fingerprint on the listener before the certificate counts as issued and the endpoint moves on.

Switching from staging to production does not convert existing certificates; reissue them. See [Certificates](../features/certificates.md) and [Public certificates](../operating.md#public-certificates).

## Endpoint states

You will see these states in the **Endpoints** list on **Domains & Endpoints**:

| Status                  | What it means                                   | What to do                                                                        |
| ----------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------- |
| `awaiting_dns`          | Records not verified, or a blocker is present.  | Create or publish the records, fix blockers, **Recheck DNS**.                     |
| `verified`              | DNS is correct; a certificate order is queued.  | Wait, or check the `certificate.issue` operation under **Activity**.              |
| `certificate_untrusted` | Staging or development certificate.             | Set `ARK_ACME_EMAIL` and `ARK_ACME_STAGING=0`, recreate `domain-worker`, reissue. |
| `testing`               | Trusted certificate issued; the edge serves it. | Check the service at its hostname.                                                |

[Core concepts](../introduction/concepts.md#endpoint-route-and-certificate-states) explains every state. **Activity** shows each operation with its steps and evidence; a failed operation shows its error there.

Once the admin endpoint's certificate is issued in public mode, the edge serves `https://admin.<domain>`. Sign in there once `BETTER_AUTH_URL` names that origin; until then keep using the tunnel. Incoming mail can become ready while outbound mail stays paused for SES.

## What to do next

- **Check the overview.** The **Overview** page shows alerts and counts; **Activity** shows every operation.
- **Mail.** Add mailboxes and aliases, and configure SES for outbound delivery: [Mail](../features/mail.md).
- **Databases.** Reveal the first database's generated credentials once, create more databases, use the SQL workspace: [Application databases](../features/databases.md), [SQL workspace](../features/sql-workspace.md).
- **Public database access.** Open the pooler and issue client certificates, for example for Vercel: [Public database access](../features/public-database-access.md).
- **IPv6.** Watch the preflight result and enable AAAA publishing: [Native IPv6 and AAAA publication](../operating.md#native-ipv6-and-aaaa-publication).
- **Front door.** Enrol the edge node if you have not, then publish tailnet services: [Guide: public routes](../guides/front-door.md).
- **Backups.** Configure the off-VPS targets and set `ARK_BACKUP_EXECUTE=1`: [Backup system](../features/backups.md).
- **Monitoring.** Review alerts and set up the off-host heartbeat: [Monitoring and alerts](../features/monitoring.md).
