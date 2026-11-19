# Ports and networks

This is the complete reference of every port Ark listens on (public, loopback, tailnet and internal), every Docker network in the Compose files and which services join it, the Tailscale node identities, the nftables tables, and the provider firewall inventory. The task-level summary is in the front door guide's [What listens where](../guides/front-door.md#1-what-listens-where).

## Public listeners

These are reachable from the internet once the provider firewall allows them. All front-door ports are published by the `edge-ts` container; HAProxy (`edge-l4`) and Caddy (`edge`) run inside its network namespace.

| Port                      | Listener                                | Published by | Present when                                                                                     | What it does                                                                                                                                      |
| ------------------------- | --------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP 80                    | Caddy `:80`                             | `edge-ts`    | Always                                                                                           | ACME HTTP-01 challenges, `308` to HTTPS for served hostnames, `404` otherwise.                                                                    |
| TCP 443                   | HAProxy `fe_tls443`                     | `edge-ts`    | Always                                                                                           | Routes by TLS SNI: HTTP routes, the login and admin hosts to Caddy on `127.0.0.1:8443`, TLS-TCP routes to their backends. Unknown SNI is refused. |
| TCP 5432                  | HAProxy `fe_pg5432`                     | `edge-ts`    | Always (rejects until a pooler endpoint or Postgres route is active)                             | Classic `SSLRequest` clients and the database hostname go to PgBouncer; direct-TLS Postgres route SNIs go to their routes.                        |
| TCP 8883, 5671, 636, 6380 | HAProxy `fe_tls<port>`                  | `edge-ts`    | Only ports listed in `ARK_EDGE_SNI_PORTS`                                                        | Shared SNI ports for TLS-TCP routes. A port that is not enabled is published only on an ephemeral loopback port, where HAProxy never listens.     |
| TCP 20000–20049           | HAProxy, one frontend per enabled route | `edge-ts`    | Range always published; a listener only per enabled raw-TCP route or Postgres compatibility port | Raw TCP routes. A port without a route has no listener and is dropped by nftables.                                                                |
| TCP 25                    | Stalwart SMTP                           | `stalwart`   | `ARK_MAIL_ENABLED` is on                                                                         | Incoming mail.                                                                                                                                    |
| TCP 465                   | Stalwart submission, implicit TLS       | `stalwart`   | Mail enabled                                                                                     | Client submission.                                                                                                                                |
| TCP 587                   | Stalwart submission, STARTTLS           | `stalwart`   | Mail enabled                                                                                     | Client submission; created by `mise run mail:up` if absent.                                                                                       |
| TCP 993                   | Stalwart IMAPS                          | `stalwart`   | Mail enabled                                                                                     | Mail client access.                                                                                                                               |
| UDP 41641                 | Host `tailscaled`                       | The host     | VPS enrolled in the tailnet                                                                      | Direct WireGuard paths for the host node.                                                                                                         |
| UDP 41642                 | `tailscaled` in `edge-ts`               | `edge-ts`    | Always                                                                                           | Direct WireGuard paths for the edge node. Without it, edge tailnet traffic is relayed through DERP.                                               |

Notes:

- **No HTTP/3.** UDP 443 is not published, and Caddy serves only HTTP/1.1 and HTTP/2.
- **A slow handshake is closed.** A connection to HAProxy that sends no TLS ClientHello or Postgres preamble within 5 seconds is closed.
- **Ports a route can never use.** `RESERVED_ROUTE_PORTS` in `shared/src/edge-l4.ts` lists 25, 80, 443, 465, 587, 993, 2019, 3000, 5432, 41641 and 41642. `GET /api/front/listeners` returns the enabled SNI ports, the raw range and the reserved ports for this host.
- **Mail ports bypass the front door.** Stalwart publishes them directly; the front door never claims them.
- **No public SSH.** After hardening, public TCP 22 is removed at the provider and SSH goes through Tailscale SSH (see [Tailnet listeners](#tailnet-listeners)).

To change the set of shared SNI ports, set `ARK_EDGE_SNI_PORTS` and re-run the installer, which writes `ARK_EDGE_SNI_PORT_8883` and its siblings for the `edge-ts` port list and recreates the edge namespace (then run `mise run edge:rejoin`). See [TLS-TCP and raw-TCP routes](../operating.md#tls-tcp-and-raw-tcp-routes).

## Loopback listeners on the host

| Address           | Service                              | Compose file                            | Purpose                                                                                         |
| ----------------- | ------------------------------------ | --------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `127.0.0.1:3000`  | `api`                                | `infra/platform/docker-compose.yml`     | Bootstrap and host-local recovery only. Reach it through an SSH tunnel; never bind it publicly. |
| `127.0.0.1:9090`  | `prometheus`                         | `infra/monitoring/docker-compose.yml`   | The Prometheus UI and API.                                                                      |
| Ephemeral         | `edge-ts` (disabled SNI ports)       | `infra/platform/docker-compose.yml`     | Placeholder publication for an SNI port that is not enabled. Nothing listens behind it.         |
| `127.0.0.1:5433`  | `postgres` (platform cluster)        | `infra/platform/docker-compose.dev.yml` | Local development only, added by `mise run db:up`.                                              |
| `127.0.0.1:5434`  | `app-postgres` (application cluster) | `infra/platform/docker-compose.dev.yml` | Local development only.                                                                         |
| `127.0.0.1:55432` | `restore-postgres`                   | `infra/restore/docker-compose.yml`      | The isolated restore target. No public port, no Tailscale identity, no outbound mail.           |

The production manifest has no host binding for either PostgreSQL engine. Public database access is only through HAProxy on 5432 and PgBouncer.

## Tailnet listeners

| Node                                                                    | Listener                                              | Who may connect                                                                                                                            |
| ----------------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Host `tailscaled` (`tag:ark-vps`)                                       | Tailscale SSH on TCP 22                               | The owner's own device, through the owner-only grant and an SSH rule in `check` mode.                                                      |
| Admin node `ark-stack-admin` (`tag:ark-stack-admin`, profile `tailnet`) | Tailscale Serve, HTTPS on TCP 443 of its tailnet name | Tailnet users whose policy grants them TCP 443 on the node. Serve proxies to `tailnet-gateway` on `127.0.0.1:8080`. Funnel stays disabled. |
| Edge node `ark-edge` (`tag:ark-edge`)                                   | None                                                  | Nobody: it runs with `--shields-up`, whatever the tailnet policy allows.                                                                   |
| Backup node `ark-backup` (`tag:ark-backup`)                             | None                                                  | Nobody: `--shields-up`.                                                                                                                    |

The `ark_host` firewall accepts all incoming traffic on the host's `tailscale0` interface; access on the tailnet is governed by the tailnet policy.

Outbound reach on the tailnet is granted per identity by the generated ACL snippet: `tag:ark-edge` gets one grant per route target `host:port`, and `tag:ark-backup` gets TCP 8000 on the home `rest-server`. Ark never writes the tailnet policy. See [The tailnet ACL snippet](../guides/front-door.md#7-the-tailnet-acl-snippet) and [Tailnet policy snippet](../operating.md#tailnet-policy-snippet).

## Tailscale node identities

The VPS carries four separate Tailscale identities, each with its own state, key and tag. Ark holds no Tailscale API key or OAuth client.

| Identity    | Runs in                              | Hostname          | Tag                   | Mode                                      | WireGuard UDP         | Enrolment key                            | State                 |
| ----------- | ------------------------------------ | ----------------- | --------------------- | ----------------------------------------- | --------------------- | ---------------------------------------- | --------------------- |
| Host node   | The VPS (Ubuntu `tailscale` package) | the VPS name      | `tag:ark-vps`         | Host system service                       | 41641 (published)     | `TS_VPS_AUTHKEY_FILE` for `--enroll-vps` | The host's tailscaled |
| Edge node   | `edge-ts`                            | `ark-edge`        | `tag:ark-edge`        | Kernel, `--shields-up`                    | 41642 (published)     | `TS_EDGE_AUTHKEY`                        | `ark_edge_ts_state`   |
| Admin node  | `tailscale` (profile `tailnet`)      | `ark-stack-admin` | `tag:ark-stack-admin` | Userspace                                 | not published         | `TS_AUTHKEY`                             | `ark_tailscale_state` |
| Backup node | `backup-ts`                          | `ark-backup`      | `tag:ark-backup`      | Userspace, `--shields-up`, SOCKS5 on 1055 | 41643 (not published) | `TS_BACKUP_AUTHKEY`                      | `ark_backup_ts_state` |

- The host, edge and backup keys are one-off, pre-approved and non-ephemeral, tagged with the node's tag. Remove each from `.env` (or delete the key file) and revoke it after the first join.
- `edge-ts` and `backup-ts` set `TS_ACCEPT_DNS=false`, so Docker's resolver keeps resolving service names.
- Each tailscaled LocalAPI socket is shared read-only with exactly one worker: `ark_edge_ts_socket` with `domain-worker` (for `edge.observe`) and `ark_backup_ts_socket` with `backup-worker`. The worker runs as a non-root user, which tailscaled limits to read access.
- Never reuse a failed node identity. Re-enrolment is described in [Edge Tailscale node](../operating.md#edge-tailscale-node) and the [backups guide](../guides/backups.md#setting-up-the-home-machine).

## Internal listeners

These listen only on Docker networks, a container's own loopback or a Unix socket.

| Listener                          | Address                                           | Network or scope                           | Clients                                                                                                         |
| --------------------------------- | ------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| API                               | `api:3000`                                        | `control`, `admin`, `monitoring`           | Workers and agent (`ARK_API_URL`), Caddy (`forward_auth`, admin and login sites), `tailnet-gateway`, Prometheus |
| Platform PostgreSQL               | `postgres:5432`                                   | `control`                                  | `api`, `migrate`, the workers                                                                                   |
| Application PostgreSQL            | `app-postgres:5432`                               | `database-management`                      | `database-worker`, `pgbouncer-public`                                                                           |
| pgBackRest executors              | `ark-platform-backup:8432`, `ark-app-backup:8432` | `backup-management`                        | `backup-worker` only                                                                                            |
| PgBouncer                         | `pgbouncer-public:5432`                           | `database-management`, `pgbouncer-ingress` | HAProxy `fe_pg5432` (through `pgbouncer-ingress`)                                                               |
| Database worker control           | `database-worker:3101`                            | `control`, `database-management`           | `api` (`ARK_DATABASE_WORKER_URL`, SQL cancellation)                                                             |
| Domain worker control             | `domain-worker:3102`                              | `control`, `admin`, `edge-control`         | `api` (`ARK_DOMAIN_WORKER_URL`, Cloudflare DNS reviews)                                                         |
| Edge watchdog                     | `edge-watchdog:2021`                              | `control`, `edge-control`                  | The Caddy and HAProxy launch guards in the `edge-ts` namespace                                                  |
| Caddy admin API                   | `edge-admin:2019`                                 | `edge-control` (alias of `edge-ts`)        | `domain-worker`, `edge-watchdog`. Nothing on `admin`, including the API, can reach it.                          |
| Caddy HTTPS sites                 | `127.0.0.1:8443`                                  | Loopback of the `edge-ts` namespace        | HAProxy only, with PROXY v2 required                                                                            |
| HAProxy TLS termination frontends | Abstract sockets (`abns@…`)                       | The `edge-ts` namespace                    | HAProxy itself, for `terminate` and `terminate_mtls` routes and Postgres routes                                 |
| Stalwart management               | `stalwart:8080`                                   | `ark_mail_management`; not published       | `mail-worker` (`STALWART_URL`)                                                                                  |
| Backup SOCKS5 proxy               | `backup-ts:1055`                                  | `backup-tailnet`                           | The home target's restic subprocess in `backup-worker` only                                                     |
| Tailnet gateway                   | `127.0.0.1:8080`, `[::1]:8080`                    | Loopback of the `tailscale` namespace      | Tailscale Serve only                                                                                            |

Unix sockets:

| Socket                                                        | Volume                                              | Shared between                                        |
| ------------------------------------------------------------- | --------------------------------------------------- | ----------------------------------------------------- |
| `/var/run/haproxy/master.sock`, `/var/run/haproxy/admin.sock` | `ark_haproxy_run` (tmpfs, group 4400, mode 2770)    | `edge-l4`, `domain-worker`, `edge-watchdog`           |
| `/var/run/haproxy-validator/validate.sock`                    | `ark_haproxy_validator_run`                         | `haproxy-validator`, `domain-worker`                  |
| PgBouncer admin console in `/var/run/pgbouncer`               | `ark_pgbouncer_socket` (tmpfs, uid 1000, mode 0700) | `pgbouncer-public`, `database-worker`                 |
| tailscaled LocalAPI                                           | `ark_edge_ts_socket`                                | `edge-ts` (read-write), `domain-worker` (read-only)   |
| tailscaled LocalAPI                                           | `ark_backup_ts_socket`                              | `backup-ts` (read-write), `backup-worker` (read-only) |
| `/var/run/docker.sock`                                        | Host bind mount                                     | `agent` only                                          |

The Docker agent opens no listener; it calls the API.

## Docker networks

Compose prefixes network names with the project: for example, `control` in the `ark-platform` project is `ark-platform_control` in Docker. The two external networks keep their own names; the installer creates them with `docker network create` when they are missing.

| Network               | Project                | Internal | IPv6 | Members                                                                                                                    | Purpose                                                                                |
| --------------------- | ---------------------- | -------- | ---- | -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `control`             | `ark-platform`         | Yes      | No   | `postgres`, `api`, `migrate`, `database-worker`, `domain-worker`, `mail-worker`, `backup-worker`, `agent`, `edge-watchdog` | The control plane: API, platform database and workers.                                 |
| `admin`               | `ark-platform`         | No       | Yes  | `api`, `domain-worker`, `edge-ts` (with `edge` and `edge-l4`), `tailscale` (with `tailnet-gateway`)                        | Proxies to the API, and outbound access for the domain worker (ACME, Cloudflare, DNS). |
| `edge-control`        | `ark-platform`         | Yes      | No   | `domain-worker`, `edge-ts` (alias `edge-admin`), `edge-watchdog`                                                           | Caddy's admin API and the watchdog, away from everything on `admin`.                   |
| `database-management` | `ark-platform`         | Yes      | No   | `app-postgres`, `database-worker`, `pgbouncer-public`                                                                      | The application cluster and its pooler.                                                |
| `pgbouncer-ingress`   | `ark-platform`         | Yes      | No   | `pgbouncer-public`, `edge-ts`                                                                                              | HAProxy to PgBouncer only. The edge namespace can never reach `app-postgres`.          |
| `backup-management`   | `ark-platform`         | Yes      | No   | `postgres` (alias `ark-platform-backup`), `app-postgres` (alias `ark-app-backup`), `backup-worker`                         | The backup worker to the pgBackRest executors on 8432.                                 |
| `backup-egress`       | `ark-platform`         | No       | No   | `backup-worker`                                                                                                            | Outbound access to S3-compatible targets.                                              |
| `backup-tailnet`      | `ark-platform`         | Yes      | No   | `backup-ts` (alias `backup-ts`), `backup-worker`                                                                           | The backup worker to the backup node's SOCKS5 proxy.                                   |
| `backup-ts-egress`    | `ark-platform`         | No       | No   | `backup-ts`                                                                                                                | Tailscale coordination, DERP and peers for the backup node.                            |
| `ark_mail_management` | external               | No       | No   | `mail-worker`, `stalwart`                                                                                                  | Stalwart management, and outbound access for the mail worker (SES).                    |
| `ark_monitoring`      | external               | No       | No   | `api`, `prometheus` (declared as `ark_platform` in the monitoring Compose file)                                            | Prometheus scraping `api:3000/api/metrics/prometheus` with a bearer token.             |
| `mail-public`         | `ark-mail`             | No       | Yes  | `stalwart`                                                                                                                 | Stalwart's public port publications.                                                   |
| `default`             | `ark-restore-isolated` | No       | No   | `restore-postgres`                                                                                                         | The isolated restore target.                                                           |

Services that do not join a network of their own:

| Service             | Network mode        | Effect                                                        |
| ------------------- | ------------------- | ------------------------------------------------------------- |
| `edge`, `edge-l4`   | `service:edge-ts`   | Share the edge node's namespace, ports and networks.          |
| `tailnet-gateway`   | `service:tailscale` | Shares the admin node's namespace.                            |
| `haproxy-validator` | `none`              | No network at all; it serves only a Unix socket.              |
| `database-ingress`  | `host`              | The host-namespace nftables reconciler. It opens no listener. |

Because `edge` and `edge-l4` join one specific `edge-ts` container, recreating or restarting `edge-ts` leaves them in a dead namespace. Run `mise run edge:rejoin` afterwards (see [Edge Tailscale node](../operating.md#edge-tailscale-node)).

### Docker IPv6

On a hardened VPS the installer enables Docker IPv6 (`ipv6`, `ip6tables` and `live-restore` in `/etc/docker/daemon.json`), migrates the published `admin` and `mail-public` networks, checks that the edge and the enabled mail service have IPv6 addresses, and only then turns off the userland proxy so client source addresses survive. See [Native IPv6 and AAAA publication](../operating.md#native-ipv6-and-aaaa-publication).

## nftables tables

| Table                                               | Installed by                                                                                                                                                                                             | Hooks                                     | Covers                                                                                                                                                                                                                                                                                                                                |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `inet ark_host`                                     | `sudo mise run host:install --harden-vps`: `/etc/nftables.d/ark-host.nft`, loaded by `ark-host-firewall.service` before `docker.service`; kept in step by `database-ingress` when `ARK_HOST_HARDENING=1` | `input` and `forward`, priority -5        | Default-deny input. Accepts established traffic, loopback, `tailscale0`, ICMP and ICMPv6, DHCPv6 replies to the link-local client, and the `public_tcp` and `public_udp` sets. The forward chain drops DNAT'd traffic (Docker publications) whose original destination port is not in those sets.                                     |
| `inet ark_front`                                    | `database-ingress`, from the `policy.nft` the domain worker writes to `tmp/edge-l4/front-ingress`                                                                                                        | `input` and `forward` (DNAT), priority -1 | TCP 80, 443 and the enabled SNI ports: a shared per-source budget (`ARK_FRONT_MAX_CONNECTIONS`, default 256 concurrent; `ARK_FRONT_RATE_PER_SECOND`, default 50 new per second; `ARK_FRONT_RATE_BURST`, default 100). TCP 20000–20049: one policy per port (`closed`, `deny-all`, `allowlist` or `internet`) with the route's limits. |
| `inet ark_db_ingress`                               | `database-ingress`, from `tmp/pgbouncer/allowlist.nft`                                                                                                                                                   | `input` and `forward` (DNAT), priority -1 | TCP 5432 per-source limits: 128 concurrent connections and 30 new per second with a burst of 60 by default, changed with `PUT /api/settings/db-ingress`. Source admission itself is HAProxy's.                                                                                                                                        |
| `inet ark_front_guard`, `inet ark_db_ingress_guard` | `database-ingress`, only after a failed apply                                                                                                                                                            | `input` and `forward`, priority -2        | A temporary drop of the covered ports until a replacement policy passes readback.                                                                                                                                                                                                                                                     |
| `inet ark_front_raw`                                | Earlier releases                                                                                                                                                                                         | none                                      | Retired: deleted in the same transaction that installs `ark_front`.                                                                                                                                                                                                                                                                   |

- IPv6 sources are counted per /64 in `ark_front` and `ark_db_ingress`.
- The `ark_host` sets contain TCP 80, 443, the enabled SNI ports, 5432, every raw port whose policy is not `closed`, the mail ports when mail is enabled, and UDP 41641 and 41642.
- Mail ports have no per-source limits ([B1 gap](../security-review.md#b1-internet--vps-public-ports)).
- Named drop counters from `ark_front` and `ark_db_ingress` are exported on `/api/metrics/prometheus` as `ark_nft_drop_packets_total`.
- Use nftables only: remove conflicting UFW rules.

The design of these tables is in the [front door design](../design/front-door.md), and the hardening procedure in [VPS hardening](../operating.md#vps-hardening).

## Provider firewall inventory

Ark generates the inbound rules your VPS provider's firewall should allow, from the same configuration as `ark_host`:

```sh
sudo mise run host:audit --inventory > ark-host-inventory.json
sudo mise run host:audit
```

The inventory is a JSON object with the effective `config` (mail on or off, enabled SNI ports, raw route policies) and `providerRules`: one TCP and one UDP rule, each with its ports and the sources `0.0.0.0/0` and `::/0`.

| Protocol | Ports in the inventory                                                                                                                |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| TCP      | 80, 443, 5432, each enabled SNI port, each raw route port whose policy is not `closed`, and 25, 465, 587 and 993 when mail is enabled |
| UDP      | 41641, 41642                                                                                                                          |

Keep the provider's required ICMP and ICMPv6 allowances. Update the provider rules whenever mail, the shared SNI ports or raw routes change.

`sudo mise run host:audit` (without arguments) checks the installed `ark_host` table, `ss` listeners and Docker port mappings against the inventory. An unexpected public bind or publication fails the audit even when the firewall blocks it. The external check, run from another machine with Nmap, scans every TCP and UDP port:

```sh
sudo mise run host:audit --external ark-host-inventory.json <public-ipv4> <public-ipv6>
```

Details, including how `open|filtered` UDP results are treated, are in [Provider firewall and audit](../operating.md#provider-firewall-and-audit).

## Off-host endpoints

Ark also talks to listeners that run outside the VPS:

| Endpoint                                    | Used by                                   | Notes                                                                                          |
| ------------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `ARK_OFFHOST_HEARTBEAT_URL`                 | Off-host heartbeat sender, IPv6 preflight | An HTTPS receiver you operate. A managed IPv6 probe runner serves `POST /preflight` behind it. |
| Home `rest-server`, TCP 8000 on the tailnet | `backup-worker` through `backup-ts`       | Append-only restic REST target, granted only to `tag:ark-backup`.                              |
| Let's Encrypt, Cloudflare and SES APIs      | `domain-worker` and `mail-worker`         | Outbound HTTPS only.                                                                           |

## Related pages

- [Front door guide](../guides/front-door.md) and [operator runbooks](../operating.md).
- [Security review, trust boundaries B1–B10](../security-review.md#front-door-trust-boundaries-b1b10).
- [Domains and DNS](../features/domains-and-dns.md), [Mail](../features/mail.md).
- [Security model](../security/security-model.md).
