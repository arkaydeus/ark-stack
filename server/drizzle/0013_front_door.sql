-- Front door data model (docs/design/front-door.md §3.1, ticket FD-04).
-- The body below is the literal §3.1 SQL, except the platform_settings `region` and
-- `vps_region_label` columns, which ship with FD-03 (region setting) in their own migration.
-- server/src/front-door-migration.test.ts keeps this file in lockstep with the design.

-- Platform settings
ALTER TABLE platform_settings
  ADD COLUMN public_ipv6 text,
  ADD COLUMN pooler_source_cidrs jsonb NOT NULL DEFAULT '[]',
  ADD COLUMN pooler_allow_internet boolean NOT NULL DEFAULT false,
  ADD COLUMN ipv6_status text NOT NULL DEFAULT 'unchecked'
    CHECK (ipv6_status IN ('unchecked', 'passed', 'failed', 'not_present')),
  ADD COLUMN ipv6_checked_at timestamptz,
  ADD COLUMN ipv6_evidence jsonb,                 -- per-port results of the last preflight
  ADD COLUMN gate_login_mode text NOT NULL DEFAULT 'disabled'
    CHECK (gate_login_mode IN ('disabled', 'public')),
  ADD COLUMN gate_login_hostname text,
  ADD COLUMN sni_extra_ports jsonb NOT NULL DEFAULT '[]',   -- subset of [8883, 5671, 636, 6380], install-time
  ADD COLUMN tcp_port_range_start integer NOT NULL DEFAULT 20000,
  ADD COLUMN tcp_port_range_end integer NOT NULL DEFAULT 20049;

-- Per-domain AAAA switch (R9). Effective AAAA = aaaa_enabled AND ipv6_status = 'passed'.
ALTER TABLE domain_claims ADD COLUMN aaaa_enabled boolean NOT NULL DEFAULT true;

-- Complete snapshots are independent for edge and backup observation sources.
CREATE TABLE tailnet_snapshots (
  source text PRIMARY KEY CHECK (source IN ('edge', 'backup')),
  generation text NOT NULL,
  completed_at timestamptz NOT NULL,
  valid_until timestamptz NOT NULL  -- completed_at + 6 minutes
);
CREATE TABLE tailnet_nodes (
  source text NOT NULL REFERENCES tailnet_snapshots(source),
  generation text NOT NULL,
  stable_id text NOT NULL,                     -- tailcfg.StableNodeID
  dns_name text NOT NULL,                         -- MagicDNS FQDN, e.g. home.tail1234.ts.net
  host_name text NOT NULL,
  ipv4 text, ipv6 text,
  tags jsonb NOT NULL DEFAULT '[]',
  is_self boolean NOT NULL DEFAULT false,
  online boolean,
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (source, stable_id)
);

-- Private CAs must precede front_routes, which references them
CREATE TABLE private_cas (
  id text PRIMARY KEY,
  purpose text NOT NULL CHECK (purpose IN ('db-client', 'tcp-client', 'http-client')),
  name text NOT NULL,
  cert_pem text NOT NULL,
  key_secret_id text NOT NULL REFERENCES secrets(id),
  crl_pem text, crl_next_update timestamptz,   -- used where the consumer supports CRLs (HAProxy)
  not_after timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- One row per public route
CREATE TABLE front_routes (
  id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('http', 'tls', 'postgres', 'tcp')),
  -- http:     Host-routed by Caddy behind the 443 SNI router
  -- tls:      SNI-routed TLS-TCP on 443 or an enabled shared SNI port (listen_port)
  -- postgres: SNI-routed direct-TLS PostgreSQL on 5432 (+ optional compat_port)
  -- tcp:      raw TCP without TLS on a dedicated port from the range (listen_port)
  endpoint_id text NOT NULL REFERENCES endpoints(id) ON DELETE RESTRICT,   -- public hostname, domain, certificate
  listen_port integer NOT NULL,                                            -- 443, 5432, 8883..., or 20000-20049
  compat_port integer,                                                     -- postgres only, opt-in, from the range
  target_input text NOT NULL,                                              -- as entered: MagicDNS name or Tailscale IP
  target_node_stable_id text NOT NULL,                                     -- pinned identity
  target_ip text NOT NULL,                                                 -- pinned address; the only thing rendered
  target_port integer NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
  access_mode text NOT NULL DEFAULT 'sso' CHECK (access_mode IN ('public', 'sso')),  -- http only
  bypass_paths jsonb NOT NULL DEFAULT '[]',                                -- http only, path prefixes
  http_options jsonb NOT NULL DEFAULT '{}',   -- maxBodyMb, hsts, timeouts, upstreamHost, rewriteLocation, streaming
  tls_mode text CHECK (tls_mode IN ('passthrough', 'terminate', 'terminate_mtls', 'plain')),
    -- tls/postgres: passthrough | terminate | terminate_mtls; tcp: plain (forced)
  tcp_options jsonb NOT NULL DEFAULT '{}',    -- maxConn, perSourceConn, perSourceRate, idleTimeout
  source_cidrs jsonb NOT NULL DEFAULT '[]',  -- empty = deny all
  allow_internet boolean NOT NULL DEFAULT false, -- explicit exposure.public step-up; renders open CIDRs
  client_ca_id text REFERENCES private_cas(id),   -- tls/postgres terminate_mtls now; http mTLS later (reserved)
  rate_limit jsonb,                               -- reserved; not rendered in v1
  enabled boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'draft',
    -- draft | awaiting_acl | awaiting_dns | issuing_certificate | ready | identity_mismatch | observation_expired | disabled | error
  last_error text,
  created_by text REFERENCES "user"(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
-- A hostname has at most one route per listener: one route on 443 (HTTP or TLS-TCP, because both are
-- told apart only by SNI), one TLS-TCP route per shared SNI port, one Postgres route on 5432.
CREATE UNIQUE INDEX front_routes_endpoint_listener ON front_routes(endpoint_id, listen_port) WHERE kind <> 'tcp';
CREATE UNIQUE INDEX front_routes_dedicated_port ON front_routes(listen_port) WHERE kind = 'tcp';
CREATE UNIQUE INDEX front_routes_compat_port ON front_routes(compat_port) WHERE compat_port IS NOT NULL;

CREATE TABLE front_route_access (           -- individual users only (R11); no groups in v1
  route_id text NOT NULL REFERENCES front_routes(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  granted_by text REFERENCES "user"(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (route_id, user_id)
);

-- Login gate
CREATE TABLE gate_handoffs (
  id text PRIMARY KEY,
  code_hash text NOT NULL UNIQUE,              -- sha256 of a 32-byte random code
  route_id text NOT NULL REFERENCES front_routes(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  auth_session_id text NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  state_hash text NOT NULL,
  return_path text NOT NULL,
  expires_at timestamptz NOT NULL,             -- now() + 60s
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE gate_sessions (
  id text PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  route_id text NOT NULL REFERENCES front_routes(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  auth_session_id text NOT NULL REFERENCES session(id) ON DELETE CASCADE,   -- sign-out and mode change cascade
  ip_address text, user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX gate_sessions_user_idx ON gate_sessions(user_id);
ALTER TABLE session ADD COLUMN origin text CHECK (origin IN ('admin', 'gate'));
-- Existing sessions were created before the public gate existed. Backfill explicitly.
UPDATE session SET origin = 'admin';
ALTER TABLE session ALTER COLUMN origin SET NOT NULL;
-- No SQL default: every future insert must supply an origin.

-- Client certificates
CREATE TABLE client_certificates (
  id text PRIMARY KEY,
  ca_id text NOT NULL REFERENCES private_cas(id) ON DELETE CASCADE,
  subject_cn text NOT NULL,
  serial text NOT NULL,
  fingerprint_sha256 text NOT NULL,
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL,              -- not_before + 90 days (R6)
  key_secret_id text REFERENCES secrets(id),   -- `once` secret; null after reveal/push or with CSR issuance
  status text NOT NULL DEFAULT 'issued' CHECK (status IN ('issued', 'revoked', 'expired')),
  rollover_state text NOT NULL DEFAULT 'current'
    CHECK (rollover_state IN ('current', 'pending', 'delivered', 'superseded')),
    -- delivered is a transient transition inside the promotion transaction; delivered_at is durable history
    -- pending: not delivered; current: delivered active successor; superseded: predecessor
  superseded_by text REFERENCES client_certificates(id),
  delivered_at timestamptz,
  revoked_at timestamptz, revoked_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ca_id, serial)
);
CREATE UNIQUE INDEX client_certificates_successor_unique
  ON client_certificates(superseded_by) WHERE superseded_by IS NOT NULL;
CREATE TABLE database_clients (
  id text PRIMARY KEY,
  database_id text NOT NULL REFERENCES managed_databases(id) ON DELETE CASCADE,
  name text NOT NULL,                          -- "storefront"
  environment text NOT NULL,                   -- "production" | "preview" | free text
  role_kind text NOT NULL CHECK (role_kind IN ('runtime', 'readonly')),  -- preview defaults to readonly (R5)
  role_id text NOT NULL REFERENCES database_roles(id),
  ca_id text NOT NULL REFERENCES private_cas(id),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (database_id, name, environment)
);

-- Optional Vercel integration (R6), one per database client
CREATE TABLE vercel_integrations (
  id text PRIMARY KEY,
  database_client_id text NOT NULL UNIQUE REFERENCES database_clients(id) ON DELETE CASCADE,
  vercel_project_id text NOT NULL,
  vercel_team_id text,
  token_secret_id text NOT NULL REFERENCES secrets(id),       -- project-scoped Vercel access token, sealed
  token_expires_at timestamptz,
  deploy_hook_secret_id text REFERENCES secrets(id),          -- optional deploy hook URL, sealed
  env_target text NOT NULL CHECK (env_target IN ('production', 'preview')),
  git_branch text,                                            -- preview only
  last_push_at timestamptz, last_push_status text, last_deployment_id text,
  created_by text REFERENCES "user"(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Off-VPS backup destinations (R8): both kinds are required for "backups healthy"
CREATE TABLE backup_targets (
  id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('s3', 'tailnet_rest')),
  name text NOT NULL,
  endpoint text,                 -- s3: https://s3.us-east-005.backblazeb2.com, https://<acct>.r2.cloudflarestorage.com, ...
  region text,                   -- s3: us-east-1, auto, ...
  bucket text,
  prefix text NOT NULL DEFAULT 'ark',
  path_style boolean NOT NULL DEFAULT false,
  rest_url text,                 -- tailnet_rest: http://backup-home.tail1234.ts.net:8000/ark
  target_node_stable_id text,    -- tailnet_rest: pinned like routes (§3.2)
  credential_secret_id text NOT NULL REFERENCES secrets(id),
  append_only_verified boolean NOT NULL DEFAULT false,
  append_only_evidence jsonb,
  last_success_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
