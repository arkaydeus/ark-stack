CREATE TABLE IF NOT EXISTS "user" (
  id text PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  email_verified boolean NOT NULL DEFAULT false,
  image text,
  two_factor_enabled boolean NOT NULL DEFAULT false,
  mfa_enrolled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS session (
  id text PRIMARY KEY,
  expires_at timestamptz NOT NULL,
  token text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  ip_address text,
  user_agent text,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS session_user_id_idx ON session(user_id);

CREATE TABLE IF NOT EXISTS account (
  id text PRIMARY KEY,
  issuer text NOT NULL,
  account_id text NOT NULL,
  provider_id text NOT NULL,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  access_token text,
  refresh_token text,
  id_token text,
  access_token_expires_at timestamptz,
  refresh_token_expires_at timestamptz,
  scope text,
  password text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS account_issuer_account_id_idx ON account(issuer, account_id);
CREATE INDEX IF NOT EXISTS account_user_id_idx ON account(user_id);

CREATE TABLE IF NOT EXISTS verification (
  id text PRIMARY KEY,
  identifier text NOT NULL,
  value text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS verification_identifier_idx ON verification(identifier);

CREATE TABLE IF NOT EXISTS two_factor (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  secret text NOT NULL,
  backup_codes text NOT NULL,
  verified boolean DEFAULT true,
  failed_verification_count integer DEFAULT 0,
  locked_until timestamptz
);

CREATE TABLE IF NOT EXISTS platform_setup (
  id text PRIMARY KEY DEFAULT 'default',
  completed boolean NOT NULL DEFAULT false,
  wizard_completed boolean NOT NULL DEFAULT false,
  bootstrap_closed_at timestamptz
);

CREATE TABLE IF NOT EXISTS platform_access (
  user_id text PRIMARY KEY REFERENCES "user"(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'viewer',
  project_ids jsonb NOT NULL DEFAULT '[]',
  domain_ids jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS platform_settings (
  id text PRIMARY KEY DEFAULT 'default',
  admin_mode text NOT NULL DEFAULT 'public',
  timezone text NOT NULL DEFAULT 'Europe/London',
  base_domain text,
  admin_hostname text,
  auth_origin text,
  public_ipv4 text,
  dns_provider text NOT NULL DEFAULT 'manual',
  default_quota_gb integer NOT NULL DEFAULT 10,
  allow_external_forwarding boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
  id text PRIMARY KEY,
  name text NOT NULL,
  slug text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS domain_claims (
  id text PRIMARY KEY,
  name text NOT NULL UNIQUE,
  ownership_token text NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  dns_provider text NOT NULL DEFAULT 'manual',
  mail_from text,
  dmarc_policy text NOT NULL DEFAULT 'none',
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dns_records (
  id text PRIMARY KEY,
  domain_id text NOT NULL REFERENCES domain_claims(id) ON DELETE CASCADE,
  type text NOT NULL,
  name text NOT NULL,
  relative_name text NOT NULL,
  expected_value text NOT NULL,
  observed_value text,
  purpose text NOT NULL,
  required boolean NOT NULL DEFAULT true,
  status text NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS dns_records_domain_idx ON dns_records(domain_id);

CREATE TABLE IF NOT EXISTS endpoints (
  id text PRIMARY KEY,
  kind text NOT NULL,
  hostname text NOT NULL UNIQUE,
  domain_id text REFERENCES domain_claims(id) ON DELETE RESTRICT,
  exposure text NOT NULL DEFAULT 'public',
  status text NOT NULL DEFAULT 'draft',
  last_verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS certificates (
  id text PRIMARY KEY,
  endpoint_id text NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  names jsonb NOT NULL,
  issuer text NOT NULL DEFAULT 'pending',
  fingerprint text,
  expires_at timestamptz,
  status text NOT NULL DEFAULT 'pending',
  last_deployed_at timestamptz
);

CREATE TABLE IF NOT EXISTS database_clusters (
  id text PRIMARY KEY,
  name text NOT NULL,
  major text NOT NULL DEFAULT '17',
  endpoint_id text REFERENCES endpoints(id),
  status text NOT NULL DEFAULT 'provisioning',
  observed_at timestamptz
);

CREATE TABLE IF NOT EXISTS managed_databases (
  id text PRIMARY KEY,
  cluster_id text NOT NULL REFERENCES database_clusters(id) ON DELETE RESTRICT,
  project_id text REFERENCES projects(id),
  name text NOT NULL,
  exposure text NOT NULL DEFAULT 'public',
  with_pgvector boolean NOT NULL DEFAULT false,
  with_test_database boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'queued'
);
CREATE UNIQUE INDEX IF NOT EXISTS managed_databases_cluster_name_idx ON managed_databases(cluster_id, name);

CREATE TABLE IF NOT EXISTS database_roles (
  id text PRIMARY KEY,
  database_id text NOT NULL REFERENCES managed_databases(id) ON DELETE CASCADE,
  name text NOT NULL,
  kind text NOT NULL,
  secret_id text,
  connection_limit integer NOT NULL DEFAULT 20
);

CREATE TABLE IF NOT EXISTS mail_domains (
  id text PRIMARY KEY,
  domain_id text NOT NULL REFERENCES domain_claims(id) ON DELETE RESTRICT,
  inbound_status text NOT NULL DEFAULT 'pending',
  outbound_status text NOT NULL DEFAULT 'paused',
  client_status text NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS mailboxes (
  id text PRIMARY KEY,
  domain_id text NOT NULL REFERENCES domain_claims(id) ON DELETE RESTRICT,
  local_part text NOT NULL,
  display_name text NOT NULL,
  quota_gb integer NOT NULL DEFAULT 10,
  lifecycle text NOT NULL DEFAULT 'active',
  credential_available boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS mailboxes_domain_local_idx ON mailboxes(domain_id, local_part);

CREATE TABLE IF NOT EXISTS aliases (
  id text PRIMARY KEY,
  domain_id text NOT NULL REFERENCES domain_claims(id) ON DELETE RESTRICT,
  local_part text NOT NULL,
  description text,
  targets jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS aliases_domain_local_idx ON aliases(domain_id, local_part);

CREATE TABLE IF NOT EXISTS services (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name text NOT NULL,
  compose text NOT NULL,
  image_digest text,
  desired_revision text NOT NULL,
  observed_revision text,
  status text NOT NULL DEFAULT 'registered',
  update_policy text NOT NULL DEFAULT 'notify',
  protected boolean NOT NULL DEFAULT false,
  observed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS secrets (
  id text PRIMARY KEY,
  kind text NOT NULL,
  key_id text NOT NULL,
  ciphertext text NOT NULL,
  iv text NOT NULL,
  auth_tag text NOT NULL,
  once boolean NOT NULL DEFAULT false,
  revealed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS operations (
  id text PRIMARY KEY,
  kind text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  actor_id text,
  idempotency_key text NOT NULL,
  plan_hash text NOT NULL,
  target_ids jsonb NOT NULL DEFAULT '[]',
  payload jsonb NOT NULL DEFAULT '{}',
  claim_token text,
  heartbeat_at timestamptz,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS operations_idempotency_idx ON operations(idempotency_key);
CREATE INDEX IF NOT EXISTS operations_status_idx ON operations(status, created_at);

CREATE TABLE IF NOT EXISTS operation_steps (
  id text PRIMARY KEY,
  operation_id text NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
  name text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  evidence jsonb NOT NULL DEFAULT '{}',
  error text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS operation_steps_op_idx ON operation_steps(operation_id);

CREATE TABLE IF NOT EXISTS backups (
  id text PRIMARY KEY,
  kind text NOT NULL,
  target_id text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  checksum text,
  restore_verified boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alerts (
  id text PRIMARY KEY,
  severity text NOT NULL,
  title text NOT NULL,
  acknowledged boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
  id text PRIMARY KEY,
  actor_id text,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text,
  role text,
  operation_id text,
  detail jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO platform_setup (id, completed, wizard_completed)
VALUES ('default', false, false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO platform_settings (id)
VALUES ('default')
ON CONFLICT (id) DO NOTHING;
