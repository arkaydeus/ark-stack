-- Database client issuance and revocation (docs/design/front-door.md §3.10.3, ticket FD-17).
-- Numbered 0018 because 0017 is taken by 0017_db_ingress_limits.sql (FD-18, PR #37).
-- `revealed_at` is the one-time reveal gate: it is set once, atomically, and a second reveal
-- fails. No column holds certificate keys, passwords or PEM material; those stay sealed in
-- `secrets` (keys and passwords) or public in `client_certificates.cert_pem`.
ALTER TABLE database_clients
  ADD COLUMN key_source text NOT NULL DEFAULT 'generated'
    CONSTRAINT database_clients_key_source_check CHECK (key_source IN ('generated', 'csr')),
  ADD COLUMN created_by text REFERENCES "user"(id) ON DELETE SET NULL,
  ADD COLUMN revealed_at timestamptz,
  ADD COLUMN revoked_at timestamptz,
  ADD COLUMN revoked_by text REFERENCES "user"(id) ON DELETE SET NULL;

-- A login role belongs to at most one database client.
CREATE UNIQUE INDEX database_clients_role_id_key ON database_clients(role_id);
