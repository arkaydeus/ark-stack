ALTER TABLE secrets ADD COLUMN IF NOT EXISTS resource_type text;
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS resource_id text;
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS purpose text;
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS sensitivity text NOT NULL DEFAULT 'credential';

CREATE TABLE IF NOT EXISTS step_up_grants (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  session_id text NOT NULL,
  action text NOT NULL,
  plan_hash text,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS step_up_grants_lookup_idx
  ON step_up_grants(user_id, session_id, action);

-- Runtime API accounts must not be able to rewrite or remove audit history.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ark_runtime') THEN
    GRANT USAGE ON SCHEMA public TO ark_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ark_runtime;
    GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO ark_runtime;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ark_runtime;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ark_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM ark_runtime;
    GRANT SELECT, INSERT ON audit_events TO ark_runtime;
  END IF;
END $$;
