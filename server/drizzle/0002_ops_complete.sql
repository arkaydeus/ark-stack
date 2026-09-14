ALTER TABLE managed_databases ADD COLUMN IF NOT EXISTS source_cidrs jsonb NOT NULL DEFAULT '[]';
ALTER TABLE services ADD COLUMN IF NOT EXISTS container_id text;
ALTER TABLE services ADD COLUMN IF NOT EXISTS adopted_from text;

CREATE TABLE IF NOT EXISTS mailbox_devices (
  id text PRIMARY KEY,
  mailbox_id text NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  label text NOT NULL,
  secret_id text,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
