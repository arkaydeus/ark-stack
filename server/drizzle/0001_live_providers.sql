ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS native_id text;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dedup_key text;
UPDATE alerts SET dedup_key = id WHERE dedup_key IS NULL;
ALTER TABLE alerts ALTER COLUMN dedup_key SET NOT NULL;

CREATE TABLE IF NOT EXISTS update_candidates (
  id text PRIMARY KEY,
  service_id text NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  image text NOT NULL,
  current_digest text,
  candidate_digest text,
  requires_approval boolean NOT NULL DEFAULT true,
  rollback_safe boolean NOT NULL DEFAULT false,
  detected_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS update_candidates_service_idx ON update_candidates(service_id);
