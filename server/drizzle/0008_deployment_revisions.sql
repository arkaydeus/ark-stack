ALTER TABLE services ADD COLUMN IF NOT EXISTS stateful boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS deployment_revisions (
  id text PRIMARY KEY,
  service_id text NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  desired_revision text NOT NULL,
  compose text NOT NULL,
  image_digest text,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS deployment_revisions_service_idx
  ON deployment_revisions(service_id, created_at);
