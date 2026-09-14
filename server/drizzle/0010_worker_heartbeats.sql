CREATE TABLE IF NOT EXISTS worker_heartbeats (
  identity text PRIMARY KEY,
  version text NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
