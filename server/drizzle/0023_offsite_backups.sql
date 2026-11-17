-- FD-21: S3-compatible off-VPS backups, append-only (docs/design/front-door.md §3.18).
-- 0022 is left to FD-09, which was being built in parallel; the runner applies files in sorted order.

-- backup_targets (0013) gains the provider recipe, the recovery window the canary must cover, the
-- sealed restic repository password, an optional read-only verifier, and canary/attempt state.
ALTER TABLE backup_targets
  ADD COLUMN provider text NOT NULL DEFAULT 'other',
  ADD COLUMN enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN recovery_window_days integer NOT NULL DEFAULT 30,
  ADD COLUMN repository_secret_id text REFERENCES secrets(id),
  ADD COLUMN verifier_secret_id text REFERENCES secrets(id),
  ADD COLUMN append_only_status text NOT NULL DEFAULT 'unverified',
  ADD COLUMN append_only_checked_at timestamptz,
  ADD COLUMN retention_until timestamptz,
  ADD COLUMN last_attempt_at timestamptz,
  ADD COLUMN last_error text,
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(),
  ADD CONSTRAINT backup_targets_provider_check CHECK (provider IN ('aws', 'b2', 'r2', 'minio', 'other')),
  ADD CONSTRAINT backup_targets_recovery_window_check CHECK (recovery_window_days BETWEEN 1 AND 3650),
  ADD CONSTRAINT backup_targets_append_only_status_check
    CHECK (append_only_status IN ('unverified', 'append_only', 'deletable', 'unknown', 'retention_short')),
  ADD CONSTRAINT backup_targets_s3_shape_check CHECK (
    kind <> 's3' OR (endpoint IS NOT NULL AND region IS NOT NULL AND bucket IS NOT NULL)
  );

-- Several targets of a kind may exist (for example two S3 providers); each is exported independently.
-- "Backups healthy" needs every enabled target healthy and at least one per required kind.
CREATE UNIQUE INDEX backup_targets_name_unique ON backup_targets (name);

-- One row per export attempt of one source to one destination: the per-destination manifest of
-- stanza, stage, backup labels, WAL coverage and last recoverable time (§3.18.1). A failed attempt
-- never carries a recovery point.
CREATE TABLE backup_exports (
  id text PRIMARY KEY,
  target_id text NOT NULL REFERENCES backup_targets(id) ON DELETE CASCADE,
  source text NOT NULL,
  status text NOT NULL,
  stage_id text,
  restic_snapshot_id text,
  backup_labels jsonb NOT NULL DEFAULT '[]'::jsonb,
  wal_segment text,
  last_recoverable_at timestamptz,
  repo_bytes bigint,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT backup_exports_status_check CHECK (status IN ('succeeded', 'failed')),
  CONSTRAINT backup_exports_recovery_point_check
    CHECK (status = 'succeeded' OR (last_recoverable_at IS NULL AND restic_snapshot_id IS NULL))
);
CREATE INDEX backup_exports_target_source_idx ON backup_exports (target_id, source, created_at DESC);

-- Latest observation of each local source (pgBackRest stanza): archiving, capacity and the newest
-- stage, reported by the PostgreSQL executors.
CREATE TABLE backup_sources (
  source text PRIMARY KEY,
  configured boolean NOT NULL DEFAULT false,
  archive_failing boolean NOT NULL DEFAULT false,
  repo_bytes bigint,
  free_bytes bigint,
  total_bytes bigint,
  last_stage_id text,
  local_recoverable_at timestamptz,
  last_full_at timestamptz,
  last_backup_at timestamptz,
  detail jsonb,
  observed_at timestamptz NOT NULL DEFAULT now()
);
