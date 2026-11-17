-- Bind canary evidence to configuration and recovery history to repository identity.
ALTER TABLE backup_targets ADD COLUMN config_revision text NOT NULL DEFAULT 'legacy';
ALTER TABLE backup_targets ADD COLUMN repository_revision text NOT NULL DEFAULT 'legacy';
ALTER TABLE backup_exports ADD COLUMN repository_revision text NOT NULL DEFAULT 'legacy';
-- Old verdicts predate the fail-closed policy coverage checks.
UPDATE backup_targets SET append_only_status = 'unverified', append_only_verified = false,
  append_only_checked_at = NULL, append_only_evidence = NULL, retention_until = NULL;
