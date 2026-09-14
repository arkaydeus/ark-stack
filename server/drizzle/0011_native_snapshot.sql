ALTER TABLE backups ADD COLUMN IF NOT EXISTS native_snapshot_id text;
UPDATE backups
SET native_snapshot_id = checksum
WHERE native_snapshot_id IS NULL
  AND checksum IS NOT NULL
  AND checksum NOT LIKE 'bak_%';
