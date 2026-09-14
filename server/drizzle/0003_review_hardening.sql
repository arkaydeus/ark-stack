ALTER TABLE managed_databases ADD COLUMN IF NOT EXISTS allowlist_enforced boolean NOT NULL DEFAULT false;

DELETE FROM alerts a USING alerts b
WHERE a.dedup_key = b.dedup_key AND a.ctid < b.ctid;

CREATE UNIQUE INDEX IF NOT EXISTS alerts_dedup_key_idx ON alerts(dedup_key);
