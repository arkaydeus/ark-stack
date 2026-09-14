ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_at timestamptz;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS silenced_until timestamptz;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_notified_at timestamptz;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notification_attempts integer NOT NULL DEFAULT 0;
