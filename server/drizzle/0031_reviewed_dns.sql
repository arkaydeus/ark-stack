-- FD-19: keep provider ownership and withdrawal evidence after a record leaves the desired set.
ALTER TABLE dns_records
  ADD COLUMN ttl integer NOT NULL DEFAULT 300 CHECK (ttl > 0),
  ADD COLUMN provider_ownership jsonb,
  ADD COLUMN automatic_withdrawal boolean NOT NULL DEFAULT false,
  ADD COLUMN published_at timestamptz,
  ADD COLUMN withdrawal_reason text CHECK (withdrawal_reason IN ('ipv6', 'endpoint_deleted')),
  ADD COLUMN withdrawal_started_at timestamptz,
  ADD COLUMN provider_removed_at timestamptz,
  ADD COLUMN withdrawal_confirmed_at timestamptz;

UPDATE dns_records SET ttl = 60 WHERE type = 'TXT' AND purpose = 'Installation-bound domain ownership proof';
