-- Keep uncertain owned writes recoverable and manual verification windows durable.
ALTER TABLE dns_records ADD COLUMN provider_update_intent jsonb;
ALTER TABLE domain_claims
  ADD COLUMN dns_watch_until timestamptz,
  ADD COLUMN proxy_aaaa_hosts jsonb NOT NULL DEFAULT '[]'::jsonb;
