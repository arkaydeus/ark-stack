-- Successful PgBouncer trust application is distinct from issuance and delivery.
-- Existing successors are reconciled by the next daily rollover/retry before delivery.
ALTER TABLE client_certificates ADD COLUMN trust_applied_at timestamptz;
