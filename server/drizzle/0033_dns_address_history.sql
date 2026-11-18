ALTER TABLE dns_records DROP CONSTRAINT dns_records_withdrawal_reason_check;
ALTER TABLE dns_records ADD CONSTRAINT dns_records_withdrawal_reason_check
  CHECK (withdrawal_reason IN ('ipv6', 'endpoint_deleted', 'address_changed'));

-- Earlier verifiers could confirm cached absence without checking a pending Cloudflare write.
UPDATE dns_records
SET withdrawal_confirmed_at = NULL, status = 'withdrawal_pending'
WHERE withdrawal_reason IS NOT NULL
  AND provider_update_intent IS NOT NULL
  AND withdrawal_confirmed_at IS NOT NULL;
