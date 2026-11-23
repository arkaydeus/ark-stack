-- The watchdog's lease reads the latest applied revocation alongside the pending rows.
CREATE INDEX gate_revocations_applied_idx ON gate_revocations (applied_at DESC, id DESC)
WHERE applied_at IS NOT NULL;
