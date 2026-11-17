-- FD-11 review repairs. 0027 remains reserved for FD-14.
-- Coalesce old pending rows before enforcing one pending generation per route.
DELETE FROM gate_revocations a USING gate_revocations b
WHERE a.applied_at IS NULL AND b.applied_at IS NULL AND a.route_id = b.route_id
  AND (a.created_at, a.id) > (b.created_at, b.id);
CREATE UNIQUE INDEX gate_revocations_pending_route_idx ON gate_revocations (route_id)
WHERE applied_at IS NULL;

-- All journal writers and the worker's retry use this same transaction lock. Separate statements
-- after the lock see concurrent commits under READ COMMITTED. Failures back off 10s, 20s, ... 5m;
-- the independent 5s lease deadline still withdraws traffic during the outage.
CREATE FUNCTION ark_gate_ensure_drain() RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  op_id text;
  pending_since timestamptz;
  failures integer;
  last_failure timestamptz;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('ark:gate:drain'));
  SELECT min(created_at) INTO pending_since FROM gate_revocations WHERE applied_at IS NULL;
  IF pending_since IS NULL OR EXISTS (
    SELECT 1 FROM operations WHERE kind = 'edge.drain' AND status IN ('queued', 'running')
      AND payload ->> 'reason' = 'gate_revocation'
  ) THEN RETURN NULL; END IF;
  SELECT count(*)::integer, max(updated_at) INTO failures, last_failure FROM operations
  WHERE kind = 'edge.drain' AND status = 'failed' AND payload ->> 'reason' = 'gate_revocation'
    AND updated_at >= pending_since;
  IF last_failure IS NOT NULL AND last_failure +
    least(300, 10 * power(2, least(failures - 1, 5))) * interval '1 second' > clock_timestamp()
  THEN RETURN NULL; END IF;
  op_id := 'op_' || replace(gen_random_uuid()::text, '-', '');
  INSERT INTO operations (id, kind, status, idempotency_key, plan_hash, target_ids, payload)
  VALUES (op_id, 'edge.drain', 'queued', 'edge.drain:gate-revocation:' || op_id,
    encode(sha256(convert_to('{"reason":"gate_revocation"}', 'UTF8')), 'hex'),
    '["platform"]'::jsonb, '{"reason":"gate_revocation"}'::jsonb);
  RETURN op_id;
END $$;

CREATE OR REPLACE FUNCTION ark_gate_revoke(p_route_id text, p_reason text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('ark:gate:drain'));
  IF NOT EXISTS (SELECT 1 FROM front_routes WHERE id = p_route_id) THEN RETURN; END IF;
  INSERT INTO gate_revocations (id, route_id, reason)
  VALUES ('grv_' || replace(gen_random_uuid()::text, '-', ''), p_route_id,
    coalesce(nullif(current_setting('ark.gate_revocation_reason', true), ''), p_reason))
  ON CONFLICT (route_id) WHERE applied_at IS NULL DO UPDATE
    -- A reload snapshots IDs. Rotate the ID so a revocation committed during that reload cannot
    -- be acknowledged by it. Keep the oldest deadline, including any watchdog alert.
    SET id = EXCLUDED.id, reason = EXCLUDED.reason;
  PERFORM ark_gate_ensure_drain();
END $$;

CREATE OR REPLACE FUNCTION ark_gate_sessions_revoked() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Token expiry never proves that a previously upgraded connection has closed.
  IF TG_OP = 'DELETE' THEN
    IF OLD.revoked_at IS NULL THEN PERFORM ark_gate_revoke(OLD.route_id, 'gate_session_deleted'); END IF;
    RETURN OLD;
  END IF;
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
    PERFORM ark_gate_revoke(NEW.route_id, 'gate_session_revoked');
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION ark_gate_mfa_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.two_factor_enabled IS DISTINCT FROM NEW.two_factor_enabled
    OR OLD.mfa_enrolled_at IS DISTINCT FROM NEW.mfa_enrolled_at THEN
    UPDATE gate_sessions SET revoked_at = now() WHERE user_id = NEW.id AND revoked_at IS NULL;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER gate_mfa_revocation AFTER UPDATE OF two_factor_enabled, mfa_enrolled_at ON "user"
FOR EACH ROW EXECUTE FUNCTION ark_gate_mfa_changed();
