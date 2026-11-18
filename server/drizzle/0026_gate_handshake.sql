-- FD-11: gate handshake and SSO routes (docs/design/front-door.md §3.9).
-- 0027 is reserved for FD-14, which is being built in parallel; the runner applies files in sorted order.

-- Durable revocation journal (§3.9.3). Every authorization revocation that can leave an open
-- upgraded connection (a WebSocket, which forward_auth never re-checks) writes a row and queues an
-- `edge.drain` in the same transaction. The worker drains the affected HAProxy backends and
-- forces a Caddy load, including when the rendered text is identical. A row is applied after
-- the drain and load succeed. After 5 s pending, the lease excludes the route and the watchdog
-- withdraws it. The API raises a critical alert.
-- No foreign key on route_id: a deleted route is withdrawn by its own drain.
CREATE TABLE gate_revocations (
  id text PRIMARY KEY,
  route_id text NOT NULL,
  reason text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- Set by the operation whose drain began after this row committed.
  applied_at timestamptz,
  applied_by text,
  -- Set once the deadline passed and the critical alert was raised.
  alerted_at timestamptz
);
CREATE INDEX gate_revocations_pending_idx ON gate_revocations (created_at) WHERE applied_at IS NULL;

CREATE INDEX gate_sessions_auth_session_idx ON gate_sessions (auth_session_id);
CREATE INDEX gate_sessions_route_user_idx ON gate_sessions (route_id, user_id);
CREATE INDEX gate_handoffs_expires_idx ON gate_handoffs (expires_at);

-- Records a revocation for one route and makes sure a forced-reload drain is queued. Callers may set
-- `ark.gate_revocation_reason` (transaction-local) to name the cause; triggers pass a default.
CREATE FUNCTION ark_gate_revoke(p_route_id text, p_reason text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  op_id text;
BEGIN
  -- A route being deleted is withdrawn by its own drain; nothing to record.
  IF NOT EXISTS (SELECT 1 FROM front_routes WHERE id = p_route_id) THEN
    RETURN;
  END IF;
  -- One row per route per transaction is enough (a mode change deletes many sessions at once).
  IF NOT EXISTS (
    SELECT 1 FROM gate_revocations
    WHERE route_id = p_route_id AND applied_at IS NULL AND created_at = now()
  ) THEN
    INSERT INTO gate_revocations (id, route_id, reason)
    VALUES (
      'grv_' || replace(gen_random_uuid()::text, '-', ''),
      p_route_id,
      coalesce(nullif(current_setting('ark.gate_revocation_reason', true), ''), p_reason)
    );
  END IF;
  -- A queued drain snapshots the pending rows when it runs, so one queued drain covers them all.
  IF NOT EXISTS (
    SELECT 1 FROM operations
    WHERE kind = 'edge.drain' AND status = 'queued' AND payload ->> 'reason' = 'gate_revocation'
  ) THEN
    op_id := 'op_' || replace(gen_random_uuid()::text, '-', '');
    INSERT INTO operations (id, kind, status, idempotency_key, plan_hash, target_ids, payload)
    VALUES (
      op_id,
      'edge.drain',
      'queued',
      'edge.drain:gate-revocation:' || op_id,
      encode(sha256(convert_to('{"reason":"gate_revocation"}', 'UTF8')), 'hex'),
      '["platform"]'::jsonb,
      '{"reason":"gate_revocation"}'::jsonb
    );
  END IF;
END $$;

-- A live gate session that is deleted (sign-out, logout everywhere, MFA reset, user deletion and
-- mode changes all cascade from `session` or `user`) or revoked (route logout, access removal).
CREATE FUNCTION ark_gate_sessions_revoked() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.revoked_at IS NULL AND OLD.expires_at > now() THEN
      PERFORM ark_gate_revoke(OLD.route_id, 'gate_session_deleted');
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND OLD.expires_at > now() THEN
    PERFORM ark_gate_revoke(NEW.route_id, 'gate_session_revoked');
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER gate_sessions_revocation
AFTER DELETE OR UPDATE OF revoked_at ON gate_sessions
FOR EACH ROW EXECUTE FUNCTION ark_gate_sessions_revoked();

-- Removing a user from a route's access list revokes that user's sessions on the route.
CREATE FUNCTION ark_front_route_access_removed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE gate_sessions
  SET revoked_at = now()
  WHERE route_id = OLD.route_id AND user_id = OLD.user_id AND revoked_at IS NULL;
  RETURN OLD;
END $$;

CREATE TRIGGER front_route_access_revocation
AFTER DELETE ON front_route_access
FOR EACH ROW EXECUTE FUNCTION ark_front_route_access_removed();
