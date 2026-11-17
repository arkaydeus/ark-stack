-- Completion gates are separate from admission/revocation intent.
ALTER TABLE database_clients
  ADD COLUMN issued_at timestamptz DEFAULT now(),
  ADD COLUMN revocation_completed_at timestamptz;
-- Preserve incomplete legacy issuance as non-revealable and resumable.
UPDATE database_clients c SET issued_at = NULL
WHERE EXISTS (SELECT 1 FROM operations o WHERE o.kind = 'database.client_issue'
  AND o.payload->>'clientId' = c.id)
AND NOT EXISTS (SELECT 1 FROM operations o WHERE o.kind = 'database.client_issue'
  AND o.payload->>'clientId' = c.id AND o.status = 'succeeded');
-- Existing revoked clients remain retryable: old jobs may have failed after changing status.
CREATE TABLE client_issue_limits (
  user_id text PRIMARY KEY REFERENCES "user"(id) ON DELETE CASCADE,
  attempts jsonb NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE INDEX client_issue_limits_updated_at_idx ON client_issue_limits(updated_at);
