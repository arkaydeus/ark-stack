-- Database client certificate rollover (docs/design/front-door.md §3.10.4, ticket FD-28).
-- Numbered 0020 because 0019_database_client_recovery.sql (FD-17, PR #38) is the latest on main.
--
-- Certificate lifecycle: a successor is issued `pending` from a fresh CA generation and linked
-- once through `superseded_by` (client_certificates_successor_unique from 0013 allows exactly one
-- successor per certificate). Confirming delivery sets `delivered_at` once and promotes it
-- through `delivered` to `current` while the predecessor becomes `superseded`. At the
-- predecessor's not_after its generation leaves the PgBouncer bundle and the row becomes
-- `retired` (status `expired`). `delivered_at` is never cleared, so it is the delivery history.
ALTER TABLE client_certificates DROP CONSTRAINT client_certificates_rollover_state_check;
ALTER TABLE client_certificates ADD CONSTRAINT client_certificates_rollover_state_check
  CHECK (rollover_state IN ('current', 'pending', 'delivered', 'superseded', 'retired'));
-- One-time reveal gate for a rollover successor (the client's first bundle keeps using
-- database_clients.revealed_at). Set once, in the transaction that deletes the sealed key.
ALTER TABLE client_certificates ADD COLUMN revealed_at timestamptz;
-- Set when the certificate's generation has been removed and its role drained.
ALTER TABLE client_certificates ADD COLUMN retired_at timestamptz;
-- The daily job and the retirement watcher scan issued certificates by expiry.
CREATE INDEX client_certificates_issued_not_after_idx
  ON client_certificates(not_after) WHERE status = 'issued';

-- Durable retirement task, one per certificate: fence, reduced-bundle reload, role and pre-auth
-- drain, reopen. The deadline is not_after + 5 s; a missed deadline is recorded, alerted and
-- retried, never treated as success. Timestamps are the measured drain timeline.
CREATE TABLE client_certificate_retirements (
  certificate_id text PRIMARY KEY REFERENCES client_certificates(id) ON DELETE CASCADE,
  client_id text NOT NULL REFERENCES database_clients(id) ON DELETE CASCADE,
  role text NOT NULL,
  database_name text NOT NULL,
  not_after timestamptz NOT NULL,
  deadline timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  lease_until timestamptz,
  last_error text,
  fenced_at timestamptz,
  reloaded_at timestamptz,
  drained_at timestamptz,
  reopened_at timestamptz,
  completed_at timestamptz,
  deadline_missed boolean NOT NULL DEFAULT false,
  watchdog_at timestamptz,
  evidence jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX client_certificate_retirements_open_idx
  ON client_certificate_retirements(deadline) WHERE completed_at IS NULL;
