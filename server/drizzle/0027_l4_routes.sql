-- FD-14: TLS-TCP routes by SNI and raw-TCP routes on dedicated ports (docs/design/front-door.md §3.8).
-- 0026 is reserved for FD-11, which is built in parallel; the runner applies files in sorted order.

-- `allow_internet` renders 0.0.0.0/0 and ::/0. It is only ever saved together with the owner's
-- exposure.public confirmation, recorded here; enable refuses an open route without it (§3.8.6).
-- `protocol_auth_confirmed`: for a `plain` route open to the internet, the owner confirmed (with
-- step-up) that the protocol authenticates itself, as SSH does (§3.8.4).
ALTER TABLE front_routes
  ADD COLUMN internet_confirmed_by text REFERENCES "user"(id),
  ADD COLUMN internet_confirmed_at timestamptz,
  ADD COLUMN protocol_auth_confirmed boolean NOT NULL DEFAULT false;

ALTER TABLE front_routes
  ADD CONSTRAINT front_routes_internet_confirmed_check
    CHECK (NOT allow_internet OR internet_confirmed_at IS NOT NULL),
  -- Listener and TLS mode by kind (§3.8.2, §3.8.4): tcp is plain-only on the dedicated range and
  -- never on a TLS-capable port; tls carries one of the three TLS modes, never plain.
  ADD CONSTRAINT front_routes_l4_shape_check CHECK (
    (kind = 'http' AND tls_mode IS NULL)
    OR (kind = 'tcp' AND tls_mode = 'plain' AND listen_port BETWEEN 20000 AND 20049)
    OR (kind = 'tls' AND tls_mode IN ('passthrough', 'terminate', 'terminate_mtls')
        AND listen_port IN (443, 8883, 5671, 636, 6380))
    OR (kind = 'postgres' AND tls_mode IN ('passthrough', 'terminate', 'terminate_mtls'))
  ),
  ADD CONSTRAINT front_routes_mtls_ca_check
    CHECK (tls_mode IS DISTINCT FROM 'terminate_mtls' OR client_ca_id IS NOT NULL),
  -- terminate (no client certificates) keeps its restricted, non-empty allowlist requirement.
  ADD CONSTRAINT front_routes_terminate_cidrs_check CHECK (
    tls_mode IS DISTINCT FROM 'terminate'
    OR (NOT allow_internet AND jsonb_array_length(source_cidrs) > 0)
  ),
  -- Empty CIDRs deny all. Enable refuses such a route (API), but tightening a live route to an
  -- empty list is allowed: it renders deny-all in HAProxy and nftables and drains its sessions.
  ADD CONSTRAINT front_routes_plain_internet_check CHECK (
    kind <> 'tcp' OR NOT allow_internet OR protocol_auth_confirmed
  );
