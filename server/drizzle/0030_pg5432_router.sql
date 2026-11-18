-- FD-26: PostgreSQL router on 5432 (docs/design/front-door.md §3.8.3, §3.8.5).
-- 0029 is reserved for FD-12, which is built in parallel; the runner applies files in sorted order.

-- One explicit pooler-wide source policy (pooler_source_cidrs / pooler_allow_internet, from 0013) is
-- enforced in HAProxy's be_pgbouncer. Classic SSLRequest carries no database name, so a database's
-- source_cidrs is only a request for that policy. `pooler_internet_confirmed_*` records the owner's
-- exposure.public confirmation saved with pooler_allow_internet. `pooler_policy_reviewed_*` records
-- the owner's explicit review of the policy against the requests it covered (a fingerprint of the
-- distinct requests); conflicting requests refuse publication until such a review matches them.
ALTER TABLE platform_settings
  ADD COLUMN pooler_internet_confirmed_by text REFERENCES "user"(id) ON DELETE SET NULL,
  ADD COLUMN pooler_internet_confirmed_at timestamptz,
  ADD COLUMN pooler_policy_reviewed_by text REFERENCES "user"(id) ON DELETE SET NULL,
  ADD COLUMN pooler_policy_reviewed_at timestamptz,
  ADD COLUMN pooler_policy_reviewed_requests text,
  -- The retirement watchdog's fallback (FD-28) when PgBouncer cannot be stopped over its admin socket:
  -- edge.l4_apply omits be_pgbouncer while set, closing public admission independently of PgBouncer.
  -- The next successful pgbouncer.reload clears it (as the old `expose` file toggle was rewritten).
  ADD COLUMN pooler_fenced_at timestamptz,
  ADD COLUMN pooler_fence_reason text;

-- Keep the Vercel -> PgBouncer path working across the cutover. Before FD-26 the host nft table
-- admitted the union of the public databases' CIDRs, or every source when none had any. Where every
-- request is the same (all databases unrestricted, possibly with Vercel clients, or all with one
-- identical CIDR list), adopt it as the explicit pooler policy. Conflicting requests are not merged:
-- the policy stays empty (deny all) and publication is refused until the owner reviews one policy.
WITH requests AS (
  SELECT CASE WHEN jsonb_array_length(d.source_cidrs) = 0 THEN 'internet'
              ELSE (SELECT string_agg(value, ',' ORDER BY value)
                    FROM jsonb_array_elements_text(d.source_cidrs) AS value) END AS key,
         d.source_cidrs AS cidrs
  FROM managed_databases d
  WHERE d.exposure = 'public'
  UNION ALL
  SELECT 'internet', '[]'::jsonb
  FROM vercel_integrations v
  JOIN database_clients c ON c.id = v.database_client_id AND c.status = 'active'
  JOIN managed_databases d ON d.id = c.database_id AND d.exposure = 'public'
), single AS (
  SELECT min(key) AS key, (array_agg(cidrs))[1] AS cidrs
  FROM requests
  HAVING count(DISTINCT key) = 1
)
UPDATE platform_settings p
SET pooler_allow_internet = (s.key = 'internet'),
    pooler_source_cidrs = CASE WHEN s.key = 'internet' THEN '[]'::jsonb ELSE s.cidrs END,
    pooler_internet_confirmed_at = CASE WHEN s.key = 'internet' THEN now() ELSE NULL END,
    updated_at = now()
FROM single s
WHERE p.id = 'default'
  AND NOT p.pooler_allow_internet
  AND jsonb_array_length(p.pooler_source_cidrs) = 0;

INSERT INTO audit_events (id, action, resource_type, resource_id, detail)
SELECT 'aud_fd26_' || substr(md5(random()::text || clock_timestamp()::text), 1, 20),
       'pooler_policy.migrated', 'platform_settings', 'default',
       jsonb_build_object(
         'sourceCidrs', pooler_source_cidrs,
         'allowInternet', pooler_allow_internet,
         'reason', 'FD-26 cutover: adopted the single pre-existing database ingress policy'
       )
FROM platform_settings
WHERE id = 'default' AND (pooler_allow_internet OR jsonb_array_length(pooler_source_cidrs) > 0);

ALTER TABLE platform_settings
  ADD CONSTRAINT platform_settings_pooler_internet_confirmed_check
    CHECK (NOT pooler_allow_internet OR pooler_internet_confirmed_at IS NOT NULL);

-- No per-database enforcement claim: the listener cannot isolate one database's sources.
ALTER TABLE managed_databases DROP COLUMN allowlist_enforced;

-- Postgres routes (§3.8.3): always on the 5432 router; the opt-in compatibility port comes from the
-- dedicated range and exists for passthrough routes only (the target terminates TLS itself).
ALTER TABLE front_routes
  DROP CONSTRAINT front_routes_l4_shape_check,
  ADD CONSTRAINT front_routes_l4_shape_check CHECK (
    (kind = 'http' AND tls_mode IS NULL)
    OR (kind = 'tcp' AND tls_mode = 'plain' AND listen_port BETWEEN 20000 AND 20049)
    OR (kind = 'tls' AND tls_mode IN ('passthrough', 'terminate', 'terminate_mtls')
        AND listen_port IN (443, 8883, 5671, 636, 6380))
    OR (kind = 'postgres' AND tls_mode IN ('passthrough', 'terminate', 'terminate_mtls')
        AND listen_port = 5432)
  ),
  ADD CONSTRAINT front_routes_compat_port_check CHECK (
    compat_port IS NULL
    OR (kind = 'postgres' AND tls_mode = 'passthrough' AND compat_port BETWEEN 20000 AND 20049)
  );
