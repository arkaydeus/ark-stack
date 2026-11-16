-- Public database port per-source limits (docs/design/front-door.md §3.11, ticket FD-18).
-- `inet ark_db_ingress` caps concurrent connections per source (`ct count`) and limits the
-- new-connection rate per source (`limit rate`) on tcp/5432; IPv6 sources are grouped by /64.
-- The defaults are §3.11's: 128 concurrent, 30 new per second with a burst of 60. Vercel egress
-- shares AWS addresses, so many function instances can arrive from one source.
-- The bounds match DB_INGRESS_LIMIT_BOUNDS in shared/src/db-ingress.ts.

ALTER TABLE platform_settings
  ADD COLUMN db_ingress_max_connections integer NOT NULL DEFAULT 128,
  ADD COLUMN db_ingress_rate_per_second integer NOT NULL DEFAULT 30,
  ADD COLUMN db_ingress_rate_burst integer NOT NULL DEFAULT 60,
  ADD CONSTRAINT platform_settings_db_ingress_limits_check
    CHECK (
      db_ingress_max_connections BETWEEN 1 AND 65535
      AND db_ingress_rate_per_second BETWEEN 1 AND 10000
      AND db_ingress_rate_burst BETWEEN db_ingress_rate_per_second AND 100000
    );
