-- FD-30: home-machine backups over the tailnet (docs/design/front-door.md §3.18.3).
-- 0022 stays free for FD-10, which is being built in parallel; the runner applies files in sorted order.

-- A `tailnet_rest` target is pinned like a route (§3.2): the StableNodeID and the address chosen from
-- backup-ts's own `source = 'backup'` observation. Only the pinned address is ever dialled (through
-- backup-ts's SOCKS5 proxy); a re-observed address for the same identity replaces it.
ALTER TABLE backup_targets
  ADD COLUMN target_ip text,
  DROP CONSTRAINT backup_targets_provider_check,
  ADD CONSTRAINT backup_targets_provider_check
    CHECK (provider IN ('aws', 'b2', 'r2', 'minio', 'other', 'rest_server')),
  ADD CONSTRAINT backup_targets_tailnet_rest_shape_check CHECK (
    kind <> 'tailnet_rest'
    OR (rest_url IS NOT NULL AND target_node_stable_id IS NOT NULL AND target_ip IS NOT NULL
        AND provider = 'rest_server')
  );
