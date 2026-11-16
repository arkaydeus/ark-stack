-- Last generated Tailscale policy snippets (docs/design/front-door.md §3.7, ticket FD-07).
-- Ark never writes the tailnet policy; it keeps the snippet it last showed for each scope so the
-- owner sees a diff when routes change. Snippets hold only public routing facts, never secrets.
CREATE TABLE tailnet_acl_snippets (
  scope text PRIMARY KEY,                                         -- 'global' or 'route:<route id>'
  route_id text REFERENCES front_routes(id) ON DELETE CASCADE,    -- set for per-route scopes
  digest text NOT NULL,                                           -- sha256 of snippet
  snippet text NOT NULL,
  generated_at timestamptz NOT NULL DEFAULT now(),
  previous_digest text,
  previous_snippet text,
  previous_generated_at timestamptz,
  CONSTRAINT tailnet_acl_snippets_scope_check CHECK (
    (scope = 'global' AND route_id IS NULL) OR (route_id IS NOT NULL AND scope = 'route:' || route_id)
  )
);
