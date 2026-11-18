-- A write can outlive either its operation claim or the integration that started it.
CREATE TABLE vercel_env_writes (
  project_id text NOT NULL,
  target text NOT NULL,
  git_branch text NOT NULL,
  operation_id text NOT NULL,
  started_at timestamptz NOT NULL,
  PRIMARY KEY (project_id, target, git_branch)
);

ALTER TABLE vercel_integrations ADD COLUMN hook_lookup_until bigint;
