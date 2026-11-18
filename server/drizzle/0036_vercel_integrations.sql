-- FD-29 activates the integration model reserved in 0013. Older rows still represent pooler
-- policy requests (FD-26). They have no verified scope and cannot be used for delivery.
ALTER TABLE vercel_integrations
  ADD COLUMN other_project_id text,
  ADD COLUMN hook_branch text,
  ADD COLUMN scope_verified_at timestamptz,
  ADD COLUMN push_certificate_id text,
  ADD COLUMN hook_requested_at timestamptz,
  ADD COLUMN hook_job_id text,
  ADD CONSTRAINT vercel_integrations_verified_shape_check CHECK (
    scope_verified_at IS NULL OR (
      vercel_team_id IS NOT NULL AND token_expires_at IS NOT NULL AND
      deploy_hook_secret_id IS NOT NULL AND hook_branch IS NOT NULL AND
      other_project_id IS NOT NULL AND other_project_id <> vercel_project_id AND
      (git_branch IS NULL OR env_target = 'preview') AND
      (last_push_status IS NULL OR last_push_status IN ('pushing', 'failed', 'delivered', 'cancelled'))
    )
  );

CREATE UNIQUE INDEX vercel_integrations_project_target_key
  ON vercel_integrations (vercel_project_id, env_target, COALESCE(git_branch, ''))
  WHERE scope_verified_at IS NOT NULL;
CREATE UNIQUE INDEX vercel_integrations_hook_branch_key
  ON vercel_integrations (vercel_project_id, env_target, hook_branch)
  WHERE scope_verified_at IS NOT NULL;

-- Existing integration credentials, if any, also stay out of the generic reveal endpoint.
UPDATE secrets SET sensitivity = 'provider'
WHERE id IN (
  SELECT token_secret_id FROM vercel_integrations
  UNION
  SELECT deploy_hook_secret_id FROM vercel_integrations
);

-- Release credentials when their last integration is removed, including by client deletion.
CREATE FUNCTION delete_vercel_integration_secrets() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM secrets s
  WHERE s.id IN (OLD.token_secret_id, OLD.deploy_hook_secret_id)
    AND s.sensitivity = 'provider'
    AND NOT EXISTS (
      SELECT 1 FROM vercel_integrations v
      WHERE s.id IN (v.token_secret_id, v.deploy_hook_secret_id)
    );
  UPDATE alerts SET resolved_at = now() WHERE resolved_at IS NULL AND dedup_key IN (
    'vercel-push:' || OLD.database_client_id, 'vercel-token-expiry:' || OLD.id
  );
  RETURN OLD;
END
$$;
CREATE TRIGGER vercel_integration_secret_cleanup
  AFTER DELETE ON vercel_integrations
  FOR EACH ROW EXECUTE FUNCTION delete_vercel_integration_secrets();
