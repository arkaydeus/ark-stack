-- FD-12: gate users (docs/design/front-door.md §3.9.6).
--
-- A gate user is a Better Auth user the owner created for "Ark login" routes. They sign in only on
-- the login origin and never have a `platform_access` row: the two tables are mutually exclusive,
-- enforced below for every writer. Deleting the `user` row cascades to this table, the user's
-- sessions, gate sessions and route access, and the FD-11 triggers journal the forced-reload drains.
CREATE TABLE gate_users (
  user_id text PRIMARY KEY REFERENCES "user"(id) ON DELETE CASCADE,
  created_by text REFERENCES "user"(id) ON DELETE SET NULL,
  -- The one-time temporary password (`secrets.once`); revealed at most once to the owner.
  temporary_password_secret_id text REFERENCES secrets(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Both triggers lock the user row first, so concurrent inserts into the two tables serialize and
-- the second one sees the first.
CREATE FUNCTION ark_gate_user_exclusive() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1 FROM "user" WHERE id = NEW.user_id FOR UPDATE;
  IF TG_TABLE_NAME = 'platform_access' THEN
    IF EXISTS (SELECT 1 FROM gate_users WHERE user_id = NEW.user_id) THEN
      RAISE EXCEPTION 'user % is a gate user and cannot have administration access', NEW.user_id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF EXISTS (SELECT 1 FROM platform_access WHERE user_id = NEW.user_id) THEN
    RAISE EXCEPTION 'user % has administration access and cannot be a gate user', NEW.user_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER platform_access_not_gate_user
BEFORE INSERT OR UPDATE OF user_id ON platform_access
FOR EACH ROW EXECUTE FUNCTION ark_gate_user_exclusive();

CREATE TRIGGER gate_users_no_platform_access
BEFORE INSERT OR UPDATE OF user_id ON gate_users
FOR EACH ROW EXECUTE FUNCTION ark_gate_user_exclusive();
