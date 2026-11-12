-- UbuntuGuard: least-privilege grants for the runtime role.
--
-- Run AFTER `alembic upgrade head`, connected to the ubuntuguard database as a
-- superuser or as ubuntuguard_owner:
--
--   psql -d ubuntuguard -f sql/02-grants.sql
--
-- DESIGN: DENY BY DEFAULT, GRANT THE EXCEPTIONS.
--
-- An earlier version of this file did the opposite - granted full DML on all
-- tables, then revoked UPDATE and DELETE on the protected ones. That read
-- cleanly and was wrong, and it was caught by the migration test rather than by
-- review: `alembic downgrade base && alembic upgrade head` DROPS and RECREATES
-- every table, the new tables pick up ALTER DEFAULT PRIVILEGES, and the app
-- role silently regained UPDATE and DELETE on audit_logs. The append-only
-- guarantee disappeared with no error anywhere.
--
-- So the default privilege is now the restrictive one. A table that gets
-- recreated by any future migration comes back as SELECT, INSERT - append-only
-- is what you get if someone forgets to re-run this file, and the worst case of
-- forgetting is a failed UPDATE rather than a silently mutable audit log.
--
-- Re-running after a migration is still correct, and `dev_db.sh migrate` does
-- it, because a recreated table loses the UPDATE and DELETE the operational
-- tables legitimately need. The application also verifies the invariant on
-- /readyz, so a deployment that lost it is visible rather than merely wrong.

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------------------
-- Schema access: use, but not extend.
-- ---------------------------------------------------------------------------
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM ubuntuguard_app;
GRANT USAGE ON SCHEMA public TO ubuntuguard_app;

-- ---------------------------------------------------------------------------
-- The safe baseline: read and append, nothing more.
-- ---------------------------------------------------------------------------
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ubuntuguard_app;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO ubuntuguard_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ubuntuguard_app;

-- Future tables inherit the SAFE default, not the permissive one.
ALTER DEFAULT PRIVILEGES FOR ROLE ubuntuguard_owner IN SCHEMA public
  REVOKE ALL ON TABLES FROM ubuntuguard_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ubuntuguard_owner IN SCHEMA public
  GRANT SELECT, INSERT ON TABLES TO ubuntuguard_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ubuntuguard_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO ubuntuguard_app;

-- ---------------------------------------------------------------------------
-- Now the exceptions, one table at a time, with the reason.
-- Anything absent from this list is append-only for the application.
-- ---------------------------------------------------------------------------

-- Password changes, deactivation, lockout timestamps, last login.
-- No DELETE: accounts are deactivated, not erased, so the audit trail keeps
-- pointing at a real row.
GRANT UPDATE ON users TO ubuntuguard_app;

-- Refresh rotation marks tokens used and revokes families; expired rows are
-- pruned by the application.
GRANT UPDATE, DELETE ON auth_tokens TO ubuntuguard_app;

-- Heartbeats, inventory timestamps, status and revocation.
GRANT UPDATE ON devices TO ubuntuguard_app;

-- The atomic single-use consume, and early revocation.
GRANT UPDATE ON enrollment_tokens TO ubuntuguard_app;

-- The 60 second idempotency cache is pruned once it is no longer useful.
GRANT DELETE ON enrollment_attempts TO ubuntuguard_app;

-- Renewal marks the old certificate superseded. No DELETE: an old fingerprint
-- seen in a log must stay attributable.
GRANT UPDATE ON issued_certificates TO ubuntuguard_app;

-- Inventory is a full replace per device, via ON CONFLICT DO UPDATE.
GRANT UPDATE ON device_inventory TO ubuntuguard_app;

-- Assignment and unassignment.
GRANT UPDATE, DELETE ON policy_assignments TO ubuntuguard_app;

-- Apply status is upserted as devices report, via ON CONFLICT DO UPDATE.
GRANT UPDATE ON device_policy_status TO ubuntuguard_app;

-- Events are facts and are never edited. DELETE only, for retention pruning.
GRANT DELETE ON events TO ubuntuguard_app;

-- Incident status transitions and notes.
GRANT UPDATE ON incidents TO ubuntuguard_app;

-- Early revocation of a time-bound exception.
GRANT UPDATE ON usb_exceptions TO ubuntuguard_app;

-- Deliberately NOT granted anything beyond SELECT, INSERT:
--   audit_logs           append-only, the whole point
--   policies             immutable versions; a change is a new row
--   login_attempts       evidence of brute forcing; the owner prunes it

-- ---------------------------------------------------------------------------
-- Defence in depth: triggers, so the guarantee does not rest on GRANTs alone.
-- ---------------------------------------------------------------------------
-- These catch the owner role too, which the GRANTs above do not. A superuser
-- can still drop the trigger; detecting THAT needs the chain head anchored
-- outside the database, which is out of prototype scope and recorded in the
-- known-limitations page.
CREATE OR REPLACE FUNCTION ubuntuguard_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
  RAISE EXCEPTION
    '% on %.% is not permitted: this table is append-only',
    TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END;
$fn$;

DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs;
CREATE TRIGGER audit_logs_append_only
  BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION ubuntuguard_reject_mutation();

DROP TRIGGER IF EXISTS policies_immutable ON policies;
CREATE TRIGGER policies_immutable
  BEFORE UPDATE OR DELETE ON policies
  FOR EACH ROW EXECUTE FUNCTION ubuntuguard_reject_mutation();

-- ---------------------------------------------------------------------------
-- Report the result, so the output is auditable rather than trusted.
-- ---------------------------------------------------------------------------
\echo ''
\echo 'Tables where ubuntuguard_app can only read and append:'
SELECT table_name, string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privileges
  FROM information_schema.role_table_grants
 WHERE grantee = 'ubuntuguard_app'
 GROUP BY table_name
HAVING string_agg(privilege_type, ', ' ORDER BY privilege_type) = 'INSERT, SELECT'
 ORDER BY table_name;

\echo 'audit_logs, policies and login_attempts MUST appear in that list.'
