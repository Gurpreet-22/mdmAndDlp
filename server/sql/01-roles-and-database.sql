-- UbuntuGuard: create the two database roles and the database.
--
-- Run as a PostgreSQL superuser, connected to any database:
--
--   psql -v owner_password="$OWNER_PW" -v app_password="$APP_PW" \
--        -f sql/01-roles-and-database.sql
--
-- Two roles, because the audit log's append-only guarantee is a property of
-- the GRANTs rather than of the application code:
--
--   ubuntuguard_owner  owns the schema and runs migrations. Has CREATE/ALTER.
--   ubuntuguard_app    the runtime role. No DDL rights at all, and no UPDATE
--                      or DELETE on audit_logs.
--
-- If the application ran as the owner, it could drop the audit table, and the
-- whole append-only story would rest on nothing but good intentions.
--
-- Passwords come from psql variables, never from this file. Note that
-- interpolation is done outside dollar-quoted strings on purpose: psql does
-- NOT substitute variables inside $$ ... $$, so the usual DO-block idiom would
-- silently create a role whose password is the literal text ":'app_password'".

\set ON_ERROR_STOP on

-- Create the roles only if absent, so the script is safe to re-run.
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', 'ubuntuguard_owner', :'owner_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ubuntuguard_owner')\gexec

SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', 'ubuntuguard_app', :'app_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ubuntuguard_app')\gexec

-- Keep the passwords in step on a re-run.
SELECT format('ALTER ROLE %I PASSWORD %L', 'ubuntuguard_owner', :'owner_password')\gexec
SELECT format('ALTER ROLE %I PASSWORD %L', 'ubuntuguard_app', :'app_password')\gexec

-- Neither role needs to create databases, bypass row security, or replicate.
ALTER ROLE ubuntuguard_owner NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ubuntuguard_app   NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- CREATE DATABASE cannot run inside a transaction block, hence \gexec here too.
SELECT format('CREATE DATABASE %I OWNER %I', 'ubuntuguard', 'ubuntuguard_owner')
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'ubuntuguard')\gexec

-- Connecting is not the same as reading; table grants come from 02-grants.sql.
GRANT CONNECT ON DATABASE ubuntuguard TO ubuntuguard_app;

\echo 'Roles ubuntuguard_owner and ubuntuguard_app ready; database ubuntuguard exists.'
\echo 'Next: run the Alembic migrations as the OWNER, then apply sql/02-grants.sql.'
