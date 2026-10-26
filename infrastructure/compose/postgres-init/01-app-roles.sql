-- Dev only. Runs once, when the pgdata volume is first created.
-- POSTGRES_USER (netsight, the migrator/owner) is a superuser inside this container, which the
-- API refuses as its own role (storage/role_check.py). The API connects as netsight_app instead:
-- it owns nothing, so it can never bypass the grants applied by `migrate up`.
CREATE ROLE netsight_app LOGIN PASSWORD 'dev-only-app-change-me'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE netsight_wan_collector LOGIN PASSWORD 'dev-only-collector-change-me'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
