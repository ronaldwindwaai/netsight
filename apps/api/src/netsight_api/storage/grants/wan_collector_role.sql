-- Least-privilege grants for the WAN collector role (security review M1).
--
-- Applied by `netsight_api.storage.migrate` (apply_grants) as the migrator/owner, AFTER the schema
-- migrations and after app_role.sql, and re-applied on every `up` (idempotent). The role name is
-- deployment configuration (DATABASE_WAN_COLLECTOR_ROLE): the runner passes it as the
-- transaction-local setting netsight.wan_collector_role and this script quotes it with format(%I).
-- No password, role creation or login handling lives here; the role is created out of band.
--
-- The collector role is the ONLY writer of the WAN evidence, and nothing else:
--   wan_link_cycles, wan_probe_samples   INSERT only (no SELECT, UPDATE, DELETE, TRUNCATE)
--   every other table                    nothing
-- It can use the schema (USAGE) but cannot create objects in it, so it can run no DDL and cannot
-- create the month partitions (that is the migrator's job); a write into a month without a
-- partition is refused. It is never the table owner, never a superuser, never the API's role.

DO $grants$
DECLARE
    collector_role text := nullif(current_setting('netsight.wan_collector_role', true), '');
    app_role       text := nullif(current_setting('netsight.app_role', true), '');
    schema_name    text := current_schema();
    role_oid       oid;
BEGIN
    IF collector_role IS NULL THEN
        RAISE EXCEPTION 'netsight.wan_collector_role is not set';
    END IF;
    IF collector_role = app_role THEN
        RAISE EXCEPTION 'the WAN collector role must differ from the application role';
    END IF;

    SELECT oid INTO role_oid FROM pg_roles WHERE rolname = collector_role;
    IF role_oid IS NULL THEN
        RAISE EXCEPTION 'WAN collector role % does not exist; create it out of band first',
            collector_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE oid = role_oid AND (rolsuper OR rolbypassrls)) THEN
        RAISE EXCEPTION 'WAN collector role % must not be a superuser or bypass row security',
            collector_role;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_class
        WHERE relnamespace = schema_name::regnamespace
          AND relkind IN ('r', 'p')
          AND pg_has_role(collector_role, relowner, 'USAGE')
    ) THEN
        RAISE EXCEPTION 'WAN collector role % owns (or inherits ownership of) tables; '
            'use a separate migrator/owner role', collector_role;
    END IF;

    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', schema_name);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, collector_role);

    -- Start from nothing so a re-run can never leave a stale wider grant behind.
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', schema_name, collector_role);

    EXECUTE format(
        'GRANT INSERT ON TABLE %I.wan_link_cycles TO %I', schema_name, collector_role);
    EXECUTE format(
        'GRANT INSERT ON TABLE %I.wan_probe_samples TO %I', schema_name, collector_role);
END
$grants$;
