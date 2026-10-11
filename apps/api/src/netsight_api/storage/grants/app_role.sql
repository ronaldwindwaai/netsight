-- Least-privilege grants for the runtime application role (S6-1 review H1).
--
-- Applied by `netsight_api.storage.migrate` (apply_grants) as the migrator/owner, AFTER the
-- schema migrations, and re-applied on every `up` (idempotent). It is not a numbered
-- migration because the role name is deployment configuration: the runner passes it as the
-- transaction-local setting netsight.app_role and this script quotes it with format(%I).
-- No password, role creation or login handling lives here; the role is created out of band.
--
-- Operates on current_schema() (public in production, the throwaway schema in tests).
--
-- Application role gets:
--   incidents                  SELECT, INSERT, UPDATE (state, assignee_id, evidence_ids,
--                              resolution, updated_at)
--   incident_timeline_events   SELECT, INSERT only (append-only)
--   alert_rules                SELECT, INSERT, UPDATE (the columns written by the edit /
--                              approve / disable statements in postgres.py)
--   maintenance_windows        SELECT, INSERT, UPDATE (status, cancelled_by, cancelled_at)
--   alert_incident_links       SELECT, INSERT, UPDATE (incident_id, linked_at, recovered_at)
--   notification_delivery_attempts  SELECT, INSERT only (append-only)
--   diagnostic_sessions        SELECT, INSERT only (a finished session is immutable)
--   wan_link_cycles            SELECT only (the API reads the SLA evidence; the collector, a
--   wan_probe_samples          SELECT only  separate role, is the only writer: wan_collector_role.sql)
--   unknown_device_findings    SELECT, INSERT, UPDATE (state, severity, severity_basis, assignee_id,
--                              last_seen_at, seen_count, endpoint, chain, comparison, proposed_action,
--                              updated_at): the identity columns and the history are not updatable
--   unknown_device_events      SELECT, INSERT only (append-only)
--   netsight_schema_migrations nothing
-- It gets no DELETE, TRUNCATE, REFERENCES, TRIGGER, CREATE or ownership anywhere.

DO $grants$
DECLARE
    app_role   text := nullif(current_setting('netsight.app_role', true), '');
    schema_name text := current_schema();
    role_oid   oid;
BEGIN
    IF app_role IS NULL THEN
        RAISE EXCEPTION 'netsight.app_role is not set';
    END IF;

    SELECT oid INTO role_oid FROM pg_roles WHERE rolname = app_role;
    IF role_oid IS NULL THEN
        RAISE EXCEPTION 'application role % does not exist; create it out of band first', app_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE oid = role_oid AND (rolsuper OR rolbypassrls)) THEN
        RAISE EXCEPTION 'application role % must not be a superuser or bypass row security',
            app_role;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_class
        WHERE relnamespace = schema_name::regnamespace
          AND relname IN ('incidents', 'incident_timeline_events', 'alert_rules',
                          'maintenance_windows', 'netsight_schema_migrations',
                          'alert_incident_links', 'notification_delivery_attempts',
                          'diagnostic_sessions', 'wan_link_cycles', 'wan_probe_samples',
                          'unknown_device_findings', 'unknown_device_events')
          AND pg_has_role(app_role, relowner, 'USAGE')
    ) THEN
        RAISE EXCEPTION 'application role % owns (or inherits ownership of) the tables; '
            'use a separate migrator/owner role', app_role;
    END IF;

    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', schema_name);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, app_role);

    -- Start from nothing so a re-run can never leave a stale wider grant behind.
    EXECUTE format(
        'REVOKE ALL ON TABLE %1$I.incidents, %1$I.incident_timeline_events, '
        '%1$I.alert_rules, %1$I.maintenance_windows, %1$I.netsight_schema_migrations, '
        '%1$I.alert_incident_links, %1$I.notification_delivery_attempts, '
        '%1$I.diagnostic_sessions, %1$I.wan_link_cycles, %1$I.wan_probe_samples, '
        '%1$I.unknown_device_findings, %1$I.unknown_device_events '
        'FROM %2$I',
        schema_name, app_role);

    EXECUTE format('GRANT SELECT, INSERT ON TABLE %I.incidents TO %I', schema_name, app_role);
    EXECUTE format(
        'GRANT UPDATE (state, assignee_id, evidence_ids, resolution, updated_at) '
        'ON TABLE %I.incidents TO %I', schema_name, app_role);

    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE %I.incident_timeline_events TO %I', schema_name, app_role);

    EXECUTE format('GRANT SELECT, INSERT ON TABLE %I.alert_rules TO %I', schema_name, app_role);
    EXECUTE format(
        'GRANT UPDATE (name, status, scope, condition, baseline_mode, window_seconds, '
        'for_seconds, cooldown_seconds, schedule, exceptions, severity, labels, actions, '
        'incident_policy, updated_at, approved_by, approved_at, version) '
        'ON TABLE %I.alert_rules TO %I', schema_name, app_role);

    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE %I.maintenance_windows TO %I', schema_name, app_role);
    EXECUTE format(
        'GRANT UPDATE (status, cancelled_by, cancelled_at) '
        'ON TABLE %I.maintenance_windows TO %I', schema_name, app_role);

    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE %I.alert_incident_links TO %I', schema_name, app_role);
    EXECUTE format(
        'GRANT UPDATE (incident_id, linked_at, recovered_at) ON TABLE %I.alert_incident_links TO %I',
        schema_name, app_role);

    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE %I.notification_delivery_attempts TO %I',
        schema_name, app_role);

    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE %I.diagnostic_sessions TO %I', schema_name, app_role);

    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE %I.unknown_device_findings TO %I', schema_name, app_role);
    EXECUTE format(
        'GRANT UPDATE (state, severity, severity_basis, assignee_id, last_seen_at, seen_count, '
        'endpoint, chain, comparison, proposed_action, updated_at) '
        'ON TABLE %I.unknown_device_findings TO %I', schema_name, app_role);
    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE %I.unknown_device_events TO %I', schema_name, app_role);

    -- Read-only on the (partitioned) WAN tables: the privilege on the parent covers reads through it;
    -- the month partitions carry no grant of their own, so they are not reachable directly.
    EXECUTE format('GRANT SELECT ON TABLE %I.wan_link_cycles TO %I', schema_name, app_role);
    EXECUTE format('GRANT SELECT ON TABLE %I.wan_probe_samples TO %I', schema_name, app_role);
END
$grants$;
