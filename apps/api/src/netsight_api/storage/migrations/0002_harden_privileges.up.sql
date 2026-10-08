-- 0002: privilege hardening that does not depend on any role name (S6-1 review H1).
-- Role-specific grants are applied separately by `python -m netsight_api.storage.migrate up`
-- (grants/app_role.sql), because the application role name is deployment configuration.
--
-- 1. PUBLIC gets nothing on the tables or the trigger function.
-- 2. Both append-only triggers become ENABLE ALWAYS so they also fire when a session
--    sets session_replication_role = replica (the usual way to skip triggers during
--    replication / bulk loads).
-- Residual risk: the table OWNER (and superusers) can still ALTER TABLE ... DISABLE TRIGGER.
-- Triggers are a guard against application bugs and least-privilege roles, not against the
-- owner; keep the owner/migrator credential out of the running service.

REVOKE ALL ON TABLE incidents, incident_timeline_events, alert_rules, maintenance_windows
    FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_reject_timeline_mutation() FROM PUBLIC;

ALTER TABLE incident_timeline_events
    ENABLE ALWAYS TRIGGER incident_timeline_events_no_update_delete;
ALTER TABLE incident_timeline_events
    ENABLE ALWAYS TRIGGER incident_timeline_events_no_truncate;
