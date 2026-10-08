-- Reverses 0002_harden_privileges.up.sql: returns both triggers to the default
-- (origin-only) firing mode. Privileges revoked from PUBLIC are not re-granted.
-- Touches no data.

ALTER TABLE incident_timeline_events
    ENABLE TRIGGER incident_timeline_events_no_truncate;
ALTER TABLE incident_timeline_events
    ENABLE TRIGGER incident_timeline_events_no_update_delete;
