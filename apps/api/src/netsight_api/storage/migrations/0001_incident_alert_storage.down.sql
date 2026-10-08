-- Reverses 0001_incident_alert_storage.up.sql. DESTRUCTIVE: removes all incident,
-- timeline, alert-rule and maintenance-window data. Take a backup first.

DROP TABLE IF EXISTS maintenance_windows;
DROP TABLE IF EXISTS alert_rules;
DROP TRIGGER IF EXISTS incident_timeline_events_no_truncate ON incident_timeline_events;
DROP TRIGGER IF EXISTS incident_timeline_events_no_update_delete ON incident_timeline_events;
DROP TABLE IF EXISTS incident_timeline_events;
DROP FUNCTION IF EXISTS netsight_reject_timeline_mutation();
DROP TABLE IF EXISTS incidents;
