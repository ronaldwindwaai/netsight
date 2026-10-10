-- Reverses 0003_evaluation_links_and_delivery.up.sql. DESTRUCTIVE: removes every alert ->
-- incident link and every stored delivery attempt. The migrator refuses to run it while either
-- table holds rows unless NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1 is set. Take a backup first.
-- Incidents are untouched; after a rollback the evaluator (if enabled) would create duplicates
-- for alerts that already have an incident, so disable it first (NETSIGHT_EVALUATION_ENABLED).

DROP TABLE IF EXISTS alert_incident_links;
DROP TRIGGER IF EXISTS notification_delivery_attempts_no_truncate ON notification_delivery_attempts;
DROP TRIGGER IF EXISTS notification_delivery_attempts_no_update_delete ON notification_delivery_attempts;
DROP TABLE IF EXISTS notification_delivery_attempts;
DROP FUNCTION IF EXISTS netsight_reject_append_only_mutation();
