-- Reverses 0006_unknown_device_findings.up.sql. DESTRUCTIVE: removes every unknown-device finding
-- and its timeline. The migrator refuses to run it while either table holds rows unless
-- NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1 is set. Take a backup first.
-- Dropping a table drops its triggers; the shared append-only function belongs to 0003 and stays.
-- The events go first: they reference the findings.

DROP TABLE IF EXISTS unknown_device_events;
DROP TABLE IF EXISTS unknown_device_findings;
DROP FUNCTION IF EXISTS netsight_guard_unknown_device_update();
