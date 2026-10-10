-- Reverses 0004_diagnostic_sessions.up.sql. DESTRUCTIVE: removes every stored diagnostic
-- session. The migrator refuses to run it while the table holds rows unless
-- NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1 is set. Take a backup first.
-- Dropping the table drops its triggers; the shared trigger function belongs to 0003 and stays.

DROP TABLE IF EXISTS diagnostic_sessions;
