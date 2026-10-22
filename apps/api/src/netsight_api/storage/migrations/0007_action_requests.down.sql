-- Reverses 0007_action_requests.up.sql. DESTRUCTIVE: removes every action request and its history,
-- including the hash-chained record of who approved and ran what. The migrator refuses to run it while
-- either table holds rows unless NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1 is set. Take a backup first (the
-- audit log is the only other record of these decisions).
-- Dropping a table drops its triggers; the shared append-only function belongs to 0003 and stays.
-- The history goes first: it references the requests.

DROP TABLE IF EXISTS action_history;
DROP TABLE IF EXISTS action_requests;
DROP FUNCTION IF EXISTS netsight_action_event_logged();
DROP FUNCTION IF EXISTS netsight_action_request_logged();
DROP FUNCTION IF EXISTS netsight_check_action_log(text);
DROP FUNCTION IF EXISTS netsight_guard_action_event_insert();
DROP FUNCTION IF EXISTS netsight_guard_action_request_update();
DROP FUNCTION IF EXISTS netsight_guard_action_request_insert();
DROP FUNCTION IF EXISTS netsight_action_state_is_final(text);
DROP FUNCTION IF EXISTS netsight_action_transition_ok(text, text);
