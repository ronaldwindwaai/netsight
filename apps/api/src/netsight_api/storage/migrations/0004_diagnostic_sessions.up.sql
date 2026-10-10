-- 0004: stored, immutable diagnostic sessions (S7 Step 4).
-- Rollback: 0004_diagnostic_sessions.down.sql (drops the table and its data).
-- Privileges: PUBLIC gets nothing; the runtime role gets SELECT and INSERT only
--   (grants/app_role.sql). No UPDATE and no DELETE exist for any role.
--
-- diagnostic_sessions: one row per finished diagnostic run. `document` is the validated
--   DiagnosticSession contract (run, per-location results, labelled cause, recent changes,
--   path), a snapshot taken when the run finished. The few columns beside it exist for the
--   newest-first list and are written from the same object in the same INSERT. `created_by` is
--   the starting identity, kept for audit and never part of the contract.
-- Defence in depth (the application already validates every document before the INSERT): the
--   database itself refuses a row whose mirrored columns (id, target, started_at, completed_at,
--   probable_fault_domain, confidence) disagree with the document, a blank target (as the
--   contract's NON_BLANK pattern does), a document over 1 MiB of text, and a document that
--   carries an incident title. Incident titles are never stored: a session keeps an incident only
--   as a reference (id, severity, time) and the title is joined at read time for callers holding
--   incidents:read (title_redacted must be true for every stored incident item).
-- Immutability: a finished session is never rewritten. The shared trigger function from 0003
--   rejects UPDATE, DELETE and TRUNCATE for every role including the owner, and the triggers
--   fire even when a session sets session_replication_role = replica. Retention: there is no
--   application delete and, today, no prune path (docs/06-data/DATA-RETENTION-MATRIX.md); the
--   retention period is a pending human decision, so no prune function is built here.
-- Residual risk (as for 0002 and 0003): the table OWNER and superusers can still DISABLE the
--   triggers, so the owner/migrator credential must stay out of the running service.
-- Requires 0003 (netsight_reject_append_only_mutation).

CREATE TABLE diagnostic_sessions (
    id uuid PRIMARY KEY,
    target text NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    probable_fault_domain text,
    confidence text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    document jsonb NOT NULL,
    CONSTRAINT diagnostic_sessions_target_valid CHECK (
        char_length(target) BETWEEN 1 AND 255 AND target ~ '\S'
    ),
    CONSTRAINT diagnostic_sessions_times_valid CHECK (completed_at >= started_at),
    CONSTRAINT diagnostic_sessions_domain_valid CHECK (
        probable_fault_domain IS NULL OR probable_fault_domain IN (
            'target', 'service', 'host', 'interface', 'access-device', 'core', 'firewall',
            'wan-dns-external'
        )
    ),
    CONSTRAINT diagnostic_sessions_confidence_valid CHECK (
        confidence IN ('low', 'medium', 'high', 'unknown')
    ),
    CONSTRAINT diagnostic_sessions_confidence_matches_domain CHECK (
        (probable_fault_domain IS NULL) = (confidence = 'unknown')
    ),
    CONSTRAINT diagnostic_sessions_creator_valid CHECK (char_length(created_by) BETWEEN 1 AND 255),
    CONSTRAINT diagnostic_sessions_document_is_object CHECK (jsonb_typeof(document) = 'object'),
    -- Bytes of the text form, not the stored column size (which is compressed and would let
    -- a highly compressible document far over the bound through).
    CONSTRAINT diagnostic_sessions_document_bounded CHECK (octet_length(document::text) <= 1048576),
    CONSTRAINT diagnostic_sessions_id_matches_document CHECK (
        document #>> '{run,id}' = 'diagnostic-' || id::text
    ),
    CONSTRAINT diagnostic_sessions_target_matches_document CHECK (
        document #>> '{run,target}' = target
    ),
    CONSTRAINT diagnostic_sessions_started_at_matches_document CHECK (
        (document #>> '{run,started_at}')::timestamptz = started_at
    ),
    CONSTRAINT diagnostic_sessions_completed_at_matches_document CHECK (
        (document #>> '{run,completed_at}')::timestamptz = completed_at
    ),
    CONSTRAINT diagnostic_sessions_domain_matches_document CHECK (
        document #>> '{run,probable_fault_domain}' IS NOT DISTINCT FROM probable_fault_domain
        AND document #>> '{probable_cause,domain}' IS NOT DISTINCT FROM probable_fault_domain
    ),
    CONSTRAINT diagnostic_sessions_confidence_matches_document CHECK (
        document #>> '{run,confidence}' = confidence
        AND document #>> '{probable_cause,confidence}' = confidence
    ),
    -- An incident item is stored as a reference: title_redacted must be exactly true. A missing
    -- or false flag on an incident item matches the path and the row is refused.
    CONSTRAINT diagnostic_sessions_no_incident_titles CHECK (
        NOT jsonb_path_exists(
            document,
            '$.recent_changes.items[*] ? (@.kind == "incident" && !exists(@.title_redacted ? (@ == true)))'
        )
    )
);

CREATE INDEX diagnostic_sessions_recent_idx ON diagnostic_sessions (completed_at DESC, id DESC);

CREATE TRIGGER diagnostic_sessions_no_update_delete
    BEFORE UPDATE OR DELETE ON diagnostic_sessions
    FOR EACH ROW EXECUTE FUNCTION netsight_reject_append_only_mutation();
CREATE TRIGGER diagnostic_sessions_no_truncate
    BEFORE TRUNCATE ON diagnostic_sessions
    FOR EACH STATEMENT EXECUTE FUNCTION netsight_reject_append_only_mutation();

-- Fire even when a session sets session_replication_role = replica (as in 0002 and 0003).
ALTER TABLE diagnostic_sessions ENABLE ALWAYS TRIGGER diagnostic_sessions_no_update_delete;
ALTER TABLE diagnostic_sessions ENABLE ALWAYS TRIGGER diagnostic_sessions_no_truncate;

REVOKE ALL ON TABLE diagnostic_sessions FROM PUBLIC;
