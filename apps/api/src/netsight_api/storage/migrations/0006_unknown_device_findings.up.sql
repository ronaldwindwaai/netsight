-- 0006: unknown-device findings and their append-only timeline (Step 8c).
-- Rollback: 0006_unknown_device_findings.down.sql (drops both tables and their data).
-- Privileges: PUBLIC gets nothing; the runtime role gets SELECT and INSERT on both tables and
--   column-level UPDATE on the findings (grants/app_role.sql). Nobody has DELETE or TRUNCATE.
--
-- unknown_device_findings: one row per endpoint that telemetry saw and NetBox did not know, for as
--   long as the finding is open. `endpoint`, `chain` (IP, MAC, switch or AP, port, VLAN: only the
--   links actually observed, the rest unknown with the reason) and `comparison` (what NetBox said)
--   are the current evidence; every change of it is an `evidence-updated` event whose `snapshot`
--   keeps the evidence of that moment. `proposed_action` is a recommendation only (the CHECK refuses
--   an executable one: executing an isolation belongs to the action engine, Step 14).
-- unknown_device_events: the append-only timeline (detected, evidence-updated, action-proposed,
--   state-changed, assignee-changed, comment).
--
-- Defence in depth (the application already validates every document and every transition):
--   * the open-finding index makes "one open finding per endpoint" a database fact, so two scanners
--     racing cannot create two;
--   * a BEFORE UPDATE trigger refuses a change of the identity columns, any change to a finished
--     finding, and any state change that is not in the lifecycle table;
--   * the events trigger rejects UPDATE, DELETE and TRUNCATE for every role including the owner, and
--     all triggers fire even when a session sets session_replication_role = replica.
-- Retention: there is no application delete and no prune path; the retention period is a pending
--   human decision (docs/06-data/DATA-RETENTION-MATRIX.md), so none is built or invented here.
-- Residual risk (as for 0002 to 0005): the table OWNER and superusers can still DISABLE the
--   triggers, so the owner/migrator credential must stay out of the running service.
-- Requires 0003 (netsight_reject_append_only_mutation).

CREATE TABLE unknown_device_findings (
    id uuid PRIMARY KEY,
    subject_key text NOT NULL,
    state text NOT NULL,
    severity text NOT NULL,
    severity_basis text NOT NULL,
    assignee_id text,
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    seen_count integer NOT NULL,
    recurrence_of uuid REFERENCES unknown_device_findings (id) ON DELETE RESTRICT,
    endpoint jsonb NOT NULL,
    chain jsonb NOT NULL,
    comparison jsonb NOT NULL,
    proposed_action jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT udf_subject_key_valid CHECK (
        subject_key ~ '^(mac:([0-9a-f]{2}:){5}[0-9a-f]{2}|ip:[0-9a-f.:]{2,45}|host:[a-z0-9._-]{1,127}|hash:[0-9a-f]{32})$'
    ),
    CONSTRAINT udf_state_valid CHECK (
        state IN ('new', 'acknowledged', 'investigating', 'resolved', 'false-positive')
    ),
    CONSTRAINT udf_severity_valid CHECK (severity IN ('low', 'medium', 'high', 'critical', 'unknown')),
    CONSTRAINT udf_severity_basis_valid CHECK (
        severity_basis IN ('policy-rule', 'policy-default', 'no-policy')
    ),
    -- Severity is the operator's policy or unknown: unknown exactly when no policy decided it.
    CONSTRAINT udf_severity_matches_basis CHECK ((severity = 'unknown') = (severity_basis = 'no-policy')),
    CONSTRAINT udf_assignee_valid CHECK (
        assignee_id IS NULL OR (char_length(assignee_id) BETWEEN 1 AND 255 AND assignee_id ~ '\S')
    ),
    CONSTRAINT udf_times_valid CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT udf_seen_count_valid CHECK (seen_count BETWEEN 1 AND 1000000),
    CONSTRAINT udf_not_its_own_recurrence CHECK (recurrence_of IS NULL OR recurrence_of <> id),
    CONSTRAINT udf_json_shapes CHECK (
        jsonb_typeof(endpoint) = 'object'
        AND jsonb_typeof(chain) = 'array' AND jsonb_array_length(chain) = 5
        AND jsonb_typeof(comparison) = 'object'
        AND (proposed_action IS NULL OR jsonb_typeof(proposed_action) = 'object')
    ),
    -- Bytes of the text forms, not the (compressed) stored size.
    CONSTRAINT udf_evidence_bounded CHECK (
        octet_length(endpoint::text) + octet_length(chain::text) + octet_length(comparison::text)
            + octet_length(coalesce(proposed_action::text, '')) <= 262144
    ),
    -- The subject key is the endpoint's identity: its MAC, else its address, else its name.
    CONSTRAINT udf_subject_matches_endpoint CHECK (
        (endpoint ->> 'mac' IS NOT NULL AND subject_key = 'mac:' || (endpoint ->> 'mac'))
        OR (endpoint ->> 'mac' IS NULL AND endpoint ->> 'ip' IS NOT NULL
            AND subject_key = 'ip:' || (endpoint ->> 'ip'))
        OR (endpoint ->> 'mac' IS NULL AND endpoint ->> 'ip' IS NULL
            AND (subject_key LIKE 'host:%' OR subject_key LIKE 'hash:%'))
    ),
    -- A quarantine is a proposal. The database refuses a document that says it can be executed.
    CONSTRAINT udf_proposal_only CHECK (
        proposed_action IS NULL OR (
            proposed_action ->> 'state' = 'proposed'
            AND proposed_action ->> 'executable' = 'false'
            AND proposed_action ->> 'action_type' = 'endpoint.isolate'
        )
    )
);

-- At most one open finding per endpoint, however many scanners run.
CREATE UNIQUE INDEX udf_one_open_per_subject
    ON unknown_device_findings (subject_key) WHERE state IN ('new', 'acknowledged', 'investigating');
CREATE INDEX udf_subject_history_idx ON unknown_device_findings (subject_key, created_at DESC, id DESC);
CREATE INDEX udf_recent_idx ON unknown_device_findings (last_seen_at DESC, id DESC);
CREATE INDEX udf_state_recent_idx ON unknown_device_findings (state, last_seen_at DESC, id DESC);

CREATE TABLE unknown_device_events (
    id uuid PRIMARY KEY,
    finding_id uuid NOT NULL REFERENCES unknown_device_findings (id) ON DELETE RESTRICT,
    seq integer NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor_id text NOT NULL,
    kind text NOT NULL,
    state_from text,
    state_to text,
    reason text,
    message text,
    subject_id text,
    snapshot jsonb,
    CONSTRAINT ude_seq_unique UNIQUE (finding_id, seq),
    CONSTRAINT ude_seq_valid CHECK (seq BETWEEN 1 AND 1000000),
    CONSTRAINT ude_actor_valid CHECK (char_length(actor_id) BETWEEN 1 AND 255),
    CONSTRAINT ude_kind_valid CHECK (
        kind IN ('detected', 'evidence-updated', 'action-proposed', 'state-changed',
                 'assignee-changed', 'comment')
    ),
    CONSTRAINT ude_state_fields_match_kind CHECK (
        (kind = 'state-changed') = (state_from IS NOT NULL AND state_to IS NOT NULL)
    ),
    CONSTRAINT ude_state_fields_only_for_state_change CHECK (
        kind = 'state-changed' OR (state_from IS NULL AND state_to IS NULL)
    ),
    -- The lifecycle table, again: a recorded state change can only be a legal one.
    CONSTRAINT ude_transition_legal CHECK (
        kind <> 'state-changed' OR (state_from, state_to) IN (
            ('new', 'acknowledged'), ('new', 'resolved'), ('new', 'false-positive'),
            ('acknowledged', 'investigating'), ('acknowledged', 'resolved'),
            ('acknowledged', 'false-positive'),
            ('investigating', 'resolved'), ('investigating', 'false-positive')
        )
    ),
    CONSTRAINT ude_final_needs_reason CHECK (
        NOT (kind = 'state-changed' AND state_to IN ('resolved', 'false-positive')) OR reason IS NOT NULL
    ),
    CONSTRAINT ude_comment_needs_message CHECK (kind <> 'comment' OR message IS NOT NULL),
    CONSTRAINT ude_text_bounded CHECK (
        (reason IS NULL OR (char_length(reason) BETWEEN 1 AND 1000 AND reason ~ '\S'))
        AND (message IS NULL OR (char_length(message) BETWEEN 1 AND 4000 AND message ~ '\S'))
        AND (subject_id IS NULL OR char_length(subject_id) BETWEEN 1 AND 255)
    ),
    CONSTRAINT ude_snapshot_valid CHECK (
        snapshot IS NULL OR (
            kind IN ('detected', 'evidence-updated')
            AND jsonb_typeof(snapshot) = 'object'
            AND octet_length(snapshot::text) <= 262144
        )
    )
);

CREATE TRIGGER unknown_device_events_no_update_delete
    BEFORE UPDATE OR DELETE ON unknown_device_events
    FOR EACH ROW EXECUTE FUNCTION netsight_reject_append_only_mutation();
CREATE TRIGGER unknown_device_events_no_truncate
    BEFORE TRUNCATE ON unknown_device_events
    FOR EACH STATEMENT EXECUTE FUNCTION netsight_reject_append_only_mutation();
-- Findings are never deleted: no application path and no role may do it.
CREATE TRIGGER unknown_device_findings_no_delete
    BEFORE DELETE ON unknown_device_findings
    FOR EACH ROW EXECUTE FUNCTION netsight_reject_append_only_mutation();
CREATE TRIGGER unknown_device_findings_no_truncate
    BEFORE TRUNCATE ON unknown_device_findings
    FOR EACH STATEMENT EXECUTE FUNCTION netsight_reject_append_only_mutation();

CREATE FUNCTION netsight_guard_unknown_device_update() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.subject_key IS DISTINCT FROM OLD.subject_key
        OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at
        OR NEW.recurrence_of IS DISTINCT FROM OLD.recurrence_of
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'unknown_device_findings identity columns are immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.state IN ('resolved', 'false-positive') THEN
        RAISE EXCEPTION 'a finished finding is not changed'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
        (OLD.state = 'new' AND NEW.state IN ('acknowledged', 'resolved', 'false-positive'))
        OR (OLD.state = 'acknowledged' AND NEW.state IN ('investigating', 'resolved', 'false-positive'))
        OR (OLD.state = 'investigating' AND NEW.state IN ('resolved', 'false-positive'))
    ) THEN
        RAISE EXCEPTION 'this state change is not part of the finding lifecycle'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER unknown_device_findings_guard_update
    BEFORE UPDATE ON unknown_device_findings
    FOR EACH ROW EXECUTE FUNCTION netsight_guard_unknown_device_update();

-- Fire even when a session sets session_replication_role = replica (as in 0002 to 0005).
ALTER TABLE unknown_device_events ENABLE ALWAYS TRIGGER unknown_device_events_no_update_delete;
ALTER TABLE unknown_device_events ENABLE ALWAYS TRIGGER unknown_device_events_no_truncate;
ALTER TABLE unknown_device_findings ENABLE ALWAYS TRIGGER unknown_device_findings_no_delete;
ALTER TABLE unknown_device_findings ENABLE ALWAYS TRIGGER unknown_device_findings_no_truncate;
ALTER TABLE unknown_device_findings ENABLE ALWAYS TRIGGER unknown_device_findings_guard_update;

REVOKE ALL ON TABLE unknown_device_findings, unknown_device_events FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_guard_unknown_device_update() FROM PUBLIC;
