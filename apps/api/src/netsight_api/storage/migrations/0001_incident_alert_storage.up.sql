-- 0001: PostgreSQL-owned incident, alert-rule and maintenance-window storage (S6-1).
-- Mirrors contracts/json-schema/incident.schema.json and alert-rule.schema.json;
-- the CHECK constraints back up the application-level contract invariants.
-- Rollback: 0001_incident_alert_storage.down.sql (drops all data in these tables).
-- Retention: nothing here is hard-deleted by the application; there is no delete path.
-- Privileges: see 0002 and grants/app_role.sql. The runtime role must not own these tables
-- and receives only SELECT/INSERT (plus column-level UPDATE where needed); the timeline is
-- never updatable by it.

CREATE TABLE incidents (
    id uuid PRIMARY KEY,
    title text NOT NULL,
    severity text NOT NULL,
    state text NOT NULL,
    assignee_id text,
    evidence_ids text[] NOT NULL DEFAULT '{}',
    resolution jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT incidents_title_valid CHECK (char_length(title) BETWEEN 1 AND 255 AND title ~ '\S'),
    CONSTRAINT incidents_severity_valid CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT incidents_state_valid CHECK (
        state IN ('open', 'acknowledged', 'investigating', 'mitigated', 'resolved', 'closed')
    ),
    CONSTRAINT incidents_assignee_valid CHECK (
        assignee_id IS NULL OR char_length(assignee_id) BETWEEN 1 AND 255
    ),
    CONSTRAINT incidents_evidence_bounded CHECK (cardinality(evidence_ids) <= 256),
    CONSTRAINT incidents_resolution_is_object CHECK (
        resolution IS NULL OR jsonb_typeof(resolution) = 'object'
    ),
    CONSTRAINT incidents_resolution_matches_state CHECK (
        (state IN ('resolved', 'closed')) = (resolution IS NOT NULL)
    )
);

CREATE INDEX incidents_created_idx ON incidents (created_at DESC, id DESC);
CREATE INDEX incidents_state_created_idx ON incidents (state, created_at DESC, id DESC);

CREATE TABLE incident_timeline_events (
    id uuid PRIMARY KEY,
    incident_id uuid NOT NULL REFERENCES incidents (id) ON DELETE RESTRICT,
    seq integer NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor_id text NOT NULL,
    kind text NOT NULL,
    state_from text,
    state_to text,
    reason text,
    message text,
    subject_id text,
    CONSTRAINT timeline_seq_unique UNIQUE (incident_id, seq),
    CONSTRAINT timeline_seq_valid CHECK (seq BETWEEN 1 AND 1000000),
    CONSTRAINT timeline_actor_valid CHECK (char_length(actor_id) BETWEEN 1 AND 255),
    CONSTRAINT timeline_kind_valid CHECK (
        kind IN (
            'alert-linked', 'alert-unlinked', 'assignee-changed', 'comment', 'diagnostic',
            'action-proposed', 'action-approved', 'action-executed', 'evidence-added',
            'state-changed', 'resolution'
        )
    ),
    CONSTRAINT timeline_states_valid CHECK (
        (state_from IS NULL OR state_from IN
            ('open', 'acknowledged', 'investigating', 'mitigated', 'resolved', 'closed'))
        AND (state_to IS NULL OR state_to IN
            ('open', 'acknowledged', 'investigating', 'mitigated', 'resolved', 'closed'))
    ),
    CONSTRAINT timeline_state_fields_match_kind CHECK (
        (kind = 'state-changed') = (state_from IS NOT NULL AND state_to IS NOT NULL)
    ),
    CONSTRAINT timeline_state_fields_only_for_state_change CHECK (
        kind = 'state-changed' OR (state_from IS NULL AND state_to IS NULL)
    ),
    CONSTRAINT timeline_reopen_requires_reason CHECK (
        NOT (kind = 'state-changed' AND state_to = 'open') OR reason IS NOT NULL
    ),
    CONSTRAINT timeline_message_required CHECK (
        kind NOT IN ('comment', 'resolution') OR message IS NOT NULL
    ),
    CONSTRAINT timeline_subject_required CHECK (
        kind NOT IN (
            'alert-linked', 'alert-unlinked', 'diagnostic', 'action-proposed',
            'action-approved', 'action-executed', 'evidence-added'
        ) OR subject_id IS NOT NULL
    ),
    CONSTRAINT timeline_text_bounded CHECK (
        (reason IS NULL OR (char_length(reason) BETWEEN 1 AND 1000 AND reason ~ '\S'))
        AND (message IS NULL OR (char_length(message) BETWEEN 1 AND 4000 AND message ~ '\S'))
        AND (subject_id IS NULL OR char_length(subject_id) BETWEEN 1 AND 128)
    )
);

-- Append-only enforcement. Rows can be inserted and read, never changed or removed, by any
-- role holding only the grants in grants/app_role.sql. The triggers are a second layer:
-- a table owner or superuser can still DISABLE them, so the owner/migrator credential must
-- never be used by the running service (see 0002 for ENABLE ALWAYS).
CREATE FUNCTION netsight_reject_timeline_mutation() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION 'incident_timeline_events is append-only (% rejected)', TG_OP
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER incident_timeline_events_no_update_delete
    BEFORE UPDATE OR DELETE ON incident_timeline_events
    FOR EACH ROW EXECUTE FUNCTION netsight_reject_timeline_mutation();

CREATE TRIGGER incident_timeline_events_no_truncate
    BEFORE TRUNCATE ON incident_timeline_events
    FOR EACH STATEMENT EXECUTE FUNCTION netsight_reject_timeline_mutation();

CREATE TABLE alert_rules (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    status text NOT NULL,
    scope jsonb NOT NULL,
    condition jsonb NOT NULL,
    baseline_mode text NOT NULL,
    window_seconds integer NOT NULL,
    for_seconds integer NOT NULL,
    cooldown_seconds integer NOT NULL,
    schedule jsonb,
    exceptions jsonb NOT NULL,
    severity text NOT NULL,
    labels jsonb NOT NULL DEFAULT '{}',
    actions text[] NOT NULL,
    incident_policy text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    approved_by text,
    approved_at timestamptz,
    version integer NOT NULL,
    CONSTRAINT alert_rules_name_valid CHECK (char_length(name) BETWEEN 1 AND 255 AND name ~ '\S'),
    CONSTRAINT alert_rules_status_valid CHECK (status IN ('draft', 'active', 'disabled')),
    CONSTRAINT alert_rules_json_shapes CHECK (
        jsonb_typeof(scope) = 'object'
        AND jsonb_typeof(condition) = 'object'
        AND (schedule IS NULL OR jsonb_typeof(schedule) = 'object')
        AND jsonb_typeof(exceptions) = 'object'
        AND jsonb_typeof(labels) = 'object'
    ),
    CONSTRAINT alert_rules_baseline_valid CHECK (
        baseline_mode IN ('none', 'above-baseline', 'below-baseline', 'outside-baseline')
    ),
    CONSTRAINT alert_rules_window_valid CHECK (window_seconds BETWEEN 60 AND 86400),
    CONSTRAINT alert_rules_for_valid CHECK (for_seconds BETWEEN 0 AND 86400),
    CONSTRAINT alert_rules_cooldown_valid CHECK (cooldown_seconds BETWEEN 0 AND 604800),
    CONSTRAINT alert_rules_severity_valid CHECK (
        severity IN ('info', 'low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT alert_rules_actions_valid CHECK (
        cardinality(actions) BETWEEN 1 AND 3
        AND actions <@ ARRAY['create_alert', 'email', 'push']::text[]
    ),
    CONSTRAINT alert_rules_incident_policy_valid CHECK (incident_policy IN ('none', 'create', 'group')),
    CONSTRAINT alert_rules_created_by_valid CHECK (char_length(created_by) BETWEEN 1 AND 255),
    CONSTRAINT alert_rules_version_valid CHECK (version BETWEEN 1 AND 1000000),
    CONSTRAINT alert_rules_approval_pair CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CONSTRAINT alert_rules_active_requires_approval CHECK (status <> 'active' OR approved_by IS NOT NULL),
    CONSTRAINT alert_rules_draft_unapproved CHECK (status <> 'draft' OR approved_by IS NULL)
);

CREATE INDEX alert_rules_status_created_idx ON alert_rules (status, created_at DESC, id DESC);

CREATE TABLE maintenance_windows (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    scope jsonb NOT NULL,
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    evaluation text NOT NULL,
    status text NOT NULL,
    reason text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    cancelled_by text,
    cancelled_at timestamptz,
    CONSTRAINT maintenance_windows_name_valid CHECK (
        char_length(name) BETWEEN 1 AND 255 AND name ~ '\S'
    ),
    CONSTRAINT maintenance_windows_scope_shape CHECK (jsonb_typeof(scope) = 'object'),
    CONSTRAINT maintenance_windows_duration_valid CHECK (
        ends_at > starts_at AND ends_at - starts_at <= interval '30 days'
    ),
    CONSTRAINT maintenance_windows_evaluation_valid CHECK (evaluation IN ('retain', 'disable')),
    CONSTRAINT maintenance_windows_status_valid CHECK (status IN ('scheduled', 'cancelled')),
    CONSTRAINT maintenance_windows_reason_valid CHECK (
        char_length(reason) BETWEEN 1 AND 1000 AND reason ~ '\S'
    ),
    CONSTRAINT maintenance_windows_created_by_valid CHECK (char_length(created_by) BETWEEN 1 AND 255),
    CONSTRAINT maintenance_windows_cancellation_pair CHECK (
        (cancelled_by IS NULL) = (cancelled_at IS NULL)
    ),
    CONSTRAINT maintenance_windows_cancelled_matches_status CHECK (
        (status = 'cancelled') = (cancelled_by IS NOT NULL)
    )
);

CREATE INDEX maintenance_windows_schedule_idx
    ON maintenance_windows (starts_at, ends_at) WHERE status = 'scheduled';
