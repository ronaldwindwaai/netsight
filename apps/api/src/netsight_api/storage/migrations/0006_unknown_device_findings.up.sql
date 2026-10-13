-- 0006: unknown-device findings and their append-only timeline (Step 8c, amended by the review fix pass).
-- Rollback: 0006_unknown_device_findings.down.sql (drops both tables, their functions and their data).
-- Not yet applied anywhere, so the review fixes amend this migration in place.
-- Privileges: PUBLIC gets nothing; the runtime role gets SELECT and INSERT on both tables and
--   column-level UPDATE on the findings (grants/app_role.sql). Nobody has DELETE or TRUNCATE.
--
-- unknown_device_findings: one row per endpoint that telemetry saw and NetBox did not know, for as
--   long as the finding is open. `endpoint`, `chain` (IP, MAC, switch or AP, port, VLAN: only the
--   links actually observed, the rest unknown with the reason) and `comparison` (what NetBox said)
--   are the current evidence; every change of it is an `evidence-updated` event whose `snapshot`
--   keeps the evidence of that moment. `proposed_action` is a recommendation only (the CHECK refuses
--   an executable one: executing an isolation belongs to the action engine, Step 14).
--   `evidence_version` counts changes of the evidence (not sightings): the trigger moves it, no role
--   can set it, and a person's decision quotes it so it loses (409) if the evidence moved on.
-- unknown_device_events: the append-only timeline (detected, evidence-updated, action-proposed,
--   state-changed, assignee-changed, comment, suppressed-sighting).
--
-- Identity policy: the MAC is authoritative. A finding is stored under ONE key (its MAC, else its
--   address, else its name) fixed at creation; the application matches a sighting against every key
--   of its endpoint (MAC and address), so a dismissal on a MAC also covers the address and the other
--   way round. Keys are lower case and canonical (the endpoint's address is canonical by contract).
--
-- Defence in depth (the application already validates every document and every transition):
--   * the open-finding index makes "one open finding per endpoint" a database fact, so two scanners
--     racing cannot create two;
--   * a BEFORE INSERT trigger makes every finding start new, unassigned, seen once, with a key that
--     is derived from its endpoint; a BEFORE UPDATE trigger refuses a change of the identity columns,
--     any change to a finished finding, a state change that is not in the lifecycle table, and a
--     finding that goes back in time or loses sightings;
--   * the TIMELINE IS THE RECORD of every decision: DEFERRABLE INITIALLY DEFERRED constraint triggers
--     fail the commit unless, in the same transaction, the finding's state is what its last
--     `state-changed` event says (starting from 'new'), its assignee is what its last
--     `assignee-changed` event says, and its evidence equals the snapshot of its last `detected` or
--     `evidence-updated` event; and conversely a `state-changed` event must start from the state the
--     timeline left the finding in, an `assignee-changed` event must change the assignee and an
--     `evidence-updated` event must change the evidence. So no row can change without its event, and
--     no event can claim a change that did not happen;
--   * the events trigger rejects UPDATE, DELETE and TRUNCATE for every role including the owner, and
--     all triggers fire even when a session sets session_replication_role = replica.
-- Retention: there is no application delete and no prune path; the retention period is a pending
--   human decision (docs/06-data/DATA-RETENTION-MATRIX.md), so none is built or invented here. The
--   designed options (SECURITY DEFINER prune with a session flag, partitioning by month) are written
--   up there and in docs/12-implementation/INVENTORY-IPAM.md, not implemented.
-- Residual risk (as for 0002 to 0005): the table OWNER and superusers can still DISABLE the
--   triggers, so the owner/migrator credential must stay out of the running service.
-- Requires 0003 (netsight_reject_append_only_mutation).

CREATE TABLE unknown_device_findings (
    id uuid PRIMARY KEY,
    subject_key text NOT NULL,
    state text NOT NULL,
    severity text NOT NULL,
    severity_basis text NOT NULL,
    evidence_version integer NOT NULL DEFAULT 1,
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
    -- Lower case, and canonical: an address key has no leading zeros (IPv4) and no upper case (IPv6).
    CONSTRAINT udf_subject_key_valid CHECK (
        subject_key = lower(subject_key)
        AND subject_key ~ (
            '^(mac:([0-9a-f]{2}:){5}[0-9a-f]{2}'
            '|ip:(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
            '|([0-9a-f]{0,4}:){2,7}[0-9a-f.]{0,15})'
            '|host:[a-z0-9._-]{1,127}|hash:[0-9a-f]{32})$'
        )
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
    CONSTRAINT udf_evidence_version_valid CHECK (evidence_version BETWEEN 1 AND 1000000),
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
        AND comparison ->> 'reason' IN ('no-match', 'name-matches-mac-does-not')
        AND (proposed_action IS NULL OR jsonb_typeof(proposed_action) = 'object')
    ),
    -- Bytes of the text forms, not the (compressed) stored size.
    CONSTRAINT udf_evidence_bounded CHECK (
        octet_length(endpoint::text) + octet_length(chain::text) + octet_length(comparison::text)
            + octet_length(coalesce(proposed_action::text, '')) <= 262144
    ),
    -- The key names the endpoint. A MAC key is the endpoint's MAC. An address key stays valid when
    -- the MAC becomes known later (the key never changes), so it only needs an address or a MAC to
    -- stand for; the INSERT trigger below derives the key exactly at creation.
    CONSTRAINT udf_subject_matches_endpoint CHECK (
        (subject_key LIKE 'mac:%'
            AND coalesce(subject_key = 'mac:' || (endpoint ->> 'mac'), false))
        OR (subject_key LIKE 'ip:%'
            AND coalesce(endpoint ->> 'mac' IS NOT NULL
                         OR subject_key = 'ip:' || (endpoint ->> 'ip'), false))
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
-- Newest sighting first: everything, and (partial, small) just the open findings the page shows.
CREATE INDEX udf_recent_idx ON unknown_device_findings (last_seen_at DESC, id DESC);
CREATE INDEX udf_open_recent_idx ON unknown_device_findings (last_seen_at DESC, id DESC)
    WHERE state IN ('new', 'acknowledged', 'investigating');
-- A sighting is matched by every key of its endpoint, including the MAC and address a finding
-- opened under another key has since gained.
CREATE INDEX udf_endpoint_mac_idx ON unknown_device_findings ((endpoint ->> 'mac'))
    WHERE endpoint ->> 'mac' IS NOT NULL;
CREATE INDEX udf_endpoint_ip_idx ON unknown_device_findings ((endpoint ->> 'ip'))
    WHERE endpoint ->> 'ip' IS NOT NULL;

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
                 'assignee-changed', 'comment', 'suppressed-sighting')
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
    -- Free text lives only where a person writes it.
    CONSTRAINT ude_message_only_for_comments CHECK (message IS NULL OR kind = 'comment'),
    CONSTRAINT ude_reason_only_for_state_changes CHECK (reason IS NULL OR kind = 'state-changed'),
    CONSTRAINT ude_subject_only_for_assignments CHECK (
        subject_id IS NULL OR kind = 'assignee-changed'
    ),
    CONSTRAINT ude_text_bounded CHECK (
        (reason IS NULL OR (char_length(reason) BETWEEN 1 AND 1000 AND reason ~ '\S'))
        AND (message IS NULL OR (char_length(message) BETWEEN 1 AND 4000 AND message ~ '\S'))
        AND (subject_id IS NULL OR char_length(subject_id) BETWEEN 1 AND 255)
    ),
    -- The first event of a finding is its detection, and it keeps the evidence of that moment.
    CONSTRAINT ude_detected_is_first CHECK (kind <> 'detected' OR seq = 1),
    CONSTRAINT ude_snapshot_valid CHECK (
        (kind IN ('detected', 'evidence-updated', 'suppressed-sighting')) = (snapshot IS NOT NULL)
        AND (
            snapshot IS NULL OR (
                jsonb_typeof(snapshot) = 'object'
                AND octet_length(snapshot::text) <= 262144
            )
        )
    )
);
CREATE INDEX ude_finding_kind_idx ON unknown_device_events (finding_id, kind, seq DESC);

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

-- What counts as "the evidence" of a finding, in one place: the endpoint, the chain, the severity and
-- its basis, the proposal, and what NetBox said (the verdict of each check and the reason, not the
-- times and details, which change on every sighting). Used for the version counter and to compare a
-- finding with the snapshot of its last evidence event.
CREATE FUNCTION netsight_udf_evidence(
    p_endpoint jsonb, p_chain jsonb, p_comparison jsonb, p_severity text, p_basis text,
    p_action jsonb
) RETURNS jsonb
    LANGUAGE sql IMMUTABLE AS
$$
    SELECT jsonb_build_object(
        'endpoint', p_endpoint,
        'chain', p_chain,
        'severity', p_severity,
        'severity_basis', p_basis,
        'proposed_action', coalesce(p_action, 'null'::jsonb),
        'reason', p_comparison -> 'reason',
        'checks', (
            SELECT coalesce(
                jsonb_agg(jsonb_build_object('field', c ->> 'field', 'result', c ->> 'result')
                          ORDER BY o),
                '[]'::jsonb)
            FROM jsonb_array_elements(p_comparison -> 'checks') WITH ORDINALITY AS t (c, o)
        )
    )
$$;

CREATE FUNCTION netsight_guard_unknown_device_insert() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NEW.state <> 'new' OR NEW.seen_count <> 1 OR NEW.assignee_id IS NOT NULL
        OR NEW.first_seen_at <> NEW.last_seen_at THEN
        RAISE EXCEPTION 'a finding starts new, unassigned and seen once'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT (
        (NEW.endpoint ->> 'mac' IS NOT NULL AND NEW.subject_key = 'mac:' || (NEW.endpoint ->> 'mac'))
        OR (NEW.endpoint ->> 'mac' IS NULL AND NEW.endpoint ->> 'ip' IS NOT NULL
            AND NEW.subject_key = 'ip:' || (NEW.endpoint ->> 'ip'))
        OR (NEW.endpoint ->> 'mac' IS NULL AND NEW.endpoint ->> 'ip' IS NULL
            AND (NEW.subject_key LIKE 'host:%' OR NEW.subject_key LIKE 'hash:%'))
    ) THEN
        RAISE EXCEPTION 'the subject key of a new finding is its MAC, else its address, else its name'
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.evidence_version := 1;
    RETURN NEW;
END;
$$;

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
    IF NEW.last_seen_at < OLD.last_seen_at OR NEW.seen_count < OLD.seen_count THEN
        RAISE EXCEPTION 'a finding does not go back in time or lose sightings'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- The version moves exactly when the evidence does, by one, whatever the statement said.
    IF netsight_udf_evidence(NEW.endpoint, NEW.chain, NEW.comparison, NEW.severity,
                             NEW.severity_basis, NEW.proposed_action)
        IS DISTINCT FROM netsight_udf_evidence(OLD.endpoint, OLD.chain, OLD.comparison, OLD.severity,
                                               OLD.severity_basis, OLD.proposed_action) THEN
        NEW.evidence_version := LEAST(OLD.evidence_version + 1, 1000000);
    ELSE
        NEW.evidence_version := OLD.evidence_version;
    END IF;
    RETURN NEW;
END;
$$;

-- The finding must be what its timeline says. Called at commit, for the finding or the event that
-- was written (see the constraint triggers below).
CREATE FUNCTION netsight_check_unknown_device_log(p_finding uuid) RETURNS void
    LANGUAGE plpgsql AS
$$
DECLARE
    f unknown_device_findings%ROWTYPE;
    logged_state text;
    logged_assignee text;
    snap jsonb;
BEGIN
    SELECT * INTO f FROM unknown_device_findings WHERE id = p_finding;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT state_to INTO logged_state FROM unknown_device_events
        WHERE finding_id = p_finding AND kind = 'state-changed' ORDER BY seq DESC LIMIT 1;
    IF f.state IS DISTINCT FROM coalesce(logged_state, 'new') THEN
        RAISE EXCEPTION 'the state of a finding is what its timeline says'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT subject_id INTO logged_assignee FROM unknown_device_events
        WHERE finding_id = p_finding AND kind = 'assignee-changed' ORDER BY seq DESC LIMIT 1;
    IF f.assignee_id IS DISTINCT FROM logged_assignee THEN
        RAISE EXCEPTION 'the assignee of a finding is what its timeline says'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT snapshot INTO snap FROM unknown_device_events
        WHERE finding_id = p_finding AND kind IN ('detected', 'evidence-updated')
        ORDER BY seq DESC LIMIT 1;
    IF snap IS NULL
        OR netsight_udf_evidence(f.endpoint, f.chain, f.comparison, f.severity, f.severity_basis,
                                 f.proposed_action)
           IS DISTINCT FROM netsight_udf_evidence(snap -> 'endpoint', snap -> 'chain',
                                                  snap -> 'comparison', snap ->> 'severity',
                                                  snap ->> 'severity_basis', snap -> 'proposed_action')
    THEN
        RAISE EXCEPTION 'the evidence of a finding is what its last snapshot says'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
END;
$$;

CREATE FUNCTION netsight_unknown_device_finding_logged() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    PERFORM netsight_check_unknown_device_log(NEW.id);
    RETURN NULL;
END;
$$;

-- An event may not claim a change that did not happen: each starts from where the timeline left off.
CREATE FUNCTION netsight_unknown_device_event_logged() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    previous_state text;
    previous_assignee text;
    previous_snapshot jsonb;
BEGIN
    IF NEW.kind = 'state-changed' THEN
        SELECT state_to INTO previous_state FROM unknown_device_events
            WHERE finding_id = NEW.finding_id AND kind = 'state-changed' AND seq < NEW.seq
            ORDER BY seq DESC LIMIT 1;
        IF NEW.state_from IS DISTINCT FROM coalesce(previous_state, 'new') THEN
            RAISE EXCEPTION 'a state change starts from the state the timeline left the finding in'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF NEW.kind = 'assignee-changed' THEN
        SELECT subject_id INTO previous_assignee FROM unknown_device_events
            WHERE finding_id = NEW.finding_id AND kind = 'assignee-changed' AND seq < NEW.seq
            ORDER BY seq DESC LIMIT 1;
        IF NEW.subject_id IS NOT DISTINCT FROM previous_assignee THEN
            RAISE EXCEPTION 'an assignment that changes nothing is not recorded'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF NEW.kind = 'evidence-updated' THEN
        SELECT snapshot INTO previous_snapshot FROM unknown_device_events
            WHERE finding_id = NEW.finding_id AND kind IN ('detected', 'evidence-updated')
              AND seq < NEW.seq
            ORDER BY seq DESC LIMIT 1;
        IF previous_snapshot IS NULL
            OR netsight_udf_evidence(NEW.snapshot -> 'endpoint', NEW.snapshot -> 'chain',
                                     NEW.snapshot -> 'comparison', NEW.snapshot ->> 'severity',
                                     NEW.snapshot ->> 'severity_basis',
                                     NEW.snapshot -> 'proposed_action')
               IS NOT DISTINCT FROM netsight_udf_evidence(
                                     previous_snapshot -> 'endpoint', previous_snapshot -> 'chain',
                                     previous_snapshot -> 'comparison',
                                     previous_snapshot ->> 'severity',
                                     previous_snapshot ->> 'severity_basis',
                                     previous_snapshot -> 'proposed_action')
        THEN
            RAISE EXCEPTION 'an evidence update changes the evidence'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    PERFORM netsight_check_unknown_device_log(NEW.finding_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER unknown_device_findings_guard_insert
    BEFORE INSERT ON unknown_device_findings
    FOR EACH ROW EXECUTE FUNCTION netsight_guard_unknown_device_insert();
CREATE TRIGGER unknown_device_findings_guard_update
    BEFORE UPDATE ON unknown_device_findings
    FOR EACH ROW EXECUTE FUNCTION netsight_guard_unknown_device_update();
CREATE CONSTRAINT TRIGGER unknown_device_findings_logged
    AFTER INSERT OR UPDATE ON unknown_device_findings
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION netsight_unknown_device_finding_logged();
CREATE CONSTRAINT TRIGGER unknown_device_events_logged
    AFTER INSERT ON unknown_device_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (NEW.kind IN ('detected', 'state-changed', 'assignee-changed', 'evidence-updated'))
    EXECUTE FUNCTION netsight_unknown_device_event_logged();

-- Fire even when a session sets session_replication_role = replica (as in 0002 to 0005).
ALTER TABLE unknown_device_events ENABLE ALWAYS TRIGGER unknown_device_events_no_update_delete;
ALTER TABLE unknown_device_events ENABLE ALWAYS TRIGGER unknown_device_events_no_truncate;
ALTER TABLE unknown_device_events ENABLE ALWAYS TRIGGER unknown_device_events_logged;
ALTER TABLE unknown_device_findings ENABLE ALWAYS TRIGGER unknown_device_findings_no_delete;
ALTER TABLE unknown_device_findings ENABLE ALWAYS TRIGGER unknown_device_findings_no_truncate;
ALTER TABLE unknown_device_findings ENABLE ALWAYS TRIGGER unknown_device_findings_guard_insert;
ALTER TABLE unknown_device_findings ENABLE ALWAYS TRIGGER unknown_device_findings_guard_update;
ALTER TABLE unknown_device_findings ENABLE ALWAYS TRIGGER unknown_device_findings_logged;

REVOKE ALL ON TABLE unknown_device_findings, unknown_device_events FROM PUBLIC;
-- The trigger functions are not callable by anyone (a trigger needs no EXECUTE to fire). The two
-- helpers they call stay executable by the invoking role: netsight_udf_evidence is pure and
-- netsight_check_unknown_device_log only reads rows that role can already read.
REVOKE ALL ON FUNCTION netsight_guard_unknown_device_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_guard_unknown_device_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_unknown_device_finding_logged() FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_unknown_device_event_logged() FROM PUBLIC;
