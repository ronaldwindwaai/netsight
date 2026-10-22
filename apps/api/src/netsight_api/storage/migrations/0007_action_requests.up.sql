-- 0007: action requests and their append-only, hash-chained history (Step 12 follow-up, D-53).
-- Rollback: 0007_action_requests.down.sql (drops both tables, their functions and their data).
-- Privileges: PUBLIC gets nothing; the runtime role gets SELECT and INSERT on both tables and
--   column-level UPDATE on the mutable columns of the requests (grants/app_role.sql). Nobody has
--   DELETE or TRUNCATE on either table.
--
-- action_requests: one row per Action Request, so requests survive a restart and are shared by every
--   worker. The identity of a request (type, target, parameters, risk, requester, reason, source,
--   deadline, digest, idempotency key) is fixed at creation and no role can change it; what moves is
--   the state, the version, the approvals, the execution record and the pre-checks. `digest` binds the
--   content a person approved and `version` is the position in the history, so a decision that quotes
--   either loses (409) if the request moved on.
-- action_history: the append-only SHA-256 hash chain of every event of a request. The application
--   computes each hash (actions/history.py); the database checks that every event continues the chain
--   (sequence, link to the previous hash, the state it starts from, a legal lifecycle move) and that
--   nothing is ever edited, deleted or truncated.
--
-- Eviction: the store holds at most 5000 requests; the oldest FINISHED one makes room for a new one.
--   Nothing is deleted: `evicted_at` hides the request (and frees its idempotency key) while the row and
--   its history stay as the record. The retention period is a pending human decision
--   (docs/06-data/DATA-RETENTION-MATRIX.md), so no prune path is built or invented here.
--
-- Defence in depth (the application already validates every transition under a row lock):
--   * partial unique indexes make "one open request per action and target", "one running action per
--     target" and "one request per requester and idempotency key" database facts;
--   * CHECK constraints mirror the lifecycle states and the contract's shapes and bounds;
--   * a BEFORE INSERT trigger makes every request start proposed at version 1 with nothing decided; a
--     BEFORE UPDATE trigger refuses a change of the identity columns, any change to a finished request
--     (but its eviction), a state change that is not in the lifecycle table, a version that does not
--     advance, an approval list that loses an entry, repeats a person or contains the requester, and
--     an execution key that changes;
--   * THE HISTORY IS THE RECORD: a DEFERRABLE INITIALLY DEFERRED constraint trigger fails the commit
--     unless, in the same transaction, the request's version and state are those of its last event, its
--     approvals match the `approved` events and its execution record matches an `execution-started`
--     event. So no request changes without its event and no event claims a change that did not happen;
--   * the history trigger rejects an event that does not continue the chain, a move the lifecycle does
--     not allow and any event after the request finished; UPDATE, DELETE and TRUNCATE are rejected for
--     every role including the owner, and all triggers fire even when a session sets
--     session_replication_role = replica.
-- search_path: the functions here pin theirs (see the end of the file). The trigger functions of 0006 (and
--   0002 to 0004) resolve their tables through the session search_path and do not; that is reported as a
--   follow-up, not changed here.
-- Residual risk (as for 0002 to 0006): the table OWNER and superusers can still DISABLE the triggers,
--   so the owner/migrator credential must stay out of the running service. A tampered history is then
--   still detectable: the stored hashes no longer verify (verify_chain).
-- Requires 0003 (netsight_reject_append_only_mutation).

-- The lifecycle table (schemas_actions.ALLOWED_TRANSITIONS), once, for the triggers and the CHECKs.
CREATE FUNCTION netsight_action_transition_ok(p_from text, p_to text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS
$$
    SELECT (p_from, p_to) IN (
        ('proposed', 'pending-approval'), ('proposed', 'rejected'), ('proposed', 'cancelled'),
        ('pending-approval', 'approved'), ('pending-approval', 'rejected'),
        ('pending-approval', 'expired'), ('pending-approval', 'cancelled'),
        ('approved', 'executing'), ('approved', 'expired'), ('approved', 'cancelled'),
        ('executing', 'succeeded'), ('executing', 'failed'), ('executing', 'rolled-back')
    )
$$;

CREATE FUNCTION netsight_action_state_is_final(p_state text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS
$$
    SELECT p_state IN ('rejected', 'expired', 'cancelled', 'succeeded', 'failed', 'rolled-back')
$$;

CREATE TABLE action_requests (
    id text PRIMARY KEY,
    action_type text NOT NULL,
    target_id text NOT NULL,
    params jsonb NOT NULL,
    risk text NOT NULL,
    state text NOT NULL,
    requester_id text NOT NULL,
    requester_kind text NOT NULL,
    reason text NOT NULL,
    source jsonb,
    approvals_required smallint NOT NULL,
    approvals jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL,
    approve_by timestamptz NOT NULL,
    execute_by timestamptz,
    execute_within_seconds integer NOT NULL,
    timeout_seconds integer NOT NULL,
    -- When a running action is failed for never reporting back; set with the execution record.
    run_by timestamptz,
    version integer NOT NULL,
    digest text NOT NULL,
    policy_checks jsonb NOT NULL,
    pre_checks jsonb NOT NULL DEFAULT '[]'::jsonb,
    execution jsonb,
    create_key text NOT NULL,
    create_fingerprint text NOT NULL,
    -- (idempotency key, person) of the run: a retry replays only for the person who started it.
    exec_key text,
    exec_actor_id text,
    evicted_at timestamptz,
    CONSTRAINT action_id_valid CHECK (
        char_length(id) = 43
        AND id ~ '^action-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+$'
    ),
    CONSTRAINT action_type_valid CHECK (
        action_type IN ('endpoint.isolate', 'switch.port.disable', 'switch.port.enable')
    ),
    CONSTRAINT action_target_valid CHECK (
        char_length(target_id) BETWEEN 1 AND 128 AND target_id ~ '^[a-z0-9][a-z0-9._:-]*$'
    ),
    CONSTRAINT action_risk_valid CHECK (risk IN ('A', 'B', 'C', 'D')),
    CONSTRAINT action_state_valid CHECK (
        state IN ('proposed', 'pending-approval', 'approved', 'rejected', 'expired', 'cancelled',
                  'executing', 'succeeded', 'failed', 'rolled-back')
    ),
    CONSTRAINT action_requester_valid CHECK (
        char_length(requester_id) BETWEEN 1 AND 255 AND requester_kind IN ('human', 'service', 'ai')
    ),
    CONSTRAINT action_reason_valid CHECK (char_length(reason) BETWEEN 3 AND 500),
    CONSTRAINT action_approvals_required_valid CHECK (approvals_required BETWEEN 1 AND 2),
    CONSTRAINT action_json_shapes CHECK (
        jsonb_typeof(params) = 'object'
        AND jsonb_typeof(approvals) = 'array'
        AND jsonb_array_length(approvals) <= approvals_required
        AND jsonb_typeof(policy_checks) = 'array' AND jsonb_array_length(policy_checks) <= 16
        AND jsonb_typeof(pre_checks) = 'array' AND jsonb_array_length(pre_checks) <= 16
        AND (source IS NULL OR jsonb_typeof(source) = 'object')
        AND (execution IS NULL OR jsonb_typeof(execution) = 'object')
    ),
    CONSTRAINT action_params_bounded CHECK (octet_length(params::text) <= 4096),
    -- Bytes of the text forms (as 0005 bounds its documents), so no column can hold an unbounded document.
    CONSTRAINT action_documents_bounded CHECK (
        octet_length(policy_checks::text) <= 1048576 AND octet_length(pre_checks::text) <= 1048576
        AND octet_length(coalesce(execution::text, '')) <= 1048576
        AND octet_length(coalesce(source::text, '')) <= 1048576
    ),
    CONSTRAINT action_seconds_valid CHECK (
        execute_within_seconds BETWEEN 1 AND 604800 AND timeout_seconds BETWEEN 1 AND 86400
    ),
    CONSTRAINT action_version_valid CHECK (version BETWEEN 1 AND 1000000),
    CONSTRAINT action_digest_valid CHECK (
        char_length(digest) = 71 AND digest ~ '^sha256:[0-9a-f]+$'
    ),
    CONSTRAINT action_create_key_valid CHECK (
        char_length(create_key) BETWEEN 16 AND 64 AND create_key ~ '^[A-Za-z0-9._-]+$'
        AND char_length(create_fingerprint) = 64 AND create_fingerprint ~ '^[0-9a-f]+$'
    ),
    CONSTRAINT action_exec_key_valid CHECK (
        (exec_key IS NULL) = (exec_actor_id IS NULL)
        AND (exec_key IS NULL OR (
            char_length(exec_key) BETWEEN 16 AND 64 AND exec_key ~ '^[A-Za-z0-9._-]+$'
            AND char_length(exec_actor_id) BETWEEN 1 AND 255
        ))
    ),
    -- The lifecycle, again: what each state implies about the rest of the request.
    CONSTRAINT action_approved_has_deadline CHECK (state <> 'approved' OR execute_by IS NOT NULL),
    CONSTRAINT action_decided_has_every_approval CHECK (
        state NOT IN ('approved', 'executing', 'succeeded', 'failed', 'rolled-back')
        OR jsonb_array_length(approvals) >= approvals_required
    ),
    CONSTRAINT action_nothing_ran_before_approval CHECK (
        state NOT IN ('proposed', 'pending-approval', 'approved')
        OR (execution IS NULL AND run_by IS NULL AND exec_key IS NULL)
    ),
    CONSTRAINT action_running_has_a_record CHECK (
        state <> 'executing' OR (execution IS NOT NULL AND run_by IS NOT NULL AND exec_key IS NOT NULL)
    ),
    CONSTRAINT action_finished_run_is_recorded CHECK (
        state NOT IN ('succeeded', 'rolled-back') OR execution IS NOT NULL
    ),
    CONSTRAINT action_only_finished_is_evicted CHECK (
        evicted_at IS NULL OR netsight_action_state_is_final(state)
    )
);

-- One open request per action type and target, however many workers propose.
CREATE UNIQUE INDEX action_one_open_per_target
    ON action_requests (action_type, target_id)
    WHERE state IN ('proposed', 'pending-approval', 'approved', 'executing');
-- At most one execution runs on a target at a time.
CREATE UNIQUE INDEX action_one_executing_per_target
    ON action_requests (target_id) WHERE state = 'executing';
-- A creation key is scoped to its requester; an evicted request gives its key back.
CREATE UNIQUE INDEX action_create_key_unique
    ON action_requests (requester_id, create_key) WHERE evicted_at IS NULL;
-- The open requests (counted per requester, swept for deadlines) are few; the finished ones many.
CREATE INDEX action_open_idx ON action_requests (requester_id)
    WHERE state IN ('proposed', 'pending-approval', 'approved', 'executing');
CREATE INDEX action_listing_idx ON action_requests (created_at DESC, id DESC)
    WHERE evicted_at IS NULL;
CREATE INDEX action_state_listing_idx ON action_requests (state, created_at DESC, id DESC)
    WHERE evicted_at IS NULL;
-- Oldest finished request first: who makes room when the store is full.
CREATE INDEX action_evictable_idx ON action_requests (created_at, id)
    WHERE evicted_at IS NULL
      AND state IN ('rejected', 'expired', 'cancelled', 'succeeded', 'failed', 'rolled-back');

CREATE TABLE action_history (
    action_id text NOT NULL REFERENCES action_requests (id) ON DELETE RESTRICT,
    seq integer NOT NULL,
    at timestamptz NOT NULL,
    type text NOT NULL,
    actor_id text,
    from_state text,
    to_state text NOT NULL,
    code text NOT NULL,
    note text,
    prev_hash text NOT NULL,
    hash text NOT NULL,
    CONSTRAINT action_history_pk PRIMARY KEY (action_id, seq),
    CONSTRAINT action_history_seq_valid CHECK (seq BETWEEN 1 AND 1000000),
    CONSTRAINT action_history_type_valid CHECK (
        type IN ('proposed', 'policy-checked', 'submitted', 'approved', 'rejected', 'cancelled',
                 'expired', 'execution-started', 'pre-check-failed', 'executed',
                 'verification-passed', 'verification-failed', 'rolled-back', 'rollback-failed',
                 'failed')
    ),
    CONSTRAINT action_history_states_valid CHECK (
        to_state IN ('proposed', 'pending-approval', 'approved', 'rejected', 'expired', 'cancelled',
                     'executing', 'succeeded', 'failed', 'rolled-back')
        AND (from_state IS NULL OR from_state IN (
            'proposed', 'pending-approval', 'approved', 'rejected', 'expired', 'cancelled',
            'executing', 'succeeded', 'failed', 'rolled-back'))
    ),
    -- Only the first event has no earlier state, and it starts the chain from the zero hash.
    CONSTRAINT action_history_first_event CHECK (
        (seq = 1) = (from_state IS NULL)
        AND (seq > 1 OR (prev_hash = repeat('0', 64) AND type = 'proposed' AND to_state = 'proposed'))
    ),
    -- The lifecycle table, again: a recorded move can only be a legal one (or none).
    CONSTRAINT action_history_move_legal CHECK (
        from_state IS NULL OR from_state = to_state OR netsight_action_transition_ok(from_state, to_state)
    ),
    CONSTRAINT action_history_code_valid CHECK (
        char_length(code) BETWEEN 2 AND 64 AND code ~ '^[a-z][a-z0-9-]+$'
    ),
    CONSTRAINT action_history_actor_valid CHECK (actor_id IS NULL OR char_length(actor_id) BETWEEN 1 AND 255),
    CONSTRAINT action_history_note_valid CHECK (note IS NULL OR char_length(note) BETWEEN 3 AND 500),
    CONSTRAINT action_history_hashes_valid CHECK (
        char_length(prev_hash) = 64 AND prev_hash ~ '^[0-9a-f]+$'
        AND char_length(hash) = 64 AND hash ~ '^[0-9a-f]+$'
    )
);

CREATE TRIGGER action_history_no_update_delete
    BEFORE UPDATE OR DELETE ON action_history
    FOR EACH ROW EXECUTE FUNCTION netsight_reject_append_only_mutation();
CREATE TRIGGER action_history_no_truncate
    BEFORE TRUNCATE ON action_history
    FOR EACH STATEMENT EXECUTE FUNCTION netsight_reject_append_only_mutation();
-- Requests are never deleted: no application path and no role may do it (eviction hides, not deletes).
CREATE TRIGGER action_requests_no_delete
    BEFORE DELETE ON action_requests
    FOR EACH ROW EXECUTE FUNCTION netsight_reject_append_only_mutation();
CREATE TRIGGER action_requests_no_truncate
    BEFORE TRUNCATE ON action_requests
    FOR EACH STATEMENT EXECUTE FUNCTION netsight_reject_append_only_mutation();

-- A request starts proposed, at version 1, with nothing decided, nothing run and nothing evicted.
CREATE FUNCTION netsight_guard_action_request_insert() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NEW.state <> 'proposed' OR NEW.version <> 1 OR NEW.approvals <> '[]'::jsonb
        OR NEW.pre_checks <> '[]'::jsonb OR NEW.execution IS NOT NULL OR NEW.execute_by IS NOT NULL
        OR NEW.run_by IS NOT NULL OR NEW.exec_key IS NOT NULL OR NEW.evicted_at IS NOT NULL THEN
        RAISE EXCEPTION 'an action request starts proposed, at version 1, with nothing decided'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION netsight_guard_action_request_update() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.action_type IS DISTINCT FROM OLD.action_type
        OR NEW.target_id IS DISTINCT FROM OLD.target_id
        OR NEW.params IS DISTINCT FROM OLD.params
        OR NEW.risk IS DISTINCT FROM OLD.risk
        OR NEW.requester_id IS DISTINCT FROM OLD.requester_id
        OR NEW.requester_kind IS DISTINCT FROM OLD.requester_kind
        OR NEW.reason IS DISTINCT FROM OLD.reason
        OR NEW.source IS DISTINCT FROM OLD.source
        OR NEW.approvals_required IS DISTINCT FROM OLD.approvals_required
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.approve_by IS DISTINCT FROM OLD.approve_by
        OR NEW.execute_within_seconds IS DISTINCT FROM OLD.execute_within_seconds
        OR NEW.timeout_seconds IS DISTINCT FROM OLD.timeout_seconds
        OR NEW.digest IS DISTINCT FROM OLD.digest
        OR NEW.policy_checks IS DISTINCT FROM OLD.policy_checks
        OR NEW.create_key IS DISTINCT FROM OLD.create_key
        OR NEW.create_fingerprint IS DISTINCT FROM OLD.create_fingerprint THEN
        RAISE EXCEPTION 'the identity of an action request is immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF netsight_action_state_is_final(OLD.state) THEN
        -- A finished request changes in one way only: it is evicted, once.
        IF to_jsonb(NEW) = to_jsonb(OLD) THEN
            RETURN NEW;
        END IF;
        IF OLD.evicted_at IS NULL AND NEW.evicted_at IS NOT NULL
            AND (to_jsonb(NEW) - 'evicted_at') = (to_jsonb(OLD) - 'evicted_at') THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'a finished action request is not changed'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state
        AND NOT netsight_action_transition_ok(OLD.state, NEW.state) THEN
        RAISE EXCEPTION 'this state change is not part of the action lifecycle'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.version <= OLD.version THEN
        RAISE EXCEPTION 'the version of an action request only advances'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.exec_key IS NOT NULL AND (NEW.exec_key IS DISTINCT FROM OLD.exec_key
        OR NEW.exec_actor_id IS DISTINCT FROM OLD.exec_actor_id) THEN
        RAISE EXCEPTION 'the execution key of an action request is fixed once set'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- Approvals are only ever added: none is lost, one person approves once, never the requester.
    IF jsonb_array_length(NEW.approvals) < jsonb_array_length(OLD.approvals)
        OR NOT (NEW.approvals @> OLD.approvals)
        OR EXISTS (
            SELECT 1 FROM jsonb_array_elements(NEW.approvals) AS a
            WHERE a ->> 'approver_id' = NEW.requester_id)
        OR (SELECT count(DISTINCT a ->> 'approver_id') FROM jsonb_array_elements(NEW.approvals) AS a)
            <> jsonb_array_length(NEW.approvals) THEN
        RAISE EXCEPTION 'approvals are only added, once per person, never by the requester'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- An event continues the chain: the next sequence number, the previous hash, the state the request
-- was left in, and nothing after the request finished. (The hash itself is computed and verified by
-- the application; SQL does not know the canonical JSON form.)
CREATE FUNCTION netsight_guard_action_event_insert() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    last_event action_history%ROWTYPE;
BEGIN
    SELECT * INTO last_event FROM action_history
        WHERE action_id = NEW.action_id ORDER BY seq DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.seq <> 1 THEN
            RAISE EXCEPTION 'the history of an action request starts at event 1'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.seq <> last_event.seq + 1 OR NEW.prev_hash <> last_event.hash
        OR NEW.from_state IS DISTINCT FROM last_event.to_state THEN
        RAISE EXCEPTION 'an event must continue the history it is appended to'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF netsight_action_state_is_final(last_event.to_state) THEN
        RAISE EXCEPTION 'a finished action request has no further events'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- The request must be what its history says. Called at commit, for the request or the event written.
CREATE FUNCTION netsight_check_action_log(p_id text) RETURNS void
    LANGUAGE plpgsql AS
$$
DECLARE
    r action_requests%ROWTYPE;
    last_seq integer;
    last_state text;
    approved_events integer;
    started_events integer;
BEGIN
    SELECT * INTO r FROM action_requests WHERE id = p_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT seq, to_state INTO last_seq, last_state FROM action_history
        WHERE action_id = p_id ORDER BY seq DESC LIMIT 1;
    IF NOT FOUND OR r.version <> last_seq OR r.state <> last_state THEN
        RAISE EXCEPTION 'the version and state of an action request are those of its last event'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT count(*) FILTER (WHERE type = 'approved'),
           count(*) FILTER (WHERE type = 'execution-started')
        INTO approved_events, started_events FROM action_history WHERE action_id = p_id;
    IF jsonb_array_length(r.approvals) <> approved_events THEN
        RAISE EXCEPTION 'the approvals of an action request are those its history records'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (r.execution IS NOT NULL) <> (started_events > 0) THEN
        RAISE EXCEPTION 'an execution is recorded exactly when its history says it started'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
END;
$$;

CREATE FUNCTION netsight_action_request_logged() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    PERFORM netsight_check_action_log(NEW.id);
    RETURN NULL;
END;
$$;

CREATE FUNCTION netsight_action_event_logged() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    PERFORM netsight_check_action_log(NEW.action_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER action_requests_guard_insert
    BEFORE INSERT ON action_requests
    FOR EACH ROW EXECUTE FUNCTION netsight_guard_action_request_insert();
CREATE TRIGGER action_requests_guard_update
    BEFORE UPDATE ON action_requests
    FOR EACH ROW EXECUTE FUNCTION netsight_guard_action_request_update();
CREATE TRIGGER action_history_guard_insert
    BEFORE INSERT ON action_history
    FOR EACH ROW EXECUTE FUNCTION netsight_guard_action_event_insert();
CREATE CONSTRAINT TRIGGER action_requests_logged
    AFTER INSERT OR UPDATE ON action_requests
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION netsight_action_request_logged();
CREATE CONSTRAINT TRIGGER action_history_logged
    AFTER INSERT ON action_history
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION netsight_action_event_logged();

-- Fire even when a session sets session_replication_role = replica (as in 0002 to 0006).
ALTER TABLE action_history ENABLE ALWAYS TRIGGER action_history_no_update_delete;
ALTER TABLE action_history ENABLE ALWAYS TRIGGER action_history_no_truncate;
ALTER TABLE action_history ENABLE ALWAYS TRIGGER action_history_guard_insert;
ALTER TABLE action_history ENABLE ALWAYS TRIGGER action_history_logged;
ALTER TABLE action_requests ENABLE ALWAYS TRIGGER action_requests_no_delete;
ALTER TABLE action_requests ENABLE ALWAYS TRIGGER action_requests_no_truncate;
ALTER TABLE action_requests ENABLE ALWAYS TRIGGER action_requests_guard_insert;
ALTER TABLE action_requests ENABLE ALWAYS TRIGGER action_requests_guard_update;
ALTER TABLE action_requests ENABLE ALWAYS TRIGGER action_requests_logged;

-- Every function resolves its tables through a pinned search_path: pg_catalog first, this schema, and
-- pg_temp LAST (it is searched first unless it is named). Without it a session could create a TEMP table
-- called action_history and make the guards read a past of its own choosing. The schema is the one the
-- migration runs in (the migrator's current_schema()); an ALTER keeps the CREATE statements readable.
DO $pin$
DECLARE
    fn regprocedure;
BEGIN
    FOR fn IN
        SELECT p.oid::regprocedure FROM pg_proc AS p
        WHERE p.pronamespace = current_schema()::regnamespace
          AND p.proname IN ('netsight_action_transition_ok', 'netsight_action_state_is_final',
                            'netsight_guard_action_request_insert', 'netsight_guard_action_request_update',
                            'netsight_guard_action_event_insert', 'netsight_check_action_log',
                            'netsight_action_request_logged', 'netsight_action_event_logged')
    LOOP
        EXECUTE format('ALTER FUNCTION %1$s SET search_path = pg_catalog, %2$I, pg_temp', fn, current_schema());
    END LOOP;
END
$pin$;

REVOKE ALL ON TABLE action_requests, action_history FROM PUBLIC;
-- The trigger functions are not callable by anyone (a trigger needs no EXECUTE to fire). The pure
-- helpers stay executable (the CHECKs call them as the invoking role); netsight_check_action_log only
-- reads rows that role can already read.
REVOKE ALL ON FUNCTION netsight_guard_action_request_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_guard_action_request_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_guard_action_event_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_action_request_logged() FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_action_event_logged() FROM PUBLIC;
