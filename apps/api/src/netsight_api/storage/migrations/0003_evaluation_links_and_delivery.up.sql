-- 0003: alert -> incident links and durable notification delivery attempts (S6 step 2).
-- Rollback: 0003_evaluation_links_and_delivery.down.sql (drops both tables and their data).
-- Privileges: PUBLIC gets nothing; the runtime role's grants are in grants/app_role.sql.
--
-- alert_incident_links: which incident an alert fingerprint ('alert') or group key ('group')
--   currently points at. Makes automatic incident creation idempotent: the evaluator reads it
--   before creating and claims a key by compare-and-set. Nothing here is deleted; resolving an
--   incident is what frees its keys (the evaluator never resolves). recovered_at records that
--   the alert was seen to recover since the claim; a claim clears it. A still-firing alert whose
--   incident a human resolved gets no new incident until it has recovered (also across restarts).
-- notification_delivery_attempts: one row per delivery attempt, identifiers and static codes
--   only (never payload text, addresses, URLs or tokens). Append-only like the incident
--   timeline. Retention: no application delete path and, today, no prune path at all: the
--   triggers also stop the owner (docs/06-data/DATA-RETENTION-MATRIX.md).
-- Residual risk (as for 0002): the table OWNER and superusers can still DISABLE the triggers,
-- so the owner/migrator credential must stay out of the running service.

CREATE TABLE alert_incident_links (
    kind text NOT NULL,
    dedup_key text NOT NULL,
    incident_id uuid NOT NULL REFERENCES incidents (id) ON DELETE RESTRICT,
    linked_at timestamptz NOT NULL,
    recovered_at timestamptz,
    PRIMARY KEY (kind, dedup_key),
    CONSTRAINT alert_incident_links_kind_valid CHECK (kind IN ('alert', 'group')),
    CONSTRAINT alert_incident_links_key_valid CHECK (dedup_key ~ '^[0-9a-f]{32}$')
);

CREATE INDEX alert_incident_links_incident_idx ON alert_incident_links (incident_id);

CREATE TABLE notification_delivery_attempts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    notification_id text NOT NULL,
    alert_ref text NOT NULL,
    channel text NOT NULL,
    destination text NOT NULL,
    attempt integer NOT NULL,
    status text NOT NULL,
    code text NOT NULL,
    attempted_at timestamptz NOT NULL,
    CONSTRAINT delivery_notification_id_valid CHECK (notification_id ~ '^[A-Za-z0-9_.:-]{1,64}$'),
    CONSTRAINT delivery_alert_ref_valid CHECK (alert_ref ~ '^[A-Za-z0-9_.:-]{1,64}$'),
    CONSTRAINT delivery_channel_valid CHECK (channel IN ('email', 'push', 'webhook')),
    CONSTRAINT delivery_destination_valid CHECK (
        char_length(destination) BETWEEN 1 AND 300 AND destination !~ '[\x01-\x1f\x7f]'
    ),
    CONSTRAINT delivery_attempt_valid CHECK (attempt BETWEEN 0 AND 5),
    CONSTRAINT delivery_status_valid CHECK (status IN ('sent', 'retrying', 'failed', 'dropped')),
    CONSTRAINT delivery_code_valid CHECK (code ~ '^[A-Za-z0-9_.:-]{1,64}$')
);

CREATE INDEX notification_delivery_notification_idx
    ON notification_delivery_attempts (notification_id, attempt, id);
CREATE INDEX notification_delivery_recent_idx
    ON notification_delivery_attempts (attempted_at DESC, id DESC);
CREATE INDEX notification_delivery_alert_sent_idx
    ON notification_delivery_attempts (alert_ref, attempted_at DESC) WHERE status = 'sent';

CREATE FUNCTION netsight_reject_append_only_mutation() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION '% is append-only (% rejected)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER notification_delivery_attempts_no_update_delete
    BEFORE UPDATE OR DELETE ON notification_delivery_attempts
    FOR EACH ROW EXECUTE FUNCTION netsight_reject_append_only_mutation();
CREATE TRIGGER notification_delivery_attempts_no_truncate
    BEFORE TRUNCATE ON notification_delivery_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION netsight_reject_append_only_mutation();

-- Fire even when a session sets session_replication_role = replica (as in 0002).
ALTER TABLE notification_delivery_attempts
    ENABLE ALWAYS TRIGGER notification_delivery_attempts_no_update_delete;
ALTER TABLE notification_delivery_attempts
    ENABLE ALWAYS TRIGGER notification_delivery_attempts_no_truncate;

REVOKE ALL ON TABLE alert_incident_links, notification_delivery_attempts FROM PUBLIC;
REVOKE ALL ON FUNCTION netsight_reject_append_only_mutation() FROM PUBLIC;
