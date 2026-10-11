-- 0005: WAN probe samples and per-cycle rollups (Step 5: Internet/WAN SLA evidence).
-- Rollback: 0005_wan_probe_samples.down.sql (drops both tables, every partition and the helpers).
-- Privileges: PUBLIC gets nothing. Two runtime roles are granted by the migrator (grants/*.sql):
--   the API role SELECT only, the collector role INSERT only. No UPDATE and no DELETE exist for
--   any role, and neither runtime role may run DDL (so neither can create a partition).
--
-- wan_probe_samples: one row per probe outcome (icmp/tcp reachability, dns) of one sampling
--   round of one WAN link: the raw evidence. `location` is the configured probe location of the
--   source that answered (NULL for the API host's own prober). Target text is validated to a
--   plain host name or address, so no operator or telemetry text is stored here. A failed or
--   unknown probe has no latency (CHECK); a passing probe may have none.
-- wan_link_cycles: one rollup row per link per round: the counts of that round's reachability
--   samples and the state they imply (up / degraded / down / unknown). The CHECK pins the state
--   to the counts, so a stored state can always be re-derived from the samples. An unknown sample
--   is neither a pass nor a failure. Time not covered by a cycle is unknown by definition
--   (netsight_api.wan.sla); nothing here ever records "up" for a gap.
--
-- Partitioning (database review H1): both tables are RANGE partitioned by sampled_at, one
--   partition per UTC calendar month (wan_link_cycles_pYYYYMM, wan_probe_samples_pYYYYMM). There
--   is no default partition: a row whose month has no partition is rejected, and the collector
--   treats that as a refusal to write (it logs it and records nothing). Partitions are created by
--   the MIGRATOR only, through netsight_ensure_wan_partition(any date in the month), which is
--   idempotent and not executable by the runtime roles. `python -m netsight_api.storage.migrate up`
--   creates the current and next month; a scheduled run of `... migrate partitions` (monthly, or
--   at least before each month ends) keeps the next month ready.
-- Retention (the period is a pending HUMAN decision, docs/06-data/DATA-RETENTION-MATRIX.md; none is
--   built or invented here): when a period is decided, the migrator removes a whole month, the
--   samples FIRST and the cycles second, and the cycles partition must be DETACHED before it can
--   be dropped (the foreign key on the samples parent references every cycles partition):
--     DROP TABLE wan_probe_samples_pYYYYMM;
--     ALTER TABLE wan_link_cycles DETACH PARTITION wan_link_cycles_pYYYYMM;
--     DROP TABLE wan_link_cycles_pYYYYMM;
--   (detach the samples partition instead of dropping it to archive the month first). This is an
--   owner action that no runtime role holds; the append-only triggers deliberately do not stand
--   in its way (they guard rows, not whole partitions).
--
-- Append-only: the shared trigger function from 0003 rejects UPDATE, DELETE and TRUNCATE for every
--   role including the owner, on the parent tables AND on every partition (row triggers are
--   cloned to partitions by PostgreSQL; the statement-level TRUNCATE trigger and ENABLE ALWAYS are
--   applied to each partition by the helper). The triggers fire even under
--   session_replication_role = replica.
-- Consistency: deferred constraint triggers (netsight_wan_cycle_matches_samples) check at COMMIT
--   that a cycle's counts equal the number of its stored reachability samples, for a new cycle and
--   for a sample added to a stored cycle. The function is SECURITY DEFINER (owned by the migrator)
--   because the insert-only collector role has no SELECT.
-- Residual risk (as for 0002 to 0004): the table OWNER and superusers can still DISABLE the
--   triggers or drop a partition, so the owner/migrator credential must stay out of the running
--   service.
-- Requires 0003 (netsight_reject_append_only_mutation).

CREATE TABLE wan_link_cycles (
    link_id text NOT NULL,
    sampled_at timestamptz NOT NULL,
    interval_seconds integer NOT NULL,
    passes smallint NOT NULL,
    fails smallint NOT NULL,
    unknowns smallint NOT NULL,
    state text NOT NULL,
    PRIMARY KEY (link_id, sampled_at),
    CONSTRAINT wan_link_cycles_link_valid CHECK (link_id ~ '^[a-z0-9][a-z0-9-]{0,47}$'),
    CONSTRAINT wan_link_cycles_whole_second CHECK (sampled_at = date_trunc('second', sampled_at)),
    CONSTRAINT wan_link_cycles_interval_valid CHECK (interval_seconds BETWEEN 30 AND 300),
    CONSTRAINT wan_link_cycles_counts_valid CHECK (
        passes BETWEEN 0 AND 64 AND fails BETWEEN 0 AND 64 AND unknowns BETWEEN 0 AND 64
        AND passes + fails + unknowns <= 64
    ),
    CONSTRAINT wan_link_cycles_state_valid CHECK (state IN ('up', 'degraded', 'down', 'unknown')),
    CONSTRAINT wan_link_cycles_state_matches_counts CHECK (
        state = CASE
            WHEN passes > 0 AND fails = 0 THEN 'up'
            WHEN passes > 0 THEN 'degraded'
            WHEN fails > 0 AND unknowns = 0 THEN 'down'
            ELSE 'unknown'
        END
    )
) PARTITION BY RANGE (sampled_at);

CREATE TABLE wan_probe_samples (
    link_id text NOT NULL,
    sampled_at timestamptz NOT NULL,
    seq smallint NOT NULL,
    probe text NOT NULL,
    target text NOT NULL,
    location text,
    outcome text NOT NULL,
    latency_ms double precision,
    PRIMARY KEY (link_id, sampled_at, seq),
    FOREIGN KEY (link_id, sampled_at) REFERENCES wan_link_cycles (link_id, sampled_at),
    CONSTRAINT wan_probe_samples_link_valid CHECK (link_id ~ '^[a-z0-9][a-z0-9-]{0,47}$'),
    CONSTRAINT wan_probe_samples_seq_valid CHECK (seq BETWEEN 1 AND 64),
    CONSTRAINT wan_probe_samples_probe_valid CHECK (probe IN ('icmp', 'tcp', 'dns')),
    CONSTRAINT wan_probe_samples_target_valid CHECK (
        target ~ '^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,251}[A-Za-z0-9])?$'
    ),
    CONSTRAINT wan_probe_samples_location_valid CHECK (
        location IS NULL
        OR location IN ('cloud-external', 'user-lan', 'server-vlan', 'branch', 'wifi', 'remote-site')
    ),
    CONSTRAINT wan_probe_samples_outcome_valid CHECK (outcome IN ('pass', 'fail', 'unknown')),
    CONSTRAINT wan_probe_samples_latency_valid CHECK (
        latency_ms IS NULL OR (latency_ms >= 0 AND latency_ms <= 3600000)
    ),
    -- Only a passing probe has a latency (a pass may report none); fail and unknown never do.
    CONSTRAINT wan_probe_samples_latency_matches_outcome CHECK (
        outcome = 'pass' OR latency_ms IS NULL
    )
) PARTITION BY RANGE (sampled_at);

-- Serves the export's "which probes, targets and locations" query from the index alone.
CREATE INDEX wan_probe_samples_sources_idx ON wan_probe_samples (link_id, sampled_at)
    INCLUDE (probe, target, location);

-- Append-only triggers on the parents (row triggers are cloned to every partition).
CREATE TRIGGER wan_link_cycles_no_update_delete
    BEFORE UPDATE OR DELETE ON wan_link_cycles
    FOR EACH ROW EXECUTE FUNCTION netsight_reject_append_only_mutation();
CREATE TRIGGER wan_link_cycles_no_truncate
    BEFORE TRUNCATE ON wan_link_cycles
    FOR EACH STATEMENT EXECUTE FUNCTION netsight_reject_append_only_mutation();
CREATE TRIGGER wan_probe_samples_no_update_delete
    BEFORE UPDATE OR DELETE ON wan_probe_samples
    FOR EACH ROW EXECUTE FUNCTION netsight_reject_append_only_mutation();
CREATE TRIGGER wan_probe_samples_no_truncate
    BEFORE TRUNCATE ON wan_probe_samples
    FOR EACH STATEMENT EXECUTE FUNCTION netsight_reject_append_only_mutation();

-- Fire even when a session sets session_replication_role = replica (as in 0002 to 0004).
ALTER TABLE wan_link_cycles ENABLE ALWAYS TRIGGER wan_link_cycles_no_update_delete;
ALTER TABLE wan_link_cycles ENABLE ALWAYS TRIGGER wan_link_cycles_no_truncate;
ALTER TABLE wan_probe_samples ENABLE ALWAYS TRIGGER wan_probe_samples_no_update_delete;
ALTER TABLE wan_probe_samples ENABLE ALWAYS TRIGGER wan_probe_samples_no_truncate;

-- A cycle's counts must equal its stored reachability samples, checked at COMMIT. SECURITY DEFINER
-- so the insert-only collector role (no SELECT) can be checked; the search_path is pinned and the
-- schema comes from the trigger, never from the caller.
CREATE FUNCTION netsight_wan_cycle_matches_samples() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    cycle_row record;
    seen record;
BEGIN
    EXECUTE format(
        'SELECT passes, fails, unknowns FROM %I.wan_link_cycles '
        'WHERE link_id = $1 AND sampled_at = $2', TG_TABLE_SCHEMA)
        INTO cycle_row USING NEW.link_id, NEW.sampled_at;
    IF cycle_row IS NULL THEN
        RETURN NULL;  -- no cycle: the foreign key has already refused the sample
    END IF;
    EXECUTE format(
        'SELECT count(*) FILTER (WHERE outcome = ''pass'') AS passes, '
        'count(*) FILTER (WHERE outcome = ''fail'') AS fails, '
        'count(*) FILTER (WHERE outcome = ''unknown'') AS unknowns '
        'FROM %I.wan_probe_samples '
        'WHERE link_id = $1 AND sampled_at = $2 AND probe IN (''icmp'', ''tcp'')', TG_TABLE_SCHEMA)
        INTO seen USING NEW.link_id, NEW.sampled_at;
    IF cycle_row.passes <> seen.passes OR cycle_row.fails <> seen.fails
       OR cycle_row.unknowns <> seen.unknowns THEN
        RAISE EXCEPTION 'a WAN cycle must equal its stored samples'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'wan_cycle_counts_match_samples';
    END IF;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION netsight_wan_cycle_matches_samples() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER wan_link_cycles_counts_match_samples
    AFTER INSERT ON wan_link_cycles
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION netsight_wan_cycle_matches_samples();
CREATE CONSTRAINT TRIGGER wan_probe_samples_counts_match_samples
    AFTER INSERT ON wan_probe_samples
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION netsight_wan_cycle_matches_samples();
ALTER TABLE wan_link_cycles ENABLE ALWAYS TRIGGER wan_link_cycles_counts_match_samples;
ALTER TABLE wan_probe_samples ENABLE ALWAYS TRIGGER wan_probe_samples_counts_match_samples;

-- The migrator-only partition helper: creates (idempotently) the cycle and sample partitions of
-- the UTC month containing p_month and gives each the append-only protection. It runs with the
-- caller's rights (only the owner can create partitions) and resolves the tables on the caller's
-- search_path, in the current schema.
CREATE FUNCTION netsight_ensure_wan_partition(p_month date) RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    first_day timestamp;
    lower_bound timestamptz;
    upper_bound timestamptz;
    target_schema text := current_schema();
    parent text;
    child text;
    trg record;
BEGIN
    IF p_month IS NULL THEN
        RAISE EXCEPTION 'a month is required';
    END IF;
    first_day := date_trunc('month', p_month::timestamp);
    lower_bound := first_day AT TIME ZONE 'UTC';
    upper_bound := (first_day + interval '1 month') AT TIME ZONE 'UTC';
    FOREACH parent IN ARRAY ARRAY['wan_link_cycles', 'wan_probe_samples'] LOOP
        child := parent || '_p' || to_char(first_day, 'YYYYMM');
        IF to_regclass(format('%I.%I', target_schema, child)) IS NULL THEN
            EXECUTE format(
                'CREATE TABLE %I.%I PARTITION OF %I.%I FOR VALUES FROM (%L) TO (%L)',
                target_schema, child, target_schema, parent, lower_bound, upper_bound);
        END IF;
        -- TRUNCATE of the partition itself (statement triggers are not cloned).
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgrelid = format('%I.%I', target_schema, child)::regclass
              AND tgname = child || '_no_truncate'
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER %I BEFORE TRUNCATE ON %I.%I FOR EACH STATEMENT '
                'EXECUTE FUNCTION netsight_reject_append_only_mutation()',
                child || '_no_truncate', target_schema, child);
        END IF;
        FOR trg IN
            SELECT tgname FROM pg_trigger
            WHERE tgrelid = format('%I.%I', target_schema, child)::regclass
              AND NOT tgisinternal AND tgenabled <> 'A'
        LOOP
            EXECUTE format('ALTER TABLE %I.%I ENABLE ALWAYS TRIGGER %I',
                           target_schema, child, trg.tgname);
        END LOOP;
    END LOOP;
END
$$;
REVOKE ALL ON FUNCTION netsight_ensure_wan_partition(date) FROM PUBLIC;

REVOKE ALL ON TABLE wan_link_cycles FROM PUBLIC;
REVOKE ALL ON TABLE wan_probe_samples FROM PUBLIC;
