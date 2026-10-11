-- Reverses 0005_wan_probe_samples.up.sql. DESTRUCTIVE: removes every stored WAN probe sample and
-- cycle (the SLA evidence) in every month partition. The migrator refuses to run it while either
-- table holds rows unless NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1 is set. Take a backup first, and
-- disable sampling (NETSIGHT_WAN_SAMPLING_ENABLED) before rolling back.
-- Dropping a partitioned table drops its partitions, their triggers and the foreign key; the shared
-- trigger function netsight_reject_append_only_mutation belongs to 0003 and stays.

DROP TABLE IF EXISTS wan_probe_samples;
DROP TABLE IF EXISTS wan_link_cycles;
DROP FUNCTION IF EXISTS netsight_ensure_wan_partition(date);
DROP FUNCTION IF EXISTS netsight_wan_cycle_matches_samples();
