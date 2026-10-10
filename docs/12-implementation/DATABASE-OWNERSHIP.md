# Database Ownership

## PostgreSQL owns
- organisations/sites;
- platform identities/roles;
- canonical entity aliases;
- identity correlations;
- incidents;
- alert rules/policies;
- maintenance windows;
- action requests/approvals;
- audit metadata;
- reports/schedules;
- user preferences;
- integration metadata/health;
- AI investigation metadata/evidence references;
- diagnostic sessions (immutable snapshots of a finished run: checks, per-location results, labelled cause, path, recent changes). The table's CHECKs tie the mirrored columns (id, target, started_at, completed_at, domain, confidence) to the document, refuse a blank target, bound the document at 1 MiB of text (`octet_length(document::text)`) and refuse any stored incident title (incidents are references; titles are joined at read time). The triggers fire under `session_replication_role = replica` (tested live). **No migrator prune function is built**: it needs an approved retention period (DATA-RETENTION-MATRIX, pending human decision) before its floor and audit row can be defined; until then deletion needs an audited manual migrator step.

## External stores remain authoritative
- detailed flow records: ClickHouse/Akvorado;
- raw Wazuh/OpenSearch security events;
- LibreNMS metrics/graphs;
- raw Suricata pipeline;
- NetBox source-of-truth data;
- Oxidized config repository.

## Principle
Persist enough incident evidence/reference to reproduce decisions without creating an uncontrolled second telemetry lake.
