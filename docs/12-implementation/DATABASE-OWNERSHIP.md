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
- AI investigation metadata/evidence references.

## External stores remain authoritative
- detailed flow records: ClickHouse/Akvorado;
- raw Wazuh/OpenSearch security events;
- LibreNMS metrics/graphs;
- raw Suricata pipeline;
- NetBox source-of-truth data;
- Oxidized config repository.

## Principle
Persist enough incident evidence/reference to reproduce decisions without creating an uncontrolled second telemetry lake.
