# Database Ownership

## PostgreSQL owns
- organisations/sites;
- platform identities/roles;
- canonical entity aliases;
- identity correlations (**not persisted yet**: Step 6 computes them on read from bounded evidence; persisting them is a pending human decision, see DATA-RETENTION-MATRIX and IDENTITY-CORRELATION.md);
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
- WAN probe samples and per-round cycle rollups (append-only evidence for the monthly SLA and the ISP-dispute export; migration 0005; range-partitioned by month with partitions created by the migrator only; the API role has `SELECT` only and a separate collector role has `INSERT` only; append-only triggers on the parents and every partition also stop the owner; deferred constraint triggers tie each cycle's counts to its samples). The probe *telemetry* (LibreNMS counters) stays in LibreNMS and is read live; only Netsight's own probe outcomes are stored. **No prune is built or scheduled**: it needs an approved retention period (DATA-RETENTION-MATRIX, pending human decision); when decided it is a migrator drop or detach of whole month partitions.
- unknown-device findings and their append-only event timeline (migration 0006; one open finding per endpoint; the timeline rejects `UPDATE`/`DELETE`/`TRUNCATE` for every role; evidence references and observed values only, never a copy of a source record; retention pending, see DATA-RETENTION-MATRIX). Inventory and IPAM are **not** stored: NetBox stays authoritative and they are computed on read.
- action requests and their append-only, SHA-256 hash-chained history (migration 0007; `action_requests`, `action_history`; written only through the `ActionStore`, so requests survive a restart and are shared by every worker). A request has a fixed identity (type, target, parameters, requester, reason, digest, idempotency key) and a few mutable columns (state, version, approvals, execution record, pre-checks); the history rejects `UPDATE`/`DELETE`/`TRUNCATE` for every role including the owner, and a deferred trigger refuses a commit in which a request is not what its history says. Partial unique indexes make one open request per action and target, one running execution per target and one request per requester and idempotency key database facts. The runtime role gets `SELECT`/`INSERT` on both tables and column-level `UPDATE` on the mutable request columns only; nobody has `DELETE` or `TRUNCATE`. The store holds at most 5 000 requests: the oldest finished one is *evicted* (hidden by `evicted_at`, its idempotency key freed), never removed. Retention pending, see DATA-RETENTION-MATRIX; no prune is built. Without `DATABASE_URL` the engine uses process memory and reports `store.durable: false`; with it, an unreachable database answers 503 and never falls back to memory.

## External stores remain authoritative
- detailed flow records: ClickHouse/Akvorado;
- raw Wazuh/OpenSearch security events;
- LibreNMS metrics/graphs;
- raw Suricata pipeline;
- NetBox source-of-truth data;
- Oxidized config repository.

## Principle
Persist enough incident evidence/reference to reproduce decisions without creating an uncontrolled second telemetry lake.
