# Akvorado + ClickHouse Integration

Purpose: NetFlow/IPFIX/sFlow traffic intelligence.

Netsight queries aggregated flow views rather than copying all flow records into PostgreSQL.

Required dimensions where available:
- time;
- source/destination;
- bytes/packets;
- ports/protocol;
- interfaces;
- ASN/country;
- application/domain enrichment where source permits;
- VLAN/site mapping.

Protect ClickHouse with a read-only query identity and query budgets/timeouts.

## Configuration (platform API)

| Variable | Meaning |
| --- | --- |
| `CLICKHOUSE_DSN` | HTTP base URL of the ClickHouse server, e.g. `http://clickhouse.internal:8123` (scheme + host + optional port only; no path). Unset ⇒ the `/api/v1/traffic/*` endpoints report `not-connected`. |
| `CLICKHOUSE_USER` | Read-only query identity. Empty means no HTTP Basic auth header. |
| `CLICKHOUSE_PASSWORD` | Password for `CLICKHOUSE_USER`. Never log or commit this value. |
| `CLICKHOUSE_FLOWS_TABLE` | Flows table, either `table` (database `default`) or `database.table`. Default `flows`. |

Credentials may alternatively be embedded in the DSN userinfo
(`http://user:password@host:8123`), but `CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD`
take precedence and are preferred so the secret stays out of the DSN string.
Secrets are read from the environment only and are excluded from client
`repr`, so they can never leak through logs.

A DSN that is set but invalid does not disable the endpoints: their queries
fail and the responses degrade to the explicit `unknown` state (configured
does not imply connected), mirroring the NetBox adapter decision from S3.

## Query behaviour

- Every read is bounded by an explicit time window (maximum 31 days at the
  API boundary) and a row limit; identifiers (table/database/columns) come
  from validated configuration or adapter constants, values are bound with
  `param_*` placeholders.
- At most two upstream ClickHouse calls per traffic request: one
  `system.columns` discovery (cached per client instance) and one data query.
  If the identity is a readonly profile that forbids settings, the client
  retries once without `max_execution_time` (at most three calls worst case).
- `max_execution_time` is sent when permitted; an `httpx` read timeout is
  always enforced as a backstop.
- The source's own schema is authoritative for discovery: queries are only
  issued against columns that discovery confirms are present, and a missing
  required column degrades the view to `unknown` rather than guessing.

### Expected columns

Required (aggregates and flows): `TimeReceived`, `SrcAddr`, `DstAddr`,
`Proto`, `Bytes`. `Packets` is used when present (otherwise `packets` is
reported as unknown at the contract level). Optional enrichment, used only
when the column exists: `DstPort`, `DstHostname`, `Application`, `User`.
Missing optional columns become `null` fields, never fabricated values.

Protocol numbers map as: 1/58 ⇒ `icmp`, 6 ⇒ `tcp`, 17 ⇒ `udp`, any other
number ⇒ `other`; a non-numeric or out-of-range protocol value fails the
read (explicit `unknown`). Flow `direction` is always `unknown`: deriving it
requires an internal-prefix view this adapter does not have.

## Verification

Adapter SQL and HTTP behaviour are pinned by mock-transport unit tests
(`test_clickhouse_adapter.py`) and validated against a live ClickHouse server
(26.10 HTTP interface) during development. An opt-in integration test runs
only when `CLICKHOUSE_TEST_DSN` is set; without it the test skips rather than
fabricating a result.
