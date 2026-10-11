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
  `system.columns` discovery (name and type; cached per client instance) and
  one data query. Server-side resource limits travel with every query when the
  identity may set them (see "Resource limits" below); an `httpx` read timeout
  is always enforced as a backstop.
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

## Resource limits (deployment requirement)

A flow query can scan billions of rows, and the client timeout only stops *waiting*: without server-side limits the query
keeps running after the API gave up. Every query therefore carries these URL settings when the ClickHouse identity may set
them (`adapters/clickhouse_limits.py`):

| Setting | Value | Why |
| --- | --- | --- |
| `readonly` | `2` | the statement can not write; the settings below may still be changed |
| `max_execution_time` | the client timeout (10 s) | stops the query, not just the wait |
| `max_memory_usage` | 2 GiB | one query can not exhaust the server |
| `max_rows_to_read` / `max_bytes_to_read` | 5,000,000,000 rows / 500 GiB | a scan ceiling (the 5-week baseline is the widest read) |
| `max_result_rows` / `max_result_bytes` | 10,000 rows / 64 MiB | the widest legitimate result is the 8,401-row baseline series |
| `read_overflow_mode`, `result_overflow_mode`, `timeout_overflow_mode` | `throw` | an exceeded limit **fails** the read (`unknown`), it never returns a silently truncated answer |
| `cancel_http_readonly_queries_on_client_close` | `1` | an abandoned or timed-out request cancels its query |

**If the identity is `readonly = 1` (the recommended least-privilege setup) it may not change settings at all.** ClickHouse then
refuses the first attempt (`Code: 164`, or `Code: 452` for a pinned constraint); the adapter retries once without settings and
**remembers the answer for the life of the process**, per (endpoint, user), so later requests pay no failed round trip. In that
mode nothing in the API can bound a query: **the limits MUST be enforced by the ClickHouse user profile.** The adapter logs one
warning, once per process, when it learns this ("resource limits can not be verified here and MUST be enforced by the
ClickHouse user profile"); the log line names no host, user or secret. Treat that line as a deployment check: the profile below
must exist.

Recommended profile (SQL; adjust the numbers to the deployment, keep every limit):

```sql
CREATE SETTINGS PROFILE IF NOT EXISTS netsight_flows_reader SETTINGS
    readonly = 1,
    max_execution_time = 10,
    max_memory_usage = 2147483648,
    max_rows_to_read = 5000000000,
    max_bytes_to_read = 536870912000,
    max_result_rows = 10000,
    max_result_bytes = 67108864,
    read_overflow_mode = 'throw',
    result_overflow_mode = 'throw',
    timeout_overflow_mode = 'throw',
    cancel_http_readonly_queries_on_client_close = 1;

CREATE USER IF NOT EXISTS netsight_reader
    IDENTIFIED WITH sha256_password BY '<generated, never committed>'
    SETTINGS PROFILE 'netsight_flows_reader';

GRANT SELECT ON default.flows TO netsight_reader;       -- the flows table only
GRANT SELECT ON system.columns TO netsight_reader;      -- schema discovery
```

The same profile as `users.d/netsight.xml`:

```xml
<clickhouse>
  <profiles>
    <netsight_flows_reader>
      <readonly>1</readonly>
      <max_execution_time>10</max_execution_time>
      <max_memory_usage>2147483648</max_memory_usage>
      <max_rows_to_read>5000000000</max_rows_to_read>
      <max_bytes_to_read>536870912000</max_bytes_to_read>
      <max_result_rows>10000</max_result_rows>
      <max_result_bytes>67108864</max_result_bytes>
      <read_overflow_mode>throw</read_overflow_mode>
      <result_overflow_mode>throw</result_overflow_mode>
      <timeout_overflow_mode>throw</timeout_overflow_mode>
      <cancel_http_readonly_queries_on_client_close>1</cancel_http_readonly_queries_on_client_close>
    </netsight_flows_reader>
  </profiles>
  <users>
    <netsight_reader>
      <profile>netsight_flows_reader</profile>
      <password_sha256_hex><!-- generated, never committed --></password_sha256_hex>
      <networks><ip>10.0.0.0/8</ip><!-- the API host only --></networks>
      <quota>default</quota>
      <access_management>0</access_management>
    </netsight_reader>
  </users>
</clickhouse>
```

Also bound concurrency server-side (`max_concurrent_queries_for_user` in the server configuration) at no more than the API's
own cap of three heavy reads per worker times the number of workers. Verify as the Netsight user with
`SELECT name, value, readonly FROM system.settings WHERE name LIKE 'max_%' OR name LIKE '%overflow_mode'`.

**Counts are approximate above small cardinalities.** Distinct source and destination addresses use `uniq` (adaptive sampling
over a 64-bit hash: exact in practice for the small groups the small-cohort rule cares about, a close estimate for large
ones), not `uniqExact`, which keeps every key in memory. The contract carries no "approximate" flag: the figures are labelled
counts of addresses, and the cohort comparison (`< k`) is made where `uniq` is exact. Filters compare the typed column
(`Application = {f:String}`, `InIfBoundary = 'external'`, and `SrcAddr IN ({f:IPv6})` when discovery reports an `IPv6`
column) rather than rendering a string for every row; an address column of any other type falls back to the text comparison.

## Verification

Adapter SQL and HTTP behaviour are pinned by mock-transport unit tests
(`test_clickhouse_adapter.py`) and validated against a live ClickHouse server
(26.10 HTTP interface) during development. An opt-in integration test runs
only when `CLICKHOUSE_TEST_DSN` is set; without it the test skips rather than
fabricating a result.

## Step 7 reads (Flow Explorer, Applications, Destinations, baselines)

Implemented in `adapters/clickhouse_explorer.py` (SQL text in `adapters/clickhouse_queries.py`, pure functions: values are
bound as typed `param_*` placeholders, identifiers are constants, nothing a caller typed is ever part of the SQL text). Every
query is a plain `SELECT` with a time window, a `LIMIT` and `FORMAT JSON`, and the whole read has a time budget (25 s,
`ExplorerClickhouse.budget_seconds`). The independent queries of one request run concurrently and are cancelled together on the
first failure; any failing query makes the whole read `unknown` (a partial answer would be dishonest).

| Read | Queries after discovery | Notes |
| --- | --- | --- |
| Flow Explorer (`/traffic/flows`) | rows, timeline, volume, application mix, top destinations (5; 4 without the application column; 4 without rows for a role that may not read them) | rows are the highest-byte flows (limit 1-500); the aggregations cover the whole filtered window |
| Applications | 1 (two windows in one pass with `sumIf`) | previous window only for windows of at most 7 days |
| Destinations | 2 (roll-up, and first-seen over a 31-day look-back restricted to the same top-N by a sub-query) | |
| Baselines | 5 (hourly totals, hourly application series for the ten largest, oldest record, first-seen ASNs, first-seen destinations) | cached 300 s by the API, see TRAFFIC-BASELINES.md |

### Additional optional columns (used only when discovery finds them)

| Column | Used for | If absent |
| --- | --- | --- |
| `ExporterName` | the `device` filter (the flow exporter, i.e. the reporting router or switch) | the read is `unknown` with `unsupported: ["device"]`, never unfiltered |
| `SrcVlan` / `DstVlan` | the `vlan` filter (either side) | `unsupported: ["vlan"]` when both are absent |
| `Application` | the `application` filter, application mix, Applications, application baselines | the mix is `null` ("not reported"); `/traffic/applications` is `unknown` with `unsupported: ["application"]` |
| `ApplicationCategory` | the category on Applications | `null` |
| `SrcPort` | the `port` filter also matches the source port | destination port only |
| `DstPort` | the `port` filter, the destination port shown | `unsupported: ["port"]` when `DstPort` is absent |
| `SrcCountry` / `DstCountry` | the `country` filter (either side); the destination country | `unsupported: ["country"]`; `null` |
| `SrcAS` / `DstAS` | the `asn` filter (either side); the destination ASN; first-seen ASNs | `unsupported: ["asn"]`; `null`; no ASN flags |
| `InIfBoundary` + `OutIfBoundary` | `direction`: external -> internal is `inbound`, internal -> external is `outbound`, internal -> internal is `internal`, anything else `unknown`; and the `direction` filter | `direction` stays `unknown`; the filter is `unsupported` |

The source's own `User` column is **no longer read**: a person is named only through the identity service, with a basis.

### Caveats stated, not hidden

* Volumes are the sum of the stored `Bytes` counter. Akvorado's UI scales by `SamplingRate`; this surface does not, because
  extrapolation is an estimate. A deployment that samples will read low by the sampling factor. Whether to offer the scaled
  figure (clearly labelled as scaled) is a human decision.
* `DstHostname` is whatever the pipeline resolved (typically reverse DNS), and whoever owns an address controls its reverse DNS.
  It is shown as untrusted text and can deny, never allow, in the operator policy.
* Address filters compare the typed `IPv6` column against the IPv4-mapped spelling (or `toString(<column>)` against both
  stored spellings when the column type is not `IPv6`), so they do not use a primary-key index on the address; the time
  window (the table's partition key) bounds the scan, and the resource limits, the query budget and the admission control
  bound the cost. A large deployment may want a materialised view per
  address; that is a follow-up.
* The SQL grammar for these reads is pinned by mock-transport tests and by an opt-in live test (`CLICKHOUSE_TEST_DSN`, which
  skips when unset). **They have not been run against a live ClickHouse in this step** (none was available); the first
  live run should be the first thing done with a real Akvorado deployment.
