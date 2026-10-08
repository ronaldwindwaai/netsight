# Threat Model — Initial STRIDE Analysis

## Assets
- user identities/sessions;
- network topology;
- device inventory;
- traffic metadata;
- security events;
- integration credentials;
- action credentials;
- incident data;
- audit logs;
- configuration history;
- AI knowledge/tools.

## Major threat actors
- external attacker;
- compromised user;
- compromised administrator;
- malicious insider;
- compromised endpoint;
- supply-chain dependency;
- malicious telemetry/log producer;
- compromised integration engine.

## Trust boundaries
See system architecture.

Additional boundary added with the topology surface (S3): the NetBox
pagination URL (`next`) is source-controlled and is followed by the service
with the NetBox token attached — it is validated to the exact configured
origin before use (`adapters/netbox.py:_next_path`). Source-reported device
names cross a second boundary into the browser as inert text.

## Threats and mitigations

### Spoofing
Risk: forged session, OIDC confusion, device/user misattribution.
Mitigation: OIDC validation, tenant/domain restrictions, immutable subject IDs, session security, evidence confidence for network identity.

### Tampering
Risk: modified incidents/config/actions/audit.
Mitigation: RBAC, integrity controls, append-only audit, approvals, versioned configs.

### Repudiation
Risk: admin denies remote change.
Mitigation: authenticated action requests, timestamps, correlation IDs, approval history, immutable audit retention.

### Information disclosure
Risk: traffic metadata/topology/security logs exposed.
Mitigation: least privilege, encrypted transport/storage, field masking, management summaries, secret redaction.
Topology specifics: cross-origin pagination URLs are rejected (SSRF/credential
leak guard), adapter tokens are `repr=False` and never logged, source failures
degrade to an explicit `unknown` state with static error data, and the
`/api/v1/topology` response is validated against the canonical schema before
it leaves the boundary. Regression tests: `test_security_matrix.py`
(hostile pagination origin, hostile node name, token echo).
Traffic specifics: the ClickHouse DSN, user and password are read from the
environment only and excluded from client `repr`, so credentials cannot leak
through logs; flow labels/hostnames are treated as untrusted source text
(passed through as data, never interpreted as markup or instructions); a
failed or schema-invalid flow read degrades to an explicit `unknown` state
with static error data; and the `/api/v1/traffic/*` responses are validated
against the canonical schema before leaving the boundary.
Traffic reads are currently unscoped by site/asset and are not separately
audit-logged. Both are recorded platform follow-ups (ABAC/site scoping and an
audit event for privacy-sensitive reads) awaiting the platform RBAC/audit
slice; deny-by-default still holds because every route requires `traffic:read`.
The adapter also refuses to follow upstream redirects (no credential re-send)
and degrades transport/TLS failures to `UNAVAILABLE`; regression tests pin
both.
Security-events specifics: the Wazuh indexer URL, user, password and CA bundle are read from the environment only and excluded from client `repr`; alert signature/category/address text is untrusted telemetry (length-bounded, passed through as data, rendered as plain text, never interpreted as markup or an AI instruction); `device_id` is only ever null until agent->device mapping exists (no IP inference); the adapter is read-only (`_search` only), verifies TLS, refuses redirects, validates URL and index pattern, and any source failure or contract-invalid row degrades to an explicit `unknown` with static error data. `/api/v1/security/events` requires `security:read` and is validated against `security.schema.json` before leaving the boundary. Security reads are not site-scoped and not audit-logged yet (same platform ABAC/audit follow-ups as traffic).

### Denial of service
Risk: expensive flow queries, diagnostics floods, upstream failures.
Mitigation: rate limits, query budgets, timeouts, async jobs, caching, degradation.
Topology specifics: one request fans out to at most 12 upstream calls (≤10
cable pages × `limit=1000` + 1 NetBox devices page + 1 LibreNMS devices page), each bounded by a 10s timeout;
graphs are capped at 10,000 nodes/edges and fail closed to `unknown`.
Open follow-up: per-IP rate limiting and response caching for `/api/v1/topology`.
Traffic specifics: each traffic request fans out to at most 2 upstream
ClickHouse calls (1 `system.columns` discovery, cached for the lifetime of the
per-request client instance, + 1 data query; ≤3 when a readonly identity forbids
settings and forces one settings-free retry), each bounded by a read timeout and
an explicit window (≤31 days) plus a row limit (≤100 for top-talker/destination,
≤500 for flows). When the identity permits `max_execution_time` it is sent as a
server-side query budget. A source failure never becomes a 5xx and never returns
partial data as if complete.
Open follow-up: per-identity rate limiting (and process-level `system.columns`
caching) for `/api/v1/traffic/*` — the `/traffic` page alone issues three reads
per render, consistent with the existing `/api/v1/topology` rate-limit follow-up.
Security-events specifics: one request issues exactly one indexer `_search` bounded by a window (<=31 days), a row cap (<=500) and a read timeout. Open follow-ups: per-identity rate limiting for `/api/v1/security/events`; a single malformed hit currently degrades the whole read to `unknown` (a `partial` state would be more useful).

### Elevation of privilege
Risk: AI/tool or user obtains write capability.
Mitigation: separate credentials, backend policy, step-up auth, approval, scoped targets.

### Incident routes (S6-2) - threat-model delta
`/api/v1/incidents` adds the first authenticated state-changing API. Status after the S6-2 review fixes:

- **Elevation of privilege / tampering (fixed).** The technician's "Assigned" scope was first checked by an unlocked read before the write, so a reassignment between the check and the write was a time-of-check/time-of-use gap. The store now receives `required_assignee` and compares it with the assignee of the *locked* incident row (`ScopeViolationError` -> 403 audited as `scope`), judged before the state machine so a caller outside the scope learns nothing about the incident. Conformance tests cover the in-memory and PostgreSQL stores; a live-PostgreSQL test reassigns the incident while the technician's write waits on the row lock and proves it is refused and nothing is written. Resolve and reopen stay human-principal only (no AI/service principal can record a root cause); closing is reserved for the full roles.
- **CSRF / cross-site request forgery (hardened).** The session is resolved once per request and the CSRF decision uses that same object; the check fails closed (403) when a session-sourced identity has no session or a human identity has unknown provenance, and the token comparison is byte-safe (a non-ASCII token is an audited 403, not a 500). Cookie-authenticated writes additionally require an `Origin` (else `Referer`) from the configured allow-list (`NETSIGHT_ALLOWED_ORIGINS` plus the origin of `NETSIGHT_PUBLIC_BASE_URL`; the Host header is never trusted because of DNS rebinding); a request with neither header (a non-browser client) is accepted only with a valid token. `SameSite=None` is rejected at start-up unless `NETSIGHT_SESSION_ALLOW_SAME_SITE_NONE=true` and the cookie is Secure.
- **Development identity bridge (hardened; residual risk accepted for local development only).** With `NETSIGHT_ENV=development` and `NETSIGHT_ENABLE_DEV_IDENTITY=true` every request is an administrator with no credential, i.e. an ambient credential a foreign page in the developer's browser could ride. Bridge writes now require a non-empty `X-CSRF-Token` header (a custom header cannot be sent cross-site without a CORS preflight, which this API never grants) and the same origin allow-list. A loopback-bind guard was rejected: the app does not know its bind address and the attack originates from the developer's own browser, which is on loopback anyway. The bridge must never be enabled outside local development.
- **Repudiation (improved, not closed).** Every mutation, refused or not, emits a structured audit record. The success and failure records are written by the worker thread right after the store call so a client disconnect cannot lose them; the refusal target is the validated incident id; free-form identifiers (assignee, evidence reference) are logged as a length and short hash; over-long actor ids are hashed rather than truncated so distinct identities never collide. The `netsight_api.audit` logger is explicitly configured at start-up (INFO, JSON lines, stderr/stdout/file; `docs/08-operations/AUDIT-LOGGING.md`): before this fix Python's default WARNING level silently dropped the INFO success records. **Still open:** the sink is an operational log, not a tamper-evident store (PRD 32); reads are not audited; the append-only incident timeline remains the authoritative record.
- **Information disclosure (open).** Reads require only `incidents:read`: the technician read scope ("Assigned") is enforced for writes only, there is no site/asset scoping, and whether the Management role should get a summary-only view is an **open human decision** (not decided here). Audit records never contain comment, reason, root-cause or resolution text.
- **Denial of service (partly mitigated).** Writes are rate limited per identity (60 per minute, per worker process, in memory). **Open:** reads have no rate limit and the store uses one connection per call (no pool); there is no request body size cap beyond field limits. A store failure degrades reads to an explicit `unknown` and writes to 503 without leaking the DSN or driver text; an unexpected exception is a 500 `INTERNAL_ERROR` with no detail (only pydantic validation errors and known domain errors map to 4xx).
- **Other open items.** The application role holds column-level `UPDATE` on `incidents` (state, assignee, evidence, resolution, updated_at): SQL run as that role (a bug or an injection) could change state without writing the timeline event, so the record and its history can diverge; a trigger or stored-procedure write path is the follow-up. Resolve/reopen have no step-up authentication yet. The session store and the rate limiter are per worker process. `POST comment` is not idempotent, so a client retry after a timeout can post it twice. `assignee_id` is validated for length only, not shape.

## AI-specific threats
- prompt injection in logs/hostnames/knowledge;
- tool injection;
- data exfiltration through model;
- hallucinated operational state;
- unsafe remediation;
- poisoned baselines.

Mitigate with:
- telemetry-as-data isolation;
- schema tools;
- policy outside LLM;
- data minimisation;
- evidence citations;
- no direct write tools in MVP;
- baseline governance.
