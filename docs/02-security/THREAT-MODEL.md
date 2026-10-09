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

### Alert rules, maintenance windows and notifications (S6-3) - threat-model delta
Adds the first routes that change monitoring configuration and the first outbound-call code (webhook notifications). The routes never send; the notification code is not yet wired to them. Status:

- **Elevation of privilege / tampering (controlled).** A rule is created as a draft and activates only through `alert-rules:approve` (administrators), bound to the `expected_version` the reviewer saw: the version check and the activation are one store operation under the row lock, so an edit that lands after review turns the approval into a 409 (proved with threads and under live PostgreSQL row locks). A rule that cannot be evaluated here never activates (checked at create, update, approve and every evaluation). All write permissions are human-only, so no AI or service principal can create, edit, approve, disable or schedule maintenance, whatever role it carries (AGENTS.md: AI may not alter monitoring configuration). A maintenance window suppresses notifications, so it is bounded (<= 30 days, must not have ended, <= 1 year ahead) and either an organisation scope or `evaluation: disable` (at any scope) needs `maintenance:write-organisation` (administrators) — a site-scope `disable` window stops all evaluation and is gated the same way. **Residual:** "Scoped" roles are not scoped (no ABAC): a Network Engineer or Security Analyst can disable any rule and schedule a window for any non-organisation scope, which is the main abuse path for silencing alerts; there is no four-eyes rule (the creator may approve) and no step-up authentication. Both are open human decisions.
- **Server-side request forgery (webhook sender).** Layered and tested with an injected resolver and transport (no real network): https only; no userinfo, backslash, control character, IP literal or numeric host spelling (decimal, hex, octal, short forms); deny-by-default host allow-list (`NETSIGHT_WEBHOOK_ALLOWED_HOSTS`, exact hosts or `*.domain`) and port allow-list; the name is resolved once and every answer must be a globally routable unicast address (loopback, private, link-local including 169.254.169.254 and fd00:ec2::254, CGNAT, special-purpose, multicast, reserved; IPv4-mapped, NAT64, 6to4, Teredo and IPv4-compatible forms are unwrapped or blocked; non-canonical answers are refused); the connection goes to the validated address while SNI and the `Host` header carry the name (certificate verified, DNS rebinding cannot swap the target between check and connect, a rebound second lookup is refused); redirects are never followed and proxy environment variables are ignored; connect/read timeouts plus a total deadline; at most the configured response bytes are read and discarded, never logged or stored. There is deliberately no setting that permits private targets. **Residual:** the OS name lookup (`system_resolver`) has no timeout of its own; a compromised allow-listed host, or a wildcard entry exposed to subdomain takeover, is trusted to receive notifications; the allow-list is the trust boundary and must be reviewed like a firewall rule.
- **Information disclosure.** Webhook URLs and header values are `Secret` objects (no repr/str/log/pickle/exception text; delivery records and audit lines carry only a hash or host label and static codes); notifications carry enough context to act and a link to authenticated Netsight, not raw telemetry. **Open:** once destinations are persisted the URLs must live in the secret store, not in the rules database.
- **Injection and untrusted text.** Rule names, labels, exception entries, entity names and observation text are untrusted: stored and returned verbatim as data under `application/json`; webhook bodies are JSON (ASCII on the wire); email subjects are a single sanitised line (no header injection, bidi overrides removed) and bodies are plain text, never HTML; nothing is interpreted as markup or as an instruction to an AI. The `matches` operator is a glob evaluated by a bit-parallel matcher (no regular-expression backtracking), with the pattern <= 256 and the text <= 4096 characters.
- **Repudiation (improved, not closed).** Every mutation and every refusal is audited with actor, target id, version and action from the worker thread; free-form values are logged as a length and short hash. This closes the S6-2 gate item that rule edits and disables carry an actor. The sink is still an operational log, not a tamper-evident store, and reads are not audited.
- **CSRF.** Reuses the S6-2 token and origin guards for every write, and also for the dry-run (a cookie POST that costs CPU); a refusal is audited and consumes no rate-limit budget; authorisation is judged before CSRF so the token is not an oracle for unauthorised callers.
- **Denial of service.** The dry-run is bounded (200 observations, 20 windows, text 4096, pattern 256, linear matcher; worst case measured at about 0.3 s) and rate limited per identity; writes share a per-identity limit; the delivery queue is bounded (overflow dropped and recorded), retries are capped at 5 attempts with delays <= 60 s, and the delivery log is a ring buffer. **Open:** no request body size cap, per-worker in-memory limiters, no read rate limit.
- **Other open items.** Escalation, routing and delivery are not yet connected to alert state; delivery attempts are not durable; production email/push senders do not exist; timezone data is a declared dependency (`tzdata>=2024.1`; without it scheduled rules fail closed and cannot be saved or approved).

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
