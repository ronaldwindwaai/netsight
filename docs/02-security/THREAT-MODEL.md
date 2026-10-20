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
- **Information disclosure (open).** Reads require only `incidents:read`: the technician read scope ("Assigned") is enforced for writes only, there is no site/asset scoping, and Management now has a summary-only view (decided 2026-10-10; see the Step 3 delta). Audit records never contain comment, reason, root-cause or resolution text.
- **Denial of service (partly mitigated).** Writes are rate limited per identity (60 per minute, per worker process, in memory). **Open:** reads have no rate limit and the store uses one connection per call (no pool); there is no request body size cap beyond field limits. A store failure degrades reads to an explicit `unknown` and writes to 503 without leaking the DSN or driver text; an unexpected exception is a 500 `INTERNAL_ERROR` with no detail (only pydantic validation errors and known domain errors map to 4xx).
- **Other open items.** The application role holds column-level `UPDATE` on `incidents` (state, assignee, evidence, resolution, updated_at): SQL run as that role (a bug or an injection) could change state without writing the timeline event, so the record and its history can diverge; a trigger or stored-procedure write path is the follow-up. Resolve/reopen step-up authentication was added in Step 3 (see that delta). The session store and the rate limiter are per worker process. `POST comment` is not idempotent, so a client retry after a timeout can post it twice. `assignee_id` is validated for length only, not shape.

### Alert rules, maintenance windows and notifications (S6-3) - threat-model delta
Adds the first routes that change monitoring configuration and the first outbound-call code (webhook notifications). The routes never send; the notification code is not yet wired to them. Status:

- **Elevation of privilege / tampering (controlled).** A rule is created as a draft and activates only through `alert-rules:approve` (administrators), bound to the `expected_version` the reviewer saw: the version check and the activation are one store operation under the row lock, so an edit that lands after review turns the approval into a 409 (proved with threads and under live PostgreSQL row locks). A rule that cannot be evaluated here never activates (checked at create, update, approve and every evaluation). All write permissions are human-only, so no AI or service principal can create, edit, approve, disable or schedule maintenance, whatever role it carries (AGENTS.md: AI may not alter monitoring configuration). A maintenance window suppresses notifications, so it is bounded (<= 30 days, must not have ended, <= 1 year ahead) and either an organisation scope or `evaluation: disable` (at any scope) needs `maintenance:write-organisation` (administrators) — a site-scope `disable` window stops all evaluation and is gated the same way. **Residual:** "Scoped" roles are not scoped (no ABAC): a Network Engineer or Security Analyst can disable any rule and schedule a window for any non-organisation scope, which is the main abuse path for silencing alerts; there is no four-eyes rule (the creator may approve; decided 2026-10-10 to keep it). Step-up authentication was decided for incident resolve/reopen only, not for rule approval (see the Step 3 delta).
- **Server-side request forgery (webhook sender).** Layered and tested with an injected resolver and transport (no real network): https only; no userinfo, backslash, control character, IP literal or numeric host spelling (decimal, hex, octal, short forms); deny-by-default host allow-list (`NETSIGHT_WEBHOOK_ALLOWED_HOSTS`, exact hosts or `*.domain`) and port allow-list; the name is resolved once and every answer must be a globally routable unicast address (loopback, private, link-local including 169.254.169.254 and fd00:ec2::254, CGNAT, special-purpose, multicast, reserved; IPv4-mapped, NAT64, 6to4, Teredo and IPv4-compatible forms are unwrapped or blocked; non-canonical answers are refused); the connection goes to the validated address while SNI and the `Host` header carry the name (certificate verified, DNS rebinding cannot swap the target between check and connect, a rebound second lookup is refused); redirects are never followed and proxy environment variables are ignored; connect/read timeouts plus a total deadline; at most the configured response bytes are read and discarded, never logged or stored. There is deliberately no setting that permits private targets. **Residual:** the OS name lookup (`system_resolver`) has no timeout of its own; a compromised allow-listed host, or a wildcard entry exposed to subdomain takeover, is trusted to receive notifications; the allow-list is the trust boundary and must be reviewed like a firewall rule.
- **Information disclosure.** Webhook URLs and header values are `Secret` objects (no repr/str/log/pickle/exception text; delivery records and audit lines carry only a hash or host label and static codes); notifications carry enough context to act and a link to authenticated Netsight, not raw telemetry. **Open:** once destinations are persisted the URLs must live in the secret store, not in the rules database.
- **Injection and untrusted text.** Rule names, labels, exception entries, entity names and observation text are untrusted: stored and returned verbatim as data under `application/json`; webhook bodies are JSON (ASCII on the wire); email subjects are a single sanitised line (no header injection, bidi overrides removed) and bodies are plain text, never HTML; nothing is interpreted as markup or as an instruction to an AI. The `matches` operator is a glob evaluated by a bit-parallel matcher (no regular-expression backtracking), with the pattern <= 256 and the text <= 4096 characters.
- **Repudiation (improved, not closed).** Every mutation and every refusal is audited with actor, target id, version and action from the worker thread; free-form values are logged as a length and short hash. This closes the S6-2 gate item that rule edits and disables carry an actor. The sink is still an operational log, not a tamper-evident store, and reads are not audited.
- **CSRF.** Reuses the S6-2 token and origin guards for every write, and also for the dry-run (a cookie POST that costs CPU); a refusal is audited and consumes no rate-limit budget; authorisation is judged before CSRF so the token is not an oracle for unauthorised callers.
- **Denial of service.** The dry-run is bounded (200 observations, 20 windows, text 4096, pattern 256, linear matcher; worst case measured at about 0.3 s) and rate limited per identity; writes share a per-identity limit; the delivery queue is bounded (overflow dropped and recorded), retries are capped at 5 attempts with delays <= 60 s, and the delivery log is a ring buffer. **Open:** no request body size cap, per-worker in-memory limiters, no read rate limit.
- **Other open items.** Escalation, routing and delivery were not yet connected to alert state, delivery attempts were not durable and production email/push senders did not exist (the first three are closed by the S6 step 2 delta below; escalation levels remain unwired); timezone data is a declared dependency (`tzdata>=2024.1`; without it scheduled rules fail closed and cannot be saved or approved).

### S5/S6 hardening pass (2026-10-10) - threat-model delta
Closes the S5 review follow-ups (M1-M4, L1-L5) and the S6-2 carry-overs for request size and read rate limiting. Status:

- **Information disclosure / spoofing (Wazuh credentials, M1).** The indexer client refuses to send Basic credentials over plain http (typed `unavailable`, no request made, so the endpoint degrades to `unknown`). The only bypass is `WAZUH_INDEXER_ALLOW_HTTP=true` and it is honoured only when `NETSIGHT_ENV=development`. A CA bundle (`WAZUH_INDEXER_CA_BUNDLE`) is loaded as an `ssl.SSLContext`; an unreadable bundle fails closed to `unavailable` without echoing the path.
- **Tampering / over-broad reads (L4).** `WAZUH_ALERTS_INDEX` must start with `wazuh-`; `_all`, `*`, `.security` and other-vendor indices are a misconfiguration, so a typo cannot widen the read-only identity's reach.
- **Denial of service (L3, body cap, read limits).** Indexer responses are streamed with an 8 MiB cap (declared length and bytes read); over the cap is `invalid-source-data`. Every POST/PUT/PATCH/DELETE body is capped at 1 MiB (declared `Content-Length` checked first; any other body is buffered up to the cap before the handler runs, so an overflow is answered 413 with the handler never invoked and never sees a truncated body; malformed lengths fall back to counted bytes), answered 413 `PAYLOAD_TOO_LARGE` in the standard envelope with the correlation id; GETs are unaffected. Device, alert, alert-rule, maintenance-window, incident, security and traffic reads are limited to 300 per minute per identity per family (a single-operator assumption: a dashboard page issues a handful of reads, so 300/min leaves large headroom while still bounding scraping; revisit if polling UIs or automation share one identity) (429 `RATE_LIMITED` with `Retry-After`), judged after authorisation so 401/403 never reveal limiter state. Same in-memory, per-worker limitation as the write limiter (a shared store is still needed before more than one worker). Residual: the diagnostics routes (`diagnostics:read`, own permission dependency) are not yet behind the read limiter; the body cap is app-level, so a reverse-proxy limit (`client_max_body_size`) should still be set at the edge.
- **Repudiation / operability (L1).** A failed security source read now logs the typed adapter status (`adapter_status`: unavailable, forbidden, invalid-source-data) next to the error type; never the detail text or credentials.
- **Integrity of the contract (M3, M4).** OpenAPI `SecurityEventsResponse` now carries the same non-ok => no-rows rule as the JSON schema, and a diff test keeps the component and its event schema equal to `security.schema.json`. Whitespace-only optional fields are treated as absent (stripped before the empty check), so one padded field no longer degrades the whole read to `unknown`.
- **Still open.** Read auditing, site scoping, shared (multi-worker) rate-limit store, `partial` state for malformed hits, live Wazuh integration test.

### Evaluation service: observations, incidents and notifications (S6 step 2) - threat-model delta
Adds the first background writer (it creates incidents and sends mail), the first outbound email and the first durable delivery
data. Off unless `NETSIGHT_EVALUATION_ENABLED` is set; enabled, it refuses to start without `DATABASE_URL` or with any invalid
channel setting. Status:

- **Spoofing / elevation of privilege (controlled).** The evaluator acts as `service:alert-evaluator`, a `PrincipalKind.SERVICE`
  with no roles, so it holds no permission and the human-only ones (resolve, reopen, rule and window changes) are denied twice.
  Its code path can create an incident, append `alert-linked`/`comment` notes and claim links; a static test fails the build if
  the `evaluation` package ever references a transition, assignment, evidence, rule or window mutation, if a route module imports
  a sender, or if anything but `evaluation/wiring.py` wires the SMTP or push senders. A recovered alert deliberately leaves its
  incident open: resolution records a human judgement and is never automatic. The evaluator reaches the incident store through a
  narrow `EvaluatorIncidents` Protocol (create, append note, get) and, when a human resolves an incident while the alert still
  fires, it opens no replacement until the alert has recovered (durable `recovered_at` mark), also across restarts. **Residual:** the application database role gained
  `INSERT` (and `UPDATE (incident_id, linked_at, recovered_at)`) on `alert_incident_links` and `INSERT` on `notification_delivery_attempts`; SQL
  executed as that role (a bug or an injection) could repoint a link, causing a duplicate or a suppressed incident, the same class
  of residual as the column-level `UPDATE` on `incidents`. Delivery attempts are append-only (grants plus `ENABLE ALWAYS`
  triggers), but the owner/migrator role can still disable the triggers: keep that credential out of the running service.
- **Tampering / spoofed telemetry (inherent).** A compromised or misbehaving LibreNMS can make the platform raise or withhold
  alerts. Only numeric values and canonical device ids enter the engine; device names and alert titles are never copied into an
  observation. A failed, refused, timed-out, oversized (> 5000 entities) or unparsable read is `unknown` and neither fires nor
  recovers an alert, an unconfigured source is `not-connected`, and a reading the source cannot state is no data: nothing is
  fabricated. A rule whose metric no source supports is reported `unsupported` and never receives data.
- **Silencing abuse (narrowed).** Maintenance windows now reach only availability metrics (`device.status`,
  `interface.oper_status`, `availability.*`; a closed list in `evaluation/source.py`), so a window cannot silence a traffic,
  security or count-based rule. Within availability, the earlier residual stands (scoped roles can schedule non-organisation
  `retain` windows for any scope).
- **Denial of service / alert flooding (bounded).** Cycle interval >= 30 s; per cycle at most 500 rules, 200 000 evaluations, 100
  incident actions, 50 notifications (the rest wait in a backlog of 1000; overflow is counted and audited as failed), 4 concurrent
  source reads with a 30 s timeout; tracked state <= 50 000 and pending or firing state is never evicted, so a flood cannot reset
  debounce or cooldown. Overlapping cycles do not queue. Incident creation is idempotent per key (compare-and-set link), so a
  sustained alert is one incident, not one per cycle. **Residual:** policy `create` opens one incident per alert, so a mass
  outage on N devices opens N incidents (up to 100 per cycle); the `group` policy exists for that and choosing it is the rule
  author's call. A slow relay is bounded: each send has an overall 60 s timeout (`SEND_TIMEOUT`, final) and the notification phase
  has a 60 s per-cycle deadline, the remainder waiting in the (severity-ordered) backlog; a hung send leaves one abandoned
  worker thread until its socket timeout fires. The OS name lookup still has no timeout (carried over from S6-3). The
  evaluation budget is shared fairly between rules and entities are visited round-robin, so one large rule cannot starve the rest.
- **Information disclosure (controlled).** SMTP password, push gateway URL and token, and push device references are `Secret`
  values (no repr, str, log, pickle or exception text; configuration errors never echo values). TLS is mandatory for email
  (STARTTLS or implicit TLS, TLS 1.2 minimum, certificate and host-name verification on, no plaintext setting, no fallback after
  a failed STARTTLS, credentials sent only after TLS). Notifications carry the rule name, entity id, severity and a link to
  authenticated Netsight, not telemetry. Audit lines and the delivery table hold a keyed hash or host, static codes and ids;
  never addresses, tokens, payload text or provider replies. **Residual:** email passes through the configured relay in plain text
  inside TLS hops (no end-to-end encryption), so the relay is trusted with rule names and device ids.
- **Server-side request forgery.** The push gateway reuses the webhook defences unchanged (https, allow-list, public addresses
  only, pinned connection, no redirects, bounded time and size). **Residual:** the gateway host shares `NETSIGHT_WEBHOOK_ALLOWED_HOSTS`
  with webhooks; the SMTP relay host is operator configuration and is not subject to the allow-list.
- **Injection and untrusted text.** Rule names and entity ids reach incident titles, timeline notes, email subjects and push text
  only through `sanitize_line` (control and bidi characters removed, one line, length bounded) and are stored and rendered as data;
  email is plain text, push is bounded plain text, nothing is interpreted as markup or as an instruction to an AI.
- **Repudiation (improved, not closed).** `incident.auto_create`, `incident.auto_attach` and `notification.send` are audited with the
  service actor and the cycle's correlation id, plus the durable `notification_delivery_attempts` table and the append-only incident
  timeline (each automatic note is written by `service:alert-evaluator`). The audit sink is still an operational log; reads are
  still not audited.
- **Fail-closed behaviour.** Rule store unreadable: nothing is evaluated. Source unknown or not connected: nothing fires, nothing
  recovers, pending debounce restarts. Durable delivery store down: the attempt stays in the in-memory ring and delivery goes on
  (counted, logged by type). Ledger unreadable for the cooldown check: the page is sent rather than muted. No public base URL: no
  notification is sent and the refusal is audited. A failed incident step does not stop the page, and a failed page does not
  undo the incident.
- **Single evaluator (enforced).** A PostgreSQL advisory lock on a dedicated, keepalive-enabled connection gates the scheduler;
  others idle and retry, and losing the lock stops evaluation and drops engine state. A lock backend error means not leader.
  Review fix (S6 step 2/3 review): the lease is re-verified against `pg_locks` before every incident write, recovery note and
  send (not once per cycle), under a 10 s timeout with a 30 s `tcp_user_timeout`, and an unlocked-but-alive session counts as lost.
  **Residual:** the lock is per database, not per schema; an overlap is possible only between a lease loss and its next check (one
  send or write); the incident-link compare-and-set still prevents duplicate incidents (an incident, its link and its note are one
  transaction, so a losing racer stores nothing), but a repeat page is then possible (the cooldown ledger limits it).
  `DATABASE_URL` must not point at a transaction-mode pooler (advisory locks are session-bound).
- **Evaluator privilege (defence in depth).** The evaluator holds a three-operation adapter, not the incident repository, and the
  storage layer refuses any `service:` actor for judgements and rule edits. **Residual / follow-up:** it still connects with the
  application database role, so SQL injected by a bug would not be limited by the database; a separate evaluator role is open.
- **Open.** Engine state is per process, so after a restart a repeat page is prevented only by a non-zero
  `cooldown_seconds` and the durable ledger; destinations come from the environment (managing them in the database, and keeping
  secrets in the secret store, is a follow-up); there is no operator-facing evaluator status endpoint yet (logs and audit only);
  the `webhook` channel is unreachable from rule `actions`; there is **no delivery-attempt prune path** (the append-only triggers also stop the owner; an audited
  disable-trigger/delete/re-enable migrator step is undesigned), so the table grows without bound until one exists; SMTP trust is
  the system roots plus the optional bundle; a recovered alert whose recovery was missed (evaluator down for the whole recovery and
  re-fire) is attributed to the old resolved incident.

### UI write actions, step-up authentication and the Management summary view (Step 3, 2026-10-10) - threat-model delta
Turns the S6-4 read-only UI into the first browser-driven writes (incident acknowledge/advance/assign/comment/resolve/reopen, alert-rule
create/edit/approve/disable, maintenance-window create/cancel) and records three human decisions: step-up for resolve/reopen, a
summary-only incident view for Management, and creators may approve their own rules. Status:

- **CSRF / cross-site writes (controlled).** The browser never holds the session CSRF token or the API credentials. Writes are Next.js
  server actions (`incidents/[incidentId]/actions.ts`, `alerts/actions.ts`): each asserts that the browser's Origin/Referer host equals the
  host the request was addressed to (`sameOrigin`, on top of the framework's own check), validates the payload (ids against the contract
  patterns, bodies rebuilt field by field with the contract bounds, `planIncidentRequest` / `planAlertingRequest`), then calls the API
  through `apiPost`, which reads the HttpOnly session cookie server-side, fetches the CSRF token with it and sends both to the loopback
  API. The API's own origin allow-list, CSRF, authorisation, rate limit and audit are unchanged and still decide every write; a server
  action is a public POST, so none of the UI checks is relied on.
- **Elevation of privilege via the UI (controlled; advisory only).** Button availability comes from `permissions` on `GET /auth/session`
  (derived from the same `is_allowed` the routes use) and the incident state. It only explains: a forged call, a stale page or a role
  change still meets the API's 403/409, which the UI shows. A role without a permission gets a disabled control with a plain-text reason
  (permission is explained before state, so a role learns nothing about state rules it cannot use).
- **Step-up authentication (new; closes the S6-2 follow-up).** `incidents:resolve` and `incidents:reopen` require a second factor proven
  within `NETSIGHT_STEP_UP_MAX_AGE_SECONDS` (default 900). The session carries `mfa_verified_at` on the store clock, set from the token's own
  `auth_time` (never session creation time) and only when the token asserts `mfa` in `amr` with a numeric, non-future, in-window `auth_time`
  that, for a step-up, is later than the request (replay of an older token is refused and audited `auth.mfa`/`step-up-replay`); local
  sign-in stamps age 0 after TOTP/recovery code; unknown fails closed with `403 STEP_UP_REQUIRED`,
  audited as `denied`/`step-up`, decided after authorisation and CSRF and before the rate limit. The UI offers "Sign in again", which
  starts a provider sign-in with `step_up=true` (`prompt=login`, `max_age=0`) or the local password + TOTP flow, then returns to the page
  (`safeNextPath` rejects anything but a same-origin path; the auth proxy forwards only `redirect_to` and `step_up`, never `state`).
  **Residual:** `auth_time` is trusted as the provider reports it (a provider that ignores `prompt=login` and reuses its session returns an
  old `auth_time`, which is then refused as stale or a replay); a provider that never emits `amr` (Google) cannot satisfy step-up through OIDC at all (resolve/reopen are then unavailable to
  that sign-in route, which fails closed); the superseded session is revoked by the re-login (see the review delta below); the stamp lives in the
  per-worker in-memory session store; the dev identity bridge is exempt (no session, development only); a step-up redirect discards a
  half-typed resolve form (the dialog says so).
- **Information disclosure - Management (controlled; partly closes the S6-2 open item).** Management loses `incidents:read` and holds
  `incidents:read-summary`: `GET /incidents/summary` returns only id, title, severity, state, timestamps, `assigned` (boolean) and
  `resolved_at`; no evidence ids, resolution text, timeline, comments or assignee identity, and no assignee filter (it would be an
  ownership oracle). Detail and timeline answer 403 for that role. The projection happens in the route, so the response model cannot carry
  the omitted fields; JSON Schema, OpenAPI, pydantic and the TS parser reject any of them (shared vectors). **Residual:** `title` is
  operator/alert-authored text and can name assets; the summary read shares the per-identity read rate limit and is not audited (read
  auditing is still open); `permissions` on `/auth/session` discloses only the caller's own grants.
- **Tampering / integrity - alerting (controlled).** Approve and edit send the `expected_version` the operator saw (a concurrent edit is a
  409, shown as "the record changed; reload"); the approval dialog restates the exact version, scope and condition. Creators may approve
  their own rules (human decision; no four-eyes), which the dialog states and the audit record attributes to the approver. Disable and
  cancel carry no version (they are state transitions the API answers 409 to when already applied). Operator text (names, labels,
  patterns, reasons, comments, assignees) is only ever placed in controls and text nodes (`no-raw-html.test.ts` still passes).
- **Repudiation / lost updates.** A write whose answer is lost (timeout, network, unparseable response) is reported as "result could not
  be confirmed; reload before repeating", never as success or as a plain failure; every control is single-flight (a ref guard, so two
  clicks in one tick send one request) and a dialog cannot be dismissed while a request is in flight. Comments are still not idempotent
  (a retry after a lost answer can duplicate one; the dialog says to reload first).
- **Still open.** Read auditing; surfacing MFA recency in the session so the UI can prompt before a long form is filled; per-site scoping of the "Scoped" roles; a draft-preserving step-up round trip; Close (resolved -> closed) is not in the UI.

### Step 3 review fix pass (2026-10-10) - threat-model delta
Closes the independent code and security review of the Step 3 UI write actions. Status:

- **Open redirect (controlled).** The sign-in destination (`redirect_to` on the API, `next` on the web) is accepted only as a same-origin
  absolute path whose first segment is a dashboard area (`overview`, `network`, `devices`, `traffic`, `security`, `diagnostics`, `incidents`,
  `alerts`), checked as written **and** after percent-decoding. Rejected: `//`, a backslash, control characters (so a tab after the first
  slash, `/` followed by a backslash and `/%09/` all fall back to `/overview`), bidi and zero-width characters, `/api`, `/auth`, `/login`, more
  than 512 characters. The same rules are implemented twice and tested on both sides (`auth/redirects.py`, `sign-in-redirect.ts`).
- **Cross-site server actions (tightened).** `sameOrigin` now requires the Origin header when present and consults Referer only when Origin is
  absent (a present-but-unusable Origin, e.g. `null`, is a rejection and never falls back); scheme **and** host (with port) must match, with
  https required in production except on loopback. `X-Forwarded-Host` / `X-Forwarded-Proto` are client-controllable, so they are honoured only
  when `NETSIGHT_TRUST_PROXY_HEADERS=true` is set explicitly (exact value; default off). Turn it on only behind a reverse proxy that
  **overwrites** both headers; with it off, the proxy must pass the public name in `Host`. A misconfiguration fails closed (writes are refused
  as "not from this site"), never open. Diagnostics and the write actions share one implementation (`fromSameOrigin`).
- **Session fixation / stale sessions (closed).** Completing an OIDC callback or a local MFA verification revokes the session the browser
  presented (`SessionManager.revoke_cookie`; a missing or forged cookie revokes nothing) before the new cookie is set. This removes the
  previously recorded residual that a superseded session aged out on its own.
- **Audit (tightened).** A denied `auth.mfa` record carries `identity_fingerprint` (a short SHA-256 of the provider-qualified identity), so
  repeated denials correlate without recording who was refused. The step-up replay check allows `STEP_UP_REPLAY_TOLERANCE_SECONDS` = 5 s
  (provider clock skew and second-granularity `auth_time`); a token older than the request by more than that is still a replay.
- **Dev identity bridge (pinned).** Tests assert it cannot be enabled when `NETSIGHT_ENV` is anything other than exactly `development`
  (production, staging, test, empty, other casing or spacing) even with `NETSIGHT_ENABLE_DEV_IDENTITY=true`, and that both flags are required.
- **ReDoS (confirmed not applicable).** The `matches` operator is a glob evaluated by a bit-parallel NFA simulation
  (`alerting/matching.py`); no regular-expression engine, `fnmatch` or backtracking is used on rule patterns. Tests pin this by source
  inspection, a catastrophic `*a*a*...b` pattern against 4000 characters, and a linear-growth check; text over 4096 characters never matches.
- **Management summary schema (pinned).** The summary item and list models forbid extra fields (a test per omitted field), so a future change
  that adds assignee identity or evidence ids to the projection fails at validation.
- **UI write safety (tightened).** An unconfirmed result (no usable answer) now **locks** the control: nothing more is sent until the operator
  clicks "Reload current state" (closing the dialog also reloads), so a lost answer can no longer lead to a second comment or rule. A definite
  refusal (409, 422, 503, 429, 403) does not lock. The dialog is a real focus trap (Tab and Shift+Tab wrap; Tab with nothing focusable stays
  on the dialog; keys are handled on the document so a submit button disabled mid-request cannot drop keyboard focus out of the modal), cannot
  be dismissed while a request is in flight, and focuses its first field on open. The 401 advice links to `/login?next=<current path>` through
  `safeNextPath`. Icon-only labels were replaced by visually-hidden text with `aria-hidden` icons. Component tests (jsdom + Testing Library,
  `apps/web/scripts/run-component-tests.mjs`) pin all of this, including the double-click single-flight guard and the per-role disabled reasons.
- **Alert-rule approve/disable are outside step-up** by decision (recorded in RBAC-MATRIX); the audit record and `expected_version` binding
  are the controls.
- **Still open.** Idempotency keys (the lock prevents a resend from this page but not from a second tab or another client); step-up for rule
  approval if the product decides it; a Playwright run of the write flows against a real stack (component tests use jsdom and stubbed server
  actions); the proxy-trust setting is read from the process environment per request and is not validated against the actual proxy; read
  auditing; the per-worker in-memory session store (a revoked session is only revoked in that worker).

### S7 Step 4 - diagnostic sessions, probe locations, path and recent changes (2026-10-10) - threat-model delta
New surface: an immutable `diagnostic_sessions` table (migration 0004), `GET /api/v1/diagnostics` and `GET /api/v1/diagnostics/{id}`, Blackbox exporter probe sources, topology and change reads made by a run, and the `/diagnostics/[id]` page. Status:

- **SSRF through exporter probe sources (controlled).** The exporter URL is operator configuration (`BLACKBOX_EXPORTER_SOURCES`), parsed fail-closed: http(s) only, a host, no userinfo, query, fragment or path, a valid port, a known location; a bad pair is dropped and only counted in the log. The request can never steer which server is contacted: only allow-listed (`BLACKBOX_ALLOWED_TARGETS`) and well-formed (`[A-Za-z0-9._:-]`) targets are sent, as URL-encoded query values; the module is picked from a fixed table (`icmp`, `tcp_connect`, `http_2xx`), never from input. `GET` only, no redirects (a 3xx is `unknown`), no environment proxies, `Accept-Encoding: identity`, a 1 MiB response cap, bounded timeouts. The response is parsed for three numbers (`probe_success`, `probe_duration_seconds`, `probe_http_status_code`) and nothing it returns is echoed, so a hostile or compromised exporter can only make a result `pass`, `fail` or `unknown`. Residual: an operator who points an exporter URL at an internal service gets a blind `GET /probe?module=...` there; exporters carry no authentication in this slice (put them on a management network or behind mTLS at the proxy).
- **Exporter failure is not target failure (integrity of the inference).** An exporter that errors, times out, is unreachable, oversize or malformed yields `unknown`; only `probe_success 0` is a `fail`. A location with no source is `not-connected` and one whose checks were all unanswered is `unknown`; neither is ever shown or inferred as healthy. A branch or remote-site result never stands in for an internal vantage, and a failing user LAN/Wi-Fi alone never names the target host.
- **Untrusted text (controlled).** Targets, symptoms, probe details, NetBox device names, incident/alert titles are untrusted. The probable-cause statements are fixed phrases built from enumerated values and counts, so probe text cannot write the operator's conclusion (a test plants an injection string in `detail` and asserts it is absent from the cause). Device names and change titles are stripped of control/format characters and bounded (255) before storage; the UI renders every value as a React text node (component tests plant `<img onerror>`/`<script>` and assert no element is created) and the session page has no button, form or input (asserted).
- **No fabricated path or correlation.** The path is grown only from explicit NetBox cables, one tier at a time, by a fixed role vocabulary; a tier with no cable, an unrecognised role or two candidates is `unknown` and so is everything beyond it (never "pick the first"). The user end is always unknown. Recent changes are `may-correlate`, `scope: target` only when the source itself ties the record to the target (an alert's device link resolved through LibreNMS), a record about a known other device is dropped, and an unconnected source is `not-connected` (never "no changes"). Configuration changes have no source and say so.
- **Integrity of stored sessions (controlled).** A finished session is never rewritten: the Protocol has no update/delete, saving an existing id is a conflict, the app role holds `SELECT, INSERT` only, and `BEFORE UPDATE OR DELETE` / `BEFORE TRUNCATE` triggers (`ENABLE ALWAYS`, reusing the 0003 function) stop every role including the owner (tests run as owner and as the app role on live PostgreSQL). The document is the validated contract (JSON schema, pydantic, OpenAPI and TS parser agree through shared vectors); the stored cross-field rules (locations equal what the run's checks imply, cause equals the run's conclusion, evidence cites existing checks, only the suspected tier is highlighted) are re-checked on every read, and a row that no longer satisfies the contract reads as `unknown` without leaking driver text. Residual (as for 0002/0003): the table owner can disable the triggers; keep the migrator credential out of the service.
- **Authorisation and disclosure.** Both reads need `diagnostics:read` (deny by default), then a per-identity read limit (300/min, authorisation first so the limiter is never revealed); a run needs the existing guard order (authorise, CSRF + origin, 10 runs/min/identity). Pages are capped (limit <= 100, offset <= 10 000) and the id path parameter is pattern-checked. Errors are fixed messages; the actor is stored for audit but is not part of the contract. **Resolved in the review fix pass below:** `diagnostics:read` is narrowed to the roles the matrix allows, and incident titles are no longer stored. **Still open:** any holder can read any session (no per-owner or per-site scoping); Security Analyst "Security scope" and Technician "Basic" are not yet distinct from Full.
- **Availability.** A run's context reads (topology, changes) are each bounded to 8 s and failures degrade the session sections to `unknown`/`not-connected`; a store that cannot be written reports `stored: false` and never loses the run; a missing store makes the reads `not-connected`. Growth is bounded by the run rate limit and, after the review fix pass, a configurable daily storage cap; there is still **no prune path** (documented in DATA-RETENTION-MATRIX).
- **Audit.** `diagnostic.run` success records now carry the run id as target and `stored`; refusals and probe failures are audited as before. Session reads are not audited (read auditing remains an open platform follow-up).
- **Still open.** Read auditing; retention/prune for sessions (audited migrator step); per-owner or per-site scoping; exporter authentication/mTLS; a configurable role-to-tier vocabulary; NetBox device pagination (a target beyond page one reads as unresolved); per-worker in-memory rate limiter; configuration-change correlation once a change source exists.

### S7 Step 4 review fix pass (2026-10-11) - threat-model delta
Closes the Step 4 independent reviews (code approve, database approve, security pass with follow-ups). Status:

- **Information disclosure (H1, incident titles to roles without `incidents:read`) - closed, fail-closed twice.** (1) `diagnostics:read` now matches RBAC-MATRIX: Management and Auditor are denied on `POST /diagnostics` (audited as a `permission` refusal), `GET /diagnostics` and `GET /diagnostics/{id}`; the sidebar hides Diagnostics and the pages show an access-denied surface (advisory; the API decides). (2) A stored session keeps an incident change only as `{id, kind, severity, time}`; the title is not in the document. The store refuses a session carrying one, and migration 0004 refuses it in the database (`diagnostic_sessions_no_incident_titles`, tested live). `GET /diagnostics/{id}` joins the current title only when the caller holds `incidents:read` at that moment, via the incident store with a per-read bounded lookup (at most 20 ids); a caller without it, a missing or failing incident store and a deleted incident all yield the placeholder with `title_redacted: true` and no error text. The `POST` response carries the run only, so it never held a title (asserted). Alert titles remain stored (all diagnostics roles hold `alerts:read`). Residual: titles already stored by the pre-fix Step 4 build do not exist (0004 was never committed or deployed).
- **SSRF / redirect handling at the exporter (M, closed by documentation + test).** The exporter follows redirects, not Netsight; `http_2xx` must set `no_follow_redirects: true`. `infrastructure/blackbox/blackbox.yml` is the reference and a test fails if it stops saying so or stops defining a module Netsight requests. BLACKBOX.md now states the exporter egress/ingress policy (deny cloud metadata and management planes; allow `GET /probe` only from the API host). Residual: Netsight cannot verify a live exporter's configuration; a misconfigured exporter remains an operator error.
- **Allow-list hardening (M, closed).** `BLACKBOX_ALLOWED_TARGETS` is validated when loaded and shared by both probers: plain names/addresses only; wildcards, CIDR, URLs, userinfo, paths, whitespace, non-ASCII and over-long entries are dropped (fail closed) and only their count is logged; at most 256 entries; nothing valid disables probing.
- **Transport and availability of the exporter client (M, closed).** A plain `http://` exporter URL is warned about (count only, never the URL) and `https` is preferred; one probe now has an overall wall-clock deadline (`BLACKBOX_TIMEOUT_SECONDS`) so a source that trickles bytes cannot pin a worker for longer than the per-read timeout allows (tested with a never-ending trickle).
- **Free text (M).** The run form warns not to paste secrets or personal data into the target or symptom. The text cannot be screened and is stored; the retention period is a **pending human decision** (DATA-RETENTION-MATRIX), not invented here.
- **Denial of service by growth (M, mitigated).** `NETSIGHT_DIAGNOSTIC_SESSIONS_DAILY_CAP` (default 5000/24 h) stops storing (the run is still answered, `stored: false`, audited `not_stored_reason`), with a warning from 80%; an invalid value stores nothing. The cap is soft under concurrency. There is still no prune path: it is **deliberately unbuilt** because its retention floor and audit shape depend on the pending retention decision, and a trigger-disabling migrator function without an approved period is risk without benefit.
- **Defence in depth (database).** The size CHECK counts `octet_length(document::text)` (the compressed column size let a compressible document through; tested with a 1 MiB+ padded document); the mirrored columns (id, target, started_at, completed_at, domain, confidence) must equal the document; a blank target is refused like the contract refuses it; the append-only triggers are proven to fire under `session_replication_role = replica`.
- **Integrity of the inference (code review).** The inferred evidence line no longer cites checks that could not be answered. `infer()` and the run route were split into small helpers with no behaviour change (the existing inference suites pass unchanged).
- **Still open.** As above, plus read auditing, per-owner/site scoping, the exact meaning of Technician "Basic" and Security Analyst "Security scope", exporter authentication/mTLS, and the retention period and prune step.

### Step 5 - Internet/WAN status, SLA and evidence export (2026-10-11) - threat-model delta
New surface: `GET /api/v1/internet`, `/internet/sla`, `/internet/sla/export`, the web `/internet` page and `/internet/export` download route, two append-only
tables (migration 0005: `wan_probe_samples`, `wan_link_cycles`), a LibreNMS port reading (`wan_port`), and an optional, off-by-default sampling collector
(`NETSIGHT_WAN_SAMPLING_ENABLED`). Status (the independent reviews were run; their findings are closed in "Review fix pass" below):

- **No new egress or probe capability (SSRF unchanged).** The collector calls the existing allow-listed probe clients only (`BLACKBOX_ALLOWED_TARGETS`, fixed
  exporter modules, no redirects, bounded responses); a declared probe target is validated to a plain host or address (`[A-Za-z0-9._:-]`) and an unlisted one
  answers `unknown` without a connection. The LibreNMS device and port identifiers come from the operator's declaration, are validated to
  `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` (no slash, backslash or `..`) and are percent-encoded into fixed paths (`/devices/{id}/ports`, `/ports/{id}/ip`); the token
  travels only as a bearer header (a test asserts it is never in a URL). Redirects are refused, errors are typed and carry no URL.
- **Fabricated telemetry (the central risk) - controlled by construction and by test.** Every API field is source-reported or `null`; non-ok blocks cannot carry
  values (JSON Schema `if/then`, pydantic validators, TS parser and OpenAPI agree through 148 shared vectors). A missing, malformed, negative, non-finite or
  boolean counter is `null` (never 0); an unrecognised interface status is `unknown`; counters older than 15 minutes are labelled `stale` and a missing poll time
  `unknown`, and neither counts as evidence about now; a lapsed probe round claims nothing about the present; "no samples yet" is empty, never 0% loss. Failover and
  link status are labelled `inferred` and are `unknown` whenever a link is silent; an interface that is up while every probe fails is `down`. The SLA treats time with
  no probe round as `unknown` (never up, never down), reports uptime over known time only and is `null` when nothing was known (never 100%).
- **Integrity of the SLA evidence.** Append-only tables: the Protocol has no update or removal method, a repeated `(link, time)` is a conflict, the app role holds
  `SELECT, INSERT` only, and `BEFORE UPDATE OR DELETE` / `BEFORE TRUNCATE` triggers (`ENABLE ALWAYS`, the 0003 function) stop every role including the owner (proven
  live as owner and app role, including under `session_replication_role = replica`). A CHECK pins each cycle's state to its sample counts, sample columns are
  validated (probe kind, location, target pattern, latency range) and a cycle is written with its samples in one transaction after the application verifies they
  agree. The computation is a pure function (`wan/sla.py`) with 43 unit tests; the PostgreSQL SLA equals the in-memory SLA for the same data (tested live).
  **Residual:** the table owner can disable the triggers or drop a partition; keep the migrator credential out of the service (as for 0002 to 0004). The
  evidence is only as trustworthy as the host that recorded it: the samples are taken and stored by the Netsight host and nothing is signed or independently
  attested, which the export's `basis` text now says. (The earlier shared-role weakness is closed: see "Review fix pass".)
- **Information disclosure.** Every role holds `internet:read` (status, quality, availability, SLA summary). The public IP, configured gateway, ISP name and
  per-link throughput need `internet:read_detail` (Admin, Network Engineer, Security Analyst) and are withheld by the API (`null`, `detail_redacted`) from
  Technician, Management and Auditor; the export (probe targets, outage windows) only to `internet:export` (Admin, Network Engineer, Auditor), and its ISP name
  needs the detail permission too (decision in RBAC-MATRIX). Responses and the export never contain a connection string, a LibreNMS URL, probe detail text or driver
  message (tests plant secrets in source errors and assert absence). The download route only relays a known content type with a fixed, anchored attachment name,
  drops every other upstream header, sets `Cache-Control: no-store` and `nosniff`, and answers upstream failures with fixed text.
- **CSV injection.** Operator-declared names (link name, ISP) are the only free text in the CSV; a leading `=`, `+`, `-`, `@`, tab, CR or LF is neutralised with a
  leading apostrophe, cells are quoted by the csv module, and the file name is derived from the validated month only (no header injection; tested).
- **Untrusted text in the UI (controlled).** Link names, ISP, gateway and every source value render as React text nodes; component tests plant `<img onerror>` and
  `<script>` in names, ISP, gateway and public IP and assert no element is created; the surfaces offer no button, input or form except the plain GET month picker
  and the two download links (asserted). No operator or telemetry text is ever interpreted as an instruction (no AI path reads it).
- **Denial of service.** Reads are bounded: months are server-bounded (current plus 24 back, otherwise 422), one cycle read is capped at twice a month of rounds at the configured interval (about 89 000 rows at 60 s, derived
  from `NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS`) and one sample read at 5 000 (over the cap is an error, never a silent cut), closed months are served from a bounded
  in-memory cache (immutable data) and the month tables are partitioned so a read touches the month's partition only, the status read touches the last 24 hours of cycles (at most 2 880 at the 30 s floor) and 15
  minutes of samples per link, at most 8 links, windows are capped at 2 000 per link with a `windows_truncated` flag. Per-identity limits after authorisation:
  status 300/min, SLA 30/min, export 10/min (in-memory, per worker, as for every other limiter). A cross-site request cannot start an export from a browser
  (`Sec-Fetch-Site` check) so a third-party page cannot spend an identity's export budget or write audit records. The collector is off by default, single-leader
  (its own advisory lock, so it cannot double-write or contend with the evaluator), bounded per probe (15 s) and per link (one interval), and a failing probe, store
  or link never stops the others. The first read of a closed month is O(cycles in the month) (later reads are cached); a persisted rollup is the follow-up if 30 s sampling over many links proves heavy.
- **Configuration risk.** `NETSIGHT_WAN_LINKS` is strict JSON (unknown keys, bad ids, two primaries, more than 8 links, control characters, bad addresses all
  refuse the whole declaration as `unknown`; the log carries a count, never the content). Enabling sampling without `NETSIGHT_WAN_COLLECTOR_DATABASE_URL` or a usable declaration fails
  start-up; an invalid flag or interval fails start-up instead of defaulting; a collector database role that is a superuser, bypasses row security, owns the
  WAN tables, equals the API's role or cannot be checked also fails start-up.
- **Repudiation.** An export is audited (`internet.export`: actor, month, format, answered state, link and row counts; never content): `success`, `failure` when
  the evidence could not be read (state `unknown`) and `denied` for a refused attempt. Status and SLA reads are not audited (platform-wide read auditing
  remains open).
- **Review fix pass (2026-10-11; closes the Step 5 independent reviews).**
  - *Role split (security M1).* The API role (`DATABASE_URL`) is `SELECT` only on `wan_link_cycles` and `wan_probe_samples`; the collector uses its own role
    (`NETSIGHT_WAN_COLLECTOR_DATABASE_URL`, `INSERT` only, no `SELECT`, no DDL), granted by `grants/wan_collector_role.sql` and proven live (the API role cannot
    insert, update, delete, truncate, alter, drop or read a partition directly; the collector cannot read, update, delete, truncate or create anything). A
    compromised API process can therefore no longer forge samples. The collector refuses to start with a superuser, row-security-bypassing or owner role, with
    the API's role, or with a role it cannot check.
  - *Detail permission (security M2)* and *export audit (security M3)* as above; the `assert` that guarded the attachment name is an explicit check.
  - *Partitioning (database H1).* Monthly range partitions, append-only triggers `ENABLE ALWAYS` on the parents and every partition (verified from
    `pg_trigger`), the partition helper is migrator-only (EXECUTE revoked), and a write into a month without a partition is refused by the database and logged by
    the collector (fail closed, a gap rather than a wrong figure). Retention is a whole-partition drop or detach by the migrator (period pending).
  - *Integrity (database M3 / LOW).* Deferred constraint triggers tie a cycle's counts to its stored samples; failed or unknown samples carry no latency (CHECK);
    only a unique violation is "cycle exists" (a deadlock or serialization failure is a failed write); samples go in with one `executemany`; the redundant
    `ON DELETE RESTRICT` was dropped.
  - *Evidence quality (code review).* The CSV carries a trailing `truncated` sentinel row and an `EXPORT INCOMPLETE` note when windows were cut, the SLA panel
    warns about it, the exact month-start instant is an empty period, the seconds always add up to the total (the rounding remainder is `unknown`), two writers'
    overlapping or contradicting cycles resolve deterministically (contradiction is `unknown`), and the export `basis` states the recorder-trust limit.
- **Still open.** The retention period and its migrator step (pending human decision); a signed or independently attested sample path (the recorder-trust limit);
  a persisted rollup if a cold month read proves heavy; a per-worker shared rate limiter; probing the gateway and reading routes (failover is inferred from link
  status only); whether probe targets in the export should be withheld too; whether Technician and Auditor should hold the detail; a live LibreNMS check that the
  ports list carries the rate and `poll_time` columns; a partition-readiness alert (the next month's partition missing) beyond the collector's error log.

### Step 6 - identity correlation, Users & Identity (2026-10-11) - threat-model delta
New surface: `GET /users`, `/users/summary`, `/users/{id}`, `/identity/resolve`; a pure correlation engine fed by read-only Wazuh-agent and NetBox-assignment adapters (and a
generic `EvidenceSource` interface); `/users` and `/users/[userId]` pages. Nothing is persisted (compute on read; no migration), nothing is written to any external system.
See IDENTITY-CORRELATION.md.

- **Privacy (PRD 92).** Per-person network history is sensitive. Controls: three permissions on a strict-subset ladder (`users:read` Admin/Network Engineer/Security Analyst;
  `users:read-limited` adds Technician, endpoint only; `users:read-summary` adds Management, counts only; Auditor none), the two per-user ones human-only (no service/AI
  principal), authorisation before the rate limit (30/min resolve, 120/min list/detail, 60/min summary), every per-user read audited with actor, target and counts only
  (no name, e-mail, signature or purpose text; denied and failed attempts too), `Cache-Control: no-store`, no per-person row for Management, and the person withheld
  (`restricted`) from the limited rung. Persons are keyed by canonical ids minted per source: **never by e-mail or display name**.
- **Inference abuse (presenting a guess as a person).** The central risk of this feature. Mitigated by construction, not convention: a link is `observed` only from a direct
  evidence kind at >= 0.8 inside its window; declarations, sign-ins, DNS and name matches are `inferred` and capped at 0.7; an unknown link has no target and no confidence;
  conflicting evidence is `ambiguous` with every candidate listed and **never picked**; a chain is as weak as its weakest hop; an **IP address alone is never identity** (the walk
  needs an account or an assignment; shared/NAT/public/CGNAT addresses are never walked through; VPN pool addresses only through a VPN session; guest/BYOD never attributed;
  ports/VLANs/switches/APs are never bridges between endpoints). The invariants live in the domain type, the pydantic model, the JSON Schema and the TS parser (four-way agreement,
  310 shared vectors), so a mapping bug is rejected as `unknown` rather than shown. The UI words uncertainty ("Inferred: possibly", "Not identified", "Ambiguous: n possible
  people") and shows the basis as a word plus an icon, never colour alone.
- **Untrusted evidence (tampering, spoofing, poisoning).** Evidence from monitored systems is untrusted. A source may only emit records stamped with its own name and of the kinds
  it declares, and a kind may only assert its own relations (an IdP sign-in cannot assert a MAC binding); a truncated, oversized, slow, malformed or impersonating batch makes that
  source `unknown`; bounds (<= 2 500 records/source, <= 5 000 total, 15 s, 24 h window, <= 16 evidence refs and <= 8 candidates per link) cap the work an attacker-controlled feed can
  cause. An attacker who can inject overlapping leases/sessions can force *ambiguity* (a loss of attribution) but not a false attribution; **a compromised direct source
  (RADIUS, VPN, directory) can still assert false observed links: that is the trust boundary** and is why every link names its evidence. Hostile hostnames, usernames, agent names,
  contact names and alert signatures are carried as data (length bounded in adapters, rendered as text, hostile-markup component tests, `no-raw-html` test) and are never interpreted as
  instructions; the AI copilot has no path to this data (human-only permissions).
- **Information disclosure through evidence ids.** A source's native record id can embed a user name (found by a test: a RADIUS session id carried an account id). A caller without
  `users:read` therefore receives opaque, stable evidence ids and endpoint links only. Authorised callers see the raw id (needed to find the record in the source). **Review fix:**
  the opaque id is now an **HMAC-SHA-256 under a server secret** (`NETSIGHT_IDENTITY_ID_KEY`, >= 32 characters), not an unkeyed hash: native ids are low-entropy (`owner-7-12`), so an
  unkeyed hash is a membership oracle (hash a guess, compare). Without the key the limited rung gets `unknown` (fail closed); only `NETSIGHT_ENV=development` generates a per-process key
  (logged once). The hostname name-match no longer cites person-device (assignment) records as endpoint evidence, so a read-limited caller cannot learn who a device is assigned to
  through a hostname lookup.
- **Spoofing across sources (review H1/M2).** Wazuh and NetBox mint different device entities, so one host conflicts with itself unless joined. The join is **only** an explicit,
  operator-controlled key (a NetBox device custom field holding the manager-assigned Wazuh agent id, `NETSIGHT_NETBOX_WAZUH_AGENT_FIELD`); **never a hostname or an agent name**, which a
  rogue host chooses. A key claimed by two NetBox devices joins neither. Without the key the answer stays `conflicting-evidence` (honest, never a wrong pick). A rogue agent reporting a
  registered address is ignored inside `NETSIGHT_IDENTITY_STATIC_CIDRS` and is otherwise a visible conflict that can lower, never raise or redirect, an attribution. Residual: someone who
  can write the NetBox custom field can join a device to an agent; and an unlisted static/guest/NAT network is treated as ordinary internal space (a deployment prerequisite, documented).
- **Enumeration / scraping.** Resolve is the scraping vector (any address -> a person): smallest budget (30/min per identity), audited with the subject, validated strictly (one subject,
  canonical IP/MAC/hostname, no reflection of the input in errors), `at` bounded to 7 days and never in the future, list pages bounded (<= 100 x 1000). A 404 for an unknown person
  reveals existence only to a `users:read` holder. **Review fix:** the audit target of a resolve is a fingerprint (short SHA-256), never the raw address, MAC or hostname asked about (the
  audit log would otherwise be a copy of every lookup); the summary denial, a denied detail (with its person id), every 429 and every rejected resolve input (422) are audited with
  static reason codes and no echo; error responses on the identity routes carry `Cache-Control: no-store` (API middleware).
- **SSRF / outbound.** The adapters call only operator-configured URLs (`WAZUH_INDEXER_URL`, `NETBOX_BASE_URL`); TLS verification stays on, redirects are refused, credentials are
  excluded from `repr`, https is required with credentials, the Wazuh index must match `wazuh-*`, NetBox pagination must stay on the configured origin and within 10 pages, response
  bodies are size-capped (Wazuh 8 MiB; **NetBox 8 MiB, declared length and streamed bytes, `Accept-Encoding: identity`** - added in the review fix). The routes take no URL from the caller.
- **One bad row must not blank a source (review fix).** A malformed Wazuh agent row (CIDR or scoped address, unknown status) or NetBox row (a contact without an id, a bad address) is
  skipped and counted in the log; the source stays `ok`. When most rows are malformed (more skipped than usable) the read fails (`invalid-source-data`), because a changed response shape
  is not "no evidence". The skipped count is logged, not yet in the API.
- **Denial of service.** Bounded gather (above), a 30 s single-entry snapshot cache shared by concurrent requests (no stampede), per-identity limits, no unbounded query or loop (the walk
  is depth-limited to 5 and path-limited to 2 000). The cache and limiter are per worker (open, as elsewhere). **Review fix:** the people computation (the heaviest step) is cached per
  snapshot and runs off the event loop (`asyncio.to_thread`, as does building the index), shared by list, detail and summary; a past-time question cannot be cached, so it spends a
  **global** budget (20/min across identities) and one of 2 concurrent slots (429 / 503 `IDENTITY_BUSY`, audited, per worker).
- **Repudiation.** `identity.users.list`, `identity.user.read`, `identity.resolve` (success, failure, denied) go to the interim audit sink with the actor and correlation id; a
  tamper-evident store remains open platform-wide.
- **Time and replay.** Evidence is trusted only inside `[valid_from, effective_end)`; an open session is trusted for a bounded TTL after it was last seen (15 min RADIUS/VPN/Wi-Fi/MAC
  table, 30 min agent and sign-in, 1 h DHCP, 24 h directory/assignment; defaults pending owner confirmation), so a stale record cannot vouch for the present. A future-dated record
  never applies. Clock drift between sources shifts windows, never creates a link.
- **Retention / legal.** Nothing is stored here, so no retention period is invented. Persisting correlation history (needed for incident reconstruction beyond the sources' own
  retention) needs an owner decision and likely a privacy/legal review first (PRD 92); until then history is as long as the sources keep (NetBox: current state only; a past-time answer resting on the register carries the note `register-is-current-state`).
- **Still open.** Live verification of the Wazuh monitoring-index and NetBox response shapes; the DHCP/RADIUS/VPN/Wi-Fi/DNS/IdP adapters (the only way to get genuinely *observed*
  answers); persisted history and its retention; site/security scoping; the Auditor and Network Engineer decisions in RBAC-MATRIX; a shared (non per-worker) cache and limiter; a
  Playwright run of the Users pages; tamper-evident audit; whether to withhold the evidence `source` names from the limited rung.

## Traffic intelligence delta (Step 7: Flow Explorer, Applications, Destinations, Anomalies)

New read-only surface: `GET /traffic/flows` (filters, aggregations, attribution), `/traffic/applications`, `/traffic/destinations`,
`/traffic/anomalies`; the existing `/traffic/top-talkers` and `/traffic/top-destinations` are re-gated. RBAC is in RBAC-MATRIX
("Traffic permissions (Step 7)"). Reviewed against the same checklist as Steps 5 and 6.

- **Injection into the flow store (the new query surface).** Every caller-controlled value (ten filter fields, the window, the limit)
  enters only as a typed `param_*` placeholder; the SQL text is built from constants and the validated table identifier
  (`adapters/clickhouse_queries.py`, asserted by tests that put `'; DROP TABLE` in each text filter and check it is absent from the SQL body).
  Filters are an **allow-list**: an unknown or repeated parameter is a 422 (never ignored, so a typo cannot widen a query), values are
  canonicalised (one spelling per address), control and invisible characters are refused, and a refusal names the field, never the value
  (so it is not reflected into an error body, a log line or the audit trail). The read-only ClickHouse identity remains the backstop.
- **A filter that cannot be honoured must not become an unfiltered answer.** A filter whose column the source lacks makes the read
  `unknown` with the filter named in `unsupported`; no query is run. (A silently dropped filter would show unfiltered data as if
  filtered.)
- **Privacy: inference and aggregation abuse (PRD 92).** (a) Rows name endpoints, so they need `traffic:read-detail`; Management gets
  aggregates only and *no row is read from the store for it*; an address filter is a 403 for it (a one-host aggregate is a row). (b) A
  person is named only through the Step 6 identity service, only for `users:read` (human principals), with the basis; the source's
  own user field is ignored. Ambiguity names nobody; `restricted` says the person is withheld. (c) Per-person traffic is audited,
  rate-limited (Explorer 30/min), cached nowhere (`no-store`) and bounded (<= 500 rows, <= 500 distinct (address, time) questions per
  request). (d) No per-user baseline, ranking or "behaviour score" is produced: anomalies are organisation-wide totals and applications.
  Residual: an authorised `users:read` caller can still enumerate people by walking filters over time; the per-identity budget, the
  audit trail and the 31-day cap are the controls, and the "who can see people at all" decision is open (RBAC-MATRIX).
- **Attribution is not fact.** `observed` / `inferred` (capped 0.7) / `unknown`, with a reason; flows older than the evidence window
  (24 h) are `source-unavailable`, not "no evidence"; external and shared addresses are never attributed (Step 6 policy). Hostile labels
  (a person's display name, a hostname, an application name) are untrusted text rendered as data (hostile-markup component tests).
- **Spoofable labels cannot buy trust.** A destination hostname comes from reverse DNS, controlled by the address owner: the operator
  policy lets a hostname **deny** but never **allow** (a domain in `allow` invalidates the file); application approval matches the
  name exactly (no prefix match), so `Zoom-malware` cannot inherit `Zoom`'s approval.
- **Policy file as input.** `NETSIGHT_TRAFFIC_POLICY_FILE` is operator-controlled, read-only, <= 256 KiB, <= 1 000 entries per list,
  duplicate keys and unknown keys refused, time zone name pattern-checked before it reaches `ZoneInfo`, re-read on change. An invalid
  file makes every classification `Unknown` (fail closed), never a partial application; an edited file takes effect without a restart.
- **Anomaly integrity.** The comparison is deterministic arithmetic (median/MAD over the same hour of the prior weeks, explained in
  TRAFFIC-BASELINES.md), so there is no model to poison or prompt-inject. Baseline poisoning: robust statistics (one bad week in four does
  not move the median); every read recomputes from source data (nothing adapts incrementally). **Open:** excluding confirmed-incident
  periods from the baseline and operator "expected behaviour" labels. "Insufficient baseline", "no data" and "no history" are explicit
  results; a gap in flow collection is never read as a drop. Outside-working-hours is context from operator policy, never a finding,
  and the response names the common legitimate causes rather than a verdict.
- **Denial of service / cost.** Windows <= 31 days (baselines <= 7 days of judged hours, over 28 + 7 days of data), row limits (flows
  500; lists 100; timeline 200 buckets; mix 11; destinations 10), a per-read time budget (25 s) with sibling cancellation, **server-side
  query limits** (below), admission control of at most 3 heavy reads, one per identity, the last slot reserved for the detail tier
  (429 / 503 + `Retry-After`), per-identity budgets (30/min; baselines 10/min), a 300 s single-flight cache for the baseline
  inputs (<= 16 windows, failures never cached). The Explorer is up to 6 ClickHouse calls per request. Per-worker limits and caches, as
  elsewhere (open). A hot dashboard refresh loop is bounded by the budgets, not eliminated.
- **Resource exhaustion of ClickHouse itself (security review HIGH-1).** A client timeout only stops waiting. Every query now carries
  `max_execution_time`, `max_memory_usage`, `max_rows_to_read`, `max_bytes_to_read`, `max_result_rows`, `max_result_bytes`, the three
  overflow modes pinned to `throw` (a limit fails the read, never truncates it) and `cancel_http_readonly_queries_on_client_close`
  whenever the identity may set them. A `readonly = 1` identity may not, and then **nothing in the API can bound a query**: the
  capability is learned once per process and a single warning says the user profile MUST enforce the limits; the exact profile is
  in AKVORADO-CLICKHOUSE.md ("Resource limits (deployment requirement)"). Distinct counts use `uniq`, not `uniqExact`. **Residual:**
  the limits are only as good as the deployed profile; the API cannot verify a `readonly` profile from the outside.
- **Small cohorts (security review HIGH-2).** An aggregate filtered to one machine is that machine's traffic. `device` and `vlan` are now
  endpoint-level filters (detail tier only), and the aggregate tier is held to a minimum cohort `k` (`NETSIGHT_TRAFFIC_MIN_COHORT`,
  default 5, at least 2): an Explorer answer about fewer than `k` source addresses is withheld whole (so two overlapping filters cannot
  be subtracted to isolate it), endpoint counts below `k` and first-seen rows reached by fewer than `k` sources are withheld, and every
  response states the verdict (`cohort`). Destinations inside the organisation are never listed to the aggregate tier. **Residual:**
  two answers that each pass can still be differenced by a caller who tries (a 6-source filter against a 5-source one); the per-identity
  budget, the one-read-at-a-time rule and the audit trail are the controls. A query-set-overlap control is a deferral.
- **Accountability for endpoint lookups.** Every read of all four routes is audited (names, counts, tier, cohort verdict; never
  values), rejected input too, each with a static reason code. A detail-tier lookup of an address, device or VLAN may carry a keyed
  HMAC fingerprint of the value so "who looked up X" is answerable without the trail holding X (AUDIT-LOGGING); it is omitted, never
  weakened, when no key is configured.
- **Policy file hardening.** Labels are compared by `casefold` only and a label that changes under NFKC is `unknown` (so a
  compatibility look-alike cannot borrow an approval or a risk); an `allow` range wider than IPv4 /8 or IPv6 /16 invalidates the whole
  file; the file is opened once and measured with `fstat` (no stat-then-read race). **Residual:** a hostname deny matches reverse DNS the
  address owner controls, so it can be evaded and can be made to match a benign address (TRAFFIC-BASELINES, "Reverse-DNS deny false
  positives").
- **Fail closed / honest states.** Every response is validated against its canonical JSON Schema before it leaves; a violation is
  `unknown` (HTTP 200, no values), never a 500 and never a guess. Not connected, unknown, restricted, withheld, not-evaluated and
  unsupported are distinct states with distinct UI.
- **Output handling.** Names, domains, applications, hostnames, labels and device names are untrusted source text: carried as data in
  the API, rendered only as React text nodes (no raw HTML anywhere; the existing source scan test covers the new files), never
  interpreted by any AI. The overview and the Explorer name people only for roles allowed to see them.
- **Still open.** A live ClickHouse run of the new SQL (none available here); a shared (non per-worker) limiter and cache; excluding
  incident periods from baselines; operator labels; per-site scoping; the people-in-rows decision; an index strategy for address filters
  on very large tables; reading `SamplingRate` (an explicit, labelled scaled view); a Playwright run of the four pages.

## Inventory, IPAM and unknown-device delta (Step 8, E03)

New surface: `GET /inventory`, `/inventory/summary`, `/inventory/{id}`; `GET /ipam`, `/ipam/prefixes`, `/ipam/vlans`, `/ipam/addresses`; `GET /unknown-devices` (+ `/summary`,
`/{id}`, `/{id}/timeline`) and the human-only `POST /unknown-devices/{id}/acknowledge|investigate|assign|comment|resolve` and `/unknown-devices/scan`; read-only NetBox adapter
additions (assets, prefixes, VLANs, addresses, ranges, interfaces by MAC); migration 0006 (two tables); an optional scheduled scan; five pages. RBAC is in RBAC-MATRIX
("Inventory, IPAM and unknown-device permissions (Step 8)"); the design is in INVENTORY-IPAM.md. Nothing is written to NetBox or any network system.

- **Write path to an external system: none.** The NetBox adapter issues `GET` only (the adapter tests assert `GET` on the requests seen by a mock transport). A quarantine is a `proposed_action`
  record with `executable: false` as a constant in every schema (JSON Schema, OpenAPI, pydantic, TS parser, vectors). No route, button, permission or code path isolates an endpoint;
  the action engine (Step 12, with its own approvals) owns execution; it can now hold the request (see "Controlled action delta (Step 12)") but ships no executor that changes anything. The UI says "Quarantine proposed, not executed".
- **Untrusted source text.** Device names, roles, sites, descriptions, hostnames, DNS names, VLAN names and NetBox custom-field values reach the API from third-party systems and may
  hold markup or instructions. They are length- and shape-bounded by the parsers, returned as JSON strings, never interpolated into SQL (all queries are parameterised), never used as
  a key without validation, never given to an AI, and rendered as React text nodes (component tests put `<img onerror>` and "ignore previous instructions" into the untrusted fields and
  assert nothing but text is produced). The Wazuh join uses a NetBox custom field the operator names, never a name match.
- **NetBox lookup injection.** The one caller-influenced NetBox query (`interfaces_by_mac`) takes a MAC that is validated as lowercase colon-hex before the request is built, asks for at most
  50 rows, and re-checks every returned row against the requested MAC on the client (an over-broad NetBox filter cannot attach someone else's device).
- **False "unknown device" findings from a failed lookup.** A finding is raised only when every NetBox check was actually made and none matched. When NetBox cannot answer (not configured, error,
  truncated, over the lookup budget) the endpoint is counted `unverified` and **no finding is made**; the scan response and UI say so. A finding states which hops are observed; a hop no connected
  source can see is Unknown with a reason, never inferred from a name or a neighbouring value.
- **Alert fatigue and denial of service through scanning.** At most 500 candidate endpoints and 100 MAC lookups per scan, a 25 s whole-read budget, a 30 s cache, scan limited to 6/min per
  identity, one scheduled scan across workers (PostgreSQL advisory lock), scheduled scans off by default. One open finding per endpoint (partial unique index) so a noisy endpoint raises one finding
  and a `seen_count`, not a flood.
- **Tampering with the lifecycle or its history.** Transitions are a fixed table enforced in the API, the store and again in PostgreSQL (trigger and CHECK constraints: a finished finding is final,
  a resolution carries a reason). The timeline is append-only for every role including the owner (`ENABLE ALWAYS` triggers from migration 0003). An advisory lock per subject and row locks serialise
  concurrent writers; a lost race is a 409 with the current state, not a silent overwrite. The app role has no `DELETE` on either table. The `down` migration is destructive and guarded.
- **Writes are human-only and guarded.** Authenticate, authorise (audited), CSRF and origin, step-up (resolve only), per-identity limit (60/min). A service or AI principal cannot acknowledge,
  assign, comment, resolve or scan whatever role it holds. A comment and a reason are stored as typed and shown as text; the audit record carries counts and names only, never the text.
- **Privacy (PRD 92).** A finding records a MAC, an IP, a hostname and, when a source reports them, the switch, port and VLAN: per-endpoint network history. Controls: Management sees counts only,
  Technician sees finding counts only, rows are `no-store`, every read is audited without values, and **no retention period is invented** (DATA-RETENTION-MATRIX, pending human decision, no prune
  built). A privacy and legal review is recommended before the scan is enabled for a site with personal devices.
- **Operator documents (class map, severity policy).** Read with one `open` and `fstat`, 64 KiB maximum, duplicate keys refused, unknown keys refused, entries bounded, values from closed sets. An
  invalid document fails closed (nothing classified; severity `unknown`; no quarantine recommended) and the response says `invalid`. Error messages are static and never echo document content.
- **Information disclosure through error paths.** A source failure is a state (`unknown`), not an error string; no exception text, URL or token reaches the response or the UI. Inventory and IPAM
  datasets fail independently, so one failing source degrades one section and does not leak the cause of another.
- **Sign-in return paths.** The login redirect allow-list (API `UI_AREAS` and the web `UI_AREAS`, kept in step) gained `inventory`, `ipam` and `unknown-devices` so a step-up on resolve returns to
  the finding. Open-redirect rules (no scheme, no `//`, no backslash, no controls) are unchanged and still tested.
- **Still open.** No live NetBox, LibreNMS or Wazuh run (shapes pinned by mock transport only); no DHCP, switch-FDB/ARP or Wi-Fi adapters, so attachment, port and VLAN stay Unknown; retention and
  prune; site scoping; whether dismissal needs step-up; a shared (non per-worker) cache and limiter; a Playwright run of the pages; tamper-evident audit; independent code and security review of this step.

## Controlled action delta (Step 12, E11)

New surface: `/api/v1/actions` (status, list, detail, propose, propose-from-finding, approve, reject, cancel, execute, kill switch), six `actions:*` permissions, two pages. Design:
ACTION-ENGINE.md. **No executor that changes anything ships**; the dry-run executor imports no network or process library (a test asserts it) and the live slot is
`disabled`/`not-connected`.

- **Arbitrary command execution (the headline threat).** There is no command field in any contract (a test walks every `Action*` schema), no route that takes one, and no executor context
  field for free text. The action type must be in a closed catalogue of three; parameters are typed and ranged (`bool` is refused for an integer); targets match a per-kind pattern with
  `fullmatch` (a trailing newline cannot slip past `$`); the dry-run plan is fixed wording filled only from validated values. Hostile reasons are bounded, stripped of control, format (bidi,
  zero-width) and separator characters, stored and shown as text, and never reach an executor, a plan or an audit record.
- **Elevation / authz bypass.** Propose, propose-high, approve, execute and kill-switch are separate permissions; approve, execute and kill-switch are human-only (service and AI principals get 403
  whatever their role) and are re-checked inside the store. A risk C or D request needs `actions:propose-high`, so a Technician cannot raise one. Authorisation is decided before CSRF, CSRF and
  origin before step-up, step-up before the budget, the body last.
- **Self-approval and collusion.** The requester can never approve (by identity id, so two sessions of one person are one identity); one person approves once; risk D needs two distinct approvers.
  The approver is the session's identity, never a body field (a body naming an approver is a 422). Not addressed: two real people colluding, or one person holding two identities.
- **Replay and TOCTOU.** Every decision quotes the request's digest and version and loses with 409 `STALE_REQUEST` if either moved; the check, the state transition and the history append happen
  under one lock (eight parallel approvals record exactly one). An execution key starts a run once; a target runs one execution at a time; a quarantine re-checks that the finding is still open
  and its evidence has not moved immediately before it runs.
- **Repudiation / audit integrity (improved, not closed).** Every mutation and every refusal is audited with actor, request id and static facts; the history is append-only and hash-chained and
  its verdict is in every detail response. The store is memory and the audit sink is a log: neither is tamper-evident storage (PRD 32 still open).
- **Denial of service.** Caps: 25 open requests per requester, 5 000 stored, 100 history events per request, 8 parameters, per-identity budgets (writes 30/min, execute 10/min, kill switch 5/min).
  A run that never reports back is failed after its timeout plus 60 s; an overrunning executor call is abandoned on a daemon thread (it cannot be killed).
- **Information disclosure.** A quarantine proposal copies no MAC, address or name into the action store; audit records carry no reason, parameter or target; executor exceptions are discarded
  (they may carry addresses or credentials); errors are fixed sentences; all responses `no-store`.
- **Fail-closed configuration.** Engine and live-execution flags fail start-up when garbled; an unreadable kill-switch value counts as engaged; a missing flag means `not-connected`.
- **Still open.** Durable multi-worker store and a tamper-evident audit sink; a per-process kill switch; approver policy (Administrator only today); no live executor, lab or connector security
  review; a Playwright run of the pages; shared (non per-worker) rate limits.

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

## PWA install/offline shell (stage 1)

New boundary: same-origin service worker with application-wide scope. Persistent
CacheStorage is restricted to three public resources: a generic offline HTML page
and two public brand icons fetched with credentials omitted. No API/auth/login
request, write, cross-origin resource or authenticated navigation response is
cached. Navigation falls back only on network failure, returns 503/no-store and
states that current health is unknown without echoing a path, identity, query or
telemetry. Worker updates bypass HTTP cache; activation deletes only obsolete
feature-owned caches. Installation uses a browser-provided prompt after a user
gesture. No push subscriptions or notification permissions are requested.

Tests exercise cache allow-listing, omitted credentials, route/method isolation,
online no-cache behavior, offline status, safe cache cleanup and browser reconnect.
Revocation must serve a reviewed retirement worker at the same URL; deleting the
script alone does not remove existing client registrations. XSS resistance and
secure hosting remain prerequisites: a compromised same-origin script can affect
service-worker registration, so the worker does not reduce existing CSP/output
encoding/authentication requirements. No additional production scope was granted
in this stage.
