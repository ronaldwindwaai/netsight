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

### Denial of service
Risk: expensive flow queries, diagnostics floods, upstream failures.
Mitigation: rate limits, query budgets, timeouts, async jobs, caching, degradation.
Topology specifics: one request fans out to at most 12 upstream calls (≤10
cable pages × `limit=1000` + 1 NetBox devices page + 1 LibreNMS devices page), each bounded by a 10s timeout;
graphs are capped at 10,000 nodes/edges and fail closed to `unknown`.
Open follow-up: per-IP rate limiting and response caching for `/api/v1/topology`.
Traffic specifics: each traffic request fans out to at most 2 upstream
ClickHouse calls (1 cached `system.columns` discovery + 1 data query; ≤3 when a
readonly identity forbids settings and forces one settings-free retry), each
bounded by a read timeout and an explicit window (≤31 days) plus a row limit
(≤100 for top-talker/destination, ≤500 for flows). When the identity permits
`max_execution_time` it is sent as a server-side query budget. A source failure
never becomes a 5xx and never returns partial data as if complete.

### Elevation of privilege
Risk: AI/tool or user obtains write capability.
Mitigation: separate credentials, backend policy, step-up auth, approval, scoped targets.

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
