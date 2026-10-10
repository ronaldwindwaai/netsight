# Critical E2E Scenarios

1. Microsoft login -> dashboard -> device detail.
2. Google login -> role-scoped dashboard.
3. Forbidden role cannot access admin API.
4. LibreNMS unavailable -> stale/unavailable UI.
5. NetBox mismatch -> reconciliation finding.
6. Top talker -> device/user drill-down.
7. After-hours anomaly -> alert -> incident -> email.
8. External service failure -> diagnostic -> fault-domain explanation.
9. Proposed high-risk action -> step-up -> approval -> executor -> verify -> audit.
10. AI question -> tool calls -> evidence-backed answer.
11. Prompt-injection string in hostname -> no instruction following.
12. Monitoring-source failure -> no fabricated AI state.

## Implementation status

- Scenarios 1-4 form the S1 identity and network-overview chain; the harness self-tests in
  `apps/api/tests/e2e/` prove the pieces they depend on.
- Scenario 8 (external service failure -> diagnostic -> fault-domain explanation) has API-level
  end-to-end coverage: `apps/api/tests/e2e/test_diagnostics_e2e.py` runs the real allowlisted probe
  client through `POST /api/v1/diagnostics` in a live API process (a resolvable target passes, a
  non-allow-listed target is an honest `unknown` with no fault domain, and a requested vantage with
  no connected prober is `unknown` with the run reporting where it actually ran), and
  `apps/api/tests/test_diagnostics_api.py` proves the conservative fault-domain inference
  (external fail + internal pass -> `firewall`, confidence never above `low`) and that the run
  reports observed provenance rather than the requested vantage.
- Scenario 8 sessions (Step 4): `apps/api/tests/test_diagnostic_sessions_api.py` proves a run is
  stored and revisited by id (per-location results, labelled cause, path, may-correlate changes),
  the degraded states (no store, failing store, failing context sources) and bounded/RBAC'd reads;
  the e2e harness (no `DATABASE_URL`) proves a run reports `stored: false` and the id reads
  `not-connected`; live PostgreSQL suites prove the INSERT/SELECT-only path as the app role.
- Scenario 11 (prompt-injection string in hostname) is covered for diagnostics by
  `test_target_is_echoed_verbatim_never_interpreted`: the target is echoed verbatim and never
  interpreted.

