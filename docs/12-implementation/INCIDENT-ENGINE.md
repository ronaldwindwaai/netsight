# Incident Engine

## States
Open -> Acknowledged -> Investigating -> Mitigated -> Resolved -> Closed

Reopen is allowed with audit.

## Correlation inputs
- topology dependency;
- temporal proximity;
- shared device/user/site;
- shared root service;
- shared configuration change;
- shared destination/threat indicator.

## Correlation output
Correlation proposes grouping with evidence and confidence. Deterministic dependency relationships may auto-group according to policy.

## Timeline
All incident events are append-only:
- alert linked/unlinked;
- assignee changed;
- comment;
- diagnostic;
- action proposed/approved/executed;
- evidence added;
- state changed;
- resolution.

## Resolution
Requires:
- resolution summary;
- root cause or "not determined";
- impact;
- restoration time;
- optional follow-up actions.

Never force an AI-generated root cause into the final record without an authorised operator accepting it.

## API (S6-2)
`/api/v1/incidents` (list, detail, timeline) and `POST /{id}/acknowledge|transition|assign|comment|evidence|resolve|reopen`.
- The state machine is adjacent-only; `transition` covers acknowledged, investigating, mitigated and closed.
  Resolve and reopen are separate operations because they need mandatory fields and human-only permissions.
- Concurrency: a transition is applied under a row lock only from the state it is legal from; the loser of a race receives 409.
- Technician "Assigned" scope is enforced by the store under the same row lock as the write
  (`required_assignee` on `transition_state`, `append_event`, `add_evidence`; `ScopeViolationError` -> 403),
  judged before the state machine, so a reassignment cannot slip between the check and the write.
- Every mutation (and every refused attempt) emits an audit record on the `netsight_api.audit` logger,
  written from the worker thread right after the store call (see `docs/08-operations/AUDIT-LOGGING.md`).
  The timeline is the durable, append-only record of who did what.
- Writes need the session CSRF token and, when the browser sends `Origin`/`Referer`, an allow-listed origin
  (`NETSIGHT_ALLOWED_ORIGINS`, plus the origin of `NETSIGHT_PUBLIC_BASE_URL`); refusals are 403 and audited.
- Reads report `not-connected` (no `DATABASE_URL`) or `unknown` (store failure) with no rows; writes answer 503.
