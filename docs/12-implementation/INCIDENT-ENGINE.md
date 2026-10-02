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
