# Data Retention Matrix Template

Set organisation-specific periods before production.

| Data class | Suggested starting point | Notes |
|---|---:|---|
| Platform audit | 1–7 years | policy/regulatory dependent |
| Incidents | 2–7 years | preserve major incidents longer |
| Configuration history | 1–3 years | or all meaningful versions |
| Flow detail | 30–180 days | storage/privacy trade-off |
| Flow aggregates | 1 year+ | trends/capacity |
| Security events | 90–365 days+ | risk/regulatory |
| Device metrics | 90 days detailed + aggregates | source dependent |
| Identity correlations | limited by operational need | privacy sensitive |
| AI traces | short, redacted | do not retain secrets |
| Notification delivery attempts | 90 days–1 year | identifiers and static codes only; append-only. **No prune path exists yet**: the application has no delete, and the append-only triggers (`ENABLE ALWAYS`) stop the owner as well, so rows accumulate until an audited migrator step (disable trigger, delete, re-enable, in one transaction, with the deletion audited) is designed and approved. Until then plan disk for the volume (one row per attempt, <= 5 per notification) |
| Diagnostic sessions | **PENDING HUMAN DECISION** (candidate range 90 days-1 year; no period is set) | one immutable snapshot per finished run (<= 1 MiB, typically a few KiB); holds the operator-typed target and symptom (free text), probe details, NetBox device names and alert titles, so treat as operationally sensitive. Incident titles are **not** stored (references only; joined at read time for `incidents:read` holders). The UI warns not to paste secrets or personal data into the target or symptom, but free text cannot be screened, so a pasted secret would be retained as long as the session. **No prune path is built**: no application delete, and the append-only triggers stop the owner as well. Growth is limited by the 10 runs/minute/identity run limit and a configurable daily storage cap (`NETSIGHT_DIAGNOSTIC_SESSIONS_DAILY_CAP`, default 5000, over which runs are answered but not stored; a warning is logged at 80%) |
| Alert -> incident links | life of the incident | one small row per alert/group key (`recovered_at` marks that the alert was seen to recover); never deleted by the app |

## Decision needed: diagnostic session retention and prune (open, human)

Not decided and **not invented here**: (1) the retention period for diagnostic sessions (the 90 days-1 year above is a candidate range, not a policy); (2) whether free text (target, symptom) may be kept for the whole period or must be minimised/expired sooner; (3) who may run the prune. Constraints any answer must respect: sessions are immutable and the triggers stop every role including the owner, so deletion needs an audited, migrator-owned step that disables the triggers and re-enables them with `ENABLE ALWAYS` in the same transaction and records what it removed. That step is **deliberately unbuilt**: its retention floor and audit shape depend on the decision above, and a trigger-disabling function that cannot be tied to an approved period is a risk with no benefit. Until then the table only grows, bounded by the daily cap.
