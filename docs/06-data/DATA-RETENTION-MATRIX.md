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
| Alert -> incident links | life of the incident | one small row per alert/group key (`recovered_at` marks that the alert was seen to recover); never deleted by the app |
