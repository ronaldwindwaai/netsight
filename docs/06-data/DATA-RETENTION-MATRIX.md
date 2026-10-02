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
