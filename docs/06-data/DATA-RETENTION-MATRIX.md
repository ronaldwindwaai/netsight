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
| Identity correlations | **PENDING HUMAN DECISION** ("limited by operational need"; no period is set) | privacy sensitive. **Nothing is stored today** (Step 6 computes correlations on read from bounded evidence, no migration): the effective history is the sources' own retention (Wazuh monitoring index; NetBox current state only), up to 7 days back through `GET /identity/resolve?at=`. Persisting history (append-only, audited, migrator-owned prune, like the diagnostic and WAN tables) needs the decision below first |
| AI traces | short, redacted | do not retain secrets |
| Notification delivery attempts | 90 days–1 year | identifiers and static codes only; append-only. **No prune path exists yet**: the application has no delete, and the append-only triggers (`ENABLE ALWAYS`) stop the owner as well, so rows accumulate until an audited migrator step (disable trigger, delete, re-enable, in one transaction, with the deletion audited) is designed and approved. Until then plan disk for the volume (one row per attempt, <= 5 per notification) |
| Diagnostic sessions | **PENDING HUMAN DECISION** (candidate range 90 days-1 year; no period is set) | one immutable snapshot per finished run (<= 1 MiB, typically a few KiB); holds the operator-typed target and symptom (free text), probe details, NetBox device names and alert titles, so treat as operationally sensitive. Incident titles are **not** stored (references only; joined at read time for `incidents:read` holders). The UI warns not to paste secrets or personal data into the target or symptom, but free text cannot be screened, so a pasted secret would be retained as long as the session. **No prune path is built**: no application delete, and the append-only triggers stop the owner as well. Growth is limited by the 10 runs/minute/identity run limit and a configurable daily storage cap (`NETSIGHT_DIAGNOSTIC_SESSIONS_DAILY_CAP`, default 5000, over which runs are answered but not stored; a warning is logged at 80%) |
| WAN probe samples and cycles | **PENDING HUMAN DECISION** (no period is set; SLA disputes usually need the contract term plus the dispute window, but that is the owner's call) | append-only evidence for the monthly SLA and the ISP-dispute export: one cycle row per link per round (default 60 s, i.e. about 43 200 rows per link-month) and one sample row per probe (about 2 to 9 per round). Rows hold identifiers, probe kinds, allow-listed target names, configured probe locations, outcomes and latencies only: no probe text, URL or response. Both tables are **partitioned by month**, so a retention period, once decided, is applied by the migrator dropping (or detaching, to archive) whole month partitions: `DROP TABLE wan_probe_samples_pYYYYMM; ALTER TABLE wan_link_cycles DETACH PARTITION wan_link_cycles_pYYYYMM; DROP TABLE wan_link_cycles_pYYYYMM;` (samples first; INTERNET-WAN.md). **No prune is scheduled or built** (no application delete; the append-only triggers stop every role including the owner at row level): the period is the owner's decision. Growth is bounded by the sampling interval (30 to 300 s), at most 8 links and at most 8 targets per link; disk is not estimated here (measure on a real deployment before sizing). The migrator must create next month's partition before the month starts (`migrate partitions`, monthly), otherwise the collector refuses to write |
| Traffic baselines and policy (Step 7) | not persisted | nothing is stored: the baseline inputs are cached in API memory for 300 s (<= 16 windows, no per-user data) and every read recomputes from the flow source, so the history available is exactly the flow source's own retention (the baseline needs 4 prior weeks of the same hour, first-seen flags need 7 days). The operator policy is a read-only file |
| Alert -> incident links | life of the incident | one small row per alert/group key (`recovered_at` marks that the alert was seen to recover); never deleted by the app |

## Decision needed: diagnostic session retention and prune (open, human)

Not decided and **not invented here**: (1) the retention period for diagnostic sessions (the 90 days-1 year above is a candidate range, not a policy); (2) whether free text (target, symptom) may be kept for the whole period or must be minimised/expired sooner; (3) who may run the prune. Constraints any answer must respect: sessions are immutable and the triggers stop every role including the owner, so deletion needs an audited, migrator-owned step that disables the triggers and re-enables them with `ENABLE ALWAYS` in the same transaction and records what it removed. That step is **deliberately unbuilt**: its retention floor and audit shape depend on the decision above, and a trigger-disabling function that cannot be tied to an approved period is a risk with no benefit. Until then the table only grows, bounded by the daily cap.

## Decision needed: WAN probe sample retention and prune (open, human)

Not decided and **not invented here**: (1) the retention period for `wan_probe_samples` and `wan_link_cycles` (and whether raw samples may be
expired sooner than the cycle rollups, which are what the SLA reads); (2) who may run the prune; (3) whether evidence exported for a dispute
must be preserved separately from the live tables. Constraints any answer must respect: both tables are append-only and the row triggers stop every
role including the owner, but they are partitioned by month, so retention is **a whole-partition drop or detach by the migrator** (no row-level
delete and no trigger disabling is needed): `DROP TABLE wan_probe_samples_pYYYYMM;` then `ALTER TABLE wan_link_cycles DETACH PARTITION
wan_link_cycles_pYYYYMM;` then `DROP TABLE wan_link_cycles_pYYYYMM;` (detach instead of dropping to archive first). The step must be audited (who,
which months, row counts) and must never run for a month that was exported for an open dispute. Scheduling it is **deliberately unbuilt** until a
period is approved. Until then the tables only grow, bounded by the sampling interval and the link and target caps.

## Decision needed: identity correlation history (open, human)

Not decided and **not invented here**: (1) whether identity correlations are persisted at all (needed to answer "who had this address on Tuesday" beyond the sources' own retention, and for
incident reconstruction, per IDENTITY-CORRELATION.md "Preserve historical correlation"); (2) if so, the retention period and whether per-person detail may be kept as long as the
aggregate; (3) who may prune and how a prune is audited; (4) whether a privacy/legal review (PRD 92) must precede any persistence of per-person network history. Constraints any answer must
respect: the table would be Netsight app state in PostgreSQL (DATABASE-OWNERSHIP), append-only with audited, migrator-owned deletion, least-privilege roles, a guarded `down`, and
evidence references rather than copies of source records. Until decided, **no migration 0006 exists and nothing is stored**.
