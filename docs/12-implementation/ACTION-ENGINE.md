# Controlled Action Engine (E11, Step 12)

> **Numbering note.** Earlier documents (INVENTORY-IPAM.md, THREAT-MODEL.md, RBAC-MATRIX.md, the Step 8 and
> Step 9 notes in BUILD-PLAN-FROM-PRD.md and the `proposedAction` contract text) call the action engine
> "Step 14". The BUILD-PLAN numbering now makes it **Step 12**. They mean the same thing; those references
> have been updated where the file was in scope of this step.

Requirements: PRD sections 24 (remote operations) and 25 (risk levels), `docs/02-security/REMOTE-ACTION-SECURITY.md`,
`RBAC-MATRIX.md` (Propose / Approve / Execute rows), `THREAT-MODEL.md`, ACCEPTANCE-SCENARIOS ("Disable Port").

## What this step is, and is not

**Built: the framework.** The Action Request lifecycle, a closed allow-list of typed action definitions,
risk classes, two-person approval, step-up, expiry, idempotency, pre-checks, verification and rollback
hooks, a kill switch, audit, rate limits, RBAC, the API, the contracts and the UI.

**Not built: any way to change a device.** The only executor that ships is the **dry-run executor**. It
records what *would* happen and never contacts a device or a network system (its module imports no socket,
HTTP, SSH, SNMP or process library, and a test keeps it that way). A `live` executor slot exists so the
framework has a real shape; it implements nothing and reports `disabled` (default) or `not-connected`
(`NETSIGHT_ACTIONS_LIVE_EXECUTION=true`, still no connector). Selecting an executor therefore always
yields the dry-run executor today. A real executor needs, at minimum: a lab that proves restricted
execution (ACTION-ENGINE design rule from before this step), its own env gate, short-lived credentials
from the secret store, and a security review. The persistent store it also needs now exists (see Storage).

## Design

**No generic command execution API.** `actions/catalog.py` is the whole allow-list:

| Action type | Risk | Approvals | Target | Parameters |
| --- | --- | --- | --- | --- |
| `endpoint.isolate` | C | 1 | `unknown-device-<uuid>` (a finding) or `endpoint:<id>` | `duration_minutes` integer 5-1440, required |
| `switch.port.disable` | D | 2 | `interface:<id>` | none |
| `switch.port.enable` | B | 1 | `interface:<id>` | none |

`service.restart` and `firewall.destination.block` (listed as examples before this step) are deliberately
absent: the design says not to build them until a lab proves restricted execution.

Each definition declares: title, risk, target kind and pattern, typed parameters (integer in a range, boolean
or a value from a fixed list; never a free string), approvals required, approve-within and execute-within
windows, executor timeout, the permission to propose it, rollback guidance and a **fixed plan** (the words a
dry run reports). A request body can name an action type, a target, parameters and a reason, and nothing
else: an unknown key anywhere is a 422, a parameter outside its type or range is a 422 with a static code,
and the plan and the executor context are built from the definition and the *validated* values, never from
request text. The executor interface (`ExecutionContext`) has no field for a reason, a requester or a
command.

### Lifecycle (append-only history)

```
proposed -> pending-approval -> approved -> executing -> succeeded
                 |                 |            |-----> failed
                 |                 |            `-----> rolled-back
                 |-> rejected      `-> expired / cancelled
                 `-> expired / cancelled
```

The table is `schemas_actions.ALLOWED_TRANSITIONS`; the store applies a move only from a legal state, under
one lock. Every move appends a history event (`proposed`, `policy-checked`, `submitted`, `approved`,
`rejected`, `cancelled`, `expired`, `execution-started`, `pre-check-failed`, `executed`,
`verification-passed`, `verification-failed`, `rolled-back`, `rollback-failed`, `failed`) carrying the actor,
the states, a static code and the actor's note for rejections and cancellations. Each event's SHA-256 hash
covers the request id, its own fields and the previous hash, so an edit, a gap, a reorder, a truncated start
or a move to another request fails `verify_chain`; the detail response reports `chain_intact`. The store's verdict
also requires the last event to be the request's current version and state and every step to start where the previous
one ended, so cutting the tail off is detected too. "Intact" means *internally consistent*: the chain has no secret key,
so anyone who can write the store (the process memory, or the database as its owner) could recompute it. This makes
tampering *detectable*, not impossible (see Limitations).

A proposal is created `proposed`, passes the policy checks (catalogue, parameters, target shape, approval
policy; `target-exists` is recorded **unknown**, because nothing here can ask the inventory) and enters
`pending-approval` in the same call (three history events).

### Approval, replay and TOCTOU

* A request carries a **`digest`** (SHA-256 over the id, the content, the deadline) and a **`version`** (the
  sequence number of its last history event). Approve, reject, cancel and execute quote both; a quote that no
  longer matches is `409 STALE_REQUEST`. A person therefore decides on exactly what they saw, and a captured
  approval cannot be replayed on a later state.
* **Requester != approver** for every risk (identity id; two sessions of one person are one identity). One
  person approves once. Risk D needs two distinct approvers, neither the requester; the second approver must
  quote the version that includes the first approval. Only a human approves (`HUMAN_ONLY_PERMISSIONS`,
  re-checked inside the store).
* All of this is decided **inside the store lock**, so concurrent approvals record exactly one (tests fire six
  and eight in parallel).
* **Step-up** (a recent second factor) for approve, execute and releasing the kill switch. Engaging the kill
  switch, proposing, rejecting and cancelling do not need it (stopping must be easy).
* **Expiry.** An unapproved request expires after `approve_within_seconds` (24 h); an approved one must be run
  within `execute_within_seconds` (1 h) or it expires; a run that never reports back is failed after its timeout
  plus 60 s (`executor-timeout`). Deadlines are applied on every touch, by the list sweep and when a request is created or
  a run is started (so an expired request or a timed-out run never keeps blocking new work). Every move made by the clock
  rather than by a person is audited as `actions.system-transition` (actor `system:actions`).
* **Idempotency.** `Idempotency-Key` (16-64 characters of `A-Za-z0-9._-`) is required on create, create-from-finding
  and execute. For create it is scoped to the requester: the same key and body returns the first request
  (`Idempotent-Replay: true`), the same key with another body is `409 IDEMPOTENCY_CONFLICT`. For execute the key
  starts a run once: a retry reports the recorded result and runs nothing again; a different key on a request that
  is not `approved` is refused. A retry replays only for the person who started the run and only with the request's
  digest (another person using the key gets `409 IDEMPOTENCY_CONFLICT`), and answers `Idempotent-Replay: true`. One open
  request per action type and target; at most 25 open per requester; at most 5 000 stored, **bounded by evicting the
  oldest finished requests** (and their idempotency keys) when full, never an open one, so a propose-and-cancel loop cannot
  fill the store; **one execution per target at a time** (`TARGET_LOCKED`).

### Pre-checks, verification, rollback, timeouts

`engine.py` runs, after the store has started the run (the whole run shares **one** time budget, the definition's
`timeout_seconds`, so it always finishes before the store's sweep would fail it; the engine-level pre-checks run under that
budget too; the kill switch is read again immediately before the executor acts; and an unexpected error after the run
started fails the request with `executor-error` instead of leaving it `executing`): re-validation of the stored request against the
catalogue (defence in depth), pre-checks (the executor's own plus the engine's, such as "the finding is still
open and its evidence version has not moved"), the executor under a timeout, verification, and rollback when
verification fails. A failed check stops before the executor acts; an *unknown* check stops a live run but not
a dry run; an exception or an overrun becomes a static failure code and **the exception text is discarded**; an
unverifiable result is `failed`, never assumed good. The framework paths (live success, failed verification with
rollback, failed rollback, timeout, executor error) are exercised by test fakes; no shipped executor takes them.

### Dry-run semantics

A dry run ends `succeeded` with `execution.mode: dry-run`, `effect: none` (a contract invariant: a dry run that
claims to have changed something is rejected by the schema, the model, the store and the parser) and
`verification: not-applicable`. The UI says "Dry run completed ... nothing was changed ... nothing was contacted",
labels the control "Record a dry run" while no live executor is ready, and shows the "Dry run only" notice from
`GET /actions/status` (`dry_run_only` is exactly "no live executor is ready").

### Kill switch

`NETSIGHT_ACTIONS_KILL_SWITCH` (an unreadable value counts as *engaged*) or the runtime switch
(`POST /actions/kill-switch`, Administrator). Engaged: no request can be proposed, approved or run
(`503 KILL_SWITCH`); reads, rejection and cancellation still work. An environment switch cannot be released
through the API (`409 KILL_SWITCH_LOCKED`). The runtime switch is per process (see Limitations).

### Quarantine proposal from a finding (Step 8)

`POST /actions/from-finding` turns a finding's `proposed_action` into an Action Request: it requires
`actions:propose-high` and `unknown-devices:read`, quotes the finding's `evidence_version`, refuses a finding with
no proposal (`NO_PROPOSAL`), a closed one (`FINDING_CLOSED`) or moved evidence (`STALE_EVIDENCE`), uses the opaque
finding id as the target (the MAC, address and name are **not** copied into the action store) and sets the default
duration (60 minutes, pre-filled, not a policy). It is still only a proposal: it waits for another person's
approval, and at run time the `finding-current` pre-check fails if the evidence moved since. The finding page shows
"Create an action request" only to a viewer who may propose high risk; the finding's own contract is unchanged
(`executable` stays `false` there).

## API

All under `/api/v1/actions`, all `no-store`, errors included. Contracts: `contracts/json-schema/actions.schema.json`,
the `step12` blocks of the OpenAPI document, pydantic `schemas_actions.py`, TS parsers `api-contracts-actions.ts`, and
`contracts/test-vectors/actions.vectors.json` driving all four verdicts (the Step 1 placeholder `action-request` schema
and `/action-requests` paths are replaced).

| Route | Permission | Notes |
| --- | --- | --- |
| `GET /status` | `actions:read` | engine state, `dry_run_only`, kill switch, executors, definitions, `store` (`kind` `memory` with `durable: false`, or `postgres` with `durable: true`), `policy.self_execute_allowed` |
| `GET /` | `actions:read` | newest first, `state`, `page`, `page_size` <= 50, unknown parameters refused |
| `GET /{id}` | `actions:read` | request + history + `chain_intact` |
| `POST /` | `actions:propose` (+ `actions:propose-high` for risk C and D) | `Idempotency-Key` |
| `POST /from-finding` | `actions:propose-high` + `unknown-devices:read` | `Idempotency-Key` |
| `POST /{id}/approve` | `actions:approve`, step-up | digest + version |
| `POST /{id}/reject` | `actions:approve` | digest + version + reason |
| `POST /{id}/cancel` | requester (`actions:propose`) or `actions:approve` | digest + version + reason |
| `POST /{id}/execute` | `actions:execute`, step-up | digest + version, `Idempotency-Key` |
| `POST /kill-switch` | `actions:kill-switch`; release needs step-up | |

Guard order for writes: authenticate, authorise (a refusal is audited), CSRF and origin, step-up, per-identity budget
(30/min; execute 10/min; kill switch 5/min; reads 120/min), then the body. Disabled engine: status and list answer
`not-connected`; everything else is `503 ACTIONS_NOT_ENABLED`.

Audit (`actions.create`, `.create-from-finding`, `.approve`, `.reject`, `.cancel`, `.execute`, `.kill-switch`, `.status.read`,
`.list.read`, `.item.read`): actor, outcome, the request id as target and static facts (risk, state, version, lengths,
counts, mode, effect, failure code). Never the reason, a parameter value or a target.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `NETSIGHT_ACTIONS_ENABLED` | off | `1/true/yes/on` enables the engine; garbled fails start-up |
| `DATABASE_URL` | unset | the application-role PostgreSQL connection shared by every durable store. Set: requests and history live in PostgreSQL (migration 0007 must be applied, with the grants). Unset: process memory, `store.durable: false`. Set but not a `postgresql://` URL: start-up fails when the engine is enabled (never a silent fall back to memory). When the runtime is built the store is probed once: a missing table, grant or enabled trigger of migration 0007 fails start-up (apply 0007 and the grants); an unreachable or failing database does **not** (it may be a restart-time outage): it is logged at ERROR and every call answers 503 until it returns |
| `NETSIGHT_ACTIONS_REQUIRE_DURABLE` | off | `1/true/yes/on`: with the engine enabled, refuse to start without `DATABASE_URL` (instead of running on volatile memory); garbled fails start-up |
| `NETSIGHT_ACTIONS_KILL_SWITCH` | off | engaged from start-up, not releasable through the API; garbled = engaged |
| `NETSIGHT_ACTIONS_LIVE_EXECUTION` | off | reported `not-connected` when on (no connector ships); garbled fails start-up |

## UI

`/actions` (status card with the dry-run notice, kill switch, executors and storage line (the volatile-storage warning appears only when `store.durable` is false); state filters as links;
table; kill-switch panel for Administrators) and `/actions/{id}` (facts, approvals "x of y", digest and version, checks
with "Not known" never shown as a pass, the result in honest words, the append-only history with the chain verdict, and
the decision panel). The decision panel shows what is being decided, sends the digest and version it showed, marks
step-up actions, explains each disabled control (role, "a different person must approve", already approved, state, kill
switch), keeps one idempotency key per request version, and locks after an unconfirmed result. Reasons, parameters and
targets are rendered as text. Menu entry "Action requests" (`actions:read`); `actions` joins the sign-in return allow-list
(web and API).

## Storage (D-53)

Two implementations of the `ActionStore` Protocol, one set of rules: both decide with `actions/lifecycle.py` (the
transition table, the quote check, approvals, the execution start and finish, the deadlines) and one conformance suite
(`tests/test_actions_store.py`) runs every behaviour test against memory, PostgreSQL as the schema owner and PostgreSQL as
the least-privilege application role.

* **Memory** (no `DATABASE_URL`): process-local, `store.durable: false`, lost on restart, not shared between workers.
  Fine for a demo; the status contract and the UI say so.
* **PostgreSQL** (`DATABASE_URL`, `actions/postgres_store.py`, migration `0007_action_requests`): `store.kind: postgres`,
  `durable: true`. Every change is one transaction that first locks the request row (`SELECT ... FOR UPDATE`) and reads
  the state it decides on, so of two workers racing one request the loser is refused (`STALE_REQUEST`) and never
  overwrites; a request and its events are written together. Creation takes one advisory lock so the caps (25 open per
  requester, 5 000 stored), one open request per action and target and the idempotency key are exact across workers
  (an idempotent replay, a duplicate and the per-requester cap are answered before the lock is taken, and again under
  it; the deadline sweep runs in its own transaction outside it; both locks use the two-integer advisory form with a
  namespace per purpose); a run takes an advisory lock on its target (a unique index is the backstop), so one execution
  runs per target. Deadlines are swept with `FOR UPDATE SKIP LOCKED`, one bounded batch (200) per call: workers divide
  the overdue requests, each is moved once and reported to the audit callback **at most once**, after commit (a crash
  between the commit and the callback loses that audit record; the move is kept). A row that no longer parses is logged
  by id and skipped by the sweep, so one corrupt row cannot block creation, a run or other expiries. A decision on a
  request that expired while it waited commits the expiry and then answers `EXPIRED`. A listing sweeps first (its own
  transaction) and then reads the page and its total in one read-only snapshot, so a `GET` writes nothing in its read
  and the total matches the page. An idempotency key stays bound to the person who started the run and to the digest.
  The 5 000 cap "evicts" the oldest *finished* request that is at least one hour old (`EVICT_MIN_AGE_SECONDS`, so a
  propose-and-cancel loop cannot push other people's records out; a store full of younger finished requests answers
  `STORE_FULL`) by hiding it (`evicted_at`) and freeing its idempotency key; each eviction is logged by request id. The
  row and its history stay, because the history is append-only and retention is a pending human decision
  (DATA-RETENTION-MATRIX; no prune is built). Both stores apply the same minimum age.
* **Append-only history.** `action_history` rows are the same hash chain (`history.py`). The database repeats the
  structure as constraints and triggers: every event continues the chain (next sequence number, the previous hash, the
  state the request was left in, a legal move, nothing after the request finished); `UPDATE`, `DELETE` and `TRUNCATE` are
  rejected for every role including the owner (`ENABLE ALWAYS`, so also under `session_replication_role = replica`); a
  deferred constraint trigger fails the commit unless the request's version and state are its last event's, its approvals
  match the `approved` events and its execution record matches an `execution-started` event. A request's identity
  columns cannot change, approvals are only added (once per person, never the requester), a finished request changes only
  by being evicted. The hash itself is computed and checked by the application, so `verify_chain` (the `chain_intact`
  verdict) additionally detects what only a table owner who disabled the triggers could do: an edit, a gap, a reorder,
  a cut-off head or tail (the last event must be the request's version and state), a history moved to another request
  (the request id is in every hash), and an approver list that differs from the `approved` events. Every hash also
  covers the request's `digest`, and the store recomputes the digest from the stored content (type, target, parameters,
  risk, requester, reason, source, approvals required, deadline) on every read: a row whose content was edited behind
  its digest is a `StoredRecordError`, and the history of a request is bound to the content an approver was shown. What
  remains (owner-level tampering only): someone who can disable the triggers *and* recompute SHA-256 can rewrite the
  content, the digest and the whole chain consistently, or edit columns that no digest covers (`execution`,
  `pre_checks`, `execute_by`); there is no secret key. The audit log and, later, a tamper-evident sink are the
  independent record. The migration's functions pin their `search_path` (`pg_catalog`, the schema, `pg_temp` last), so a
  session cannot shadow the tables with a `TEMP` table; the trigger functions of 0006 (and 0002 to 0004) do not yet
  (follow-up).
* **Failures.** An unreachable or failing database is `503 STORE_UNAVAILABLE` on that call; it never falls back to
  memory and never answers with an empty list; the exception class and SQLSTATE are logged at ERROR (never the DSN, a
  parameter or a row). A stored row that no longer parses as the contract, or whose content no longer matches its digest,
  is a `StoredRecordError` (a `StorageError`, a 500; nothing of the row is served, and only its id and the names of
  the bad fields are logged). The `reason` of a rejection or cancellation is kept permanently in the append-only history
  (retention is pending); worker clocks decide windows (the caller's `now`), so skew between workers moves a deadline by
  the skew: keep hosts on NTP.
* **Privileges.** The application role has `SELECT` and `INSERT` on both tables and `UPDATE` only on the mutable
  request columns (state, version, approvals, execute_by, run_by, pre_checks, execution, exec_key, exec_actor_id,
  evicted_at); no `DELETE`, `TRUNCATE`, `REFERENCES` or `TRIGGER`; `PUBLIC` has nothing (`storage/grants/app_role.sql`).
* **Operations.** Apply migration 0007 and the grants (`python -m netsight_api.storage.migrate up`) before enabling the
  engine with `DATABASE_URL`; `grants/app_role.sql` references the 0007 tables, so the grants must run after 0007 (`up`
  does this in order). `check()` (run once at start-up) verifies the tables, the `SELECT`/`INSERT`/`UPDATE` grants and
  that all nine triggers are enabled `ALWAYS`. Follow-ups, not built: a connection pool (one connection per call today),
  `FOR NO KEY UPDATE`, immutable `Held`/`_Tx`, and retention/prune. `down` is destructive (it removes every request and its history): it needs
  `allow_destructive` and `NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1` while rows exist.

## Limitations (read before any live executor)

1. **Memory store is volatile.** Without `DATABASE_URL`, requests, approvals and history are in process memory: lost on
   restart, not shared between workers. `store.durable: false` is in the status contract and the UI says so. The
   PostgreSQL store (see Storage) removes this; the kill switch below is still per process.
2. **Tamper-evident, not tamper-proof.** The hash chain detects edits and the PostgreSQL triggers refuse them, but the
   table owner and superusers can disable the triggers (keep the owner credential out of the running service), the
   chain has no secret key, and the audit log is an operational log sink, not a tamper-evident store (PRD 32 is still
   open).
3. **Kill switch is per process**, with either store: the runtime engage/release affects only the worker that handled
   the request. The environment variable plus a restart is the hard stop across workers. Persisting the flag in a
   one-row table read inside each decision transaction is a documented follow-up (not built).
4. Approvals are Administrator-only for now (the matrix says "Policy"); site scoping does not exist.
5. **Gates before any live executor ships** (found in review, harmless with the dry-run executor): (a) a timed-out executor
   call cannot be interrupted, it is abandoned on a daemon thread and the target lock is released, so a second action could
   start while the first is still working: a live executor must honour its own deadline/cancellation, or the engine must
   keep the target locked until the call has actually returned; (b) engaging the kill switch does not abort a run already
   past its last check; (c) ~~the requester may run their own request~~ fixed: the requester cannot execute their own request unless `NETSIGHT_ACTIONS_ALLOW_SELF_EXECUTE` is set (default off; `409 SELF_EXECUTION`; dry runs included, so a lone Administrator cannot run their own request). The status contract carries the flag as `policy.self_execute_allowed` (additive; false when the engine is not connected), so the web decision panel disables Run / Record a dry run for the requester with "The person who requested an action cannot execute it" instead of enabling a control the API then refuses (the API stays authoritative);
   (d) one person holding two identities (for example a local and an OIDC account) is two people to the requester rule. Both the requester rule and the per-requester open-request cap key on `Identity.id` (`provider:subject`, the immutable provider subject; never an email address or display name). A local account's id is `local:<username>`, a login name rather than an opaque id, so it is stable only while usernames are never reused;
   (e) a tamper-evident audit sink (the durable store now exists: see Storage).

## Human decisions needed

(1) Who may approve: the matrix says "Policy" for Network Engineer and Security Analyst; today only the Administrator holds
`actions:approve`, `actions:execute` and `actions:kill-switch` (so a risk D request needs two Administrators). (2) Whether
the requester-may-not-approve rule should be relaxed for risk A and B (it is not). (3) The approval and execution windows
(24 h and 1 h) and the default isolation duration (60 minutes). (4) Which action types, in which order, get a real
executor, and the lab that proves them. (5) ~~Where the durable store lives~~ decided as D-53 (PostgreSQL, behind the
`ActionStore` Protocol); still open: how long finished requests and their history are kept (DATA-RETENTION-MATRIX; no
prune is built). (6) Whether Technician may propose risk B (`switch.port.enable`) at all.

## Rollback

Unregister `actions_router` in `main.py`, drop the `actions` menu entry and the sign-in allow-list entry, remove the
`actions:*` permissions (or leave `NETSIGHT_ACTIONS_ENABLED` unset: the surface answers `not-connected` and stores nothing).
With the memory store nothing was persisted. With `DATABASE_URL` the requests and history are in migration 0007: to stop
using them, unset `DATABASE_URL` (the engine falls back to memory) or leave the engine disabled; to remove the tables, back
up first and run `apply_down(..., allow_destructive=True)` with `NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1` (this destroys every
request and its hash-chained history; the audit log is the only other record). Reverting the code needs no data change: the
tables are only read by the PostgreSQL store.
