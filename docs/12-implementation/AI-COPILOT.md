# AI Read-Only Copilot (Step 10)

Roadmap epic **E09 - AI copilot** (BUILD-PLAN "E09", PRD 26-29 "AI Copilot / AI authority / AI security / Knowledge/RAG", `docs/07-ai/*`, `docs/02-security/AI-SECURITY.md`).
Authority: PRD levels 1-2 only (observe/explain/recommend and run approved read-only tools). Level 3+ (prepare remediation) needs the Action Request framework (E11) and is **not built**; the copilot has no write, execute, approval or `propose_action` path.

## Constraints applied

* **Read-only, no tools for the model.** The model is offered no tool, function or action. It can only return text. Which read tools run is decided by deterministic code (`copilot/planner.py`), not by the model, so injected text cannot cause a tool call, widen a window or raise a limit.
* **All retrieved, device and log text is untrusted data.** Documents, device names, commit messages, incident titles and the question itself are cleaned (control, format and bidi characters removed, one line, bounded), secret-redacted, scanned for instruction-like text and labelled. Instruction-like text is flagged and shown, never trusted and never dropped (`copilot/sanitize.py`).
* **Per-user RBAC on every tool call.** Each call is authorised against the *asker's* identity (never a service identity). A denial is a `denied` gap, not an empty result, and the source is not touched.
* **No fabrication.** No model configured: `not-connected`, nothing is read. Model failure, timeout or an answer that fails validation: `unknown`, no answer. Sources return nothing: `no-evidence`, the model is not asked. Only `ok` carries an answer, and every fact and inference must cite at least one evidence id that is in the bundle.
* **Audit without content.** Every ask and every tool call is audited (actor, state, counts, tool names, question *length*). The question, evidence and answer are never written to the audit trail.

## What is built

| Surface | Route | Permission |
|---|---|---|
| Status: model configured?, knowledge corpus, tools and whether each is permitted | `GET /api/v1/copilot/status` | `copilot:ask` |
| Ask a question | `POST /api/v1/copilot/ask` (page `/copilot`, menu "Ask Netsight") | `copilot:ask` |

`copilot:ask` is held by Administrator, Network Engineer, Security Analyst, Technician and Auditor; **Management holds none** (it holds none of the tools' data either; open decision). It is in `HUMAN_ONLY_PERMISSIONS`: a service or AI principal cannot start a conversation whatever its role (no model-drives-model, no unaccountable spend). Unknown roles are denied.

### Tool broker (`copilot/tools.py`)

Explicit allow-list, strict typed arguments (extra keys refused), per-call authorisation, 10 s budget per call, at most 6 evidence items per tool, audit callback per call. A name outside the list raises `UnknownTool` and nothing runs (`run_shell`, `propose_action`, `disable_port`, ... are simply not registered).

| Tool | Needs | Reads |
|---|---|---|
| `search_knowledge(query)` | `copilot:ask` | The local knowledge index |
| `list_open_incidents(limit)` | `incidents:read` | The incident store, open/acknowledged/investigating/mitigated |

These three are the subset of `AI-TOOL-CATALOG.md` built now (`list_open_incidents` is new to the catalog). The catalog's device, flow, security, probe and identity tools need per-tool review (identity/people tools are deliberately never available to the AI, RBAC-MATRIX) and are follow-ups.

### Evidence bundles

Every tool returns `Evidence` (source, kind, title, bounded redacted excerpt, reference with provenance, observed time, freshness, `instruction_like`). The service numbers them `ev-001`... (cap 12) and sends **only** that bundle plus the cleaned question to the model. Coverage is evidence too: the config tool always adds a summary item stating devices checked vs total and "incomplete" when truncated; the incident tool states the count (and whether the read was capped), so an empty list is a real zero and not a gap.

### Retrieval (`copilot/knowledge.py`)

Lexical TF-IDF over `*.md` files under `NETSIGHT_KNOWLEDGE_DIR`; no embedding service, nothing leaves the host to index. Symlinks, hidden and vendored directories and files over 512 KiB are skipped; a path that resolves outside the root is skipped; at most 2 000 documents / 20 000 chunks. Provenance: relative path, heading and a content-hash version in the reference; documents older than 365 days are `stale`. Re-read at most every 5 minutes (a failed read is retried after 30 s), one build at a time, and always off the event loop. Unset directory is `not-connected`; unreadable is `unknown`. **Access control per document:** an optional `---` header with `roles: administrator, network_engineer` limits who may retrieve it; the filter runs at search time against the asker's roles, so the shared index never leaks across users. No header means every `copilot:ask` holder; a `roles:` entry that names no known role means nobody (fail closed). The corpus size in `/status` is not role specific. Excerpts are redacted again at use. Redaction is best-effort (keyword and token-shape based): a bare password in prose (`login admin / P@ssw0rd`) cannot be recognised, so the corpus must not contain secrets.

### Model provider (`copilot/provider.py`)

`ModelProvider.complete(messages) -> text`. The only implementation is OpenAI-compatible chat completions (works with local servers and gateways). Configured **only** by environment: `NETSIGHT_AI_BASE_URL`, `NETSIGHT_AI_MODEL`, optional `NETSIGHT_AI_API_KEY`, `NETSIGHT_AI_ALLOW_EXTERNAL`, `NETSIGHT_AI_TIMEOUT_SECONDS`. No key or model name is in source. Unusable configuration (credentials in the URL, non-http(s), a key over cleartext to another host, a non-loopback endpoint without `NETSIGHT_AI_ALLOW_EXTERNAL=true`, or a link-local/metadata/multicast/unspecified address even with it) is treated as not configured. Proxy environment variables are ignored (`trust_env=False`). Evidence is sent to the model, so leaving the host is an explicit decision. Redirects are not followed, replies are size-capped, errors never carry the key or the body, `repr` hides configuration, and `/status` returns only `ok`/`not-connected` (never the name or endpoint). Tests use a scripted fake provider; no test reaches a model.

### Prompt and answer (`copilot/prompt.py`, `copilot/answer.py`)

System message: fixed rules plus the output contract, never data. User message: question, source status and evidence, each in a block opened and closed by a **per-request random nonce**; every value is one cleaned line so data cannot start a fake block or close a real one. The model's reply must be exactly one JSON object with exactly the contract's keys (a single code fence is tolerated, prose around it is not); extra keys (`actions`, `tool_calls`, ...) reject the whole answer; strings are cleaned, redacted and bounded; any citation outside the bundle rejects the answer. The service then adds, itself, an unknown for every denied/not-connected/unreadable source and a recommendation to review every instruction-like item, so a silent model cannot hide a gap or a poisoned input.

## Contracts

`contracts/json-schema/copilot.schema.json` (root = ask response, 5 `$defs` plus the request and the status), 7 OpenAPI components (`Copilot*`) and 2 paths, pydantic `schemas_copilot.py`, TS parsers `api-contracts-copilot.ts`, shared vectors `copilot.vectors.json` (7 entities) driving all four verdicts plus an OpenAPI-vs-schema structural diff. An answer is also a valid generic `ai_answer`. A test asserts no `Copilot*` contract can carry a tool argument, an action, a credential or a model name, and that the only routes under `/copilot` are the status GET and the ask POST.

## Evals (`apps/api/tests/test_copilot_evals.py`)

A real model is non-deterministic, so the evals score what the *code* guarantees for every possible reply (scripted model): grounded answers cite only bundle evidence and keep facts apart from inferences; fabricated or missing citations are rejected; no evidence means the model is not called; unavailable sources become unknowns; AI-EVALS golden scenario 5 (malicious hostname) and PRD scenarios 11 and 12 (a model that obeys injected text and emits actions, tool calls or approvals is rejected, and no tool runs because of the model); secrets reach neither the model nor the operator. **Not evaluated here** (needs a live model and a reviewer): answer wording quality, root-cause fault-domain selection, anomaly explanation quality, latency and cost. Run those against the real provider before relying on answers operationally.

## Review (2026-10-18)

Security review (ecc:security-reviewer): no CRITICAL; 2 HIGH, 5 MEDIUM, 4 LOW. Fixed test-first: HIGH standalone secret shapes (Slack, GitLab, Google API, Stripe-style, URL and `user:pass@host` userinfo, `Basic`) now redacted; HIGH no per-document access control (now `roles:` header filtered per asker at search time); MEDIUM zero-width and homoglyph bypass of the instruction flag (text is stripped, NFKC-normalised and look-alike folded first, titles are scanned too); MEDIUM blocking index build on the event loop (now `asyncio.to_thread` with a single-build lock); MEDIUM one identity could hold every concurrency slot (2 per identity); MEDIUM environment proxy could carry evidence (`trust_env=False`); MEDIUM metadata/link-local model address with external enabled (refused); LOW audit gap on a crash (now audited as `state=error`); LOW regular-file check on corpus files. Code review (ecc:code-reviewer): APPROVE, no CRITICAL/HIGH; fixed MEDIUM source starvation under the 12-item cap (one slot per source first, then round robin; a cut source is named to the model and added to unknowns), MEDIUM server-stated gaps pushed out by a verbose model (they now come first), MEDIUM blocking work (above); LOW planner types, "configure" over-trigger, failed-read cache TTL, dead code. **Deferred:** scanning model output for URLs and shell-like lines (the UI renders only text and only citation links, so nothing is clickable or executable; a model can still write a persuasive sentence that cites real evidence); an entropy heuristic for bare secrets (false positives on hashes); an allow-list of model hosts; shared (cross-worker) limits.

## Bounds

Question 3-1000 characters; 12 evidence items; excerpt 600; answer: summary 800, 10 facts, 10 inferences, 10 unknowns, 8 recommendations; model reply 16 000 characters / 256 KiB; 10 s per tool; 60 s model call (UI waits 75 s). Ask: 10/min per identity (with `Retry-After`), 2 concurrent per identity and 4 concurrent per worker (refused with 429, not queued); status 60/min. Responses `Cache-Control: no-store`.

## Storage

None. Nothing is persisted: no conversation history, no cache of answers. Evidence is re-read on every question.

## Configuration

`NETSIGHT_AI_BASE_URL`, `NETSIGHT_AI_MODEL`, `NETSIGHT_AI_API_KEY` (optional), `NETSIGHT_AI_ALLOW_EXTERNAL`, `NETSIGHT_AI_TIMEOUT_SECONDS`, `NETSIGHT_KNOWLEDGE_DIR`. See `.env.example`.

## Security delta

* New `copilot:ask` (human-only). Authorise, then CSRF/origin, then per-identity limit, then concurrency cap; a 422 echoes nothing.
* Prompt injection: no model-controlled tool selection, nonce-delimited data blocks, flagged instruction-like text, strict output contract, citation check, server-added gaps and warnings, UI renders every string as text (the only links are citations built from validated ids).
* Data minimisation: only the cleaned question and the evidence bundle reach the model; configuration text never (only redacted summaries), no author names, no people/identity data.
* Residual risk: a model can still write a misleading *sentence* that cites real evidence. The UI shows the evidence beside every claim and labels flagged items; a person decides what to do.

## Rollback

Unregister `copilot_router` in `main.py`, drop the Ask Netsight menu entry and `copilot:ask`; unset `NETSIGHT_AI_*` to return every surface to `not-connected`. Nothing was persisted.

## Human decisions needed

1. Which model and where it runs (local vs approved external), and whether evidence may leave the host at all (`NETSIGHT_AI_ALLOW_EXTERNAL`); data-processing terms if external.
2. The RBAC reading (Management has no copilot access; Auditor and Technician may ask) and whether answers may be shown to roles whose tools are all denied.
3. The knowledge corpus: which documents, their `roles:` headers, and the staleness threshold (365 days).
4. Per-user and global model budgets (cost/concurrency), currently 10/min per identity and 4 concurrent per worker.
5. Retention policy if conversation history is ever wanted (none stored today).
6. An approved design for the page (DESIGN-INVENTORY gap).

## Follow-ups

Remaining catalog tools with per-tool review (device health, flows, security events, probes, path context); `propose_action` only through the Action Request framework (E11); embeddings/vector retrieval; ACLs from the document source instead of a header; scanning model output for URLs and shell-like lines; streaming; conversation memory with retention rules; a shared (non per-worker) limiter and concurrency cap; live-model eval run with human-scored rubric; a Playwright run of the page.

**Integration note (2026-10-19).** The `get_recent_config_changes` tool and the `config` evidence source were removed when this step was rebased onto the reviewed metadata-only Configuration stage 1 (`configuration:read`): that stage deliberately exposes no configuration text, diffs or commit messages, so there is nothing safe for a tool to read. Re-add a configuration tool only after a reviewed content/diff stage exists. The tools are `search_knowledge` and `list_open_incidents`.
