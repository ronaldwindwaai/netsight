# Capacity Forecasting and Advisory Optimisation (Step 13)

Roadmap epic **E12 - Forecasting/Optimisation** (IMPLEMENTATION-ROADMAP.md: "Capacity, predictive warnings and safe recommendations").
PRD: section 21 (Internet/WAN: capacity), section 35 (data quality: missing telemetry must be visible), reporting list ("capacity forecast"), phase P11.
Report type: `REPORTING.md` "capacity". Inputs borrow the honesty rules of `TRAFFIC-BASELINES.md` (coverage, absent is not zero, no model).

## Constraints applied

* **Source-reported history only.** A forecast is made from days a source reported, nothing else. A day with no data is *absent*, never zero. A first day the store covers only from mid-day is dropped as partial.
* **Deterministic and explainable.** Two methods, both a few lines of arithmetic: a straight-line trend and a weekly repeat. No training, no hidden state, no tuning. The response says which ran and why.
* **Never a fabricated point.** `history` holds measurements; `forecast` holds projections with a band. A series that is not `ok` has no method, no projected point and no crossing (pydantic, JSON Schema where expressible, and the TS parser all enforce it).
* **Explicit states.** `ok`, `insufficient-data` (with the reason and the measured days it had), `not-connected` (no source), `unknown` (source configured but unreadable). Never an empty success.
* **Advice is text.** A recommendation has `advisory: true` and `executable: false` as contract constants and no field that could carry an action. No forecast module imports the Action Request framework (a test asserts it). Nothing is executed, scheduled or turned into an action request.
* **Read-only.** No write route. Computed on read; nothing is stored, no migration.
* **Privacy.** Only the organisation-wide daily byte total is read. No endpoint, address, application, user or device appears in any request, response, cache key or audit record.

## What is built

| Surface | Route | Permission |
|---|---|---|
| Capacity forecast and recommendations | `GET /api/v1/forecast/capacity?horizon_days=&history_days=` (`/forecast`) | `forecast:read` |
| Capacity report (CSV) | `GET /api/v1/forecast/capacity/export` (`/forecast/export`, a download link on the page) | `forecast:export` |

Query: `horizon_days` 1-30 (default 14), `history_days` 14-120 (default 56). Unknown, repeated or malformed parameters are a 422 that echoes nothing. The page offers 7/14/30 and 28/56/90.

### Series

| Series | Source | State today |
|---|---|---|
| `traffic-volume` (bytes per day, whole UTC days, organisation total) | the ClickHouse flow store (`ExplorerClickhouse.daily_totals`, two bounded read-only queries) | `ok` / `insufficient-data` / `not-connected` / `unknown` |
| `wan-utilisation` (percent) | none: LibreNMS gives the *current* rate only, and Netsight stores probe samples (reachability, latency), not utilisation | always `not-connected`, reason `no-history-source` |
| `inventory-growth` (devices) | none: NetBox and LibreNMS are read for current state; no history is stored | always `not-connected`, reason `no-history-source` |

The two `not-connected` series are listed on purpose: the gap is visible, with its reason, and each produces a `connect-history-source` recommendation. They become real when a source that reports history exists (a LibreNMS port-history read, a stored inventory snapshot); the engine, contract and page already handle any series.

### The method (`forecast/engine.py`)

1. **Window.** The last `history_days` *complete* UTC days (today is never used), sliced from one fixed 120-day read. Gaps are counted only after the first observed day (days before the store's history began are not "missing"). A forecast starts the day after the **newest observed** day, so it continues the measurements without a jump even when the newest day is 1-3 days behind the window end (the days in between are forecast, never measured).
2. **Minimum history (refusals, no points).** `too-few-days`: fewer than 14 observed days. `history-stale`: newest observed day more than 3 days before the window end. `too-many-gaps`: more than 25 % of the days from the first observed day have no data. `horizon-too-long`: horizon above half the observed days.
3. **Linear trend.** Ordinary least squares on (day number, bytes). Band: the approximate 95 % prediction interval `t * s * sqrt(1 + 1/n + (x - mean)^2 / Sxx)`, `s` the residual standard deviation and `t` the two-sided 95 % Student-t value for `n - 2` degrees of freedom (a table, rounded up between rows: 2.179 at the 14-day minimum, so a short history is not given a normal-sized band). A perfectly regular history gives a zero-width band; that is not a claim of certainty.
4. **Weekly seasonal naive.** Considered with at least 28 observed days and 14 same-weekday pairs. Each forecast day repeats the same weekday from the latest week observed (looking back at most four more weeks over a gap). Band: `t * rms(value - value a week earlier) * sqrt(weeks ahead)` (`t` for pairs - 1 degrees of freedom). Used only when its mean absolute error on the history is lower than the straight line's on the same days (the line is judged in-sample, which favours the line).
5. Values and band edges are floored at zero and rounded half up to whole numbers. The method, its error figures and the reason it was chosen are in the response and on the page.

The band describes how far past values sat from the method. It does not allow for a change in behaviour, a new site or an outage; the page says so.

### Threshold and predictive warning

`NETSIGHT_FORECAST_TRAFFIC_DAILY_LIMIT_BYTES` (optional, whole bytes per day) is the only limit and is always the operator's (`basis: operator-configured`). Netsight never infers a limit from link speed or history. With a limit, an `ok` series carries a *derived* crossing: the first forecast day the point forecast reaches it and the first day the upper band reaches it (pydantic and the TS parser recompute it from the forecast, so the chart and the text cannot disagree). A garbled value is treated as unset and logged once without the value.

### Recommendations (`forecast/recommend.py`)

Fixed-order rules; each recommendation carries its evidence lines (the numbers it came from) and the method's own explanation.

| Kind | Fires when |
|---|---|
| `capacity-review` | a configured limit is reached by the point forecast within the horizon |
| `capacity-watch` | only the upper edge of the band reaches it |
| `growth-no-limit` | no limit is configured and the average forecast is at least 20 % above the average of the last measured days |
| `weekend-headroom` | at least 4 weekend and 10 weekday measured days, weekends under 60 % of weekdays |
| `connect-history-source` | a series is `not-connected` |
| `collect-more-history` | a series is `insufficient-data` |

An empty list is shown as "not a statement that capacity is fine".

### The capacity report

`REPORTING.md` names a capacity report type. It is built as a **synchronous, bounded CSV** of the same response the page shows (like the WAN SLA export): one row per series day, `kind` = `measured` | `forecast` | `state` | `notice`, `lower`/`upper` only on forecast rows, the method name on forecast rows, a `state` row for a series with nothing to show (the reason and detail), and a closing notice row ("Forecast, not measurement ... Generated ..."). Fixed header, CRLF, quoting by the csv module, a leading apostrophe on any text cell a spreadsheet could execute. Download name fixed (`netsight-capacity-forecast.csv`); `Cache-Control: no-store`, `nosniff`. Each export is rate-limited (6/min) and audited.

**Not built (REPORTING.md architecture):** report definitions, snapshots/archive, async generation, scheduled delivery, PDF/Excel, and the *inventory* report type (inventory has no history to report beyond the current-state pages and the IPAM/inventory summaries already shown).

## API behaviour

* Guard order: authenticate, `forecast:read` (or `forecast:export`), per-identity rate limit (30/min read, 6/min export; separate budgets), strict query, then the read. An unauthorised caller never sees limiter state.
* The flow store is read **once per UTC day in one fixed 120-day window**, whatever `horizon_days` and `history_days` are (a request is a slice of that read, computed per request in microseconds), so a caller cannot multiply scans by varying the window. The read is shared for 5 minutes across callers (it holds no per-person data) and takes one of the existing heavy-read admission slots (refused with 429/503 and `Retry-After`, never queued). A failed read is never kept as a result, but it is remembered for 15 seconds so a store that is down is not hammered and concurrent waiters fail fast with `unknown`.
* A response that fails its canonical contract is not sent as data: it degrades to `unknown` with no projected point.
* Every read, export, refusal and denial is audited (actor, action, state, window sizes, counts; never a value). Responses are `Cache-Control: no-store`. A source failure is logged by exception type only.

## Contracts

`contracts/json-schema/forecast.schema.json` (root = `ForecastResponse`, 7 defs), OpenAPI components `ForecastResponse`, `ForecastSeries`, `ForecastHistoryPoint`, `ForecastPoint`, `ForecastMethod`, `ForecastThreshold`, `ForecastCrossing`, `ForecastRecommendation` and the two paths (blocks `step13:*`), pydantic `schemas_forecast.py`, TS parsers `api-contracts-forecast.ts`, shared vectors `forecast.vectors.json` (8 entities, valid and invalid cases) driving all four verdicts plus an OpenAPI-vs-schema structural diff. Cross-field rules JSON Schema cannot express (band contains the point, crossing derived from forecast and limit, overall state follows the series, consecutive days, forecast length equals the horizon) are marked `jsonschema_rejects: false` and enforced by pydantic and the TS parser.

## UI (`/forecast`, menu "Capacity forecast", gated by `forecast:read`)

* A "Forecast, not measurement" note comes before any figure; window controls (plain GET form); a "Download capacity report (CSV)" link only for `forecast:export`.
* One card per series: state as a word and an icon, the chart, the limit sentence, the method in words ("a transparent calculation, not a model", why, history used, range meaning), or the reason it cannot be forecast.
* Chart: measured days solid, forecast dashed with a hatched band (shape and pattern, not colour alone), a break at missing days, an isolated day as a dot, a dotted limit line only when it is within the scale, a key, an `svg role="img"` with a title and a description ("Measured: 14 days ... Forecast, not measured: 7 days ... approximate 95 %"), and a data table in a `details` element labelling every row Measured or Forecast. Chart colours come from theme variables, so both themes work.
* States: loading, permission, unauthenticated, error, nothing connected, unknown, not enough history, forecast. Recommendations are a region labelled advisory, with no control.
* Sign-in return allow-list extended (web and API).

## Security notes

* Permissions: `forecast:read` for all six roles (aggregates only: the same rung as `traffic:read`); `forecast:export` for Administrator, Network Engineer, Security Analyst, Management and Auditor, **not** Technician. Neither is human-only (a service principal with the role may read).
* ClickHouse: SQL from constants, parameters bound, window of at most 120 whole days, `LIMIT`, a time budget, a result at its row cap fails instead of being truncated, negative or fractional counts fail the read, a bucket off a UTC midnight or outside the window fails the read.
* The web export route validates the query against the offered windows, refuses a browser-marked cross-site request, relays only a `text/csv` attachment with the fixed file name, drops every other upstream header and answers failures with fixed text.
* Untrusted text (series names are fixed server text, but advice, evidence and details are rendered as text; nothing uses `dangerouslySetInnerHTML`).

## Limitations and decisions needed

* Only organisation-wide daily bytes are forecast. No per-link, per-site, per-application or per-VLAN series (a deliberate privacy position shared with the Step 7 baselines).
* WAN utilisation and inventory growth need a history source: a LibreNMS port-history read or a stored snapshot (with a retention decision, DATA-RETENTION-MATRIX). Until then they are `not-connected`.
* The band is approximate and assumes the future resembles the past. The straight-line band is computed on residuals that still contain any weekly pattern, so real coverage on strongly weekly data is likely below 95 % when the trend method is chosen.
* Only the first observed day can be recognised as partly covered (retention began mid-day). A partial last day or a collector outage inside the window understates that day's bytes and is not detected: the day is shown as measured. (A first day at the very edge of the 120-day read is kept, because older data may exist behind it.) Day-of-month, holiday and one-off effects are not modelled. Seasonal-naive selection is judged on the same history it is fitted to.
* A flow store with retention shorter than 14 days can never produce a forecast (the page says why).
* Human decisions: whether Technician should export; the traffic daily limit and how it relates to link capacity; whether a scheduled/archived capacity report and an inventory report are wanted (REPORTING.md architecture); the 20 % growth and 60 % weekend rule thresholds.
* Not verified against a live ClickHouse or in a browser: the adapter is mock-transport tested, the UI is jsdom/typecheck/lint/build tested only.

## Rollback

Unregister `forecast_router` in `main.py`, drop the Capacity forecast menu entry, the `forecast` sign-in allow-list entry and the `forecast:*` permissions. Nothing was persisted and there is no migration; unset `NETSIGHT_FORECAST_TRAFFIC_DAILY_LIMIT_BYTES`.
