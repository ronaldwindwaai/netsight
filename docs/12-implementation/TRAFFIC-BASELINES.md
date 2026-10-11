# Traffic Baselines and Anomaly Signals

## Baseline dimensions
Per entity:
- time-of-day;
- day-of-week;
- upload/download;
- connection count;
- destinations;
- application mix;
- protocol mix.

## Context
Different baselines for:
- workstation;
- server;
- CCTV/NVR;
- guest/BYOD;
- backup system;
- network infrastructure.

## Signals
- volume deviation;
- first-seen destination;
- unusual country/ASN;
- unusual app/protocol;
- high upload ratio;
- unusual time;
- unusual DNS rate.

## Poisoning resistance
- exclude confirmed incident periods;
- limit adaptation rate;
- keep robust historic reference windows;
- allow operator "expected behaviour" labels without automatically weakening global policy.

## Output
Anomaly score is evidence, not automatic maliciousness.

---

# Implemented in Step 7 (anomalies, applications, destinations)

Everything above is the design target. This section is what is built, and exactly what it does not do.
Code: `apps/api/src/netsight_api/traffic/` (`anomaly.py` the arithmetic, `anomaly_report.py` the response,
`policy.py` the operator policy), the reads in `adapters/clickhouse_explorer.py`, the routes in
`traffic_routes.py`. Contracts: `traffic-anomalies.schema.json`, `traffic-applications.schema.json`,
`traffic-destinations.schema.json`, vectors `traffic.vectors.json`.

## The baseline algorithm (deterministic, no model)

Question per (series, hour): *is this hour's byte count unlike the same hour in the previous weeks?*

1. **Series.** The organisation-wide total, plus the ten applications with the most bytes in the judged window
   (only when the flow source reports an application field). No per-user, per-device or per-VLAN series: that is a
   deliberate privacy choice (PRD 92) and a deferral, not an oversight.
2. **Judged hours.** Whole, complete UTC hours: the last complete hour back as many hours as the requested window spans
   (the current partial hour is never judged). At most 168 hours (7 days) and 11 series.
3. **Samples.** The same hour of the week, 1 to 4 weeks earlier (fixed 168 h steps in UTC; across a daylight-saving change
   the local hour shifts by one for the weeks before it, see "Daylight saving" below). A prior hour counts only if the flow source holds **any** flow for
   that hour; an hour the source never saw (collector outage) is *absent*, not zero. A covered hour in which the series is
   missing is a real zero (that application was not used).
4. **Minimum history.** Fewer than `3` samples is `insufficient-baseline`: no baseline, no anomaly, and the response says
   how many hourly checks were skipped. An observed hour with no source data is `no-data` (a gap is not a drop).
5. **Baseline.** The median of the samples, rounded half up to whole bytes. The median is robust: one exfiltration week in
   four does not become the baseline (tested).
6. **Scale.** `max(1.4826 x MAD, 10% of the median, 1 MiB)`. The first term makes MAD comparable to a standard deviation;
   the floors stop a perfectly steady history from turning ordinary noise into a huge score.
7. **Flag.** `score = (observed - median) / scale`. Flagged when `|score| >= 3.5` **and** `|observed - baseline| >= 10 MiB`.
8. **Confidence.** `high`: `|score| >= 8` with all four weeks; `medium`: `|score| >= 5`; otherwise `low`. It describes the
   statistical separation, not the likelihood of malice.
9. **Output.** For every flag: the subject, the hour, the baseline (and how many weeks it rests on), the observed value, the
   signed difference, the ratio (absent when the baseline is zero), the score, the confidence and the context. The method
   constants are returned in the response so the figures can be recomputed by hand.

Constants (`traffic/anomaly.py`, returned in `method`): `WEEKS = 4`, `MIN_WEEKS = 3`, `THRESHOLD = 3.5`,
`MIN_DIFFERENCE_BYTES = 10 MiB`. They are **not** operator-tunable yet (human decision below).

### Boundaries are inclusive, and pinned

A flag needs **both** `|score| >= 3.5` and `|observed - baseline| >= 10 MiB`; each is inclusive and tested at its exact edge
(`test_traffic_anomaly_boundaries.py`). A median of 100 MiB (scale 10 MiB, the 10% floor) with 135 MiB observed is a score of
exactly 3.5 and is flagged; one byte less is not. A median of 2 MiB (scale 1 MiB, the floor) with 12 MiB observed is a difference
of exactly 10 MiB and is flagged; 12 MiB less one byte is not, even though its score is about 10 (the minimum difference holds it
back). A drop is judged by the same two conditions.

### Daylight saving

The weeks compared are fixed 168-hour UTC weeks, so across a daylight-saving change in the policy time zone the *local* hour of
the earlier weeks is one hour off. The score never uses local time and is unaffected; what can differ is whether an earlier week
fell inside working hours. The response says when it happens: `evaluation.daylight_saving` is `crossed` when the policy zone's
UTC offset differs anywhere between the oldest baseline week (four weeks before the first judged hour) and the end of the judged
range, `none` when it does not, and `not-applicable` when no zone is configured. The Anomalies page shows a note for `crossed`.
Nothing is re-aligned to local time: a local-time baseline is a separate design (and a different, less reproducible
algorithm).

## Context, not a verdict

* **After-hours is not assumed malicious.** `outside_working_hours` comes only from the operator policy (`working_hours`:
  IANA time zone, weekdays, start and end). Without it the flag is `null` ("working hours not configured"), never a guess. An
  hour that is not wholly inside working hours counts as outside. `end` may be `24:00` (the end of the day, in the policy zone);
  `start` may not, and `24:00` is the only value above `23:59`. When an hour *above* its baseline falls outside working
  hours the response lists the common legitimate causes from PRD 15 (backups, cloud sync, CCTV/NVR uploads, patching and
  updates, replication, scheduled maintenance, antivirus updates, authorised remote work). A drop gets no such list and
  carries a note that it can also be flow loss.
* **First-seen ASN / destination.** An ASN or destination is "first seen" if it appears in the window and not in the
  look-back (four weeks before the window). It needs history: if the source holds less than 7 days before the window,
  everything would look new, so none is raised and the status says why. The destination check covers the 1 000
  highest-volume destinations of the window; private, shared, link-local and multicast space is excluded. Documentation
  ranges are treated as external. Each row carries how many distinct source addresses reached it, and the aggregate tier is
  not shown a row that fewer than the minimum cohort reached (see "Small cohorts" below).
* **Poisoning resistance.** Median/MAD rather than mean/standard deviation; adaptation is not incremental (every read
  recomputes from source data), so nothing "learns" the incident. **Not yet done:** excluding confirmed-incident periods
  (needs the incident store joined to the baseline) and operator "expected behaviour" labels. Both stay on the follow-up list.

## Bounds and cost

Per uncached baseline read: one discovery plus five queries (hourly totals, hourly application series for the top ten,
oldest record, first-seen ASNs, first-seen destinations) over `[window start - 28 days, window end)`. Row caps
(1 000 hourly totals, 8 400 application rows) fail the read instead of truncating. The inputs hold no per-user data, so they
are cached in memory for 300 s, at most 16 windows, shared across identities, with one in-flight load per window; a failure is
never cached. Per-identity limit 10/min; at most 3 heavy reads in flight across identities (503 + `Retry-After` when busy).

## The operator policy file (`NETSIGHT_TRAFFIC_POLICY_FILE`)

One JSON file is the *only* source of approval, risk, reputation and working hours. Unset: everything is `Unknown`
(`not-configured`). A file that does not validate makes every classification `Unknown` (`invalid`: half a policy is never
applied) and is logged once per change. Read-only input, at most 256 KiB, 1 000 entries per list, duplicate keys refused,
re-read when the file changes. The file is opened **once** and measured with `fstat` on that handle (it must be a regular file),
and read with a hard bound, so there is no stat-then-read window in which it could be swapped or grown past the limit.

```json
{
  "version": 1,
  "working_hours": {"timezone": "Africa/Johannesburg", "days": ["mon","tue","wed","thu","fri"], "start": "08:00", "end": "17:00"},
  "applications": {
    "approved": ["Microsoft 365"],
    "unapproved": ["BitTorrent"],
    "risk": {"BitTorrent": "high", "Zoom": "low"}
  },
  "destinations": {
    "allow": ["203.0.113.0/24", "AS64500", "198.51.100.7"],
    "deny": ["bad.example", "192.0.2.0/28", "AS64666"]
  }
}
```

* Application names match exactly (`casefold` only), never by prefix, so `Zoom-malware` cannot borrow `Zoom`. A label that
  **changes under NFKC** (full-width letters, ligatures, no-break spaces: anything that imitates an ASCII name) is `Unknown`,
  never folded onto the name it imitates; an *entry* in the file that changes under NFKC could never match, so it invalidates
  the file instead of sitting there dead. "Approved" is not "low risk" and "not listed" is not "unapproved": each is `Unknown`
  unless a line says otherwise.
* Destinations: an address, a CIDR, an `AS<number>` or (deny only) a domain, which matches the domain and its sub-domains.
  **A hostname can deny but never allow**: reverse DNS is controlled by whoever owns the address, so an allow-listing earned
  by a hostname would be spoofable; a domain in `allow` invalidates the file. Deny wins over allow.
* **Overly broad allow ranges invalidate the whole file**: an `allow` CIDR shorter than /8 (IPv4: /0 to /7) or /16 (IPv6: /0 to
  /15) would make most of the Internet "allow-listed" on one slip, so it is refused like any other malformed entry. Deny ranges
  may be as broad as the operator likes: denying too much flags a destination, allowing too much hides one.
* **Reverse-DNS deny false positives.** A hostname deny entry (`bad.example`) matches the destination's *reverse-DNS name*, which
  whoever owns the address controls. That makes a deny-by-hostname both **evadable** (an attacker simply does not publish the
  name) and **spoofable the other way**: anyone can point the reverse DNS of an address they own at `bad.example`, so a benign
  address (or a competitor's, or one your own staff use) may show as `deny-listed`. `deny-listed` is therefore a prompt to look,
  never proof; prefer address, range and ASN entries for anything that matters, and read a hostname-only deny as a hint.
* No reputation or risk is read from any flow-source field today (none is standardised); a future source field would be an
  additional, explicitly documented input.

## What the applications and destinations lists report

* **Applications.** Name and category as the source reports them (untrusted text); bytes, packets and share (of all bytes in
  the window, including unlabelled traffic); `endpoints` = distinct source addresses seen using the application (not people,
  not inventory devices); `users` = `null` (counting people needs per-flow identity attribution, unbounded; deferred);
  `trend` against the immediately preceding window of equal length (windows over 7 days have none; `flat` is within 10%;
  `unknown` when the earlier window carried no traffic at all, so absence of history is never read as "new").
* **Destinations.** Address, domain, ASN and country as reported; `first_seen` is the earliest time seen inside a stated
  31-day look-back (`first_seen_since`), not the destination's history; `last_seen`, volume, `endpoints`, `users` = `null`.
* Volume is the sum of the stored `Bytes` counter. Akvorado's own UI multiplies by `SamplingRate`; this surface does not,
  because an extrapolation is an estimate.

## Small cohorts and internal destinations (the aggregate tier)

An aggregate that is really about one machine is that machine's traffic. The aggregate tier (`traffic:read` without
`traffic:read-detail`: Management) is therefore held to a **minimum cohort** `k` of distinct source addresses,
`NETSIGHT_TRAFFIC_MIN_COHORT` (default **5**, whole number 2 to 1000; an invalid value falls back to 5, never to a weaker rule,
and is logged once). The detail tier is not subject to the rule. Every Explorer, Applications, Destinations and Anomalies response
carries `cohort: {state, minimum}`:

| `cohort.state` | Meaning |
| --- | --- |
| `not-applied` | the caller holds the detail tier, or nothing was read (`not-connected`, `unknown`) |
| `sufficient` | the aggregate tier, and every figure shown rests on at least `minimum` source addresses |
| `too-few-sources` | the aggregate tier, and something was **withheld** because fewer than `minimum` source addresses stood behind it |

* **Explorer.** If the filtered window covers fewer than `k` source addresses (`volume.source_addresses`), the aggregations are
  withheld **whole**: volume, timeline, application mix and destinations (`aggregations: null`). They are not thinned: the byte
  count of a one-host answer *is* that host's usage, and two overlapping filters could otherwise be subtracted to isolate it.
  This is why a filter that narrows to a place (`source_ip`, `destination_ip`, **`device`, `vlan`**) needs the detail tier too.
* **Applications and Destinations.** An `endpoints` count below `k` is `null` (withheld) and the response is `too-few-sources`.
* **Anomalies.** A first-seen ASN or destination that fewer than `k` sources reached is not listed (one with no count is not
  listed either: fail closed). The anomaly series are organisation-wide totals and the ten largest applications; they carry no
  per-endpoint figure.
* **Internal destinations.** A destination inside the organisation (private, loopback, link-local, shared/CGNAT, multicast) is
  not listed to the aggregate tier in `/destinations` or in the Explorer's top destinations; the detail tier sees it labelled
  `scope: "internal"`. The aggregate list can therefore hold fewer than `limit` rows; `total_bytes` is still the source's total
  and shares are still shares of it, nothing is recomputed from what is shown.

What this does not do: a caller who holds two answers that are each above the minimum can still difference them (a wide filter
with 6 sources against a narrower one with 5 isolates one source). The controls for that residual are the per-identity rate
limit, the one-heavy-read-at-a-time rule, and the audit trail. A query-set-overlap control is a deferral.
