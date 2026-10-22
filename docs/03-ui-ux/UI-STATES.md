# Required UI States

Every data surface must define:
- loading;
- loaded;
- empty;
- filtered-empty;
- stale;
- partial;
- permission denied;
- source unavailable;
- error;
- maintenance.

"0 alerts" and "alert data unavailable" must never look identical.

## List views: URL state and export

- Search text, filters and sort on a list table live in the URL (`?q=`, one parameter per filter such
  as `status=` or `severity=`, and `sort=name` / `sort=-name`), so a filtered view can be shared and
  the back button undoes a filter or sort change. Typing replaces the history entry; choosing a
  filter or sort adds one. Unknown parameters and values are ignored.
- Filters on a paginated table apply to the loaded page only, and the table says so. "Clear filters"
  resets the URL parameters and restores every loaded row.
- "Export CSV" downloads exactly the rows in view (after filtering and sorting), built in the
  browser. Cells starting with `=`, `+`, `-` or `@` are prefixed with a quote so a spreadsheet does
  not run them. Rows the API withheld (small-cohort rule) export as empty cells.
- Timestamps in tables read relative ("3 min ago") with the exact UTC time in the tooltip and in
  `<time datetime>`; the server render shows the absolute time until the browser takes over.

## Paginated lists: page, page size and partial results

- `GET /api/v1/devices` and `GET /api/v1/alerts` paginate on the server (`page`, `page_size` up to
  100, and `total`) but have **no server-side search, filter or sort**. The Devices and Alerts
  screens therefore keep `page` and `page_size` (25, 50 or 100; default 50) in the URL, next to the
  `q`, filter and `sort` parameters, which are all preserved when paging.
- Above the table the screen says "Showing 51-100 of 230 devices" and, whenever the loaded rows are
  fewer than the total, "Search and filters only look at the N loaded on this page". A result such
  as "No devices match" on one page therefore never reads as "none exist". Gap, tracked: a search
  that must cover every page needs a server-side filter parameter in the API (not added here).
- Changing the page size returns to page 1. A page past the end says so and keeps the total.
- Alert rules and maintenance windows page with their own offset links; those links do not carry
  `page_size` (known gap, cosmetic: the source-alert page size resets to the default).

## Times and long text

- Every "created", "updated", "attempt" and "saved" time in the incident, action and configuration
  screens is relative with the exact UTC instant in the tooltip (`RelativeTime`). Detail timelines and
  audit-like records keep the absolute UTC time, because order and exact time are the point there.
- Operator-entered text (incident titles, assignee ids, comments) wraps (`text-break`) and keeps a
  minimum column width, so a phone shows a readable title and scrolls the table sideways rather than
  breaking it into single characters.
- A configuration backup that failed or never ran shows "Not assessed" for freshness (freshness is
  only judged for a successful backup) instead of "Freshness unknown". The version history names the
  device, marks the newest version and states that contents and differences are not shown (the API
  returns only version identifiers and save times; there is no diff endpoint).

## Demo data

`scripts/demo-local.py` serves fixture LibreNMS devices, Oxidized configuration backups (loopback
stub `apps/api/tests/e2e/stub_oxidized.py`) and seeded in-memory incidents (`tests/e2e/demo_app.py`
overrides only the incident-store dependency of the unmodified API). Action requests are enabled
with the volatile store; none are pre-seeded. There is no audit screen in the web app yet.

## Known dev-only warning

In `next dev`, React logs "tree hydrated but some attributes ... didn't match" for `role="table"`.
Cause: `@adminlte/react`'s `Accessibility` effect (mounted by `DashboardLayout`) adds `role="table"`
to every `<table>` already in the DOM, and the page content hydrates after the layout, so React sees
the attribute as server-only. It is harmless (production does not warn) and cannot be fixed in app
code without either an explicit `role="table"` on every table (the vendor `Table` widget accepts no
such prop) or a pnpm patch of the vendor package; neither was done here.
