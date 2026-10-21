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
