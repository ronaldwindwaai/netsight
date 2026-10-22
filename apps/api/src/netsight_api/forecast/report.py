"""The capacity report: the forecast response as a CSV a person can open (Step 13).

REPORTING.md names a *capacity* report type. Like the WAN SLA export it is synchronous and bounded (at
most 3 series x (120 measured + 30 forecast days) rows), built from the same response the page shows,
so the two cannot disagree. There is no scheduler, snapshot archive or delivery yet (see
FORECASTING.md).

One row per series day. ``kind`` says what the row is: ``measured`` (a source-reported value),
``forecast`` (a projection, with ``lower`` and ``upper``), ``state`` (a series with nothing to show
and the reason why) or the final ``notice`` row. A forecast is never left unlabelled. The header is
fixed, lines end CRLF, quoting is the csv module's, and any text cell a spreadsheet could read as a
formula starts with an apostrophe.
"""

from __future__ import annotations

import csv
import io
from typing import Final

from netsight_api.schemas_forecast import ForecastResponse, ForecastSeries

CSV_COLUMNS: Final = (
    "series_id",
    "series_name",
    "unit",
    "kind",
    "day",
    "value",
    "lower",
    "upper",
    "state",
    "method",
    "note",
)
_FORMULA_STARTS: Final = ("=", "+", "-", "@", "\t", "\r", "\n")


def safe_cell(value: str) -> str:
    """Neutralise a cell a spreadsheet would execute as a formula (OWASP CSV injection)."""
    return "'" + value if value.startswith(_FORMULA_STARTS) else value


def _rows(series: ForecastSeries) -> list[tuple[str, ...]]:
    head = (series.id, safe_cell(series.name), series.unit)
    method = series.method.name if series.method else ""
    rows: list[tuple[str, ...]] = [
        (*head, "measured", p.day, str(p.value), "", "", series.state, "", "")
        for p in series.history
    ]
    rows += [
        (
            *head,
            "forecast",
            p.day,
            str(p.value),
            str(p.lower),
            str(p.upper),
            series.state,
            method,
            "",
        )
        for p in series.forecast
    ]
    if series.state != "ok":
        note = safe_cell(f"{series.reason}: {series.detail}")
        rows.append((*head, "state", "", "", "", "", series.state, "", note))
    return rows


def export_csv(response: ForecastResponse) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for series in response.series:
        writer.writerows(_rows(series))
    stamp = response.generated_at.isoformat().replace("+00:00", "Z")
    writer.writerow(
        (
            "",
            "",
            "",
            "notice",
            "",
            "",
            "",
            "",
            response.state,
            "",
            f"{response.notice} Generated {stamp}.",
        )
    )
    return out.getvalue()


def row_count(response: ForecastResponse) -> int:
    """The number of data rows ``export_csv`` writes (header and notice excluded)."""
    return sum(
        len(series.history) + len(series.forecast) + (1 if series.state != "ok" else 0)
        for series in response.series
    )
