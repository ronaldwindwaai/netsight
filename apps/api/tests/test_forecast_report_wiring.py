"""The capacity report's CSV safety and the operator limit setting (Step 13)."""

from __future__ import annotations

import csv
import io

import pytest
from forecast_support import GB, NOW, FakeSource, growing, totals

from netsight_api.forecast import report, service, wiring


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx", "\nx"])
def test_a_cell_a_spreadsheet_could_execute_is_neutralised(value: str) -> None:
    assert report.safe_cell(value) == "'" + value


def test_ordinary_text_is_left_alone() -> None:
    assert report.safe_cell("Network traffic volume") == "Network traffic volume"


@pytest.mark.asyncio
async def test_the_csv_has_a_fixed_header_crlf_lines_and_a_closing_notice() -> None:
    response = await service.build_capacity_forecast(
        source=FakeSource(totals(growing(30))),
        now=NOW,
        horizon_days=7,
        history_days=30,
        traffic_limit=None,
    )
    text = report.export_csv(response)
    assert text.endswith("\r\n") and "\n" not in text.replace("\r\n", "")
    rows = list(csv.reader(io.StringIO(text)))
    assert tuple(rows[0]) == report.CSV_COLUMNS
    assert rows[-1][3] == "notice" and "Generated 2026-10-18T06:00:00Z" in rows[-1][-1]
    assert report.row_count(response) == len(rows) - 2  # header and notice are not data rows


def test_no_limit_is_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(wiring.LIMIT_ENV, raising=False)
    assert wiring.traffic_daily_limit() is None


def test_a_plain_positive_number_is_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(wiring.LIMIT_ENV, f" {500 * GB} ")
    assert wiring.traffic_daily_limit() == 500 * GB


@pytest.mark.parametrize("raw", ["0", "-5", "1.5", "5GB", "1e9", "abc", "9" * 17, "٣"])
def test_anything_else_is_no_limit_and_is_logged_without_the_value(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, raw: str
) -> None:
    wiring.reset_for_tests()
    monkeypatch.setenv(wiring.LIMIT_ENV, raw)
    assert wiring.traffic_daily_limit() is None
    assert raw not in caplog.text and wiring.LIMIT_ENV in caplog.text


def test_a_cache_can_be_asked_whether_a_key_is_fresh_and_told_a_value() -> None:
    from netsight_api.traffic.cache import TtlCache

    now = [0.0]
    cache = TtlCache(ttl_seconds=10.0, clock=lambda: now[0])
    assert cache.peek("k") is False
    cache.put("k", True)
    assert cache.peek("k") is True
    now[0] = 11.0
    assert cache.peek("k") is False


def test_the_row_count_matches_the_rows_without_rebuilding_them() -> None:
    import asyncio

    response = asyncio.run(
        service.build_capacity_forecast(
            source=FakeSource(totals(growing(30))),
            now=NOW,
            horizon_days=7,
            history_days=30,
            traffic_limit=None,
        )
    )
    rows = list(csv.reader(io.StringIO(report.export_csv(response))))
    assert report.row_count(response) == len(rows) - 2


def test_an_amount_never_rounds_up_to_1000_of_a_smaller_unit() -> None:
    from netsight_api.forecast.recommend import amount

    assert amount(999_949, "bytes-per-day") == "999.9 kB/day"
    assert amount(999_950, "bytes-per-day") == "1.0 MB/day"
    assert amount(999_950_000, "bytes-per-day") == "1.0 GB/day"
    assert amount(999_950_000_000, "bytes-per-day") == "1.0 TB/day"
    assert amount(999, "bytes-per-day") == "999 B/day"
    assert amount(1_000, "bytes-per-day") == "1.0 kB/day"
