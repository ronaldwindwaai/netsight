"""End-to-end: the real API reads a WAN port from the (stub) LibreNMS over real HTTP.

The route tests use fakes for the sources. This scenario closes the gap: a real API process with a
declared WAN link, a real LibreNMS adapter talking to the loopback stub, a signed-in operator and a
real session cookie. There is no database in this harness, so the probe-sample store is absent and
quality, availability and the SLA must say ``not-connected`` rather than invent a number.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

from conftest import SignIn, http_request

from netsight_api.contracts import validate


def _lower(items: Any) -> dict[str, str]:
    return {key.lower(): value for key, value in items}


def _get_text(url: str, cookie: str) -> tuple[int, str, dict[str, str]]:
    request = urllib.request.Request(url, headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read().decode(), _lower(response.headers.items())
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(), _lower(error.headers.items())


def test_the_internet_surface_requires_a_session(e2e_api: dict[str, str]) -> None:
    for path in ("/api/v1/internet", "/api/v1/internet/sla", "/api/v1/internet/sla/export"):
        status, _, _ = http_request(f"{e2e_api['apiUrl']}{path}")
        assert status == 401, path


def test_a_declared_wan_port_is_read_from_librenms_and_labelled(
    e2e_api: dict[str, str], signed_in: SignIn
) -> None:
    status, body, _ = http_request(f"{e2e_api['apiUrl']}/api/v1/internet", cookie=signed_in.cookie)
    assert status == 200, body
    validate("internet_response", body)
    assert body["state"] == "ok"
    link = body["links"][0]
    assert (link["id"], link["role"]) == ("e2e-wan", "primary")
    assert link["configured"]["isp"] == "Example ISP"
    interface = link["interface"]
    assert interface["state"] == "ok" and interface["oper_status"] == "up"
    assert interface["capacity_bps"] == 1_000_000_000
    assert (interface["rx_bps"], interface["tx_bps"]) == (100_000_000, 20_000_000)
    assert interface["utilisation_pct"] == 10.0
    assert interface["public_ip"] == "8.8.4.4"
    assert interface["freshness"]["state"] == "fresh"
    assert interface["freshness"]["source"] == "librenms"
    # No sample store in this harness: nothing about quality or availability is invented.
    for block in ("quality", "availability"):
        assert link[block]["state"] == "not-connected", block
    assert link["quality"]["latency_ms"] is None and link["availability"]["uptime_pct"] is None
    assert link["status"] == "up"  # from the interface alone
    assert body["failover"] == {"state": "single-link", "basis": "inferred"}


def test_the_sla_and_the_export_say_not_connected_without_a_sample_store(
    e2e_api: dict[str, str], signed_in: SignIn
) -> None:
    api = e2e_api["apiUrl"]
    status, sla, _ = http_request(f"{api}/api/v1/internet/sla", cookie=signed_in.cookie)
    assert status == 200 and sla["state"] == "not-connected" and sla["links"] == []
    validate("internet_sla_response", sla)

    status, text, headers = _get_text(
        f"{api}/api/v1/internet/sla/export?format=json", signed_in.cookie
    )
    assert status == 200
    assert headers["content-disposition"].startswith('attachment; filename="netsight-wan-sla-')
    assert '"state": "not-connected"' in text

    status, csv_text, headers = _get_text(
        f"{api}/api/v1/internet/sla/export?format=csv", signed_in.cookie
    )
    assert status == 200
    assert headers["content-type"].startswith("text/csv")
    assert csv_text.strip().splitlines() == [
        "month,link_id,link_name,isp,kind,started_at,ended_at,duration_seconds,sample_count,sources"
    ]


def test_an_out_of_range_month_is_refused(e2e_api: dict[str, str], signed_in: SignIn) -> None:
    status, body, _ = http_request(
        f"{e2e_api['apiUrl']}/api/v1/internet/sla?month=2001-01", cookie=signed_in.cookie
    )
    assert status == 422
    error: dict[str, Any] = body["error"]
    assert error["code"] == "VALIDATION_ERROR"
