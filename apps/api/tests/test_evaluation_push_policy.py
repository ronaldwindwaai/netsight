"""The push gateway must be reachable by policy, or start-up fails (a missing allow-list entry
used to drop every page silently at send time)."""

from __future__ import annotations

import pytest
from test_evaluation_wiring import ON, build

PUSH = {"NETSIGHT_PUSH_GATEWAY_URL": "https://push.example.com/v1/hook"}


@pytest.mark.parametrize(
    "extra",
    [
        {},  # no allow-list at all: every page would be refused at send time
        {"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "other.example.com"},  # gateway host not on it
        {
            "NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "push.example.com",
            "NETSIGHT_WEBHOOK_ALLOWED_PORTS": "8443",
        },  # the gateway's port (443) is not allowed
    ],
)
def test_a_push_gateway_the_policy_would_refuse_fails_start_up(extra: dict[str, str]) -> None:
    with pytest.raises(ValueError) as raised:
        build({**ON, **PUSH, **extra})
    assert "push" in str(raised.value).lower()
    assert "/v1/hook" not in str(raised.value)  # the URL is a secret and is never echoed


def test_a_push_gateway_on_the_allow_list_builds() -> None:
    service = build({**ON, **PUSH, "NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "*.example.com"})
    assert service is not None and service.channels == ("push",)
