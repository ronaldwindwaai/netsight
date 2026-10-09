"""S6-3 security review hardening of the notification code (M1, M2, M3, L2, L3).

* M1: the address classifier is an explicit allow/deny table, not the standard library's
  ``is_global`` tables, so a Python upgrade cannot change which addresses are refused.
* M2: the OS name lookup has a hard timeout and a bounded number of in-flight lookups.
* M3: destinations are de-duplicated on a keyed identity, never on the display label.
* L2: wildcard allow-list entries match exactly one label and never a public suffix.
* L3: a payload link is https and, when a base URL is configured, under it.

Nothing here touches the real network (``no_network``); lookups are injected.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from net_guard import no_network  # noqa: F401  (pytest fixture)

from netsight_api.notifications.dispatcher import (
    InMemoryDeliveryRecorder,
    Notification,
    NotificationDispatcher,
)
from netsight_api.notifications.models import (
    EmailDestination,
    NotificationPayload,
    PushDestination,
    SendResult,
    WebhookDestination,
    link_is_under,
    unique_destinations,
)
from netsight_api.notifications.secret import Secret
from netsight_api.notifications.senders import FakeSender
from netsight_api.notifications.settings import NotificationSettings
from netsight_api.notifications.ssrf import (
    BoundedResolver,
    WebhookTargetError,
    is_blocked_address,
    parse_webhook_url,
    resolve_and_pin,
    system_resolver,
)

pytestmark = pytest.mark.usefixtures("no_network")

NOW = datetime(2026, 10, 8, 10, 0, tzinfo=UTC)

# --- M1: explicit classifier ---------------------------------------------------------------------

# Every row is (address, blocked). Both sides of each boundary are listed.
CLASSIFIER_TABLE: list[tuple[str, bool]] = [
    # --- IPv4 deny ranges: first, last and one outside each edge
    ("0.0.0.0", True),
    ("0.255.255.255", True),
    ("1.0.0.1", False),
    ("10.0.0.0", True),
    ("10.255.255.255", True),
    ("11.0.0.1", False),
    ("100.64.0.0", True),
    ("100.127.255.255", True),
    ("100.63.255.255", False),
    ("100.128.0.1", False),
    ("127.0.0.1", True),
    ("127.255.255.255", True),
    ("169.254.169.254", True),
    ("169.253.255.255", False),
    ("169.255.0.1", False),
    ("172.16.0.0", True),
    ("172.31.255.255", True),
    ("172.15.255.255", False),
    ("172.32.0.1", False),
    ("192.0.0.0", True),
    ("192.0.0.192", True),
    ("192.0.0.255", True),
    ("192.0.1.1", False),
    ("192.0.2.1", True),
    ("192.88.98.255", False),
    ("192.88.99.0", True),
    ("192.88.99.1", True),
    ("192.88.99.255", True),
    ("192.88.100.1", False),
    ("192.168.0.1", True),
    ("192.169.0.1", False),
    ("198.17.255.255", False),
    ("198.18.0.1", True),
    ("198.19.255.255", True),
    ("198.20.0.1", False),
    ("198.51.100.7", True),
    ("203.0.113.7", True),
    ("224.0.0.1", True),
    ("239.255.255.255", True),
    ("240.0.0.1", True),
    ("255.255.255.255", True),
    ("223.255.255.254", False),
    ("93.184.216.34", False),
    ("8.8.8.8", False),
    # --- IPv6: only 2000::/3 is accepted, minus the deny list
    ("2606:4700:4700::1111", False),
    ("2001:4860:4860::8888", False),
    ("2a00:1450:4001::1", False),
    ("2001:200::1", False),  # first address after 2001::/23
    ("2000::1", False),
    ("3fff:1000::1", False),  # just after the 3fff::/20 documentation range
    ("::", True),
    ("::1", True),
    ("1::1", True),  # outside 2000::/3
    ("5f00::1", True),  # outside 2000::/3 (SRv6 SIDs)
    ("4000::1", True),
    ("e000::1", True),
    ("fc00::1", True),
    ("fd00:ec2::254", True),
    ("fe80::1", True),
    ("fec0::1", True),  # deprecated site-local
    ("ff02::1", True),
    ("100::1", True),  # discard prefix
    ("::7f00:1", True),  # IPv4-compatible
    ("::ffff:127.0.0.1", True),
    ("::ffff:7f00:1", True),
    ("::ffff:8.8.8.8", True),  # embedded IPv4 forms are refused outright, even if public
    ("::ffff:0:7f00:1", True),  # SIIT (::ffff:0:0:0/96)
    ("::ffff:0:808:808", True),
    ("64:ff9b::7f00:1", True),  # NAT64
    ("64:ff9b::808:808", True),
    ("64:ff9b:1::7f00:1", True),  # local-use NAT64 (64:ff9b:1::/48)
    ("64:ff9b:1:ffff::1", True),
    ("2002::1", True),  # 6to4: every embedded-IPv4 form refused, public or not
    ("2002:7f00:1::1", True),
    ("2002:808:808::1", True),
    ("2001::1", True),  # Teredo
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2", True),
    ("2001:1::1", True),  # IETF protocol assignments 2001::/23
    ("2001:1ff:ffff::1", True),  # last of 2001::/23
    ("2001:db8::1", True),
    ("2001:db8:ffff::1", True),
    ("2001:db9::1", False),
    ("3fff::1", True),  # documentation 3fff::/20
    ("3fff:fff::1", True),
]

NOT_ADDRESSES = [
    "",
    " 8.8.8.8",
    "8.8.8.8 ",
    "8.8.8.8%eth0",
    "2606:4700:4700::1111%eth0",
    "localhost",
    "example.com",
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "127.1",
    "08.8.8.8",
    "8.8.8",
    "2606:4700:4700::1111/64",
]


@pytest.mark.parametrize(("address", "blocked"), CLASSIFIER_TABLE)
def test_the_explicit_table(address: str, blocked: bool) -> None:
    assert is_blocked_address(address) is blocked


@pytest.mark.parametrize("text", NOT_ADDRESSES)
def test_anything_that_is_not_a_canonical_address_is_blocked(text: str) -> None:
    assert is_blocked_address(text) is True


def test_the_classifier_does_not_depend_on_the_standard_library_range_tables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If a Python upgrade moved a range between is_global/is_private, results must not move."""

    def forbidden(self: object) -> bool:
        raise AssertionError("the classifier consulted a standard-library range table")

    for cls in (ipaddress.IPv4Address, ipaddress.IPv6Address):
        for name in (
            "is_global",
            "is_private",
            "is_reserved",
            "is_loopback",
            "is_link_local",
            "is_multicast",
            "is_unspecified",
            "is_site_local",
        ):
            if hasattr(cls, name):
                monkeypatch.setattr(cls, name, property(forbidden))
    for address, blocked in CLASSIFIER_TABLE:
        assert is_blocked_address(address) is blocked, address


def test_the_table_covers_every_edge_it_claims_to() -> None:
    """Guards the guard: each deny range has an address inside it in the table."""
    blocked = [ipaddress.ip_address(a) for a, b in CLASSIFIER_TABLE if b]
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "64:ff9b:1::/48",
        "::ffff:0:0:0/96",
        "fec0::/10",
    ):
        net = ipaddress.ip_network(network)
        assert any(a in net for a in blocked if a.version == net.version), network


def test_a_name_resolving_to_an_embedded_ipv4_form_is_refused() -> None:
    settings = NotificationSettings(webhook_allowed_hosts=frozenset({"hooks.example.com"}))
    target = parse_webhook_url("https://hooks.example.com/x", settings)
    for answer in ("::ffff:0:7f00:1", "64:ff9b:1::7f00:1", "2002:7f00:1::1", "fec0::1"):
        with pytest.raises(WebhookTargetError) as caught:
            resolve_and_pin(target, lambda _h, _p, answer=answer: [answer])
        assert caught.value.code == "ADDRESS_BLOCKED"


# --- M2: resolver timeout ---------------------------------------------------------------------------


@pytest.fixture
def release() -> Iterator[threading.Event]:
    """Lets a slow fake lookup finish at teardown so no thread outlives the test."""
    event = threading.Event()
    yield event
    event.set()


def test_a_slow_lookup_times_out_instead_of_hanging_the_caller(release: threading.Event) -> None:
    def slow(_host: str, _port: int) -> list[str]:
        release.wait(10)
        return ["93.184.216.34"]

    resolver = BoundedResolver(lookup=slow, timeout_seconds=0.2)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        resolver("hooks.example.com", 443)
    assert time.monotonic() - started < 2


def test_the_pin_step_maps_a_resolver_timeout_to_a_retryable_refusal(
    release: threading.Event,
) -> None:
    def slow(_host: str, _port: int) -> list[str]:
        release.wait(10)
        return []

    resolver = BoundedResolver(lookup=slow, timeout_seconds=0.1)
    settings = NotificationSettings(webhook_allowed_hosts=frozenset({"hooks.example.com"}))
    target = parse_webhook_url("https://hooks.example.com/x", settings)
    with pytest.raises(WebhookTargetError) as caught:
        resolve_and_pin(target, resolver)
    assert caught.value.code == "RESOLUTION_FAILED" and caught.value.retryable


def test_a_dead_resolver_cannot_pile_up_threads_or_queued_lookups(
    release: threading.Event,
) -> None:
    started = threading.Semaphore(0)

    def blocked(_host: str, _port: int) -> list[str]:
        started.release()
        release.wait(10)
        return []

    resolver = BoundedResolver(lookup=blocked, timeout_seconds=0.3, workers=1)
    with pytest.raises(TimeoutError):  # the single worker is now stuck in the dead lookup
        resolver("a.example.com", 443)
    assert started.acquire(timeout=1)
    began = time.monotonic()
    with pytest.raises(TimeoutError):  # refused at once: no free worker, nothing is queued
        resolver("a.example.com", 443)
    assert time.monotonic() - began < 0.15
    assert not started.acquire(blocking=False)  # the refused lookup was never started
    release.set()


def test_a_finished_lookup_frees_its_worker() -> None:
    resolver = BoundedResolver(
        lookup=lambda _h, _p: ["93.184.216.34"], timeout_seconds=1, workers=1
    )
    for _ in range(5):
        assert resolver("a.example.com", 443) == ["93.184.216.34"]


def test_lookup_errors_propagate_and_free_the_worker() -> None:
    def failing(_host: str, _port: int) -> list[str]:
        raise OSError("nxdomain")

    resolver = BoundedResolver(lookup=failing, timeout_seconds=1, workers=1)
    for _ in range(3):
        with pytest.raises(OSError):
            resolver("a.example.com", 443)


def test_the_default_resolver_is_bounded_and_uses_the_os_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    seen: list[tuple[Any, ...]] = []

    def fake_getaddrinfo(host: str, port: int, **kwargs: Any) -> list[Any]:
        seen.append((host, port, kwargs.get("type")))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert isinstance(system_resolver, BoundedResolver)
    assert system_resolver("hooks.example.com", 443) == ["93.184.216.34"]
    assert seen == [("hooks.example.com", 443, socket.SOCK_STREAM)]


def test_resolver_limits_are_validated() -> None:
    for kwargs in ({"timeout_seconds": 0}, {"workers": 0}, {"timeout_seconds": 31}):
        with pytest.raises(ValueError):
            BoundedResolver(lookup=lambda _h, _p: [], **kwargs)


# --- M3: identity, not label ----------------------------------------------------------------------


def hook(url: str, **headers: str) -> WebhookDestination:
    return WebhookDestination(Secret(url), tuple((k, Secret(v)) for k, v in headers.items()))


def test_two_webhooks_on_one_host_with_different_paths_stay_distinct() -> None:
    first, second = hook("https://hooks.example.com/a"), hook("https://hooks.example.com/b")
    assert first.label == second.label  # the display label is only the host
    assert unique_destinations([first, second]) == (first, second)


def test_the_same_webhook_twice_collapses_and_keeps_the_first() -> None:
    first, again = hook("https://hooks.example.com/a"), hook("https://hooks.example.com/a")
    assert unique_destinations([first, again]) == (first,)


def test_webhook_identity_includes_the_header_names_but_not_their_values() -> None:
    plain = hook("https://hooks.example.com/a")
    with_auth = hook("https://hooks.example.com/a", Authorization="x")
    other_value = hook("https://hooks.example.com/a", Authorization="y")
    assert unique_destinations([plain, with_auth]) == (plain, with_auth)
    assert unique_destinations([with_auth, other_value]) == (with_auth,)


def test_same_host_different_query_stays_distinct() -> None:
    first, second = hook("https://hooks.example.com/a?k=1"), hook("https://hooks.example.com/a?k=2")
    assert len(unique_destinations([first, second])) == 2


def test_email_and_push_identity() -> None:
    upper, lower = EmailDestination("Ops@Example.com"), EmailDestination("ops@example.com")
    assert unique_destinations([upper, lower]) == (upper,)
    one, two = PushDestination(Secret("device-1")), PushDestination(Secret("device-2"))
    assert unique_destinations([one, two, one]) == (one, two)
    assert len(unique_destinations([EmailDestination("a@example.com"), one])) == 2


def test_identity_keys_are_keyed_hashes_that_never_contain_the_value() -> None:
    destination = hook("https://hooks.example.com/services/s3cr3t")
    key = destination.identity_key
    assert "s3cr3t" not in key and "hooks.example.com" not in key
    assert len(key) == 64 and key == destination.identity_key
    assert key != hook("https://hooks.example.com/services/other").identity_key


def test_the_same_value_under_two_channels_is_not_one_destination() -> None:
    assert (
        EmailDestination("a@example.com").identity_key
        != PushDestination(Secret("a@example.com")).identity_key
    )


# --- L2: wildcard semantics -----------------------------------------------------------------------


def settings_for(*hosts: str) -> NotificationSettings:
    return NotificationSettings(webhook_allowed_hosts=frozenset(hosts))


def test_a_wildcard_matches_exactly_one_label() -> None:
    wild = settings_for("*.example.com")
    assert parse_webhook_url("https://a.example.com/x", wild).host == "a.example.com"
    for host in ("a.b.example.com", "a.b.c.example.com", "example.com", "evilexample.com"):
        with pytest.raises(WebhookTargetError) as caught:
            parse_webhook_url(f"https://{host}/x", wild)
        assert caught.value.code == "HOST_NOT_ALLOWED", host


def test_a_deeper_wildcard_is_written_out() -> None:
    wild = settings_for("*.eu.example.com")
    assert parse_webhook_url("https://a.eu.example.com/x", wild).host == "a.eu.example.com"
    with pytest.raises(WebhookTargetError):
        parse_webhook_url("https://a.b.eu.example.com/x", wild)


@pytest.mark.parametrize(
    "entry",
    [
        "*.co.uk",
        "*.org.uk",
        "*.ac.uk",
        "*.com.au",
        "*.co.za",
        "*.com.na",
        "*.co.jp",
        "*.github.io",
        "*.gitlab.io",
        "*.herokuapp.com",
        "*.azurewebsites.net",
        "*.cloudfront.net",
        "*.amazonaws.com",
        "*.s3.amazonaws.com",
        "*.pages.dev",
        "*.workers.dev",
        "*.vercel.app",
        "*.netlify.app",
        "*.blogspot.com",
        "*.appspot.com",
        "*.com",
        "*.uk",
    ],
)
def test_public_suffix_like_wildcards_are_rejected_at_start_up(entry: str) -> None:
    with pytest.raises(ValueError, match="wildcard|invalid host entry"):
        NotificationSettings.from_env({"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": entry})


@pytest.mark.parametrize("entry", ["*.co.uk", "*.github.io", "*.herokuapp.com"])
def test_public_suffix_like_wildcards_never_match_even_if_constructed_directly(entry: str) -> None:
    unsafe = settings_for(entry)
    host = entry[2:]
    with pytest.raises(WebhookTargetError):
        parse_webhook_url(f"https://attacker.{host}/x", unsafe)


def test_ordinary_wildcards_and_exact_public_suffix_children_are_accepted() -> None:
    parsed = NotificationSettings.from_env(
        {"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "*.example.com, *.corp.example.co.uk, hooks.github.io"}
    )
    assert parsed.webhook_allowed_hosts == frozenset(
        {"*.example.com", "*.corp.example.co.uk", "hooks.github.io"}
    )


# --- L3: payload links ----------------------------------------------------------------------------


def payload(**overrides: Any) -> NotificationPayload:
    fields: dict[str, Any] = {
        "notification_id": "n-1",
        "alert_ref": "a" * 32,
        "severity": "high",
        "title": "Large upload",
        "summary": "device-1 exceeded the threshold",
        "link": "https://netsight.example.com/alerts/aaaa",
        "occurred_at": NOW,
    }
    fields.update(overrides)
    return NotificationPayload(**fields)


@pytest.mark.parametrize(
    "link",
    [
        "http://netsight.example.com/alerts/a",
        "javascript:alert(1)",
        "data:text/html,<script>1</script>",
        "ftp://netsight.example.com/a",
        "//netsight.example.com/a",
        "/alerts/a",
        "https://",
        "https://user:pw@netsight.example.com/a",
        "",
        "not a url",
    ],
)
def test_a_payload_link_must_be_an_https_url_without_credentials(link: str) -> None:
    with pytest.raises(ValueError, match="link"):
        payload(link=link)


@pytest.mark.parametrize(
    ("link", "base", "expected"),
    [
        ("https://netsight.example.com/alerts/a", "https://netsight.example.com", True),
        ("https://netsight.example.com/alerts/a", "https://netsight.example.com/", True),
        ("https://NETSIGHT.example.com/alerts/a", "https://netsight.example.com", True),
        ("https://netsight.example.com:443/alerts/a", "https://netsight.example.com", True),
        ("https://netsight.example.com/app/alerts/a", "https://netsight.example.com/app", True),
        ("https://netsight.example.com/app", "https://netsight.example.com/app", True),
        ("https://netsight.example.com/application", "https://netsight.example.com/app", False),
        ("https://netsight.example.com/other", "https://netsight.example.com/app", False),
        ("https://evil.example.com/alerts/a", "https://netsight.example.com", False),
        ("https://netsight.example.com.evil.example/a", "https://netsight.example.com", False),
        ("https://netsight.example.com:8443/a", "https://netsight.example.com", False),
        ("https://netsight.example.com/../x", "https://netsight.example.com/app", False),
        ("https://netsight.example.com/app/../x", "https://netsight.example.com/app", False),
        ("https://netsight.example.com/app/%2e%2e/x", "https://netsight.example.com/app", False),
        ("http://netsight.example.com/a", "https://netsight.example.com", False),
        ("https://u@netsight.example.com/a", "https://netsight.example.com", False),
        ("https://netsight.example.com/a", "", True),  # no base configured: https is enough
        ("https://anywhere.example/a", None, True),
    ],
)
def test_a_link_must_sit_under_the_configured_base(
    link: str, base: str | None, expected: bool
) -> None:
    assert link_is_under(link, base) is expected


def test_the_base_url_comes_from_the_environment_and_must_be_https() -> None:
    parsed = NotificationSettings.from_env(
        {"NETSIGHT_PUBLIC_BASE_URL": "https://netsight.example.com/"}
    )
    assert parsed.public_base_url == "https://netsight.example.com"
    assert NotificationSettings.from_env({}).public_base_url is None
    for bad in (
        "http://netsight.example.com",
        "https://u:p@netsight.example.com",
        "netsight",
        "https://",
    ):
        with pytest.raises(ValueError, match="NETSIGHT_PUBLIC_BASE_URL"):
            NotificationSettings.from_env({"NETSIGHT_PUBLIC_BASE_URL": bad})


class Harness:
    def __init__(self, base: str | None, sender: FakeSender) -> None:
        self.recorder = InMemoryDeliveryRecorder()
        self.dispatcher = NotificationDispatcher(
            {"email": sender},
            self.recorder,
            clock=lambda: NOW,
            sleep=lambda _s: None,
            public_base_url=base,
        )


def test_a_link_outside_the_configured_base_is_not_sent_and_is_recorded() -> None:
    sender = FakeSender("email")
    harness = Harness("https://netsight.example.com", sender)
    email = EmailDestination("ops@example.com")
    outside = Notification("n-1", payload(link="https://phish.example/alerts/a"), email)
    outcome = harness.dispatcher.deliver(outside)
    assert (outcome.status, outcome.code, outcome.attempts) == ("failed", "LINK_REJECTED", 0)
    assert sender.calls == []
    (attempt,) = harness.recorder.attempts
    assert (attempt.status, attempt.code) == ("failed", "LINK_REJECTED")
    inside = Notification("n-2", payload(notification_id="n-2"), email)
    assert harness.dispatcher.deliver(inside).status == "sent"
    assert len(sender.calls) == 1


def test_without_a_base_any_https_link_is_delivered() -> None:
    sender = FakeSender("email")
    harness = Harness(None, sender)
    email = EmailDestination("ops@example.com")
    note = Notification("n-1", payload(link="https://elsewhere.example/a"), email)
    assert harness.dispatcher.deliver(note).status == "sent"


def test_queued_notifications_are_checked_when_drained() -> None:
    sender = FakeSender("email")
    harness = Harness("https://netsight.example.com", sender)
    email = EmailDestination("ops@example.com")
    harness.dispatcher.submit(Notification("n-1", payload(link="https://phish.example/a"), email))
    (outcome,) = harness.dispatcher.drain()
    assert outcome.code == "LINK_REJECTED" and sender.calls == []


def test_send_results_stay_static_codes() -> None:
    assert SendResult("permanent", "LINK_REJECTED").code == "LINK_REJECTED"
