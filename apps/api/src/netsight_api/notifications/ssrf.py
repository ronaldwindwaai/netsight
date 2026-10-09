"""Webhook target validation (SSRF defence), in layers.

1. ``parse_webhook_url``: syntax and policy. https only, no userinfo, no backslashes or control
   characters, no IP literal or numeric host spelling (decimal, hex, octal, short forms), a
   port from the settings (default 443) and a host on the settings allow-list. Deny by default.
2. ``resolve_and_pin``: resolve the name once (a single lookup, bounded by a hard timeout)
   through an injected resolver and require *every* answer to pass an explicit allow/deny table
   (``is_blocked_address``): IPv4 outside the listed special-purpose networks, IPv6 only inside
   2000::/3 and outside the listed networks. Loopback, private, link-local (including cloud
   metadata 169.254.169.254 and fd00:ec2::254), CGNAT, documentation, benchmarking, multicast
   and reserved space are refused, and every IPv6 form that embeds an IPv4 address (mapped,
   SIIT, NAT64, 6to4) is refused outright. An answer that is not a canonical address is refused
   rather than guessed at. The first answer is pinned and the caller connects to it, never
   re-resolving, so a rebinding DNS server never gets a second question to answer differently.
   Only the answers of that one lookup are judged: the pinned address is the one that was
   checked.

Failures raise :class:`WebhookTargetError` carrying a static code. The URL is never in the
message: webhook URLs routinely embed a secret token.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from netsight_api.notifications.settings import NotificationSettings, is_public_suffix_like

MAX_URL_LENGTH: Final = 2048
MAX_RESOLVED_ADDRESSES: Final = 16
_FORBIDDEN_URL_CHARS: Final = re.compile(r"[\x00-\x20\x7f\\]")
_NUMERIC_LABEL: Final = re.compile(r"^(0x[0-9a-f]+|[0-9]+)$")

Resolver = Callable[[str, int], Sequence[str]]


class WebhookTargetError(ValueError):
    """The webhook target is refused. ``str(error)`` is the static ``code`` only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    @property
    def retryable(self) -> bool:
        """Only a resolution failure can be transient; every policy refusal is final."""
        return self.code == "RESOLUTION_FAILED"


@dataclass(frozen=True, repr=False)
class WebhookTarget:
    host: str
    port: int
    path_and_query: str

    def __repr__(self) -> str:
        return f"WebhookTarget(host={self.host!r}, port={self.port})"  # never the path or query


@dataclass(frozen=True)
class PinnedAddress:
    host: str
    port: int
    ip: str


def _wildcard_matches(entry: str, host: str) -> bool:
    """``*.base`` matches exactly one label in front of ``base`` and never a public suffix."""
    if not entry.startswith("*."):
        return False
    base = entry[2:]
    if is_public_suffix_like(base) or not host.endswith("." + base):
        return False
    label = host[: -len(base) - 1]
    return bool(label) and "." not in label


def _host_allowed(host: str, settings: NotificationSettings) -> bool:
    if host in settings.webhook_allowed_hosts:
        return True
    return any(_wildcard_matches(entry, host) for entry in settings.webhook_allowed_hosts)


def _extract(url: str) -> tuple[str, int | None, str]:
    """(host, explicit port, path+query) or raise; scheme and userinfo are judged here."""
    if not url or len(url) > MAX_URL_LENGTH or _FORBIDDEN_URL_CHARS.search(url):
        raise WebhookTargetError("URL_INVALID")
    try:
        parts = urlsplit(url)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise WebhookTargetError("URL_INVALID") from None
    if parts.scheme.lower() != "https":
        raise WebhookTargetError("SCHEME_NOT_HTTPS")
    if "@" in parts.netloc:
        raise WebhookTargetError("USERINFO_PRESENT")
    if not host:
        raise WebhookTargetError("URL_INVALID")
    path = parts.path or "/"
    return host, port, path + (f"?{parts.query}" if parts.query else "")


def _normalise_host(host: str) -> str:
    host = host.rstrip(".").lower()
    if not host:
        raise WebhookTargetError("URL_INVALID")
    labels = host.split(".")
    if ":" in host or all(_NUMERIC_LABEL.fullmatch(label) for label in labels):
        raise WebhookTargetError("HOST_IS_IP_LITERAL")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        raise WebhookTargetError("URL_INVALID") from None


def parse_webhook_url(url: str, settings: NotificationSettings) -> WebhookTarget:
    """Layer 1: URL syntax, port policy and the allow-list."""
    raw_host, explicit_port, path_and_query = _extract(url)
    host = _normalise_host(raw_host)
    if not _host_allowed(host, settings):
        raise WebhookTargetError("HOST_NOT_ALLOWED")
    port = 443 if explicit_port is None else explicit_port
    if port not in settings.webhook_allowed_ports:
        raise WebhookTargetError("PORT_NOT_ALLOWED")
    return WebhookTarget(host=host, port=port, path_and_query=path_and_query)


# --- address classification -----------------------------------------------------------------
#
# An explicit allow/deny table. Nothing here asks the standard library whether an address is
# "global" or "private": those tables change between Python releases, and a webhook target
# check must not change meaning on an interpreter upgrade (tests/test_notifications_hardening.py
# pins every boundary and fails if the answer for any listed address moves).
#
# IPv4: everything is allowed except the networks below.
# IPv6: only global unicast 2000::/3 is allowed, minus the networks below. That already refuses
# ::/128, ::1, ::/96 (IPv4-compatible), ::ffff:0:0/96 (IPv4-mapped), 64:ff9b::/96 (NAT64),
# 100::/64, fc00::/7, fe80::/10, fec0::/10 and ff00::/8 because none lies in 2000::/3.
# Forms that embed an IPv4 address are refused outright rather than unwrapped and re-judged: a
# public-looking embedded address could still be a translation gateway into a private network.

_DENIED_V4: Final = tuple(
    ipaddress.IPv4Network(network)
    for network in (
        "0.0.0.0/8",  # "this" network
        "10.0.0.0/8",  # RFC 1918
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, including cloud metadata 169.254.169.254
        "172.16.0.0/12",  # RFC 1918
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "192.168.0.0/16",  # RFC 1918
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation
        "203.0.113.0/24",  # documentation
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, including the limited broadcast 255.255.255.255
    )
)
_GLOBAL_UNICAST_V6: Final = ipaddress.IPv6Network("2000::/3")
_DENIED_V6: Final = tuple(
    ipaddress.IPv6Network(network)
    for network in (
        "2001::/23",  # IETF protocol assignments (includes Teredo 2001::/32, ORCHID, ...)
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4: embeds an IPv4 address
        "3fff::/20",  # documentation (RFC 9637)
        # Not inside 2000::/3, so already refused; listed so the intent survives a change of
        # the allow rule above.
        "::ffff:0:0:0/96",  # SIIT-translated IPv4
        "64:ff9b:1::/48",  # local-use NAT64
        "fec0::/10",  # deprecated site-local
    )
)


def _blocked_v4(address: ipaddress.IPv4Address) -> bool:
    return any(address in network for network in _DENIED_V4)


def _blocked_v6(address: ipaddress.IPv6Address) -> bool:
    if address not in _GLOBAL_UNICAST_V6:
        return True
    return any(address in network for network in _DENIED_V6)


def is_blocked_address(text: str) -> bool:
    """True unless ``text`` is a canonical IP address outside every denied range."""
    if text != text.strip() or "%" in text:
        return True  # padding and zone ids are not canonical addresses
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True  # decimal / hex / octal spellings, hostnames, junk: fail closed
    if isinstance(address, ipaddress.IPv4Address):
        return _blocked_v4(address)
    return _blocked_v6(address)


# --- name resolution --------------------------------------------------------------------------

RESOLVE_TIMEOUT_SECONDS: Final = 5.0
MAX_RESOLVE_TIMEOUT_SECONDS: Final = 30.0
RESOLVER_WORKERS: Final = 4

Lookup = Callable[[str, int], Sequence[str]]


def _os_lookup(host: str, port: int) -> list[str]:
    """TCP answers from the OS resolver; ``socket.getaddrinfo`` is read at call time."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


class BoundedResolver:
    """A resolver with a hard timeout and a hard cap on threads stuck in lookups.

    ``socket.getaddrinfo`` cannot be interrupted and has no timeout of its own, so the call runs
    in a small worker pool and the caller waits at most ``timeout_seconds``. A lookup that
    outlives its caller keeps its worker until the OS gives up; when every worker is stuck the
    next call fails at once with ``TimeoutError`` (nothing is queued and no thread is added), so
    a dead resolver costs at most ``workers`` threads and never stalls the dispatcher for more
    than the timeout. ``TimeoutError`` and ``OSError`` are mapped to ``RESOLUTION_FAILED`` by
    :func:`resolve_and_pin`.
    """

    def __init__(
        self,
        lookup: Lookup = _os_lookup,
        *,
        timeout_seconds: float = RESOLVE_TIMEOUT_SECONDS,
        workers: int = RESOLVER_WORKERS,
    ) -> None:
        if not 0 < timeout_seconds <= MAX_RESOLVE_TIMEOUT_SECONDS:
            raise ValueError("timeout_seconds must be in (0, 30]")
        if not 1 <= workers <= 32:
            raise ValueError("workers must be between 1 and 32")
        self._lookup = lookup
        self._timeout = timeout_seconds
        self._workers = workers
        self._lock = threading.Lock()
        self._busy = 0
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ns-resolve")

    def _run(self, host: str, port: int) -> list[str]:
        try:
            return list(self._lookup(host, port))
        finally:
            with self._lock:
                self._busy -= 1

    def __call__(self, host: str, port: int) -> list[str]:
        with self._lock:
            if self._busy >= self._workers:
                raise TimeoutError("every resolver worker is busy")
            self._busy += 1
        try:
            future = self._pool.submit(self._run, host, port)
        except BaseException:
            with self._lock:
                self._busy -= 1
            raise
        try:
            return future.result(timeout=self._timeout)
        except FutureTimeout:
            if future.cancel():  # never started: give its place back; a running one finishes alone
                with self._lock:
                    self._busy -= 1
            raise TimeoutError("name resolution timed out") from None


system_resolver: Final = BoundedResolver()


def resolve_and_pin(target: WebhookTarget, resolver: Resolver) -> PinnedAddress:
    """Layer 2: resolve once, require every answer to be public, pin the first."""
    try:
        answers = list(resolver(target.host, target.port))
    except Exception:  # noqa: BLE001 - any resolver failure fails closed; detail is not exposed
        raise WebhookTargetError("RESOLUTION_FAILED") from None
    if not answers or len(answers) > MAX_RESOLVED_ADDRESSES:
        raise WebhookTargetError("RESOLUTION_FAILED")
    if any(is_blocked_address(answer) for answer in answers):
        raise WebhookTargetError("ADDRESS_BLOCKED")
    return PinnedAddress(host=target.host, port=target.port, ip=answers[0])
