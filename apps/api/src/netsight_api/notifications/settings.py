"""Notification settings: the webhook allow-list and the delivery bounds.

Environment (read once by ``NotificationSettings.from_env``; an invalid value raises so a bad
configuration fails start-up instead of silently widening what the platform may call):

* ``NETSIGHT_WEBHOOK_ALLOWED_HOSTS``: comma-separated exact host names, or ``*.example.com``.
  A wildcard matches exactly one label (``a.example.com``, not ``a.b.example.com``; write
  ``*.b.example.com`` for that) and is refused at start-up when its base is a public suffix
  such as ``co.uk`` or ``github.io`` (``is_public_suffix_like``: a small built-in list, no
  network). Empty or unset means no webhook target is allowed (deny by default).
  IP literals are never accepted: there is deliberately no switch that allows loopback,
  private or link-local targets.
* ``NETSIGHT_PUBLIC_BASE_URL`` (optional, https origin without credentials): when set, every
  notification link must sit under it (``models.link_is_under``).
* ``NETSIGHT_WEBHOOK_ALLOWED_PORTS`` (default ``443``), ``NETSIGHT_WEBHOOK_TIMEOUT_SECONDS``
  (1-30, default 5), ``NETSIGHT_WEBHOOK_MAX_RESPONSE_BYTES`` (1024-1048576, default 65536),
  ``NETSIGHT_NOTIFY_MAX_ATTEMPTS`` (1-5, default 3), ``NETSIGHT_NOTIFY_QUEUE_LIMIT``
  (1-10000, default 1000).
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

_HOST_ENTRY: Final = re.compile(
    r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"
)
MAX_ALLOWED_HOSTS: Final = 256

# Shared hosting and registry suffixes: a wildcard on one of these would trust every tenant.
# Deliberately small and offline (no public-suffix-list download); extend it when needed.
_PUBLIC_SUFFIXES: Final = frozenset(
    {
        # country second-level registries
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
        "co.za", "org.za", "ac.za", "gov.za", "web.za", "co.na", "com.na", "org.na", "edu.na",
        "gov.na", "co.jp", "ne.jp", "or.jp", "ac.jp", "co.kr", "or.kr", "co.in", "net.in",
        "org.in", "co.il", "com.br", "com.cn", "com.mx", "com.ar", "com.sg", "com.hk", "com.tw",
        "com.tr", "com.ua", "co.ke", "co.zw", "co.zm", "co.bw", "co.ao", "com.ng",
        # hosting platforms where every customer owns a subdomain
        "github.io", "githubusercontent.com", "gitlab.io", "herokuapp.com", "appspot.com",
        "azurewebsites.net", "azurefd.net", "azureedge.net", "cloudapp.net", "windows.net",
        "cloudfront.net", "amazonaws.com", "s3.amazonaws.com", "elasticbeanstalk.com",
        "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "myshopify.com",
        "netlify.app", "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
        "onrender.com", "fly.dev", "run.app", "cloudfunctions.net", "ngrok.io",
        "ngrok-free.app", "trycloudflare.com", "repl.co", "glitch.me", "surge.sh", "now.sh",
    }
)  # fmt: skip
_REGISTRY_SECOND_LEVEL: Final = re.compile(
    r"^(co|com|org|net|gov|edu|ac|mil|ne|or|go|gob|nom|sch|ltd|plc)\.[a-z]{2}$"
)


def is_public_suffix_like(domain: str) -> bool:
    """True for a domain under which unrelated parties register names (``co.uk``, ``github.io``).

    A wildcard on such a base would let any tenant of the suffix receive notifications.
    """
    domain = domain.lower().strip(".")
    if domain in _PUBLIC_SUFFIXES or _REGISTRY_SECOND_LEVEL.fullmatch(domain):
        return True
    return domain.count(".") == 0  # a bare TLD


def _bounded_int(source: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = source.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


def _parse_hosts(raw: str) -> frozenset[str]:
    hosts: set[str] = set()
    for entry in (item.strip().lower() for item in raw.split(",")):
        if not entry:
            continue
        if _HOST_ENTRY.fullmatch(entry) is None:
            raise ValueError("NETSIGHT_WEBHOOK_ALLOWED_HOSTS holds an invalid host entry")
        if entry.startswith("*.") and entry.count(".") < 2:
            raise ValueError("a wildcard host entry needs at least two labels after '*.'")
        if entry.startswith("*.") and is_public_suffix_like(entry[2:]):
            raise ValueError("a wildcard host entry may not cover a public suffix")
        hosts.add(entry)
    if len(hosts) > MAX_ALLOWED_HOSTS:
        raise ValueError("NETSIGHT_WEBHOOK_ALLOWED_HOSTS has too many entries")
    return frozenset(hosts)


def _parse_base_url(raw: str) -> str | None:
    value = raw.strip()
    if not value:
        return None
    message = "NETSIGHT_PUBLIC_BASE_URL must be an https URL without credentials"
    try:
        parts = urlsplit(value)
        _ = parts.port  # an invalid port raises ValueError here
    except ValueError:
        raise ValueError(message) from None
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(message)
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(message)
    return value.rstrip("/")


def _parse_ports(raw: str) -> frozenset[int]:
    if not raw.strip():
        return frozenset({443})
    ports: set[int] = set()
    for item in raw.split(","):
        try:
            port = int(item.strip())
        except ValueError:
            raise ValueError("NETSIGHT_WEBHOOK_ALLOWED_PORTS must be integers") from None
        if not 1 <= port <= 65535:
            raise ValueError("NETSIGHT_WEBHOOK_ALLOWED_PORTS must be valid TCP ports")
        ports.add(port)
    return frozenset(ports)


@dataclass(frozen=True)
class NotificationSettings:
    webhook_allowed_hosts: frozenset[str] = frozenset()
    webhook_allowed_ports: frozenset[int] = frozenset({443})
    webhook_timeout_seconds: float = 5.0
    webhook_max_response_bytes: int = 65_536
    max_attempts: int = 3
    queue_limit: int = 1000
    public_base_url: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> NotificationSettings:
        source = os.environ if env is None else env
        return cls(
            webhook_allowed_hosts=_parse_hosts(source.get("NETSIGHT_WEBHOOK_ALLOWED_HOSTS", "")),
            webhook_allowed_ports=_parse_ports(source.get("NETSIGHT_WEBHOOK_ALLOWED_PORTS", "")),
            webhook_timeout_seconds=float(
                _bounded_int(source, "NETSIGHT_WEBHOOK_TIMEOUT_SECONDS", 5, 1, 30)
            ),
            webhook_max_response_bytes=_bounded_int(
                source, "NETSIGHT_WEBHOOK_MAX_RESPONSE_BYTES", 65_536, 1024, 1_048_576
            ),
            max_attempts=_bounded_int(source, "NETSIGHT_NOTIFY_MAX_ATTEMPTS", 3, 1, 5),
            queue_limit=_bounded_int(source, "NETSIGHT_NOTIFY_QUEUE_LIMIT", 1000, 1, 10_000),
            public_base_url=_parse_base_url(source.get("NETSIGHT_PUBLIC_BASE_URL", "")),
        )
