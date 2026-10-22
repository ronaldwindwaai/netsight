"""Secret redaction of device configuration text (Step 9). A secret must never reach a response."""

from __future__ import annotations

import random
import string

import pytest

from netsight_api.configuration.redact import REDACTED, redact_lines

# Assembled at runtime so no PEM header literal sits in source (the secret scanner would flag it).
DASHES = "-" * 5
BEGIN_RSA = DASHES + "BEGIN RSA PRIVATE " + "KEY" + DASHES
END_RSA = DASHES + "END RSA PRIVATE " + "KEY" + DASHES
BEGIN_PLAIN = DASHES + "BEGIN PRIVATE " + "KEY" + DASHES

CASES = [
    ("enable secret 5 $1$abcd$xyz", "enable secret " + REDACTED),
    ("snmp-server community public RO", "snmp-server community " + REDACTED),
    (
        "username admin privilege 15 password 7 0822455D0A16",
        "username admin privilege 15 password " + REDACTED,
    ),
    ("crypto isakmp key MySecret address 1.2.3.4", "crypto isakmp key " + REDACTED),
    ("set password ENC abcdef", "set password " + REDACTED),
    ('encrypted-password "$9$abc";', "encrypted-password " + REDACTED),
    ("Enable Password cisco", "Enable Password " + REDACTED),
    ("ip ospf authentication-key SECRET1", "ip ospf authentication-key " + REDACTED),
    ("ip ospf message-digest-key 1 md5 SECRET1", "ip ospf message-digest-key " + REDACTED),
    ("snmp-server host 10.0.0.9 version 2c TRAPSTR", "snmp-server host " + REDACTED),
    ("snmp-server user bob grp v3 auth sha AAA priv aes 128 BBB", "snmp-server user " + REDACTED),
    ("wpa-psk ascii 0 hunter2hunter2", "wpa-psk " + REDACTED),
    ("set password=hunter2 mode=x", "set password=" + REDACTED),
    ("secret=abc123", "secret=" + REDACTED),
    ("pre-shared-key=abcdef trailing", "pre-shared-key=" + REDACTED),
    ("key: value", "key: " + REDACTED),
    ("password:hunter2", "password:" + REDACTED),
    ('"password": "hunter2",', '"password": ' + REDACTED),
    ("SECRET=Abc", "SECRET=" + REDACTED),
    ("secret_key = abc", "secret_key " + REDACTED),
    ("private_key: abc", "private_key: " + REDACTED),
    ('"api_key": "AKIA123"', '"api_key": ' + REDACTED),
    ("set apikey=zzz", "set apikey=" + REDACTED),
    ("authkey abc", "authkey " + REDACTED),
    ("shared_secret abc", "shared_secret " + REDACTED),
    ("community-string foo", "community-string " + REDACTED),
    ("pw hunter2", "pw " + REDACTED),
    ("pwd: abc", "pwd: " + REDACTED),
    ("pass abc", "pass " + REDACTED),
    ("bind-pw: abc", "bind-pw: " + REDACTED),
    ("passwordhash: abc", "passwordhash: " + REDACTED),
    ("authentication text hunter2", "authentication text " + REDACTED),
    ("Authorization: Bearer abc.def", "Authorization: " + REDACTED),
    ("hash: abc", "hash: " + REDACTED),
]


@pytest.mark.parametrize(("raw", "expected"), CASES)
def test_a_secret_bearing_line_loses_everything_after_the_keyword(raw: str, expected: str) -> None:
    assert redact_lines([raw]).lines == [expected]


@pytest.mark.parametrize(
    "line", ["interface GigabitEthernet0/1", "hostname core-1", " switchport mode access", "!", ""]
)
def test_ordinary_lines_are_untouched(line: str) -> None:
    result = redact_lines([line])
    assert result.lines == [line] and result.redacted == 0


def test_a_keyword_with_nothing_after_it_is_left_alone() -> None:
    assert redact_lines(["no snmp-server community"]).lines == ["no snmp-server community"]


def test_a_pem_block_is_redacted_including_every_inner_line() -> None:
    raw = [
        "crypto pki certificate",
        BEGIN_RSA,
        "MIIEowIBAAKCAQEAxxxxxxxx",
        "yyyyyyyyyyyyyyyyyyyyyyyy",
        END_RSA,
        "hostname after",
    ]
    result = redact_lines(raw)
    assert result.lines == [
        "crypto pki certificate",
        BEGIN_RSA,
        REDACTED,
        REDACTED,
        END_RSA,
        "hostname after",
    ]
    assert result.redacted == 2


def test_an_unterminated_pem_block_redacts_to_the_end() -> None:
    result = redact_lines([BEGIN_PLAIN, "secretdata", "more"])
    assert result.lines[1:] == [REDACTED, REDACTED]


def test_redaction_is_idempotent_and_counts_lines() -> None:
    first = redact_lines([c[0] for c in CASES])
    assert first.redacted == len(CASES)
    assert redact_lines(first.lines).lines == first.lines


def test_a_random_secret_never_survives_any_keyword() -> None:
    rng = random.Random(7)
    alphabet = string.ascii_letters + string.digits + "$./+="
    for keyword in ("password", "secret", "community", "token", "key", "psk", "passphrase"):
        for _ in range(25):
            secret = "".join(rng.choice(alphabet) for _ in range(rng.randint(6, 30)))
            line = f"some prefix {keyword} {secret} trailing"
            assert secret not in redact_lines([line]).lines[0]


@pytest.mark.parametrize(
    "line", ["ip ospf passive-interface default", "interface Vlan10", "description passport office"]
)
def test_look_alike_words_are_not_secrets(line: str) -> None:
    assert redact_lines([line]).lines == [line]


def test_a_value_on_the_line_after_a_dangling_separator_is_redacted() -> None:
    result = redact_lines(["password:", "  hunter2", "hostname after"])
    assert result.lines == ["password:", REDACTED, "hostname after"]
    assert redact_lines(["secret =", "", "abc123"]).lines == ["secret [REDACTED]", "", REDACTED]


MARKUP_CASES = [
    ("<password>hunter2</password>", "<password>" + REDACTED + "</password>"),
    ("<snmp-community>x</snmp-community>", "<snmp-community>" + REDACTED + "</snmp-community>"),
    (
        '  <apiKey type="x">abc123</apiKey> <name>sw1</name>',
        '  <apiKey type="x">' + REDACTED + "</apiKey> <name>sw1</name>",
    ),
    ("<secret>unterminated value", "<secret>" + REDACTED),
    ('{"secret":"x"}', '{"secret":' + REDACTED),
    ('"apiKey": "x"', '"apiKey": ' + REDACTED),
    ('{"password": "x", "name": "sw1"}', '{"password": ' + REDACTED),
    ("privateKey: abc", "privateKey: " + REDACTED),
    ("sharedSecret=abc", "sharedSecret=" + REDACTED),
    ("authToken: abc", "authToken: " + REDACTED),
]


@pytest.mark.parametrize(("raw", "expected"), MARKUP_CASES)
def test_markup_json_and_camel_case_secrets_are_redacted(raw: str, expected: str) -> None:
    assert redact_lines([raw]).lines == [expected]
    assert redact_lines([expected]).lines == [expected]  # idempotent


@pytest.mark.parametrize(
    "line",
    [
        "<description>passport office</description>",
        "<hostname>core-1</hostname>",
        '{"name": "sw1", "site": "HQ"}',
        "keepAlive: 10",
        "compassRose: north",
        "<name>sw1</name>",
    ],
)
def test_markup_look_alikes_are_untouched(line: str) -> None:
    assert redact_lines([line]).lines == [line]


def test_a_tag_value_on_the_next_line_is_redacted() -> None:
    result = redact_lines(["<password>", "  hunter2", "</password>"])
    assert result.lines == ["<password>", REDACTED, "</password>"]


def test_pathological_markup_stays_fast() -> None:
    import time

    started = time.perf_counter()
    redact_lines(["<" + "a" * 5000 + " " * 5000, "<a>" + "<" * 5000, "{" + '"' * 5000])
    assert time.perf_counter() - started < 1.0
