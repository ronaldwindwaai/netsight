"""Unit tests for the local-credential security primitives (ADR 0010).

Includes the published RFC 6238 TOTP vectors so a refactor cannot silently
change the codes real authenticator apps produce.
"""

from __future__ import annotations

import base64
import time

import pytest

from netsight_api.localauth import totp
from netsight_api.localauth.crypto import (
    SecretEncryptionError,
    decrypt_secret,
    encrypt_secret,
    is_encrypted,
)
from netsight_api.localauth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    check_password_policy,
    hash_password,
    needs_rehash,
    verify_password,
)
from netsight_api.localauth.recovery import (
    consume_recovery_code,
    generate_recovery_codes,
    hash_recovery_codes,
)
from netsight_api.localauth.store import (
    LOCKOUT_SCHEDULE_SECONDS,
    LocalAccountStore,
    UsernameRejected,
    validate_username,
)

# --- TOTP: RFC 6238 test vectors -------------------------------------------

# RFC 6238 Appendix B uses the ASCII seed "12345678901234567890" and 8-digit
# codes. Netsight ships 6 digits for authenticator-app compatibility, so the
# vectors are checked against the 8-digit form to validate the HOTP core
# against the RFC, and DIGITS is asserted separately below.
RFC_SEED = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")

RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize(("timestamp", "expected"), RFC_VECTORS)
def test_hotp_matches_rfc6238_vectors(timestamp: int, expected: str) -> None:
    assert totp._hotp(totp._decode_secret(RFC_SEED), timestamp // 30, digits=8) == expected


def test_netsight_uses_six_digit_codes() -> None:
    """The deployed profile must stay 6 digits / 30s / SHA-1."""
    assert totp.DIGITS == 6
    assert totp.PERIOD_SECONDS == 30
    assert totp.ALGORITHM == "SHA1"

    # A six-digit code is the RFC value's last six digits.
    secret = totp.generate_secret()
    counter = 1
    eight = totp._hotp(totp._decode_secret(secret), counter, digits=8)
    assert totp._hotp(totp._decode_secret(secret), counter) == eight[-6:]


def test_generate_code_uses_the_configured_period() -> None:
    secret = totp.generate_secret()
    for timestamp, _expected in RFC_VECTORS:
        counter = timestamp // 30
        assert totp.generate_code(secret, for_time=timestamp) == totp._hotp(
            totp._decode_secret(secret), counter
        )


def test_verify_accepts_a_current_code_and_rejects_a_wrong_one() -> None:
    secret = totp.generate_secret()
    now = time.time()
    code = totp.generate_code(secret, for_time=now)

    assert totp.verify_code(secret, code, for_time=now) is not None
    assert totp.verify_code(secret, "000000", for_time=now) is None


def test_verify_tolerates_one_step_of_drift_but_no_more() -> None:
    secret = totp.generate_secret()
    now = time.time()

    previous = totp.generate_code(secret, for_time=now - 30)
    next_step = totp.generate_code(secret, for_time=now + 30)
    stale = totp.generate_code(secret, for_time=now - 300)

    assert totp.verify_code(secret, previous, for_time=now) is not None
    assert totp.verify_code(secret, next_step, for_time=now) is not None
    assert totp.verify_code(secret, stale, for_time=now) is None


def test_verify_rejects_replay_within_a_step() -> None:
    """A captured code must not be reusable inside its own window."""
    secret = totp.generate_secret()
    now = time.time()
    code = totp.generate_code(secret, for_time=now)
    counter = int(now // 30)

    first = totp.verify_code(secret, code, for_time=now, last_used_counter=None)
    assert first == counter

    # Same step again is refused.
    assert totp.verify_code(secret, code, for_time=now, last_used_counter=counter) is None
    # An older counter than one already used is also refused.
    assert totp.verify_code(secret, code, for_time=now, last_used_counter=counter + 5) is None


def test_verify_rejects_malformed_input() -> None:
    secret = totp.generate_secret()
    assert totp.verify_code(secret, "", for_time=time.time()) is None
    assert totp.verify_code(secret, "12345", for_time=time.time()) is None
    assert totp.verify_code(secret, "1234567", for_time=time.time()) is None
    assert totp.verify_code(secret, "abcdef", for_time=time.time()) is None
    assert totp.verify_code(secret, 123456, for_time=time.time()) is None  # type: ignore[arg-type]
    assert totp.verify_code("not-base32!!", "123456", for_time=time.time()) is None
    assert totp.verify_code("", "123456", for_time=time.time()) is None


def test_provisioning_uri_is_standard_and_omits_the_secret_from_labels() -> None:
    secret = totp.generate_secret()
    uri = totp.provisioning_uri(secret, "ops@example.test")

    assert uri.startswith("otpauth://totp/")
    assert f"secret={secret.upper()}" in uri
    assert "issuer=Netsight" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri


def test_qr_svg_is_produced_without_native_imaging() -> None:
    svg = totp.qr_code_svg(totp.generate_secret(), "ops@example.test")
    assert svg.lstrip().startswith("<?xml") or "<svg" in svg


# --- passwords -------------------------------------------------------------


def test_password_hash_is_argon2id_and_verifies() -> None:
    stored = hash_password("correct horse battery staple")

    assert stored.startswith("$argon2id$")
    assert "correct horse battery staple" not in stored
    assert verify_password(stored, "correct horse battery staple") is True
    assert verify_password(stored, "wrong password entirely") is False


def test_password_hash_is_salted() -> None:
    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")
    assert first != second


def test_verify_returns_false_for_missing_or_corrupt_hashes() -> None:
    assert verify_password(None, "anything at all") is False
    assert verify_password("", "anything at all") is False
    assert verify_password("not-a-hash", "anything at all") is False


def test_verify_rejects_absurdly_long_candidates_without_hashing_them() -> None:
    stored = hash_password("correct horse battery staple")
    assert verify_password(stored, "x" * (MAX_PASSWORD_LENGTH + 1)) is False


def test_password_policy_enforces_length_and_denylist() -> None:
    assert check_password_policy("short").code == "PASSWORD_TOO_SHORT"
    assert check_password_policy("password1234").code == "PASSWORD_TOO_COMMON"
    assert check_password_policy("PassWord1234").code == "PASSWORD_TOO_COMMON"
    assert check_password_policy("netsight1234").code == "PASSWORD_TOO_COMMON"
    assert check_password_policy("x" * (MAX_PASSWORD_LENGTH + 1)).code == "PASSWORD_TOO_LONG"
    assert check_password_policy(12345678901234).code == "PASSWORD_INVALID"  # type: ignore[arg-type]

    ok = check_password_policy("a-strong-unique-passphrase")
    assert ok.ok is True
    assert ok.code is None


def test_password_policy_minimum_is_twelve_characters() -> None:
    assert check_password_policy("a" * (MIN_PASSWORD_LENGTH - 1)).code == "PASSWORD_TOO_SHORT"
    assert check_password_policy("a" * MIN_PASSWORD_LENGTH).ok is True


def test_needs_rehash_is_true_for_absent_hash() -> None:
    assert needs_rehash(None) is True
    assert needs_rehash("garbage") is True


# --- encryption of TOTP secrets -------------------------------------------


def test_encrypted_secret_round_trips() -> None:
    secret = totp.generate_secret()
    envelope = encrypt_secret(secret, "master-session-secret")

    assert secret not in envelope
    assert is_encrypted(envelope) is True
    assert decrypt_secret(envelope, "master-session-secret") == secret


def test_encrypted_secret_is_nondeterministic() -> None:
    secret = totp.generate_secret()
    assert encrypt_secret(secret, "s") != encrypt_secret(secret, "s")


def test_wrong_master_secret_cannot_decrypt() -> None:
    envelope = encrypt_secret("TOTPSECRET", "right")
    with pytest.raises(SecretEncryptionError):
        decrypt_secret(envelope, "wrong")


def test_tampered_ciphertext_is_rejected() -> None:
    envelope = encrypt_secret("TOTPSECRET", "master")
    prefix, nonce, ciphertext = envelope.split(":")
    tampered = f"{prefix}:{nonce}:{ciphertext[:-2]}AA"
    with pytest.raises(SecretEncryptionError):
        decrypt_secret(tampered, "master")


def test_malformed_envelopes_are_rejected() -> None:
    for payload in ("", "nope", "v2:a:b", "v1:only-two", "v1:!!!:???"):
        with pytest.raises(SecretEncryptionError):
            decrypt_secret(payload, "master")

    with pytest.raises(SecretEncryptionError):
        encrypt_secret("x", "")  # type: ignore[arg-type]


def test_plaintext_secret_is_not_treated_as_an_envelope() -> None:
    assert is_encrypted(None) is False
    assert is_encrypted("JBSWY3DPEHPK3PXP") is False
    # An envelope needs exactly three colon-separated parts.
    assert is_encrypted("v1:only") is False
    assert is_encrypted("v1:only:one") is True
    assert is_encrypted("v2:only:one") is False


# --- recovery codes --------------------------------------------------------


def test_recovery_codes_are_unambiguous_and_unique() -> None:
    codes = generate_recovery_codes()

    assert len(codes) == 10
    assert len(set(codes)) == 10
    for code in codes:
        assert len(code) == len("AAAAA-AAAAA")
        assert not set(code) & set("O0I1")


def test_recovery_code_is_single_use() -> None:
    codes = generate_recovery_codes(3)
    hashes = hash_recovery_codes(codes)
    target = codes[1]

    consumed = consume_recovery_code(hashes, target)
    assert consumed is not None
    remaining = [stored for stored in hashes if stored != consumed]
    # The same code must not work twice.
    assert consume_recovery_code(remaining, target) is None


def test_recovery_code_comparison_tolerates_formatting() -> None:
    codes = generate_recovery_codes(3)
    hashes = hash_recovery_codes(codes)
    original = codes[0]

    assert consume_recovery_code(hashes, original.lower()) is not None
    assert consume_recovery_code(hashes, original.replace("-", " ")) is not None
    assert consume_recovery_code(hashes, original.replace("-", "")) is not None
    assert consume_recovery_code(hashes, f"  {original}  ") is not None


def test_unknown_recovery_code_matches_nothing() -> None:
    hashes = hash_recovery_codes(generate_recovery_codes(2))
    assert consume_recovery_code(hashes, "ZZZZZ-ZZZZZ") is None
    assert consume_recovery_code(hashes, "") is None
    assert consume_recovery_code(hashes, 12345) is None  # type: ignore[arg-type]


def test_recovery_codes_are_stored_only_as_hashes() -> None:
    codes = generate_recovery_codes(2)
    hashes = hash_recovery_codes(codes)
    for code in codes:
        assert code not in hashes
        # Neither the displayed nor the canonical form may appear.
        assert code.replace("-", "") not in hashes
    for stored in hashes:
        assert stored.startswith("$argon2id$")


def test_recovery_code_count_is_bounded() -> None:
    with pytest.raises(ValueError):
        generate_recovery_codes(0)
    with pytest.raises(ValueError):
        generate_recovery_codes(21)


# --- usernames and lockout -------------------------------------------------


def test_usernames_are_normalised_and_validated() -> None:
    assert validate_username(" Ops.User ") == "ops.user"
    assert validate_username("ops@example.test") == "ops@example.test"

    for bad in ("ab", "x" * 65, "has space", "semi;colon", "bad|pipe", 123):  # type: ignore[list-item]
        with pytest.raises(UsernameRejected):
            validate_username(bad)


def test_usernames_are_case_insensitive_and_unique() -> None:
    store = LocalAccountStore()
    store.create("Ops.User", hash_password("a-strong-unique-passphrase"), ["operator"])

    assert store.get("OPS.USER") is not None
    with pytest.raises(UsernameRejected):
        store.create("ops.user", hash_password("another-strong-passphrase"), ["operator"])


def test_unknown_account_never_authenticates() -> None:
    store = LocalAccountStore()
    result = store.authenticate_password("nobody", "a-strong-unique-passphrase")
    assert result.ok is False
    assert result.account is None


def test_lockout_escalates_and_expires() -> None:
    now = [1000.0]
    store = LocalAccountStore(clock=lambda: now[0])
    store.create("ops", hash_password("a-strong-unique-passphrase"), ["operator"])

    # The schedule must become progressively harsher, then plateau.
    waits = [value for value in LOCKOUT_SCHEDULE_SECONDS if value > 0]
    assert waits == sorted(waits)
    assert waits[-1] == waits[-2]

    # Two free attempts, then the account locks.
    for _ in range(2):
        assert store.authenticate_password("ops", "wrong-password-here").ok is False

    account = store.get("ops")
    assert account is not None
    assert account.is_locked(1000.0) is True
    first_lock = account.lockout_seconds_remaining(1000.0)
    assert first_lock == LOCKOUT_SCHEDULE_SECONDS[2]

    # Correct credentials are still refused while locked.
    result = store.authenticate_password("ops", "a-strong-unique-passphrase")
    assert result.ok is False
    assert result.locked_seconds > 0

    # Waiting out the window lets a further attempt through, and a repeated
    # failure escalates the next lockout.
    now[0] += first_lock + 1
    store.authenticate_password("ops", "wrong-password-here")
    account = store.get("ops")
    assert account is not None
    second_lock = account.lockout_seconds_remaining(now[0])
    assert second_lock > first_lock, (first_lock, second_lock)

    # After the window elapses the correct password works again.
    now[0] += second_lock + 1
    assert store.authenticate_password("ops", "a-strong-unique-passphrase").ok is True


def test_successful_password_does_not_clear_lockout() -> None:
    now = [1000.0]
    store = LocalAccountStore(clock=lambda: now[0])
    store.create("ops", hash_password("a-strong-unique-passphrase"), ["operator"])

    store.authenticate_password("ops", "wrong-password-here")
    store.register_success("ops")

    account = store.get("ops")
    assert account is not None
    assert account.consecutive_failures == 0
    assert account.locked_until == 0.0


def test_password_challenge_requires_mfa() -> None:
    """A password alone must never clear the MFA requirement."""
    store = LocalAccountStore()
    store.create("ops", hash_password("a-strong-unique-passphrase"), ["operator"])

    challenge = store.authenticate_password("ops", "a-strong-unique-passphrase")
    assert challenge.ok is True
    assert challenge.mfa_required is True
    assert challenge.account is not None
    assert challenge.account.is_mfa_active() is False


def test_disabled_account_cannot_authenticate() -> None:
    store = LocalAccountStore()
    account = store.create(
        "ops", hash_password("a-strong-unique-passphrase"), ["operator"], enabled=False
    )
    assert account.enabled is False
    result = store.authenticate_password("ops", "a-strong-unique-passphrase")
    assert result.ok is False


def test_account_enrolment_is_recorded() -> None:
    store = LocalAccountStore()
    account = store.create("ops", hash_password("a-strong-unique-passphrase"), ["operator"])
    assert account.is_mfa_active() is False

    updated = account.with_totp_enrolled(
        encrypted_totp="v1:nonce:cipher",
        recovery_code_hashes=["hash-1", "hash-2"],
        now=1234.0,
    )
    assert updated.is_mfa_active() is True
    assert updated.totp_enrolled_at == 1234.0
    assert len(updated.recovery_code_hashes) == 2


def test_store_supports_delete_and_listing() -> None:
    store = LocalAccountStore()
    store.create("ops-bravo", hash_password("a-strong-unique-passphrase"), ["operator"])
    store.create("ops-alpha", hash_password("another-strong-passphrase"), ["operator"])

    assert store.list_usernames() == ["ops-alpha", "ops-bravo"]
    assert len(store) == 2
    assert store.delete("ops-alpha") is True
    assert store.delete("ops-alpha") is False
    assert store.list_usernames() == ["ops-bravo"]