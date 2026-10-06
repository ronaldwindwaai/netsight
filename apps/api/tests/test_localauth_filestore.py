"""Durability tests for the local account store (ADR 0010).

The API and the operator CLI are separate processes. An in-memory store made
an account created on the host invisible to the running service, so the store
must persist. These tests pin that behaviour and the secrecy of the file.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from netsight_api.localauth.crypto import decrypt_secret, encrypt_secret
from netsight_api.localauth.filestore import (
    SCHEMA_VERSION,
    AccountFileError,
    FileAccountStore,
)
from netsight_api.localauth.passwords import hash_password
from netsight_api.localauth.recovery import generate_recovery_codes, hash_recovery_codes
from netsight_api.localauth.store import UsernameRejected

PASSWORD = "a-strong-unique-passphrase"
SECRET_SESSION = "x" * 48


@pytest.fixture
def account_file(tmp_path: Path) -> Path:
    return tmp_path / "state" / "accounts.json"


def test_account_survives_a_restart(account_file: Path) -> None:
    first = FileAccountStore(account_file)
    first.load()
    first.create("ops.user", hash_password(PASSWORD), ["network_engineer"])

    # A brand new store instance, as a restarted process would build.
    second = FileAccountStore(account_file)
    second.load()

    account = second.get("ops.user")
    assert account is not None
    assert account.roles == frozenset({"network_engineer"})
    assert second.authenticate_password("ops.user", PASSWORD).ok is True


def test_cli_written_account_is_visible_to_a_new_process(account_file: Path) -> None:
    """The regression that motivated the durable store."""
    writer = FileAccountStore(account_file)
    writer.load()
    writer.create("ops.user", hash_password(PASSWORD), ["technician"])

    reader = FileAccountStore(account_file)
    reader.load()
    assert reader.get("ops.user") is not None
    assert reader.authenticate_password("ops.user", PASSWORD).ok is True


def test_file_contains_no_plaintext_secret(account_file: Path) -> None:
    store = FileAccountStore(account_file)
    store.load()
    account = store.create("ops.user", hash_password(PASSWORD), ["technician"])

    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    codes = generate_recovery_codes(3)
    store.save(
        account.with_totp_enrolled(
            encrypted_totp=encrypt_secret(secret, SECRET_SESSION),
            recovery_code_hashes=hash_recovery_codes(codes),
            now=0.0,
        )
    )

    raw = account_file.read_text(encoding="utf-8")
    document = json.loads(raw)

    assert PASSWORD not in raw
    assert secret not in raw
    for code in codes:
        assert code not in raw
        assert code.replace("-", "") not in raw

    # The password must appear only as an Argon2id hash.
    entry = document["accounts"][0]
    assert entry["password_hash"].startswith("$argon2id$")
    assert entry["encrypted_totp"].startswith("v1:")
    for stored in entry["recovery_code_hashes"]:
        assert stored.startswith("$argon2id$")

    # The TOTP secret is recoverable only with the session secret.
    assert decrypt_secret(entry["encrypted_totp"], SECRET_SESSION) == secret


def test_file_permissions_are_owner_only(account_file: Path) -> None:
    store = FileAccountStore(account_file)
    store.load()
    store.create("ops.user", hash_password(PASSWORD), ["technician"])

    if os.name != "posix":
        # Windows has no POSIX mode bits; os.chmod only toggles read-only there.
        # The deployment target is Linux, so the strict check applies there.
        pytest.skip("POSIX mode bits are not meaningful on this platform")

    mode = stat.S_IMODE(os.stat(account_file).st_mode)
    assert mode == 0o600, oct(mode)


def test_no_temporary_file_is_left_behind(account_file: Path) -> None:
    store = FileAccountStore(account_file)
    store.load()
    store.create("ops.user", hash_password(PASSWORD), ["technician"])

    leftovers = list(account_file.parent.glob("*.tmp"))
    assert leftovers == []


def test_lockout_state_survives_a_restart(account_file: Path) -> None:
    now = [1_700_000_000.0]
    first = FileAccountStore(account_file, clock=lambda: now[0])
    first.load()
    first.create("ops.user", hash_password(PASSWORD), ["technician"])
    for _ in range(3):
        first.authenticate_password("ops.user", "wrong-password-here")

    # A restart must not hand an attacker a fresh budget.
    second = FileAccountStore(account_file, clock=lambda: now[0])
    second.load()
    assert second.authenticate_password("ops.user", PASSWORD).ok is False

    # Once the wall-clock window passes, sign-in works again.
    now[0] += 86_400
    third = FileAccountStore(account_file, clock=lambda: now[0])
    third.load()
    assert third.authenticate_password("ops.user", PASSWORD).ok is True


def test_delete_persists(account_file: Path) -> None:
    first = FileAccountStore(account_file)
    first.load()
    first.create("ops.user", hash_password(PASSWORD), ["technician"])
    assert first.delete("ops.user") is True

    second = FileAccountStore(account_file)
    second.load()
    assert second.get("ops.user") is None
    assert second.list_usernames() == []


def test_duplicate_registration_is_refused_persistently(account_file: Path) -> None:
    store = FileAccountStore(account_file)
    store.load()
    store.create("ops.user", hash_password(PASSWORD), ["technician"])

    reloaded = FileAccountStore(account_file)
    reloaded.load()
    with pytest.raises(UsernameRejected):
        reloaded.create("OPS.USER", hash_password("another-strong-passphrase"), ["technician"])


def test_malformed_file_is_refused_not_ignored(account_file: Path) -> None:
    """A corrupt file must fail loudly rather than silently disabling auth."""
    account_file.parent.mkdir(parents=True, exist_ok=True)
    account_file.write_text("{not json", encoding="utf-8")

    with pytest.raises(AccountFileError):
        FileAccountStore(account_file).load()

    account_file.write_text(json.dumps({"version": 999, "accounts": []}), encoding="utf-8")
    with pytest.raises(AccountFileError):
        FileAccountStore(account_file).load()

    account_file.write_text(
        json.dumps({"version": SCHEMA_VERSION, "accounts": [{"unknown": 1}]}),
        encoding="utf-8",
    )
    with pytest.raises(AccountFileError):
        FileAccountStore(account_file).load()


def test_changes_from_another_process_are_seen_without_a_restart(
    account_file: Path,
) -> None:
    """The regression: the API cached the file forever and ignored the CLI.

    A recovery code or reset password written by the operator CLI was silently
    rejected by the running service until it restarted, because the store read
    the file once at first use and never again.
    """
    api = FileAccountStore(account_file)
    api.load()
    api.create("ops.user", hash_password(PASSWORD), ["technician"])

    # The operator CLI, in its own process, issues fresh recovery codes.
    cli = FileAccountStore(account_file)
    cli.load()
    codes = generate_recovery_codes(2)
    account = cli.get("ops.user")
    assert account is not None
    account.recovery_code_hashes = hash_recovery_codes(codes)
    cli.save(account)

    # The API process must now accept them, with no restart.
    from netsight_api.localauth.recovery import consume_recovery_code

    assert consume_recovery_code(api.get("ops.user").recovery_code_hashes, codes[0]) is not None  # type: ignore[union-attr]

    # A password reset by the CLI must be honoured immediately too.
    cli = FileAccountStore(account_file)
    cli.load()
    reset = cli.get("ops.user")
    assert reset is not None
    reset.password_hash = hash_password("another-strong-passphrase")
    cli.save(reset)

    assert api.authenticate_password("ops.user", "another-strong-passphrase").ok is True
    assert api.authenticate_password("ops.user", PASSWORD).ok is False


def test_an_account_created_elsewhere_appears(account_file: Path) -> None:
    api = FileAccountStore(account_file)
    api.load()

    cli = FileAccountStore(account_file)
    cli.load()
    cli.create("ops.user", hash_password(PASSWORD), ["technician"])

    # No restart, and no reload() call.
    assert api.get("ops.user") is not None
    assert api.list_usernames() == ["ops.user"]


def test_a_deletion_elsewhere_is_seen(account_file: Path) -> None:
    api = FileAccountStore(account_file)
    api.load()
    api.create("ops.user", hash_password(PASSWORD), ["technician"])

    cli = FileAccountStore(account_file)
    cli.load()
    assert cli.delete("ops.user") is True

    assert api.get("ops.user") is None


def test_our_own_write_is_not_mistaken_for_an_external_change(
    account_file: Path,
) -> None:
    """A local mutation must not trigger a pointless reload."""
    store = FileAccountStore(account_file)
    store.load()
    store.create("ops.user", hash_password(PASSWORD), ["technician"])

    assert store._stamp == store._source_stamp()

    # No exception and state intact after further reads.
    store.register_success("ops.user")
    assert store.get("ops.user") is not None


def test_store_accepts_a_plain_string_path(tmp_path: Path) -> None:
    """Callers routinely pass an environment value, which is a str."""
    target = tmp_path / "nested" / "accounts.json"
    store = FileAccountStore(str(target))
    store.load()
    store.create("ops.user", hash_password(PASSWORD), ["technician"])

    assert target.exists()
    assert FileAccountStore(str(target)).load() is None
    assert FileAccountStore(str(target)).get("ops.user") is not None


def test_missing_file_is_treated_as_empty(account_file: Path) -> None:
    store = FileAccountStore(account_file)
    store.load()
    assert store.list_usernames() == []
    assert len(store) == 0
    assert store.get("anyone") is None


def test_returned_accounts_are_snapshots(account_file: Path) -> None:
    """Mutating a returned object must not silently alter the store."""
    store = FileAccountStore(account_file)
    store.load()
    store.create("ops.user", hash_password(PASSWORD), ["technician"])

    account = store.get("ops.user")
    assert account is not None
    account.roles = frozenset({"administrator"})

    assert store.get("ops.user").roles == frozenset({"technician"})  # type: ignore[union-attr]
