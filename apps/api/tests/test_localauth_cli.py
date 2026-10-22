"""Operator CLI tests, including the MFA bootstrap invariant (ADR 0010).

MFA is mandatory but enrolment needs a session and a session needs MFA. The
only place a factor can be bound to a new account is provisioning, so `add`
must complete enrolment. These tests pin that, and that the CLI never puts a
secret on the command line.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsight_api.localauth import account_store, reset_account_store, totp
from netsight_api.localauth.cli import main
from netsight_api.localauth.crypto import decrypt_secret
from netsight_api.localauth.filestore import FileAccountStore

SESSION_SECRET = "s" * 48
PASSWORD = "a-strong-unique-passphrase"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import netsight_api.auth.session as session_module

    monkeypatch.setenv("NETSIGHT_SESSION_SECRET", SESSION_SECRET)
    monkeypatch.setenv("NETSIGHT_LOCAL_ACCOUNT_FILE", str(tmp_path / "accounts.json"))
    session_module.session_policy.cache_clear()
    reset_account_store()
    yield
    reset_account_store()
    session_module.session_policy.cache_clear()


def _add(
    capsys: pytest.CaptureFixture[str],
    username: str = "ops.user",
    roles: list[str] | None = None,
) -> dict[str, object]:
    """Run `add`, feeding the password twice, and return the printed JSON."""
    arguments = ["add", username]
    if roles is not None:
        arguments += ["--roles", *roles]

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("netsight_api.localauth.cli._read_passwords", lambda *_: PASSWORD)
        assert main(arguments) == 0

    return json.loads(capsys.readouterr().out)


# --- the bootstrap invariant ----------------------------------------------


def test_add_enrols_mfa_and_prints_the_factor_once(capsys: pytest.CaptureFixture[str]) -> None:
    """A new account must be able to satisfy MFA on its very first login."""
    output = _add(capsys, roles=["network_engineer"])

    secret = output["totp_secret"]
    assert isinstance(secret, str) and secret
    assert output["provisioning_uri"] == totp.provisioning_uri(secret, "ops.user")
    assert isinstance(output["recovery_codes"], list)
    assert len(output["recovery_codes"]) == 10
    assert output["mfa_required"] is True


def test_enrolled_account_can_complete_a_full_login(capsys: pytest.CaptureFixture[str]) -> None:
    """The bootstrapped factor must actually verify against the store."""
    output = _add(capsys)
    secret = str(output["totp_secret"])

    store = account_store()
    account = store.get("ops.user")
    assert account is not None
    assert account.is_mfa_active() is True

    # The stored envelope decrypts with the session secret only.
    envelope = account.encrypted_totp
    assert envelope is not None
    assert secret not in envelope
    assert decrypt_secret(envelope, SESSION_SECRET) == secret

    challenge = store.authenticate_password("ops.user", PASSWORD)
    assert challenge.ok is True
    assert challenge.mfa_required is True

    # A current code verifies against the stored secret.
    from netsight_api.localauth.routes import _verify_second_factor

    assert _verify_second_factor(store.get("ops.user"), totp.generate_code(secret)) is True


def test_recovery_codes_from_add_work_against_the_store(
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = _add(capsys)
    codes = [str(code) for code in output["recovery_codes"]]  # type: ignore[union-attr]

    from netsight_api.localauth.routes import _verify_second_factor

    store = account_store()
    account = store.get("ops.user")
    assert account is not None

    assert _verify_second_factor(account, codes[0]) is True
    # Consumed on use.
    assert _verify_second_factor(store.get("ops.user"), codes[0]) is False
    assert _verify_second_factor(store.get("ops.user"), codes[1]) is True


def test_enrolment_survives_a_restart(capsys: pytest.CaptureFixture[str]) -> None:
    output = _add(capsys)
    secret = str(output["totp_secret"])

    # A fresh store, as a restarted API process would build.
    reloaded = FileAccountStore()
    reloaded.load()
    account = reloaded.get("ops.user")
    assert account is not None
    assert account.is_mfa_active() is True
    assert decrypt_secret(account.encrypted_totp or "", SESSION_SECRET) == secret


# --- refusals --------------------------------------------------------------


def test_add_refuses_a_weak_password(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("netsight_api.localauth.cli._read_passwords", lambda *_: "short")
        assert main(["add", "ops.user"]) == 2

    assert "rejected" in capsys.readouterr().err
    assert account_store().get("ops.user") is None


def test_add_refuses_a_duplicate_username(capsys: pytest.CaptureFixture[str]) -> None:
    _add(capsys)
    capsys.readouterr()

    # A case variant of an existing username must not create a second account.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("netsight_api.localauth.cli._read_passwords", lambda *_: PASSWORD)
        assert main(["add", "OPS.USER"]) == 2

    assert "already registered" in capsys.readouterr().err
    assert account_store().list_usernames() == ["ops.user"]


def test_add_without_a_session_secret_creates_nothing(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the encryption key the factor cannot be stored, so refuse.

    Leaving a half-provisioned account behind would be worse than failing.
    """
    import netsight_api.auth.session as session_module

    monkeypatch.setenv("NETSIGHT_SESSION_SECRET", "")
    session_module.session_policy.cache_clear()

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("netsight_api.localauth.cli._read_passwords", lambda *_: PASSWORD)
        assert main(["add", "ops.user"]) == 2

    assert "NETSIGHT_SESSION_SECRET" in capsys.readouterr().err
    assert account_store().list_usernames() == []


# --- lifecycle -------------------------------------------------------------


def test_set_password_re_enrols_when_a_factor_is_missing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """MFA is mandatory, so a new password cannot leave the user locked out."""
    store = account_store()
    account = store.create("ops.user", "hash", ["technician"], mfa_required=True)
    assert account.is_mfa_active() is False

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("netsight_api.localauth.cli._read_passwords", lambda *_: PASSWORD)
        assert main(["set-password", "ops.user"]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["password_changed"] == "ops.user"
    assert output["totp_secret"]
    assert store.get("ops.user").is_mfa_active() is True  # type: ignore[union-attr]


def test_list_reports_enrolment_state(capsys: pytest.CaptureFixture[str]) -> None:
    _add(capsys)
    capsys.readouterr()

    assert main(["list"]) == 0
    printed = capsys.readouterr().out
    assert "ops.user" in printed
    assert "mfa=active" in printed


def test_disable_and_enable_round_trip(capsys: pytest.CaptureFixture[str]) -> None:
    _add(capsys)
    capsys.readouterr()

    assert main(["disable", "ops.user"]) == 0
    assert json.loads(capsys.readouterr().out)["enabled"] is False
    assert account_store().get("ops.user").enabled is False  # type: ignore[union-attr]

    assert main(["enable", "ops.user"]) == 0
    assert json.loads(capsys.readouterr().out)["enabled"] is True


def test_delete_removes_the_account(capsys: pytest.CaptureFixture[str]) -> None:
    _add(capsys)
    capsys.readouterr()

    assert main(["delete", "ops.user"]) == 0
    assert json.loads(capsys.readouterr().out)["removed"] is True
    assert account_store().list_usernames() == []

    # Deleting again reports nothing was removed.
    assert main(["delete", "ops.user"]) == 1


def test_password_is_never_a_command_line_argument() -> None:
    """The parser must not accept a password flag, so it cannot leak in argv."""
    from netsight_api.localauth.cli import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["add", "ops.user", "--password", "hunter2"])


def test_cli_does_not_print_the_password(capsys: pytest.CaptureFixture[str]) -> None:
    _add(capsys)
    combined = capsys.readouterr()
    assert PASSWORD not in combined.out
    assert PASSWORD not in combined.err
