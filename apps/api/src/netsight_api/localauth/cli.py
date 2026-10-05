"""Operator CLI for Netsight-managed local accounts (ADR 0010).

Account creation is deliberately *not* an HTTP endpoint. Provisioning an
identity is a privileged operation, so it requires shell access to the
deployment host, which is a control the platform already relies on.

Usage:
    python -m netsight_api.localauth.cli list
    python -m netsight_api.localauth.cli add <username> --roles network_engineer
    python -m netsight_api.localauth.cli set-password <username>
    python -m netsight_api.localauth.cli enable <username> | disable <username>
    python -m netsight_api.localauth.cli delete <username>

``add`` completes MFA enrolment and prints the TOTP secret, provisioning URI
and recovery codes once. This is deliberate: MFA is mandatory, enrolment needs
a session, and a session needs MFA, so provisioning is the only place the
factor can be bound to an account.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence
from typing import Any

from netsight_api.localauth import account_store
from netsight_api.localauth.passwords import check_password_policy, hash_password
from netsight_api.localauth.store import UsernameRejected
from netsight_api.rbac import Role

USERNAME_CHOICES = sorted(role.value for role in Role)


def _prompt_password(prompt: str = "Password: ") -> str:
    # Read from the controlling terminal, never from argv, so a password is not
    # visible in the process list or shell history.
    return getpass.getpass(prompt)


def _read_passwords(confirm: bool = True) -> str:
    """Prompt for a password twice, without echoing it.

    Callers apply the policy separately so the reason for a rejection can be
    shown to the operator.
    """
    password = _prompt_password()
    if confirm and password != _prompt_password("Confirm password: "):
        raise SystemExit("passwords did not match")
    return password


def _session_secret() -> str:
    """Read the secret used to encrypt the TOTP envelope at rest."""
    from netsight_api.auth.settings import session_policy

    secret = session_policy().secret
    if not secret:
        raise SystemExit(
            "NETSIGHT_SESSION_SECRET must be set to enrol MFA, because the TOTP "
            "secret is encrypted with a key derived from it."
        )
    return secret


def _enrol(account: Any) -> dict[str, Any]:
    """Enrol TOTP and mint recovery codes, returning them to print once.

    MFA is mandatory (ADR 0010) but enrolment requires a session, and a
    session requires MFA. Provisioning therefore has to complete enrolment,
    otherwise a new account could never sign in.
    """
    from netsight_api.localauth import totp
    from netsight_api.localauth.crypto import encrypt_secret
    from netsight_api.localauth.recovery import generate_recovery_codes, hash_recovery_codes

    secret = totp.generate_secret()
    codes = generate_recovery_codes()
    updated = account.with_totp_enrolled(
        encrypted_totp=encrypt_secret(secret, _session_secret()),
        recovery_code_hashes=hash_recovery_codes(codes),
        now=0.0,
    )
    account_store().save(updated)
    return {
        "totp_secret": secret,
        "provisioning_uri": totp.provisioning_uri(secret, account.username),
        "recovery_codes": codes,
    }


def _add(args: argparse.Namespace) -> int:
    password = _read_passwords()
    check = check_password_policy(password)
    if not check.ok:
        print(f"rejected: {check.message}", file=sys.stderr)
        return 2

    roles = args.roles or ["technician"]
    try:
        account = account_store().create(
            args.username,
            hash_password(password),
            roles,
            mfa_required=not args.no_mfa,
        )
    except UsernameRejected as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 2

    enrolled: dict[str, Any] = {}
    if not args.no_mfa:
        try:
            enrolled = _enrol(account)
        except SystemExit as exc:
            account_store().delete(account.username)
            print(f"rejected: {exc}", file=sys.stderr)
            return 2

    print(
        json.dumps(
            {
                "created": account.username,
                "roles": sorted(account.roles),
                "mfa_required": account.mfa_required,
                "next_step": (
                    "Add the provisioning URI to an authenticator app, then sign in."
                    if enrolled
                    else "MFA is disabled for this account."
                ),
                **enrolled,
            },
            indent=2,
        )
    )
    return 0


def _list(_args: argparse.Namespace) -> int:
    store = account_store()
    print(f"{len(store)} local account(s):")
    for account in store:
        print(
            f"  {account.username:<24} roles={','.join(sorted(account.roles)) or '-'}"
            f"  mfa={'active' if account.is_mfa_active() else 'enrolled' if account.mfa_required else 'not-required'}"
            f"  enabled={account.enabled}"
        )
    return 0


def _set_password(args: argparse.Namespace) -> int:
    store = account_store()
    account = store.get(args.username)
    if account is None:
        print("no such account", file=sys.stderr)
        return 1

    password = _read_passwords()
    check = check_password_policy(password)
    if not check.ok:
        print(f"rejected: {check.message}", file=sys.stderr)
        return 2

    account.password_hash = hash_password(password)
    account.record_success()
    store.save(account)
    result: dict[str, Any] = {"password_changed": account.username}

    # MFA is mandatory, so a new password must not be issued without a way to
    # satisfy the second factor.
    if account.mfa_required and not account.is_mfa_active():
        try:
            result.update(_enrol(account))
        except SystemExit as exc:
            print(f"rejected: {exc}", file=sys.stderr)
            return 2
    print(json.dumps(result, indent=2))
    return 0


def _set_enabled(args: argparse.Namespace, enabled: bool) -> int:
    store = account_store()
    account = store.get(args.username)
    if account is None:
        print("no such account", file=sys.stderr)
        return 1
    account.enabled = enabled
    store.save(account)
    print(json.dumps({"username": account.username, "enabled": enabled}, indent=2))
    return 0


def _delete(args: argparse.Namespace) -> int:
    removed = account_store().delete(args.username)
    print(json.dumps({"deleted": args.username, "removed": removed}, indent=2))
    return 0 if removed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netsight-localauth", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List local accounts").set_defaults(handler=_list)

    add = sub.add_parser("add", help="Create a local account")
    add.add_argument("username")
    add.add_argument("--roles", nargs="*", choices=USERNAME_CHOICES, default=None)
    add.add_argument(
        "--no-mfa",
        action="store_true",
        help="Permit sign-in without a second factor (not recommended)",
    )
    add.set_defaults(handler=_add)

    set_password = sub.add_parser("set-password", help="Set an account password")
    set_password.add_argument("username")
    set_password.set_defaults(handler=_set_password)

    enable = sub.add_parser("enable", help="Enable an account")
    enable.add_argument("username")
    enable.set_defaults(handler=lambda args: _set_enabled(args, True))

    disable = sub.add_parser("disable", help="Disable an account")
    disable.add_argument("username")
    disable.set_defaults(handler=lambda args: _set_enabled(args, False))

    remove = sub.add_parser("delete", help="Delete an account")
    remove.add_argument("username")
    remove.set_defaults(handler=_delete)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = args.handler
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
