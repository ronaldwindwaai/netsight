"""Operator CLI for Netsight-managed local accounts (ADR 0010).

Account creation is deliberately *not* an HTTP endpoint. Provisioning an
identity is a privileged operation, so it requires shell access to the
deployment host, which is a control the platform already relies on.

Usage:
    python -m netsight_api.localauth.cli list
    python -m netsight_api.localauth.cli add <username> --roles operator
    python -m netsight_api.localauth.cli set-password <username>
    python -m netsight_api.localauth.cli enable <username> | disable <username>
    python -m netsight_api.localauth.cli delete <username>
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence

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
    password = _prompt_password()
    if check_password_policy(password).ok:
        # The policy check is advisory here: the password is never stored
        # unless it passes, and the operator sees the reason if it does not.
        pass
    if confirm and password != _prompt_password("Confirm password: "):
        raise SystemExit("passwords did not match")
    return password


def _add(args: argparse.Namespace) -> int:
    password = _read_passwords()
    check = check_password_policy(password)
    if not check.ok:
        print(f"rejected: {check.message}", file=sys.stderr)
        return 2

    roles = args.roles or [Role.OPERATOR.value if hasattr(Role, "OPERATOR") else "technician"]
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

    print(
        json.dumps(
            {
                "created": account.username,
                "roles": sorted(account.roles),
                "mfa_required": account.mfa_required,
                "next_step": "Sign in and enrol an authenticator; MFA is required.",
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
    print(json.dumps({"password_changed": account.username}, indent=2))
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
