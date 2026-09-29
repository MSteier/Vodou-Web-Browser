#!/usr/bin/env python3
"""Manage the Vodou noVNC viewer's LAN password (the nginx Basic-Auth gate).

This is the credential-management layer for LAN access to the browser-viewable
container. The VNC/RFB server itself runs passwordless behind the reverse proxy
(bound to container-localhost); the password that actually gates LAN access is
the reverse proxy's htpasswd file. See docker/viewer_auth.py for the details and
docker/README.md for the security model.

There is deliberately NO "force change at first VNC login": the RFB protocol has
no such hook and HTTP Basic Auth is stateless. Enforcement is therefore at
provisioning time — `seed` installs a bootstrap credential with a password
generated for this install (shown once), `status` reports (and can fail a setup
script) while the old published default is still in use, and `change`
replaces it.

Examples
--------
    # Seed a bootstrap credential with a random password, printed once
    # (no-op if one exists):
    python manage_viewer_password.py seed --file /path/to/vodou.htpasswd

    # In a setup script: stop with a nonzero exit while the old published
    # default password is still in use
    python manage_viewer_password.py status --file ... --fail-if-default

    # Change the password (prompts, never echoes):
    python manage_viewer_password.py change --file ...

The htpasswd path comes from --file or the VODOU_VIEWER_HTPASSWD environment
variable. Passwords are never logged or written except as $apr1$ hashes; the
only plaintext output is the one-time display of a freshly seeded password.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

import viewer_auth as va


def _resolve_path(args) -> str:
    path = args.file or os.environ.get("VODOU_VIEWER_HTPASSWD")
    if not path:
        sys.exit("error: no htpasswd path given (use --file or set "
                 "VODOU_VIEWER_HTPASSWD)")
    return path


def _cmd_seed(args) -> int:
    path = _resolve_path(args)
    password = va.seed_default(path, args.username)
    if password is not None:
        print(f"Seeded bootstrap credential for “{args.username}” at {path}.")
        print(f"    username: {args.username}")
        print(f"    password: {password}")
        print("This password was generated for this install and is shown "
              "ONLY now —\nsave it in a password manager. To pick your own:")
        print(f"    python {os.path.basename(__file__)} change --file {path}")
        return 0
    print(f"A credential for “{args.username}” already exists at {path}; "
          f"left unchanged.")
    return 0


def _cmd_status(args) -> int:
    path = _resolve_path(args)
    entries = va.read_htpasswd(path)
    if args.username not in entries:
        print(f"No credential configured for “{args.username}” at {path}.")
        return 2
    if va.uses_published_default(path, args.username):
        print(f"“{args.username}” is still using the old PUBLISHED default "
              f"password, which anyone can look up — change it now.")
        return 1 if args.fail_if_default else 0
    print(f"“{args.username}” is not using the published default password.")
    return 0


def _cmd_change(args) -> int:
    path = _resolve_path(args)
    # getpass reads without echoing; nothing here prints the entered values.
    current = getpass.getpass("Current password: ")
    new = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm new password: ")
    try:
        va.change_password(path, args.username, current, new, confirm)
    except va.PasswordChangeError as exc:
        print(f"Password not changed: {exc}", file=sys.stderr)
        return 1
    print(f"Password for “{args.username}” changed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Manage the Vodou viewer's LAN (nginx Basic-Auth) password.")
    parser.add_argument("--file", help="Path to the htpasswd file "
                        "(or set VODOU_VIEWER_HTPASSWD).")
    parser.add_argument("--username", default=va.DEFAULT_USERNAME,
                        help=f"Username to manage (default: "
                             f"{va.DEFAULT_USERNAME}).")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("seed", help="Install a bootstrap credential with a "
                   "generated password, shown once (never overwrites).")

    p_status = sub.add_parser("status", help="Report whether the old "
                              "published default password is still in use.")
    p_status.add_argument("--fail-if-default", action="store_true",
                          help="Exit nonzero while the published default is "
                               "in use (for setup scripts).")

    sub.add_parser("change", help="Change the password (prompts; no echo).")

    args = parser.parse_args(argv)
    return {"seed": _cmd_seed,
            "status": _cmd_status,
            "change": _cmd_change}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
