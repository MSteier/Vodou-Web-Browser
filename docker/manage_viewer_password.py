#!/usr/bin/env python3
"""Manage the Vodou noVNC viewer's LAN password (the nginx Basic-Auth gate).

This is the credential-management layer for LAN access to the browser-viewable
container. The VNC/RFB server itself runs passwordless behind the reverse proxy
(bound to container-localhost); the password that actually gates LAN access is
the reverse proxy's htpasswd file. See docker/viewer_auth.py for the details and
docker/README.md for the security model.

There is deliberately NO "force change at first VNC login": the RFB protocol has
no such hook and HTTP Basic Auth is stateless. Enforcement is therefore at
provisioning time — `seed` (run by setup.sh / setup.ps1) installs a
credential with a password generated for this install and shown once, and
replaces the old published default on installs that still use it; `status`
reports (and can fail a setup script) while that default is in use; `change`
sets a password of your choosing.

Examples
--------
    # Create the credential with a random password, or replace the old
    # published default with one; prints the new password once. A no-op when
    # the credential already has its own password:
    python manage_viewer_password.py seed --file /path/to/vodou.htpasswd

    # In a setup script: stop with a nonzero exit while the old published
    # default password is still in use
    python manage_viewer_password.py status --file ... --fail-if-default

    # Change the password (prompts, never echoes):
    python manage_viewer_password.py change --file ...

The htpasswd path comes from --file, else the VODOU_VIEWER_HTPASSWD environment
variable, else docker/viewer-auth/vodou.htpasswd on the host (gitignored). It is
a host file, never part of an image, so the credential survives
`docker compose down/up` and image rebuilds. Passwords are never logged or
written except as $apr1$ hashes; the only plaintext output is the one-time
display of a newly generated password.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

import viewer_auth as va

DEFAULT_HTPASSWD = Path(__file__).resolve().parent / "viewer-auth" / \
    "vodou.htpasswd"


def _resolve_path(args) -> str:
    return (args.file or os.environ.get("VODOU_VIEWER_HTPASSWD")
            or str(DEFAULT_HTPASSWD))


def _cmd_seed(args) -> int:
    path = _resolve_path(args)
    outcome, password = va.ensure_credential(path, args.username)
    if outcome == "kept":
        print(f"The viewer login “{args.username}” at {path} already has its "
              f"own password; left unchanged.")
        return 0
    if outcome == "rotated":
        print(f"WARNING: “{args.username}” was still using the old published "
              f"default password,\nwhich anyone can look up. It has been "
              f"replaced with a new random password.")
    else:
        print(f"Created the viewer login “{args.username}” at {path}.")
    print()
    print("  ============ Vodou viewer LAN password (shown once) ============")
    print(f"    username: {args.username}")
    print(f"    password: {password}")
    print("  ================================================================")
    print("Save it in a password manager now; it is stored only as a hash and")
    print("won't be shown again. To choose your own instead:")
    print(f"    python {os.path.basename(__file__)} change --file {path}")
    return 0


def _cmd_status(args) -> int:
    path = _resolve_path(args)
    entries = va.read_htpasswd(path)
    if args.username not in entries:
        print(f"No credential configured for “{args.username}” at {path}.")
        return 2
    if va.uses_published_default(path, args.username):
        print(f"WARNING: “{args.username}” is still using the old PUBLISHED "
              f"default password, which anyone can look up. Run `seed` to "
              f"replace it with a random one, or `change` to pick your own.")
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
    # The one-time password banner must never crash on a legacy console code
    # page (e.g. cp1252 when setup.ps1 pipes our output).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(
        description="Manage the Vodou viewer's LAN (nginx Basic-Auth) password.")
    parser.add_argument("--file", help="Path to the htpasswd file (default: "
                        "$VODOU_VIEWER_HTPASSWD, else "
                        "docker/viewer-auth/vodou.htpasswd).")
    parser.add_argument("--username", default=va.DEFAULT_USERNAME,
                        help=f"Username to manage (default: "
                             f"{va.DEFAULT_USERNAME}).")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("seed", help="Create the credential with a random "
                   "password, or replace the old published default; prints "
                   "the new password once. Never touches a password you set.")

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
