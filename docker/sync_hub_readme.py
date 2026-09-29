"""Publish docker/HUB_README.md as the Docker Hub description of msteier/vodou.

Docker Hub never reads this file on its own (the repo isn't linked through
Autobuild), so without this the page drifts behind every release. Run it after
pushing a new image:

    python docker/sync_hub_readme.py            # update Docker Hub
    python docker/sync_hub_readme.py --check    # only report whether it's current

No credentials live in the repo. The script borrows the Docker Hub login that
`docker login` / Docker Desktop already keeps in the OS credential store
(Windows Credential Manager, macOS Keychain, Secret Service, ...), holds it in
memory only, and never prints or writes it. It only works on a machine that is
logged in to Docker Hub as the repository's owner.

Standard library only, so it runs without installing anything.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPOSITORY = "msteier/vodou"
README = Path(__file__).resolve().parent / "HUB_README.md"
HUB = "https://hub.docker.com/v2"
REGISTRY_KEYS = ("https://index.docker.io/v1/", "index.docker.io", "docker.io")


def _docker_config() -> dict:
    root = Path(os.environ.get("DOCKER_CONFIG") or Path.home() / ".docker")
    try:
        return json.loads((root / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def docker_hub_login() -> tuple[str, str]:
    """(username, secret) from Docker's own credential storage."""
    config = _docker_config()
    helpers = config.get("credHelpers", {})
    for key in REGISTRY_KEYS:
        helper = helpers.get(key) or config.get("credsStore")
        if not helper:
            continue
        try:
            out = subprocess.run([f"docker-credential-{helper}", "get"], input=key,
                                 capture_output=True, text=True, check=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        cred = json.loads(out)
        if cred.get("Username") and cred.get("Secret"):
            return cred["Username"], cred["Secret"]
    # Older setups keep a base64 "user:secret" directly in config.json.
    for key in REGISTRY_KEYS:
        auth = config.get("auths", {}).get(key, {}).get("auth")
        if auth:
            user, _, secret = base64.b64decode(auth).decode().partition(":")
            if user and secret:
                return user, secret
    sys.exit("No Docker Hub login found. Run `docker login` (or sign in to Docker Desktop) first.")


def _request(method: str, url: str, body: dict | None = None, token: str | None = None) -> dict:
    req = urllib.request.Request(url, method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read() or b"{}")


def live_description() -> str:
    return _request("GET", f"{HUB}/repositories/{REPOSITORY}/").get("full_description") or ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true",
                        help="only report whether Docker Hub matches the file; change nothing")
    args = parser.parse_args()

    text = README.read_text(encoding="utf-8")
    if live_description().strip() == text.strip():
        print(f"Docker Hub description for {REPOSITORY} already matches {README.name}.")
        return 0
    if args.check:
        print(f"Docker Hub description for {REPOSITORY} is OUT OF DATE; "
              "run without --check to update it.")
        return 1

    username, secret = docker_hub_login()
    try:
        token = _request("POST", f"{HUB}/users/login/",
                         {"username": username, "password": secret})["token"]
    except urllib.error.HTTPError as e:
        sys.exit(f"Docker Hub rejected the stored login (HTTP {e.code}). Run `docker login` "
                 "again with your password or a personal access token.")
    finally:
        secret = None
    try:
        _request("PATCH", f"{HUB}/repositories/{REPOSITORY}/", {"full_description": text}, token)
    except urllib.error.HTTPError as e:
        sys.exit(f"Docker Hub refused the update (HTTP {e.code}); is {username} allowed to "
                 f"edit {REPOSITORY}?")

    if live_description().strip() != text.strip():
        sys.exit("Update was accepted, but the live description still differs. Check Docker Hub.")
    print(f"Updated the Docker Hub description for {REPOSITORY} from {README.name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
