"""Registering Vodou as the OS default browser.

Neither Windows nor Linux lets an application flip this switch entirely by
itself — and for good reason: Windows has ignored programmatic
default-browser changes since Windows 8 (the registry's UserChoice value is
hashed against the OS build and a per-user salt, so writing it from outside
`explorer.exe` is simply discarded), and a desktop environment's default-apps
setting is meant to record a choice the user made, not one an app made for
itself. What Vodou CAN do without any elevated privilege is the honest half
of the job on each platform: register itself as a valid candidate, then hand
off to the system's own picker to finish it in one click.

  Windows   Write the app + URL/file associations to HKEY_CURRENT_USER (no
            admin needed) so Vodou appears in Settings -> Apps -> Default
            apps, then open that page.
  Linux     `xdg-settings set default-web-browser` against the .desktop file
            packaging/install-linux.sh installs — this one IS allowed to
            just work, no picker needed, provided that file is installed.
  macOS     Not packaged yet (no .app bundle / LSHandlers registered), so
            reported as unsupported rather than silently doing nothing.

This only matters because BrowserWindow now reads a URL off argv (see
main._startup_url_from_argv) — registering as default without that would
hand back the home page for every clicked link, which is exactly why
packaging/vodou.desktop used to leave MimeType out on purpose.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

APP_NAME = "Vodou"
PROG_ID = "VodouHTML"

_REPO_DIR = Path(__file__).resolve().parent


def _launch_command() -> str:
    """The command line the OS should run to open a URL: the frozen exe's
    own path with a %1 placeholder, or (in a source checkout) the same
    "python[w] + main.py" relaunch main._restart_app already uses, pointed
    at %1 instead of a session snapshot."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" "%1"'
    exe = Path(sys.executable)
    # Prefer pythonw.exe so a link click doesn't flash a console window,
    # matching Vodou.spec's console=False for the packaged build.
    pythonw = exe.with_name("pythonw.exe")
    if pythonw.exists():
        exe = pythonw
    script = _REPO_DIR / "main.py"
    return f'"{exe}" "{script}" "%1"'


def _icon_path() -> str:
    ico = _REPO_DIR / "vodou.ico"
    return str(ico) if ico.exists() else ""


def register() -> tuple[bool, str]:
    """Register Vodou as an OS-level browser candidate and hand the rest off
    to the system. Returns (ok, message) for the caller to show the user."""
    if sys.platform == "win32":
        return _register_windows()
    if sys.platform.startswith("linux"):
        return _register_linux()
    return False, (
        f"Setting the default browser isn't supported on {sys.platform} yet "
        "— only Windows and Linux are. If your system offers its own "
        "default-apps setting, choose Vodou there instead.")


def _register_windows() -> tuple[bool, str]:
    import os
    import winreg

    command = _launch_command()
    icon = _icon_path()
    client_key = rf"Software\Clients\StartMenuInternet\{APP_NAME}"

    def _set(root, path: str, value: str, name: str = "") -> None:
        with winreg.CreateKey(root, path) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

    try:
        _set(winreg.HKEY_CURRENT_USER, client_key, APP_NAME)
        _set(winreg.HKEY_CURRENT_USER, rf"{client_key}\shell\open\command",
             command)
        if icon:
            _set(winreg.HKEY_CURRENT_USER, rf"{client_key}\DefaultIcon",
                 f"{icon},0")
        _set(winreg.HKEY_CURRENT_USER, rf"{client_key}\Capabilities",
             APP_NAME, "ApplicationName")
        _set(winreg.HKEY_CURRENT_USER, rf"{client_key}\Capabilities",
             "Privacy-centric browser with a built-in password manager",
             "ApplicationDescription")
        _set(winreg.HKEY_CURRENT_USER,
             rf"{client_key}\Capabilities\URLAssociations", PROG_ID, "http")
        _set(winreg.HKEY_CURRENT_USER,
             rf"{client_key}\Capabilities\URLAssociations", PROG_ID, "https")
        _set(winreg.HKEY_CURRENT_USER,
             rf"{client_key}\Capabilities\FileAssociations", PROG_ID, ".htm")
        _set(winreg.HKEY_CURRENT_USER,
             rf"{client_key}\Capabilities\FileAssociations", PROG_ID, ".html")
        _set(winreg.HKEY_CURRENT_USER, "Software\\RegisteredApplications",
             rf"{client_key}\Capabilities", APP_NAME)
        # The ProgID the associations above point at.
        _set(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROG_ID}",
             "Vodou HTML Document")
        _set(winreg.HKEY_CURRENT_USER,
             rf"Software\Classes\{PROG_ID}\shell\open\command", command)
        if icon:
            _set(winreg.HKEY_CURRENT_USER,
                 rf"Software\Classes\{PROG_ID}\DefaultIcon", f"{icon},0")
    except OSError as exc:
        return False, f"Couldn't register Vodou with Windows: {exc}"

    try:
        os.startfile("ms-settings:defaultapps")
        opened = True
    except OSError:
        opened = False

    tail = (
        "Windows' Settings app should now be open on Default apps — find "
        "Vodou (or the http/https/.htm/.html entries) and switch them over."
        if opened else
        "Vodou is registered, but Settings didn't open on its own — go to "
        "Settings -> Apps -> Default apps and choose Vodou there yourself.")
    return True, (
        "Vodou is now registered as a browser Windows can see.\n\n"
        "Windows itself has to make the final switch — it won't let any app "
        f"set itself as default silently. {tail}")


def _register_linux() -> tuple[bool, str]:
    if shutil.which("xdg-settings") is None:
        return False, (
            "Couldn't find xdg-settings, which is what sets the default "
            "browser on most Linux desktops (it ships in xdg-utils). "
            "Install it, or set Vodou as default from your desktop's own "
            "Settings app instead.")
    desktop_file = (
        Path.home() / ".local" / "share" / "applications" / "vodou.desktop")
    if not desktop_file.exists():
        return False, (
            "Vodou isn't installed as an application yet — run "
            "packaging/install-linux.sh first, then try this again.")
    try:
        result = subprocess.run(
            ["xdg-settings", "set", "default-web-browser", "vodou.desktop"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Couldn't run xdg-settings: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return False, (
            "xdg-settings couldn't set Vodou as the default browser"
            + (f":\n\n{detail}" if detail else ".")
            + "\n\nSome sessions (a minimal window manager with no desktop "
            "environment, for instance) don't support this — set it from "
            "your desktop's own Settings app instead.")
    return True, "Vodou is now your default browser for http and https links."
