# Vodou Browser

A privacy-centric web browser with a built-in encrypted password manager.
Python + PyQt6 on Qt WebEngine (the Chromium engine).

## Installation

**Requirements**

- **Python 3.9+** (developed on 3.10)
- **pip**
- Windows, macOS, or Linux (the bundled Qt WebEngine build is platform-specific
  but installs automatically via pip)

**Install**

```bash
# 1. Get the code
git clone https://github.com/MSteier/Vodou-Web-Browser.git
cd Vodou-Web-Browser

# 2. (recommended) create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# 3. Install dependencies (PyQt6, PyQt6-WebEngine, cryptography)
pip install -r requirements.txt
```

**Run**

```bash
python main.py
```

> **Behind a TLS-intercepting antivirus (e.g. Norton)?** If `pip install` fails
> with `CERTIFICATE_VERIFY_FAILED`, run
> `python -m pip install pip-system-certs` once, then retry — it teaches pip to
> trust your system certificate store.

**Optional — private search:** the home page and default search point at a local
[SearXNG](https://github.com/searxng/searxng) instance
(`https://localhost/searxng`). Vodou works fine without it (just type full URLs),
but running SearXNG locally keeps your searches off third-party engines.

**Optional — desktop shortcut / icon:** the repo ships `vodou.ico` for creating a
desktop or Start-menu shortcut that points at `python main.py`.

## Privacy features

| Feature | How |
|---|---|
| No history/cookies/cache on disk | Off-the-record profile; everything is memory-only and erased on exit |
| Tracker & ad blocking | Request interceptor blocks ~100 known tracker/ad domains (counter in the status bar) |
| Opt-out signals | `DNT: 1` and `Sec-GPC: 1` (Global Privacy Control) on every request |
| Reduced fingerprinting | Generic Chrome user agent; DNS prefetch, hyperlink auditing, and plugins disabled |
| WebRTC IP-leak protection | Chromium flag restricts WebRTC to the public interface |
| HTTPS-first | Bare domains typed in the address bar load over HTTPS |
| Private search | Local SearXNG instance (`https://localhost/searxng`) as home page and default search — queries never go to a third-party engine directly. Self-signed certificates are accepted for localhost only. |
| No telemetry | The browser phones home to no one — there is no "home" |
| Certificate viewer | Padlock next to the address bar (green = verified HTTPS, red = unencrypted); click it for a full certificate view: subject, SANs, issuer, validity, key, fingerprints, TLS version, with verification against the system root store |

Extend the blocklist by adding domains (one per line) to
`~/.vodou/blocklist.txt`.

## Password manager

- Vault stored at `~/.vodou/vault.dat`, encrypted with
  **Fernet (AES-128-CBC + HMAC-SHA256)** under a key derived from your master
  password with **scrypt** (memory-hard, GPU-resistant). Nothing is ever
  written to disk unencrypted, and a forgotten master password is
  unrecoverable by design.
- **🗄 / Ctrl+Shift+V** — open the vault: add, edit, delete, copy entries,
  and generate strong random passwords (`secrets` module).
- **🔑 / Ctrl+Shift+F** — fill the saved login on the current page.
  Filling is always user-initiated (never automatic), warns on non-HTTPS
  pages, and matches entries by domain (subdomains included).
- Copied passwords are wiped from the clipboard after 30 seconds.
- The vault auto-locks after 5 minutes of inactivity.
- Downloads always require confirmation (no silent drive-by downloads),
  and suggested filenames are stripped of any path components.

## Shortcuts

| Keys | Action |
|---|---|
| Ctrl+T / Ctrl+W | New / close tab |
| Ctrl+Tab | Next tab |
| Ctrl+L | Focus address bar |
| Ctrl+R / F5 | Reload |
| Ctrl+Shift+F | Fill login |
| Ctrl+Shift+V | Open vault |

## Honest limitations

This is a real, working browser, but it's a personal/educational project:
the tracker blocklist is domain-based (no cosmetic filtering or EasyList
rules), fingerprinting resistance is partial, and the vault — while using
sound, standard cryptography — has not been professionally audited. For
credentials you truly care about, an audited manager (Bitwarden, 1Password,
KeePassXC) is the safer home.

## License

Released under the [MIT License](LICENSE) — free to use, modify, and
distribute, with no warranty.
