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
| Clear on demand | **Ctrl+Shift+Del** (or the ☰ menu) wipes the session cache, cookies, visited-link history, and every tab's back/forward memory, with a confirmation of what was cleared |
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
- **In-memory hardening** — while unlocked, passwords are not held as
  plaintext; each is re-encrypted under a random per-session key and only
  decrypted at the instant it is used (fill, copy, edit).
- **Import / export** — pull passwords in from a Chrome, Edge, Firefox, Brave,
  or Bitwarden **CSV** export, or export the vault to CSV (behind a plain-text
  warning). Buttons are in the vault dialog; import is also on the ☰ menu.
- Downloads always require confirmation (no silent drive-by downloads),
  and suggested filenames are stripped of any path components.

## Bookmarks

Bookmarks are the one thing kept between sessions — saved as plain JSON at
`~/.vodou/bookmarks.json` (they hold no secrets), with atomic writes.

- **☆ / Ctrl+D** — bookmark (or un-bookmark) the current page; the star fills
  in when a page is saved.
- **▤ toolbar dropdown** and the **☰ menu → Bookmarks** submenu both list your
  bookmarks and rebuild each time they open.
- **Manage bookmarks…** — a full manager to add, edit (rename / change URL),
  delete, and open bookmarks.
- **Import** a browser's exported bookmarks HTML (Netscape format).
- Only `http`/`https` URLs are ever stored or opened — `javascript:`, `data:`,
  and `file:` are rejected, even from a tampered file or import.

## Plugins

Qt WebEngine can't load Chrome Web Store extensions, and arbitrary script
injection would be a security hole — so Vodou ships a **curated catalog of
reviewed plugins** (☰ menu → Plugins…) that you simply switch on or off.

- All plugin code lives in Vodou's reviewed source; you never paste code.
- The saved state is **enabled IDs only** (no executable content), so tampering
  with it can at most toggle vetted plugins.
- Each plugin declares a **host allowlist** (least privilege), runs in an
  **isolated world** hidden from page scripts, and shows a **SHA-256 code
  fingerprint** so its identity is tamper-evident.
- Bundled: *Dark Mode Everywhere*, *Cookie Banner Zapper*, *Text Selection
  Unlocker*.

## Appearance

- **☰ menu → Appearance** — five built-in themes (*Vodou Violet*, *Blood
  Ritual*, *Swamp Green*, *Midnight Blue*, *Bone Amber*) plus a **dark / light**
  toggle. Each theme tints the whole chrome, so the switch is unmistakable.
- Changes apply live and are remembered in `~/.vodou/theme.json`.

## Developer tools

- **F12** or **☰ menu → Developer tools** — the full Chromium DevTools
  (inspector, console, network, sources) **docked to the right** of the window
  in a resizable split. It follows the active tab.
- Close it with the **✕** in its header or by pressing **Esc**. It runs on the
  off-the-record profile, so it persists nothing.

## About & updates

**☰ menu → About Vodou…** shows the app version and the live Chromium / Qt /
PyQt / Python versions, and offers an **Update browser engine** button that
upgrades the bundled Chromium/Qt via pip and reports whether an update was
applied or you're already current.

## Shortcuts

| Keys | Action |
|---|---|
| Ctrl+T / Ctrl+W | New / close tab |
| Ctrl+Tab | Next tab |
| Ctrl+L | Focus address bar |
| Ctrl+R / F5 | Reload |
| Ctrl+D | Bookmark current page |
| Ctrl+Shift+F | Fill login |
| Ctrl+Shift+V | Open vault |
| Ctrl+Shift+Del | Clear history & memory |
| F12 | Toggle developer tools |

## Honest limitations

This is a real, working browser, but it's a personal/educational project:
the tracker blocklist is domain-based (no cosmetic filtering or EasyList
rules), fingerprinting resistance is partial, and the vault — while using
sound, standard cryptography — has not been professionally audited. For
credentials you truly care about, an audited manager (Bitwarden, 1Password,
KeePassXC) is the safer home.

### Google sign-in

Google normally **blocks sign-in from embedded rendering engines** (Qt
WebEngine, CEF, Electron webviews, Selenium, …) with *"This browser or app may
not be secure."* This is engine fingerprinting on Google's side, not a security
problem with Vodou — every Qt WebEngine–based browser (Falkon, qutebrowser,
etc.) hits the same wall, and no amount of Chrome-identity consistency defeats
it.

Vodou solves it the way qutebrowser has since 2020 (see
[qutebrowser#5182](https://github.com/qutebrowser/qutebrowser/issues/5182),
shipped there as `content.site_specific_quirks`): a **site-specific identity
quirk**. On Google's account hosts only (`accounts.google.com`,
`accounts.youtube.com`), Vodou presents as Firefox — user agent, HTTP headers,
and `navigator.userAgent` — and sends no `Sec-CH-UA` client hints, exactly
like real Firefox. Everywhere else it keeps its usual generic-Chrome identity.
Firefox identities have remained unblocked for years while Chrome- and
Edge-flavored spoofs keep getting re-blocked, so **signing in to Gmail and
YouTube works normally in Vodou**.

Two implementation notes for the curious (they cost real debugging time):
changing a `QWebEngineProfile` user agent from inside `acceptNavigationRequest`
aborts the process, so the switch is deferred one event-loop tick; and a UA
change reloads the current page, cancelling the in-flight navigation, so the
navigation is re-issued after the switch (a no-op on re-entry, so it can't
loop). One behavioral caveat: the identity is profile-wide, so if another tab
navigates in the middle of a sign-in flow, reload the sign-in page and
continue.

## License

Released under the [MIT License](LICENSE) — free to use, modify, and
distribute, with no warranty.
