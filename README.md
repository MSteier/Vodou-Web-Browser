# Vodou Browser

**by Mist Technologies** — co-authored by Claude Fable 5

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
| Cookies & history never persist | Cookies are memory-only and die with the process, except for sites you explicitly allowlist — see *Cookie exceptions*. The bulky, low-sensitivity artifacts (HTTP cache, site storage) live in a size-capped disk folder for performance and are **securely shredded** on every exit — see *Performance & secure shredding* |
| Tracker & ad blocking | Request interceptor blocks ~100 known tracker/ad domains (counter in the status bar). Click the counter — or ☰ menu → Settings → Pause tracker blocking — to let requests through on a site that breaks with blocking on; session-only, so protection always resumes on the next start |
| Opt-out signals | `DNT: 1` and `Sec-GPC: 1` (Global Privacy Control) on every request |
| Reduced fingerprinting | Generic Chrome user agent; DNS prefetch, hyperlink auditing, and plugins disabled |
| WebRTC IP-leak protection | Chromium flag restricts WebRTC to the public interface |
| HTTPS-first | Bare domains typed in the address bar load over HTTPS |
| Private search | Local SearXNG instance (`https://localhost/searxng`) as home page and default search — queries never go to a third-party engine directly. Self-signed certificates are accepted for localhost only. |
| No telemetry | Nothing about you or your browsing is ever sent anywhere. The only outbound calls of Vodou's own are the two anonymous version checks described in *About & updates* |
| Download manager | Every download is user-approved (no drive-by saves), then tracked in a Downloads panel (**Ctrl+J**) with live progress, cancel, and open-folder; the list is session-only like everything else |
| Clear on demand | **Ctrl+Shift+Del** (or the ☰ menu) wipes the session cache (memory and disk), cookies, visited-link history, and every tab's back/forward memory, with a confirmation of what was cleared |
| Certificate viewer | Padlock next to the address bar (green = verified HTTPS, red = unencrypted); click it for a full certificate view: subject, SANs, issuer, validity, key, fingerprints, TLS version, with verification against the system root store |

Extend the blocklist by adding domains (one per line) to
`~/.vodou/blocklist.txt`.

## Performance & secure shredding

Early versions kept *everything* — including Chromium's HTTP cache — in RAM,
which starved machines with 16 GB or less during heavy browsing. Vodou now
uses a **hybrid profile** that keeps the security posture while cutting the
memory footprint:

- **Memory-only (unchanged):** cookies — the truly sensitive record of your
  logins — never touch disk and die with the process.
- **On disk, capped at 512 MB:** the HTTP cache and site storage
  (localStorage etc.) live in `~/.vodou/profile`. Revisited pages come from
  disk cache instead of RAM or the network.
- **Securely shredded:** on every clean exit, every file in that folder is
  overwritten with random bytes (forced to disk with `fsync`) and then
  deleted — a recovery tool finds noise, not your browsing. The same shred
  runs again **at startup**, so a crash or a briefly-locked file can't leave
  anything readable behind; nothing survives more than one launch cycle.

**Reload always fetches fresh.** The disk cache exists to spare RAM, not to
speed up reloads — and a page whose content depends on a cookie (site
preference pages are the classic case) often ships no `Cache-Control` or
`Vary`, so a cache-allowed reload can serve a stale copy after you change a
setting. **Ctrl+R / F5 / ⟳** therefore bypass the cache and re-fetch, so an
explicit reload always shows the live page; ordinary link-clicking and
re-navigation still use the cache.

*Honest caveat:* on SSDs, wear-leveling means an overwrite isn't guaranteed
to hit the same physical cells as the original data. The complete answer to
that is full-disk encryption (BitLocker / FileVault / LUKS); the shredder is
defence in depth on top, not a substitute. Mid-session, **Ctrl+Shift+Del**
clears the disk cache with ordinary deletion (the engine holds the files
open, so they can't be overwritten while running) — the secure shred always
covers the whole folder at exit.

## Cookie exceptions

Memory-only cookies are the right default, but they also forget the logins
and site settings you *want* kept. **☰ menu → Settings → Cookie
exceptions…** lists the sites that are exempt: add a bare host like
`youtube.com` (subdomains included), `localhost`, or an IP.

- Everything not on the list is unchanged: memory-only, erased on exit.
- Listed sites' cookies are mirrored to `~/.vodou/cookies.dat` and restored
  at the next start. QtWebEngine's cookie persistence is profile-wide
  (all-or-nothing), so Vodou does the selection itself: it watches the live
  cookie store and keeps only the allowlisted subset.
- **Encrypted at rest with Windows DPAPI** — the same per-user OS
  encryption Chrome uses for its own cookie database, so no password prompt
  and no other Windows account can read it. *Honest limit:* as with
  Chrome's jar, software running as **you** could decrypt it. On
  non-Windows platforms the jar is written unencrypted.
- Only real persistent cookies are kept: session cookies (which the site
  itself marks as "die with the browser") are never saved, and expired ones
  are dropped on restore.
- Writes are debounced (≤1 per 3 s of cookie churn), so busy sites cost
  nothing and a crash loses at most a few seconds of updates.
- **Ctrl+Shift+Del** empties the saved jar too — clearing cookies means all
  of them. The exception *list* survives; only the cookies are wiped.

Note that a site's login cookies often live on a parent or sibling domain
(YouTube's live on `google.com`), so keeping one site signed in can take
more than one entry.

## Crash recovery

If Vodou closes unexpectedly (crash, forced kill, power loss), the next start
asks whether to pick up where you left off — **Restore tabs** reopens
everything; **Start fresh** discards it and opens the usual home tab.

- While running, the open-tab URLs are snapshotted to
  `~/.vodou/session.json` — just the tabs, no history, titles, or form data.
  Writes are debounced (at most one per second, skipped when nothing
  changed), so heavy browsing never queues up disk churn.
- The snapshot is **deleted on every clean exit**, so its presence at
  startup is itself the crash signal — after a normal close, no page URLs
  remain on disk. Declining the restore deletes it too.
- Restored background tabs load **lazily**: each starts loading the first
  time you switch to it (until then the tab shows the site's hostname), so
  recovering a big session costs one page load, not one per tab.

## Password manager

- Vault stored at `~/.vodou/vault.dat`, encrypted with
  **Fernet (AES-128-CBC + HMAC-SHA256)** under a key derived from your master
  password with **scrypt** (memory-hard, GPU-resistant). Nothing is ever
  written to disk unencrypted, and a forgotten master password is
  unrecoverable by design.
- **🗄 / Ctrl+Shift+V** — open the vault: add, edit, delete, copy entries,
  and generate strong random passwords (`secrets` module). The vault is an
  ordinary window, not a modal dialog — it stays usable alongside the
  browser and other apps, drops behind when you click elsewhere, and
  returns via its taskbar button.
- **🔑 / Ctrl+Shift+F** — fill the saved login on the current page.
  Filling is always user-initiated (never automatic), warns on non-HTTPS
  pages, and matches entries by domain (subdomains included). When several
  logins match, a picker lists them — **Select** (or double-click / Enter)
  fills the highlighted one, and **Delete login** removes stale entries
  right from the picker.
- **Change master password** — button in the vault window; re-enters and
  verifies the current master first, then re-encrypts the whole vault under
  the new one (with a fresh salt and current-strength scrypt parameters).
- Copied passwords are wiped from the clipboard after 30 seconds.
- The vault auto-locks after 5 minutes of inactivity; because the vault
  window can be left open in the background, auto-locking closes it too.
  Active use (any add/edit/reveal dialog open) defers the lock.
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
- Bundled: *Dark Mode Everywhere*, *Cookie Banner Zapper*, *Glass Blur
  Deflicker*, *Text Selection Unlocker*.
- *Dark Mode Everywhere* darkens **light** pages only. Its dark styling is
  applied immediately so light pages never flash white, then — once the
  site's own stylesheets have loaded — it measures the page's background
  and withdraws itself if the site was already dark. Without that, its
  inversion would turn an already-dark page light and override whatever
  theme the site (or you) chose, which looks exactly like the site's own
  theme setting being ignored.
- *Glass Blur Deflicker* strips CSS `backdrop-filter` blur ("frosted
  glass"), which can flicker under the hardware compositor on some Windows
  GPU drivers. It reduces the effect while keeping *Hardware* graphics; if
  flicker persists, the real fix is **☰ menu → Settings → Graphics →
  Compatibility** (see the Graphics section).

## Appearance

- **☰ menu → Appearance** — five built-in themes (*Vodou Violet*, *Blood
  Ritual*, *Swamp Green*, *Midnight Blue*, *Bone Amber*) plus a **dark / light**
  toggle. Each theme tints the whole chrome, so the switch is unmistakable.
- Changes apply live and are remembered in `~/.vodou/theme.json`.
- **Zoom** — `Ctrl` `+` / `Ctrl` `-` (or **Ctrl + mouse wheel**, or
  **☰ menu → Zoom**) steps page zoom along Chrome's ladder from 25% to
  500%; `Ctrl+0` resets. The level you pick applies to new tabs for the
  rest of the session, and the footer shows each change (e.g. "Zoom: 125%").

## Graphics

Some Windows GPU drivers make Qt WebEngine's hardware compositor flicker on
pages that combine "frosted glass" (`backdrop-filter`) styling, WebGL, and a
blinking text caret — chat UIs like my.replika.ai are the classic case (the
input field and chat bubbles pulse while the window is focused). No Chromium
flag fixes it; switching the compositor does.

- **☰ menu → Settings → Graphics** — three profiles, remembered in
  `~/.vodou/graphics.json` and applied on the next start:
  *Hardware* (fastest), *Compatibility* (software compositing, WebGL stays on
  the GPU — **fixes the flicker**), and *Software* (no GPU at all, most
  stable).
- Per-launch override for debugging: `python main.py --gfx
  default|vanilla|compat|gl|warp|software`.

## Developer tools

- **F12** or **☰ menu → Developer tools** — the full Chromium DevTools
  (inspector, console, network, sources) **docked to the right** of the window
  in a resizable split. It follows the active tab.
- Close it with the **✕** in its header or by pressing **Esc**. It runs on the
  off-the-record profile, so it persists nothing.

## Help, issue reporting & updates

**☰ menu → Help** collects the support tools:

- **Report an issue…** — opens a new GitHub issue with the environment
  pre-filled: Vodou version **and the exact git commit**, Chromium / Qt /
  PyQt / Python versions, and your OS. Every report pins the precise code
  it's about.
- **View on GitHub** — opens the repository.
- **About Vodou…** — version info and the one-click updater (below).

Version numbers everywhere (footer, About dialog, issue reports) include the
short hash of the checked-out commit — e.g. `v1.5.0 (28fae28)` — read
directly from the repo's `.git` files, so it works even where git isn't
installed.

**Help → About Vodou…** shows the app version and the live Chromium / Qt /
PyQt / Python versions, and offers an **Update Vodou & engine** button that
updates both parts of the browser in one click: it pulls the latest Vodou
from GitHub (`git pull --ff-only`, so a locally modified checkout is never
silently merged), then upgrades the bundled Chromium/Qt engine via pip. The
summary tells you what was updated or that you're already current.

The footer shows the running version (click it to open the GitHub repo).
About ten seconds after startup, Vodou checks whether a newer version of
either part exists; if so, the footer tag changes to **"update available"**
and clicking it takes you to the one-click updater.

*Privacy note:* the startup check makes two anonymous HTTPS GETs of public
files — `raw.githubusercontent.com` (Vodou's version number) and `pypi.org`
(the engine package index). No identifiers, telemetry, or browsing data are
sent, and a failed check does nothing.

## Shortcuts

| Keys | Action |
|---|---|
| Ctrl+T / Ctrl+W | New / close tab |
| Ctrl+Tab | Next tab |
| Ctrl+L | Focus address bar |
| Ctrl+R / F5 | Reload (bypasses the cache — always fetches fresh) |
| Ctrl + + / − (or Ctrl + wheel) | Zoom in / out |
| Ctrl+0 | Reset zoom |
| Ctrl+D | Bookmark current page |
| Ctrl+J | Downloads |
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
YouTube works normally in Vodou** — passkeys via Windows Hello included.

Reliability details (each cost real debugging time):

- **The navigation waits for the disguise.** A navigation that requires an
  identity switch is held, the switch is applied (deferred one event-loop
  tick — mutating the profile from inside `acceptNavigationRequest` aborts
  the process), and only then is the navigation re-issued. The first request
  to reach Google therefore always carries a fully consistent Firefox
  identity; early versions let the two race, which made first sign-in
  attempts fail intermittently. Re-issuing can't loop: on re-entry no switch
  is needed.
- **The identity is sticky through the flow.** The profile identity is
  shared across tabs, and a sign-in bounces through redirects, popups, and
  the site's OAuth callback. Vodou keeps the Firefox identity for a 90-second
  grace period after the last auth-host navigation, so none of those hops
  (nor another tab navigating mid-flow) flips the identity — and reloads
  pages — in the middle of the handshake. The first navigation after the
  grace period quietly reverts to the generic Chrome identity. While the
  Firefox identity is active it is consistent *everywhere*: every request
  presents as Firefox with no Chrome client hints, and on the auth pages a
  main-world script removes the JS-visible Chromium giveaways
  (`window.chrome`, `navigator.userAgentData`, `navigator.vendor`) and adds
  Firefox's own (`buildID`, `oscpu`).
- **Passkeys (Windows Hello) work on the first attempt.** Qt WebEngine
  performs WebAuthn ceremonies fine, but its
  `PublicKeyCredential.getClientCapabilities()` promise never settles
  ([qutebrowser#8930](https://github.com/qutebrowser/qutebrowser/issues/8930)),
  so any sign-in flow that awaits capability detection stalls and gets
  reported as a defective client — Google showed "this browser may not be
  secure" *after* a successful passkey ceremony (rejection code `rrk=46`,
  next to `rrk=47` "JavaScript disabled"), and only about one attempt in
  four got through. Vodou shims the call on every site to resolve
  immediately with the engine's true capabilities — user-verifying platform
  authenticator: yes; conditional/autofill passkey UI: no — which steers
  sites onto the modal Windows Hello flow that works. The same engine bug
  also breaks e.g. ChatGPT's login modal, so the shim is site-agnostic.

## License

Released under the [MIT License](LICENSE) — free to use, modify, and
distribute, with no warranty.
