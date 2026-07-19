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
| Tracker & ad blocking | Request interceptor blocks ~100 known tracker/ad domains (counter in the status bar; charts in ☰ menu → *Blocking report*). Click the counter — or ☰ menu → Settings → Pause tracker blocking — to let requests through on a site that breaks with blocking on; session-only, so protection always resumes on the next start |
| Opt-out signals | `DNT: 1` and `Sec-GPC: 1` (Global Privacy Control) on every request |
| Reduced fingerprinting | Generic Chrome user agent; DNS prefetch, hyperlink auditing, and plugins disabled |
| WebRTC IP-leak protection | Chromium flag restricts WebRTC to the public interface |
| HTTPS-first | Bare domains typed in the address bar load over HTTPS |
| Private search | Local SearXNG instance (`https://localhost/searxng`) as home page and default search — queries never go to a third-party engine directly. Self-signed certificates are accepted for localhost only. |
| No telemetry | Nothing about you or your browsing is ever sent anywhere. Vodou's only outbound calls of its own are the two anonymous version checks (*About & updates*) and the anonymous periodic download of the public Safe Browsing lists (*Safe Browsing*) — public files fetched by IP, carrying no identifiers and no browsing data. The optional AI search summaries talk only to a **local** Ollama instance, so they add no off-device traffic either |
| AI search summaries (local) | Optional, off-by-default: a ✨ button on a search-results page summarizes the top results using your **own local [Ollama](https://ollama.com) instance**. Vodou reads the results from the local SearXNG page and streams a summary into a side panel — SearXNG is local, Ollama is local, so nothing about your search leaves the machine. Vodou is only an HTTP client of Ollama and never changes its models or config. See *AI search summaries* |
| Deceptive-site protection | Every address you navigate to is checked **locally** for look-alike (homograph), mixed-alphabet/punycode, and typosquatting imitations of well-known brands. A suspected spoof is blocked with a full-screen warning that shows the real vs. deceptive address and its un-fakeable punycode spelling. See *Deceptive-site protection* |
| Safe Browsing (local) | Navigations are checked **entirely on your device** against public phishing/malware **domain** lists — no per-URL lookup, so nothing about your browsing is ever sent out. A reported host is blocked with the same full-screen warning. See *Safe Browsing* |
| Download manager | Every download is user-approved (no drive-by saves); executable/installer types (`.exe`, `.msi`, `.bat`, `.ps1`, `.dmg`, …) that can run code get a sterner, default-**No** warning. Approved downloads are tracked in a Downloads panel (**Ctrl+J**) with live progress, cancel, and open-folder; the list is session-only like everything else |
| Clear on demand | **Ctrl+Shift+Del** (or the ☰ menu) wipes the cache (memory and disk), cookies — *including* the saved jar for allowlisted sites — this session's blocking counts, visited-link history, and every tab's back/forward memory, with a confirmation of what was cleared. Quitting is not a substitute for the cookies: exit deliberately keeps the saved cookie jar, so this is the only control that destroys it (and the only way to drop cookies without losing your open tabs) |
| Certificate viewer | A security pill **inside** the address bar (green closed padlock = verified HTTPS, red open padlock = unencrypted, muted info dot = internal page); click it for a full certificate view: subject, SANs, issuer, validity, key, fingerprints, TLS version, with verification against the system root store |

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

## Blocking report

**☰ menu → Blocking report…** opens a native window (not a page) charting
what the blocker actually did: a headline total for the period, a column
chart of requests blocked, and a ranked list of the trackers that came up
most. The period selector picks the window *and* its bar size — **Past
hour** (per-minute) or **Past 24 hours** (per-hour) — figures stay live while
it's open, and hovering any column gives its exact figure. It follows the
active theme in dark and light.

Because which trackers you meet implies where you were, the counts are
treated as browsing data — and kept the same way as your history:

- **In memory only.** Nothing about what was blocked is ever written to
  disk. The counts live in RAM and die with the process, exactly like
  cookies and history — so there is no persisted record of when you browse.
- **Bounded to the session**, per blocked host, per minute. No URLs, no
  record of which site you were on, no ordering. That 24-hour in-memory
  buffer is why the longest period the report offers is the past 24 hours.
- **Ctrl+Shift+Del drops them immediately**, and the window has its own
  *Reset statistics…* button; otherwise they simply go when Vodou closes.

## Deceptive-site protection

Phishing sites impersonate a real address to steal passwords and payment
details. Vodou checks every main-frame navigation **entirely on the machine** —
no Google Safe Browsing, no reputation service, nothing about where you go
leaves your computer — against three heuristics computed from the hostname:

- **Look-alike (homograph)** — confusable characters that collapse a domain
  onto a brand it is not: Cyrillic `pаypal.com`, Greek letters, digit swaps
  (`g00gle`, `paypa1`), and the `rn`→`m` ligature (`arnazon`).
- **Mixed-alphabet / punycode** — a single label fusing Latin with
  Cyrillic/Greek, or a domain that renders from punycode (`xn--`). This is
  almost always an attack and needs no brand list.
- **Typosquatting** — a one-character misspelling of a known brand
  (`gooogle`, `faceook`), limited to longer brand names so ordinary domains
  aren't false-flagged.

Detection is heuristic and protects a **curated list of the most-impersonated
brands** (big tech, mail, payments, banks, crypto), not the whole web, and
errs toward silence over false alarms.

A suspected spoof is **blocked before it loads** and replaced with a full-page
warning that names the brand it imitates, shows the deceptive address, and —
crucially — reveals its **punycode "true spelling"** (`xn--pypal-4ve.com`),
the one form two identical-looking homographs can't share. **Go back (safe)**
returns you to safety; **Continue anyway** trusts that host for the rest of
the session only (the warning returns next launch). The whole page is
generated locally with no network access, and the deceptive host is only ever
displayed as escaped text, never executed.

The check only runs on an actual navigation: a bare word with no dot typed in
the address bar is a search, as in any browser — but clicking a search result
that leads to a look-alike domain is still caught.

## Safe Browsing

Where the deceptive-site check reasons about a name, Safe Browsing checks it
against **public lists of already-reported phishing and malware domains** —
and it does so **without the privacy cost that "safe browsing" usually
carries.** The mainstream approach sends every URL you visit to a server for a
verdict, which is a browsing log by another name. Vodou never does that:

- **Checked entirely on your device.** The bad-domain lists are downloaded and
  held in memory; each navigation is a local set-membership test. **No URL, no
  hash, and no hash prefix ever leaves your machine.**
- **The only network activity** is an anonymous, periodic download of the
  public lists (on startup and every 12 hours), fetched by IP like any public
  file — the same kind of request as the version check, carrying nothing about
  your browsing. The merged list is cached at `~/.vodou/safebrowsing.dat` so
  protection is live at startup, and a failed refresh keeps the cache rather
  than dropping cover.
- A reported host is **blocked before it loads** with the same full-screen
  warning as the deceptive-site check; **Continue anyway** trusts it for the
  session only.

Honest limits, stated plainly: this is **domain-level, not per-URL** (a bad
path on an otherwise-fine host isn't caught), and it's **periodically
refreshed**, so a brand-new phishing domain can slip the window until the next
update. It layers with the deceptive-site detection, which needs no list.

- **☰ menu → Settings → Safe Browsing** toggles it (on by default);
  **Safe Browsing status…** shows the host count and last update.
- Default sources are no-API-key public feeds (abuse.ch URLhaus for malware,
  the Phishing.Database ACTIVE list for phishing). Point it elsewhere by
  listing URLs in `~/.vodou/safebrowsing_sources.txt`, or add your own hosts
  in `~/.vodou/safebrowsing_extra.txt`.

## AI search summaries

An optional, **on-device** summary of your search results, produced by your
own local [Ollama](https://ollama.com) instance. It keeps the same privacy
guarantee as the rest of Vodou: your search never leaves the machine.

- Run a search (local SearXNG as usual), then click the **✨ button** in the
  toolbar. A side panel opens and streams a concise summary of the top results,
  with citations you can click to open a source in a new tab.
- A **model dropdown** at the top of the panel lists the models installed in
  your local Ollama (refreshed each time the panel opens, so anything you
  `ollama pull` later shows up). Pick one and click **Regenerate**; your choice
  is saved for next time.
- **How it stays private:** Vodou reads the top results straight from the
  rendered SearXNG page (no SearXNG configuration needed) and sends them, with
  your query, to Ollama on `127.0.0.1`. SearXNG is local and Ollama is local,
  so nothing about the search is transmitted off-device. Vodou is purely an
  HTTP client of Ollama's API — it never changes Ollama's models, config, or
  environment, so anything else you run against Ollama keeps working unchanged.
- **On-demand only**, so it never loads a model behind your back. Reasoning
  models (e.g. `deepseek-r1`) show a *Reasoning…* indicator while they think;
  their `<think>` scratchpad is hidden and only the final summary is shown.
- **☰ menu → Settings → AI search summaries (Ollama)** toggles the feature
  (off by default); **AI summary options…** shows the current model, endpoint,
  and config-file path.
- Configure it in `~/.vodou/ai_search.json` — `model`, `endpoint`,
  `max_results`, `keep_alive` (how long Ollama keeps the model resident after a
  summary), and `temperature`. Tip: set `model` to whichever model you already
  keep loaded to avoid a VRAM swap.

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
- Downloads always require confirmation (no silent drive-by downloads), and
  the server-suggested filename is sanitised: path components, NTFS
  alternate-data-stream colons (`report.pdf:evil.exe`), reserved device names
  (`CON`, `NUL`, `COM1`…), and trailing dots/spaces are stripped so a crafted
  name can't write outside Downloads or hide an executable.

## Bookmarks

Bookmarks are the one thing kept between sessions — saved as plain JSON at
`~/.vodou/bookmarks.json` (they hold no secrets), with atomic writes.

- **☆ / Ctrl+D** — bookmark (or un-bookmark) the current page; the star fills
  in when a page is saved.
- **Bookmarks bar** — a strip under the address bar listing your bookmarks,
  kept in **alphabetical order automatically**, with a `»` overflow menu when
  there are more than fit. Clicking one opens it in a **new tab**. It hides
  itself when you have no bookmarks.
  - **Favicons** on the bar are captured from pages **as you browse** and at
    the moment you bookmark — never fetched from a third-party favicon service
    (which would leak your bookmark list). They're cached only for hosts you
    have bookmarked (under `~/.vodou/favicons/`) and pruned when a bookmark is
    removed; a bookmark with no captured icon yet shows a generic globe.
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
- Bundled: *Cookie Banner Zapper*, *Glass Blur Deflicker*, *Text Selection
  Unlocker*.
- A *Dark Mode Everywhere* plugin was bundled until v1.8.0 and has been
  removed. Forcing a dark scheme onto arbitrary sites means inverting them,
  which fights whatever styling a site already has: it turned already-dark
  pages light, overrode sites' own theme settings, and distorted page
  colours. That is inherent to the approach, not a bug that could be tuned
  out. Use a site's own dark theme where it has one; **☰ menu →
  Appearance** still themes Vodou's own chrome.
- *Glass Blur Deflicker* strips CSS `backdrop-filter` blur ("frosted
  glass"), which can flicker under the hardware compositor on some Windows
  GPU drivers. It reduces the effect while keeping *Hardware* graphics; if
  flicker persists, the real fix is **☰ menu → Settings → Graphics →
  Compatibility** (see the Graphics section).

## Appearance

- **Window layout**, top to bottom: the **tab bar** (with a **+** button just
  to the right of the last tab), then the **address bar**, then the
  **bookmarks bar**, then the page. Tabs can be dragged to reorder, and
  **right-clicking a tab** offers *New tab*, *Close tab* (the one you clicked),
  and *Close other tabs*.
- **☰ menu → Appearance** — five built-in themes (*Vodou Violet*, *Blood
  Ritual*, *Swamp Green*, *Midnight Blue*, *Bone Amber*) plus a **dark / light**
  toggle. Each theme tints the whole chrome, so the switch is unmistakable.
- The toolbar and address-bar icons are **crisp vectors drawn at runtime**
  (no image files) and repaint in the active theme's colours when you switch
  theme or mode — the bookmark star fills in the accent colour, the security
  pill in semantic green/red. The footer centres the version tag, with the
  tracker-blocked counter at the right.
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
silently merged), then upgrades the bundled Chromium/Qt engine via pip. When
an update is actually applied, the summary spells out **what** changed — the
new Vodou version (e.g. `1.10.0 → 1.11.0`), a bulleted list of the changes
that came in (read from the local git log, nothing sent anywhere), and the
new engine package versions — and gives a clear per-part verdict: *applied
successfully*, *partly applied*, *failed*, or *nothing needed updating*. It no
longer reports "you're already current" when something was in fact updated.

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
  pages — in the middle of the handshake. Because Google's sign-in is a
  single-page app (advancing from the email screen to the password screen
  fires no navigation), that grace period is kept alive by the requests the
  sign-in page itself makes while it's open — otherwise a slow password entry
  could outlast it and the post-password redirect would flip the profile back
  to Chrome mid-handshake, the cause of password sign-in taking several tries
  where a near-instant passkey never did. The first navigation after the
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
