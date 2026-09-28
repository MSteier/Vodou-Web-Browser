<!--
  This file is NOT auto-synced to Docker Hub. After editing it, manually
  paste the full contents into Docker Hub's "Full Description" field
  (msteier/vodou repo -> General tab -> edit description) or the changelog
  on the live page goes stale. See CLAUDE.md's "Docker Hub release
  checklist" for the full release steps.
-->

# Vodou (containerized)

A privacy-first desktop web browser built on **PyQt6 / QtWebEngine**, packaged
to run in a container and viewed in your web browser — no host X server needed.

**Source & full docs:** https://github.com/MSteier/Vodou-Web-Browser

## Quick start

```bash
docker run -p 8080:8080 -v vodou-data:/home/vodou/.vodou msteier/vodou
```

Then open **http://localhost:8080/** in any browser. Vodou appears there,
running inside the container. Works the same on Windows, macOS, and Linux.

- `-p 8080:8080` — serves the noVNC web viewer. Change the left number to use a
  different local port (e.g. `-p 9000:8080` → http://localhost:9000/).
- `-v vodou-data:/home/vodou/.vodou` — persists your profile (bookmarks, vault,
  plugins) across runs. Drop it for a fully disposable session.
- `-e VNC_GEOMETRY=1920x1080` — optional, sets the virtual screen size.

## Tags
- `latest` — most recent build (includes the built-in web viewer)
- `1.54.6` — pinned version

## Changelog
- **1.54.6** — Fixed an intermittent crash in **Check Bookmarks**: freeing a
  finished link check mid-scan let Qt reuse its memory for a newer check
  before PyQt was done with the old one. On Linux (including this image) that
  aborted the scan with "wrapped C/C++ object of type QNetworkReply has been
  deleted"; on Windows it could close the whole browser. Finished checks are
  now kept until the scan ends and freed together. The Qt & WebEngine
  updater window and its diagnostics report now also show the Chromium
  **security-patch** version, matching About Vodou.
- **1.54.5** — Moved the image to Python 3.14: the base is now
  `python:3.14-slim` (still the slim Debian variant, pinned by digest) instead
  of `python:3.13-slim`, matching the Python the desktop app is developed and
  tested on. The required dependency-audit check now resolves against 3.14 too,
  so it audits the same interpreter the image ships. About Vodou also gained a
  **Security patches** row: Qt WebEngine backports Chrome's security fixes onto
  an older Chromium base, so this shows the Chrome release the engine is
  actually patched through, next to the base Chromium version.
- **1.54.4** — Removed roughly 40 more vulnerabilities by no longer installing
  noVNC and websockify via apt: Debian's `novnc` package hard-depends on
  `websockify`, which drags in `python3-numpy`, `python3-redis`,
  `python3-jwcrypto`, and Node.js — none of which noVNC's static web assets or
  websockify's actual runtime use — plus stale duplicate copies of
  `cryptography`/`urllib3` alongside the current ones Vodou's own dependencies
  install. websockify is now installed via pip (same upstream project, no
  extra baggage); noVNC's web assets are fetched directly from its pinned,
  checksum-verified upstream release — the same v1.6.0 Debian's package
  shipped. No functional change to the web viewer.
- **1.54.3** — Docker Scout found 249 vulnerabilities in the 1.54.2 image, all
  in third-party OS packages and Python libraries, none in Vodou's own code.
  Root causes: the pinned `python:3.13-slim` base digest had gone stale since
  it was set, freezing in since-patched Debian `perl`/`glibc`/`openssl` CVEs
  (all 6 critical findings were here); and a reused Docker build-cache layer
  meant `pip install` never re-resolved `cryptography`/`urllib3` to newer
  patched releases despite floating version requirements. This build bumps
  the base image digest and forces a clean dependency install.
- **1.54.2** — Security and reliability fixes from a full-repo review: a
  deceptive-site warning that could get stuck disabled for the rest of a tab
  after leaving it any way other than its own buttons; a Safe Browsing cache
  that never actually hit for known-safe sites and could lose a feed's
  malware hosts if only one of two feeds failed to refresh; a cross-site
  confirmation for password capture/update on shared-suffix domains (e.g.
  `*.github.io`), matching the existing fill-time warning; vault auto-lock no
  longer stays deferred just because an unrelated dialog is open; a hung
  security-key ceremony can no longer freeze the whole window; the vault file
  gets the same permission hardening on Windows that it already had on Linux;
  a malformed bookmarks file can no longer crash startup; a TOCTOU symlink
  race in secure delete is closed; and credential capture no longer risks
  grabbing an unrelated form field as the username.
- **1.54.1** — **Manage bookmarks… → Check Bookmarks…**, a fast HEAD/GET link
  checker that needs no AI model: only failed bookmarks are listed (HTTP
  errors, DNS failures, timeouts, SSL errors, redirect loops), with adjustable
  timeout and concurrency. A rate-limited or overloaded server (429/503) is
  backed off and retried on the same method — honoring `Retry-After` — instead
  of being hammered or misreported as broken. Also adds **Review with local
  AI…**, which compares fetched page text against the saved title/URL via your
  local Ollama model to flag replaced pages, parked domains, or soft error
  pages that a status-code check alone would miss; failures are retried up to
  three times before being shown for review, and removal always requires
  confirmation. Local AI chat also gained an optional **Search web** toggle
  that sends only the latest typed question through SearXNG to upstream search
  engines for current results and source links — inference stays local, and
  the toggle is remembered.
- **1.53.1** — The **☰ menu → Bookmarks** submenu and the **▤ toolbar
  dropdown** now list saved bookmarks alphabetically by title (case-
  insensitively); the stored order, and bookmarks-bar drag ordering, are
  unchanged. This build also refreshes the bundled PyQt6 / Qt WebEngine
  runtime wheels.
- **1.53.0** — New coordinated updater for the Qt stack (**About → "Qt &
  WebEngine…"**). It treats PyQt6, PyQt6-WebEngine and their bundled Qt +
  Chromium runtime as one dependency group: resolves a mutually compatible
  set from PyPI, never upgrades Python or mixes incompatible versions, backs
  up the current packages before touching anything, verifies every download
  against PyPI's published SHA-256, and finishes on restart via a separate
  helper that rolls back automatically and relaunches Vodou if anything
  fails. Adds a copy-paste diagnostics report (versions, OS, packaging,
  install directory). This image ships the updated **Qt WebEngine 6.11.2**
  runtime. *In the container you update by pulling a newer image tag — the
  in-app Qt updater is for source installs and reports itself unavailable
  here.*
- **1.52.0** — Password vault overhaul: local strength analysis, a strong-
  password generator, cross-site password-reuse detection, automatic exact-
  duplicate cleanup, and a redesigned dashboard (Website / Website Safety /
  Username-Email / Password / Strength / Duplicated / Last Changed columns).
  Ask AI gained "Check this site," which grounds answers about a page's
  safety in Vodou's own local spoofcheck/Safe Browsing/certificate checks
  instead of the model guessing. Fixed a credential-capture race where a
  fast post-login redirect could occasionally attribute a submitted
  password to the wrong site.
- **1.50.0** — Fixed a crash-loop on Linux hosts with no desktop keyring
  (Secret Service/KWallet unavailable, e.g. this VNC image): the session
  autosave and setting-protection snapshot writers only caught `OSError`
  around at-rest sealing, but a missing keyring raises a different
  exception — it escaped a Qt timer slot and crashed the app every ~13s,
  which under `--restart unless-stopped` looked like the container
  restarting forever. Both writers now fail closed the same way the
  cookie jar already did: skip the write, keep running.

## How it works

The image carries its own virtual display: **Xvfb** (headless X server) + a
light window manager + **x11vnc** + the **noVNC** web client. The container
renders Vodou onto the virtual display and streams it to your browser over the
port you published. There is nothing to install on the host.

## Security note — Chromium sandbox

To run with **no special flags**, this image starts with Chromium's sandbox
**OFF** (`QTWEBENGINE_DISABLE_SANDBOX=1`); the container prints a notice saying
so at startup. To keep the sandbox on, run with:

```bash
docker run -p 8080:8080 --cap-add SYS_ADMIN \
  -e QTWEBENGINE_DISABLE_SANDBOX=0 \
  -v vodou-data:/home/vodou/.vodou msteier/vodou
```

Runs as a **non-root** user (`vodou`, uid 10001).

## Notes
- One Windows-only feature — unlocking the vault with a **FIDO2 security key** —
  is not available in the Linux container (the vault still works via password);
  everything else runs normally.
- Prefer a native window (Linux host with its own X server, no VNC)? The
  repository ships a minimal `./Dockerfile` for that; build it yourself and run
  with `-e DISPLAY` + `--cap-add SYS_ADMIN`. See the repo for details.

## License / issues
See the GitHub repository for source, license, and issue tracking:
https://github.com/MSteier/Vodou-Web-Browser
