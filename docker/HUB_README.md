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
- `1.53.1` — pinned version

## Changelog
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
