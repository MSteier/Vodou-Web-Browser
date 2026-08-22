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
- `1.49.0` — pinned version

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
