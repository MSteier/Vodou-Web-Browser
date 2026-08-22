# Vodou (containerized)

A privacy-first desktop web browser built on **PyQt6 / QtWebEngine**. This image
packages Vodou to run inside a Linux container.

**Source & full docs:** https://github.com/MSteier/Vodou-Web-Browser

> ⚠️ **This is a GUI desktop app, not a headless server.** The container has no
> display of its own — you run it against an X11 display you provide. It's aimed
> at **Linux hosts**. On macOS/Windows the native install is the better path.

## Tags
- `latest` — most recent build
- `1.49.0` — pinned version (reproducible)

## Run it (Linux host with an X server)

```bash
xhost +local:
docker run --rm \
  -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix \
  --cap-add SYS_ADMIN --shm-size=1g \
  -v vodou-data:/home/vodou/.vodou \
  msteier/vodou:latest
```

**Why those flags:**
- `--cap-add SYS_ADMIN` — lets Chromium's sandbox initialise. The sandbox is
  left **on** in this image; it is not silently disabled.
- `--shm-size=1g` — Docker's default 64 MB `/dev/shm` is too small for Chromium
  and causes crashes.
- `-v vodou-data:/home/vodou/.vodou` — persists your profile (bookmarks, vault,
  plugins) across runs.
- `-e DISPLAY` + the `/tmp/.X11-unix` mount — connects the app to your host's
  X server. Wayland hosts can add `-e QT_QPA_PLATFORM=wayland`.

If you prefer not to grant `SYS_ADMIN`, you can instead set
`-e QTWEBENGINE_DISABLE_SANDBOX=1` — but that turns the browser sandbox off, so
only do it if you understand the trade-off.

## Notes
- Runs as a **non-root** user (`vodou`, uid 10001).
- The image bundles Qt6 + Chromium via the official PyQt6 wheels plus the system
  libraries they need at runtime.
- One Windows-only feature — unlocking the vault with a **FIDO2 security key** —
  is not available in the Linux container (the vault still works via password);
  everything else runs normally.

## License / issues
See the GitHub repository for source, license, and issue tracking:
https://github.com/MSteier/Vodou-Web-Browser
