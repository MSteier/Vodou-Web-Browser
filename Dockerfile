# Vodou — privacy browser (PyQt6 / QtWebEngine) in a container.
#
# This is a GUI desktop app, not a server. The container has no display of its
# own: you run it against an X11 display you provide (your host's X server, or
# an Xvnc/Xephyr you point it at). See the run instructions in docker/README or
# the notes at the bottom of this file.
#
# The PyQt6 / PyQt6-WebEngine wheels bundle Qt6 and Chromium, so we only install
# the low-level system libraries those bundled binaries load at runtime, plus
# fonts. No Qt is built from source here.

FROM python:3.13-slim

# ---- Runtime system libraries Qt6 + the bundled Chromium dlopen at runtime ---
# Grouped roughly: GL/EGL + GBM, glib/dbus, X11 + the xcb platform plugin set,
# xkbcommon, the X extensions Chromium needs, NSS (TLS), ALSA, and a font.
RUN apt-get update && apt-get install --no-install-recommends -y \
        libgl1 libegl1 libgbm1 libglib2.0-0 libdbus-1-3 \
        libx11-6 libx11-xcb1 libxext6 libxrender1 libxcb1 \
        libxcb-glx0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
        libxcb-randr0 libxcb-render-util0 libxcb-render0 libxcb-shape0 \
        libxcb-shm0 libxcb-sync1 libxcb-util1 libxcb-xfixes0 \
        libxcb-xinerama0 libxcb-xkb1 libxcb-cursor0 \
        libxkbcommon0 libxkbcommon-x11-0 libxkbfile1 \
        libxcomposite1 libxdamage1 libxrandr2 libxi6 libxtst6 libxcursor1 \
        libnss3 libnspr4 libasound2t64 libpulse0 \
        libgssapi-krb5-2 libcups2 libharfbuzz0b \
        libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libcairo-gobject2 \
        libatk1.0-0t64 libgdk-pixbuf-2.0-0 libgtk-3-0t64 \
        fonts-dejavu-core fontconfig \
    && rm -rf /var/lib/apt/lists/*

# ---- Python dependencies -----------------------------------------------------
# Copied first so a code-only change doesn't reinstall the (large) wheel set.
# fido2 is declared win32-only in requirements.txt, so pip skips it on Linux.
WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
        -r requirements.txt

# ---- Application source -------------------------------------------------------
COPY . .

# ---- Run as a non-root user (keeps the Chromium sandbox usable and is good
#      hygiene for a browser). HOME is where Vodou keeps ~/.vodou state; mount a
#      volume there to persist bookmarks/vault/plugins across runs.
RUN useradd --create-home --uid 10001 vodou \
    && chown -R vodou:vodou /app
USER vodou
ENV HOME=/home/vodou
VOLUME ["/home/vodou/.vodou"]

# X11 is the default Qt platform; a Wayland host can override with
# -e QT_QPA_PLATFORM=wayland. We deliberately do NOT set
# QTWEBENGINE_DISABLE_SANDBOX here — the sandbox stays on. Run the container
# with --cap-add SYS_ADMIN so Chromium's sandbox can initialise, or (at your
# own risk) set QTWEBENGINE_DISABLE_SANDBOX=1 at run time.
ENV QT_QPA_PLATFORM=xcb

CMD ["python", "main.py"]

# ---- How to run --------------------------------------------------------------
# Linux host (share your X server):
#   xhost +local:
#   docker run --rm \
#     -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix \
#     --cap-add SYS_ADMIN --shm-size=1g \
#     -v vodou-data:/home/vodou/.vodou \
#     <namespace>/vodou:latest
#
#   --shm-size=1g stops Chromium crashing on the default 64MB /dev/shm.
#   -v vodou-data:/home/vodou/.vodou persists your profile.
#
# macOS / Windows hosts have no native X server the container can reach; use an
# X server (XQuartz / VcXsrv) or a VNC-based image instead. On those hosts the
# native installers are the better path.
