#!/usr/bin/env sh
# Adds Vodou to the application menu for the current user.
#
# Installs per-user (~/.local/share), so no root and no package manager. It
# only writes a launcher and an icon — the code keeps running from this
# checkout, which is what the in-app updater (About -> Update) expects, since
# that updater does `git pull` against this directory.
#
# Undo:  rm ~/.local/share/applications/vodou.desktop \
#           ~/.local/share/icons/hicolor/128x128/apps/vodou.png
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname -- "$here")

# Prefer the venv the README tells people to create, so the launcher keeps
# working when it is started from a menu with no shell environment.
if [ -x "$repo/.venv/bin/python" ]; then
    python_bin="$repo/.venv/bin/python"
else
    python_bin=$(command -v python3 || command -v python) || {
        echo "error: no python found on PATH" >&2
        exit 1
    }
    echo "note: no .venv found, using $python_bin"
fi

if [ ! -f "$repo/main.py" ]; then
    echo "error: main.py not next to packaging/ — run this from the checkout" >&2
    exit 1
fi

apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
icons="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/128x128/apps"
mkdir -p "$apps" "$icons"

# The launcher must cd into the checkout: main.py resolves sibling modules
# relative to itself, but the updater resolves the repo relative to cwd.
exec_line="sh -c 'cd \"$repo\" && exec \"$python_bin\" main.py'"

sed "s|@EXEC@|$exec_line|" "$here/vodou.desktop" > "$apps/vodou.desktop"
cp "$here/vodou.png" "$icons/vodou.png"

# Non-fatal: the entry still works after a re-login without these.
command -v update-desktop-database >/dev/null 2>&1 \
    && update-desktop-database "$apps" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null 2>&1 \
    && gtk-update-icon-cache -f -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null || true

echo "Installed. Vodou should appear in your application menu."
echo "  launcher: $apps/vodou.desktop"
echo "  icon:     $icons/vodou.png"
