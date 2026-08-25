#!/usr/bin/env sh
# Adds Vodou to the application menu for the current user.
#
# Installs per-user (~/.local/share), so no root and no package manager. It
# only writes a launcher and an icon — the code keeps running from this
# checkout, which is what the in-app updater (About -> Update) expects, since
# that updater does `git pull` against this directory.
#
# Undo:  rm ~/.local/share/applications/vodou.desktop \
#           ~/.local/share/icons/hicolor/128x128/apps/vodou.png \
#           ~/.local/share/vodou/launch.sh
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
vodou_dir="${XDG_DATA_HOME:-$HOME/.local/share}/vodou"
mkdir -p "$apps" "$icons" "$vodou_dir"

# The Desktop Entry spec's Exec grammar has its own (limited) quoting rules —
# distinct from shell quoting, and stricter: single quotes are a "reserved
# character" that can't appear at all, so a `sh -c '...'` one-liner embedded
# directly in Exec= (as this used to be) is invalid regardless of how
# carefully it's escaped, and desktop-file-validate correctly rejects it. A
# plain launcher *file* sidesteps the whole problem: Exec just names an
# executable plus %u, with no shell operators or quoting for the spec to
# object to.
#
# The launcher must cd into the checkout: main.py resolves sibling modules
# relative to itself, but the updater resolves the repo relative to cwd. The
# trailing "$@" forwards a launched-with-a-link's URL through to main.py (see
# main._startup_url_from_argv) — %u in the .desktop file supplies that
# argument when Vodou is opened via a link.
launcher="$vodou_dir/launch.sh"
cat > "$launcher" <<LAUNCHER
#!/bin/sh
cd "$repo" && exec "$python_bin" main.py "\$@"
LAUNCHER
chmod +x "$launcher"

exec_line="\"$launcher\" %u"

# Escape the sed-replacement metacharacters before substituting: in a sed
# replacement, & means "the matched text" and \ and the | delimiter are also
# special, and $launcher could in principle contain either. Prefix each with
# a backslash so the launcher path always survives substitution literally.
exec_esc=$(printf '%s' "$exec_line" | sed 's/[&\|]/\\&/g')
sed "s|@EXEC@|$exec_esc|" "$here/vodou.desktop" > "$apps/vodou.desktop"
cp "$here/vodou.png" "$icons/vodou.png"

# Non-fatal: the entry still works after a re-login without these.
command -v update-desktop-database >/dev/null 2>&1 \
    && update-desktop-database "$apps" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null 2>&1 \
    && gtk-update-icon-cache -f -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null || true

echo "Installed. Vodou should appear in your application menu."
echo "  launcher: $apps/vodou.desktop"
echo "  icon:     $icons/vodou.png"
