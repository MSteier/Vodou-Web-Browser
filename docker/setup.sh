#!/usr/bin/env sh
# One-time setup for the Vodou backend bundle (macOS / Linux).
#   1. creates .env from .env.example (if missing)
#   2. writes a unique random secret_key into searxng/settings.yml
#   3. creates the noVNC viewer's LAN password (random per install, shown
#      once) or replaces the old published default -- see README.md
#
# Run from this folder:  ./setup.sh
# Then:  docker compose up -d          (search only)
#        docker compose --profile ai up -d   (search + AI summaries)

set -eu
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
else
  echo ".env already exists — leaving it as is"
fi

SETTINGS="searxng/settings.yml"
if grep -q "__REPLACE_WITH_RANDOM_SECRET__" "$SETTINGS"; then
  if command -v openssl >/dev/null 2>&1; then
    SECRET="$(openssl rand -hex 32)"
  else
    SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
  # Portable in-place edit (BSD/macOS and GNU sed).
  sed -i.bak "s/__REPLACE_WITH_RANDOM_SECRET__/$SECRET/" "$SETTINGS" && rm -f "$SETTINGS.bak"
  echo "Wrote a unique secret_key into $SETTINGS"
else
  echo "secret_key already set — leaving it as is"
fi

# Viewer LAN password: generated here, on the host, never at image build time.
# Only its hash is stored, in a host file that survives `docker compose
# down/up`. Re-running is safe: an existing password is kept, and an install
# still on the old published default gets a new random one.
HTPASSWD="${VODOU_VIEWER_HTPASSWD:-}"
if [ -z "$HTPASSWD" ] && [ -f .env ]; then
  HTPASSWD="$(sed -n 's/^VODOU_VIEWER_HTPASSWD=//p' .env | tail -n 1 | tr -d '\r"')"
fi
PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
done
if [ -z "$PY" ]; then
  echo "WARNING: Python not found, so the viewer LAN password was not set up."
  echo "         Install Python, then run:  python manage_viewer_password.py seed"
elif [ -n "$HTPASSWD" ]; then
  "$PY" manage_viewer_password.py --file "$HTPASSWD" seed
else
  "$PY" manage_viewer_password.py seed
fi

cat <<'EOF'

Done. Next:
  docker compose up -d                  # search only
  docker compose --profile ai up -d     # search + AI summaries

Then open Vodou — it defaults to https://localhost/searxng
EOF
