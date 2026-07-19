#!/usr/bin/env sh
# One-time setup for the Vodou backend bundle (macOS / Linux).
#   1. creates .env from .env.example (if missing)
#   2. writes a unique random secret_key into searxng/settings.yml
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

cat <<'EOF'

Done. Next:
  docker compose up -d                  # search only
  docker compose --profile ai up -d     # search + AI summaries

Then open Vodou — it defaults to https://localhost/searxng
EOF
