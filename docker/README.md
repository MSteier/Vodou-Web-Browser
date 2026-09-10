# Vodou backend (Docker)

Vodou is a **desktop app**, so it isn't run from Docker — but the services it
talks to are. This bundle stands those up reproducibly, so Vodou works the
same on any machine without hand-configuring SearXNG, a TLS proxy, and Ollama.

| Service | What it is | Where Vodou reaches it |
|---|---|---|
| `searxng` | Private metasearch engine | via Caddy below |
| `redis` (valkey) | SearXNG's cache/limiter backend | internal only |
| `caddy` | TLS reverse proxy, self-signed via its internal CA | `https://localhost/searxng` |
| `ollama` *(optional)* | Local LLM for AI summaries and chat | `http://127.0.0.1:11434` |

Ollama is also accessible from your WLAN at `http://<host-LAN-IP>:11434` when
the AI service is running. `OLLAMA_BIND_ADDRESS` defaults to `0.0.0.0` (all
IPv4 host interfaces). To restrict access to this computer instead, set it to
`127.0.0.1` in `.env`. Apply a changed binding with
`docker compose --profile ai up -d ollama` from this directory.

Vodou trusts `localhost` certificates, so Caddy's self-signed cert needs **no**
trust-store install.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (Docker Desktop on Windows/macOS)
- The Vodou app itself (see [`../README.md`](../README.md) — `pip install -r
  requirements.txt`, then `python main.py`)

## Quick start

```sh
cd docker
cp .env.example .env          # once

# Windows (PowerShell):  ./setup.ps1
./setup.sh                    # generates a unique SearXNG secret key

# Search only:
docker compose up -d

# ...or search + local AI summaries (also pulls the default model once):
docker compose --profile ai up -d
```

Then launch Vodou. It defaults to `https://localhost/searxng` for search and
`http://127.0.0.1:11434` for AI summaries — exactly what this stack serves.

To stop: `docker compose down` (add `--profile ai` if you started it). Data
(SearXNG cache, Ollama models) persists in named volumes across restarts.

## AI summaries (the `ai` profile)

Starting with `--profile ai` also runs `ollama` and a one-shot `ollama-init`
that pulls the model named by `OLLAMA_MODEL` in `.env` (default `llama3.2`).
Pull more anytime:

```sh
docker compose exec ollama ollama pull mistral
```

They then appear in Vodou's in-panel model picker.

**GPU:** Ollama runs on CPU by default. For NVIDIA acceleration, install the
[nvidia-container-toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
and uncomment the `deploy:` block on the `ollama` service in
`docker-compose.yml`.

**Already run Ollama natively?** Then skip the `ai` profile (plain
`docker compose up -d`) and keep using your native Ollama on `:11434` — Vodou
can't tell the difference. Running both would collide on port 11434.

## Using your own nginx (instead of Caddy)

Caddy is included so this works out of the box. If you'd rather terminate TLS
with your **own nginx** (or any other reverse proxy), you must **remove — or
comment out — the `caddy` service in `docker-compose.yml` before running
`docker compose up`.** Do not run both.

If both start, they fight over port 443 and each presents a *different*
certificate for `localhost` (nginx's cert vs. Caddy's internal-CA cert), which
shows up as a port collision and/or a certificate error. Use exactly one TLS
terminator.

With Caddy removed, expose the SearXNG container to your nginx (e.g. publish it
on the host by adding `ports: ["127.0.0.1:8081:8080"]` to the `searxng`
service), then have nginx proxy the sub-path — matching `SEARXNG_BASE_URL`:

```nginx
location /searxng/ {
    proxy_pass         http://127.0.0.1:8081/;   # trailing slash strips /searxng
    proxy_set_header   Host              $host;
    proxy_set_header   X-Forwarded-Proto https;
    proxy_set_header   X-Forwarded-For   $remote_addr;
}
```

Vodou still opens `https://localhost/searxng` and trusts the localhost
certificate either way.

## LAN viewer password (noVNC gate)

The browser-viewable image (`Dockerfile.vnc`) runs the VNC server with **no VNC
password** (`x11vnc -nopw`), bound to the container's own localhost. That's on
purpose: LAN access is gated one layer up, by **HTTP Basic Auth on the reverse
proxy** that fronts the viewer (nginx `auth_basic` → a `vodou.htpasswd` file).
That htpasswd entry is the credential that actually protects LAN access.

**Bootstrap credential (fresh install).** When no credential has been configured
yet, seed the default:

```
username: vodou
password: vodou-lan-2026
```

`manage_viewer_password.py` manages this file. It **never overwrites** an entry
that already exists, so upgrading or re-running is safe and an installation that
already set its own password keeps it.

```sh
# Point it at your proxy's htpasswd (or export VODOU_VIEWER_HTPASSWD):
export VODOU_VIEWER_HTPASSWD=/etc/nginx/vodou.htpasswd   # e.g. on Windows:
#   set VODOU_VIEWER_HTPASSWD=C:\nginx-1.27.4\conf\vodou.htpasswd

# Fresh install: install the bootstrap credential (no-op if one exists)
python manage_viewer_password.py seed

# Change it before normal use (prompts; nothing is echoed or logged)
python manage_viewer_password.py change

# Report whether the default is still in use (exit != 0 with --fail-if-default,
# so a setup script can refuse to finish until it's changed)
python manage_viewer_password.py status --fail-if-default
```

Passwords are stored only as salted Apache-MD5 (`$apr1$`) hashes — the format
nginx accepts on every platform, including Windows — never in plaintext, and are
never logged or echoed. Whether the bootstrap password is still in use is
derived from the stored hash itself (no separate flag to drift out of sync).

**Limitation (by design).** There is **no "force a password change at first VNC
login."** The RFB/VNC protocol has no password-change-on-login mechanism, and
HTTP Basic Auth is stateless (it has no login event to intercept). Enforcement
is therefore at **provisioning time**: `seed` installs the default, `status
--fail-if-default` lets your setup step block until it's changed, and `change`
replaces it. Adding a stateful web login purely to simulate a first-login prompt
would mean standing up a second authentication system, which this deliberately
avoids.

## Notes & gotchas

- **Port 443/80 must be free.** Caddy binds them for `https://localhost`. If
  something else already serves those ports (another web server, or an
  existing native SearXNG/nginx), stop it first or change the published ports
  in `docker-compose.yml` (and point Vodou at the new URL — see below).
- **Pointing Vodou elsewhere.** To use a different search URL, set the
  `VODOU_SEARXNG_URL` environment variable or create
  `~/.vodou/config.json` with `{ "searxng_url": "https://localhost/searxng" }`.
  The AI endpoint lives in `~/.vodou/ai_search.json` (`endpoint`).
- **Keep your secret private.** `setup` writes a real `secret_key` into
  `searxng/settings.yml`; don't commit that change (the repo ships a
  placeholder on purpose).
