# Vodou backend (Docker)

Vodou is a **desktop app**, so it isn't run from Docker — but the services it
talks to are. This bundle stands those up reproducibly, so Vodou works the
same on any machine without hand-configuring SearXNG, a TLS proxy, and Ollama.

| Service | What it is | Where Vodou reaches it |
|---|---|---|
| `searxng` | Private metasearch engine | via Caddy below |
| `redis` (valkey) | SearXNG's cache/limiter backend | internal only |
| `caddy` | TLS reverse proxy, self-signed via its internal CA | `https://localhost/searxng` |
| `ollama` *(optional)* | Local LLM for AI search summaries | `http://127.0.0.1:11434` |

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
