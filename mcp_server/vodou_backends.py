"""Backends for the Vodou MCP server — all logic, no MCP/Qt dependency.

Kept separate from vodou_mcp.py so it can be unit-tested without the `mcp` SDK
installed and without importing PyQt (this module never imports Qt). It reads
Vodou's on-disk profile (``~/.vodou``) and talks to the same local backends
Vodou uses — a private SearXNG instance for search and a loopback Ollama for
summaries — over the standard library only.

Design constraints that mirror Vodou's own guarantees:
  * The Ollama endpoint MUST be loopback (is_local_endpoint) — a question never
    leaves the machine. A non-loopback endpoint is refused, not silently used.
  * Nothing here reads, decrypts, or returns vault secrets. vault_status()
    reports only whether a vault file exists.
  * TLS verification is skipped ONLY for loopback SearXNG (a self-signed cert on
    127.0.0.1/localhost, where there is no meaningful MITM to defend against).
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

# Reuse Vodou's own modules where they are GUI-free, so schemas/guards stay in
# one place. The repo root (this file's parent's parent) holds them.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

VODOU_DIR = Path.home() / ".vodou"

DEFAULT_SEARXNG_URL = "https://localhost/searxng"
DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2:latest"

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


# -- config resolution -------------------------------------------------------

def _read_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def is_local_endpoint(endpoint: str) -> bool:
    """True if ``endpoint`` addresses this machine over http(s).

    Mirrors ai_search.is_local_endpoint but with no Qt dependency: the host is
    parsed as an address when it is an IP literal (so ``127.0.0.1.example.net``
    is NOT treated as loopback).
    """
    parts = urllib.parse.urlsplit(str(endpoint))
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower()
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolve_searxng_url(vodou_dir: Path = VODOU_DIR,
                        env: dict | None = None) -> str:
    """SearXNG base URL: env VODOU_SEARXNG_URL, then config.json, then default."""
    import os
    env = os.environ if env is None else env
    url = (env.get("VODOU_SEARXNG_URL") or "").strip()
    if url:
        return url.rstrip("/")
    cfg = _read_json(Path(vodou_dir) / "config.json") or {}
    url = str(cfg.get("searxng_url", "")).strip()
    return (url or DEFAULT_SEARXNG_URL).rstrip("/")


def resolve_ai_config(vodou_dir: Path = VODOU_DIR) -> dict:
    """Ollama endpoint/model from ai_search.json, with the loopback guard.

    A non-loopback endpoint in the file is refused and the safe default is used
    instead — the same protection Vodou applies to its own AI features.
    """
    cfg = _read_json(Path(vodou_dir) / "ai_search.json") or {}
    endpoint = str(cfg.get("endpoint", "")).strip() or DEFAULT_OLLAMA_ENDPOINT
    if not is_local_endpoint(endpoint):
        endpoint = DEFAULT_OLLAMA_ENDPOINT
    model = str(cfg.get("model", "")).strip() or DEFAULT_OLLAMA_MODEL
    return {"endpoint": endpoint.rstrip("/"), "model": model}


# -- SearXNG search ----------------------------------------------------------

def build_search_url(base: str, query: str, max_results: int = 8) -> str:
    q = urllib.parse.urlencode({"q": query, "format": "json"})
    return f"{base.rstrip('/')}/search?{q}"


def _ssl_context_for(url: str) -> ssl.SSLContext | None:
    """An unverified context for loopback HTTPS (self-signed localhost), else
    None (normal verification). Returns None for plain HTTP too."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        return None
    host = (parts.hostname or "").lower()
    loopback = host in _LOOPBACK_HOSTS
    if not loopback:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
    if loopback:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def normalize_results(data: dict, max_results: int = 8) -> list[dict]:
    """Reduce a SearXNG JSON payload to ``[{title, url, snippet}]``."""
    out = []
    for r in (data or {}).get("results", [])[:max_results]:
        url = str(r.get("url", "")).strip()
        if not url:
            continue
        out.append({
            "title": str(r.get("title", "")).strip(),
            "url": url,
            "snippet": str(r.get("content", "")).strip(),
        })
    return out


def _http_json(url: str, data: bytes | None = None, timeout: float = 20.0):
    req = urllib.request.Request(
        url, data=data,
        headers={"Accept": "application/json",
                 "Content-Type": "application/json",
                 "User-Agent": "vodou-mcp"})
    ctx = _ssl_context_for(url)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.load(resp)


def search(query: str, max_results: int = 8,
           vodou_dir: Path = VODOU_DIR) -> list[dict]:
    """Run a private SearXNG search; returns [{title, url, snippet}]."""
    query = (query or "").strip()
    if not query:
        return []
    base = resolve_searxng_url(vodou_dir)
    return normalize_results(_http_json(build_search_url(base, query,
                                                         max_results)),
                             max_results)


# -- Ollama summary ----------------------------------------------------------

def build_summary_messages(query: str, results: list[dict]) -> list[dict]:
    lines = []
    for i, r in enumerate(results, 1):
        lines.append(f"[{i}] {r.get('title','')}\n{r.get('url','')}\n"
                     f"{r.get('snippet','')}")
    context = "\n\n".join(lines) if lines else "(no search results)"
    system = ("You are a concise research assistant. Answer the user's question "
              "using ONLY the numbered search results provided. Cite sources as "
              "[n]. If the results do not contain the answer, say so.")
    user = f"Question: {query}\n\nSearch results:\n{context}"
    return [{"role": "system", "content": system},
            {"role": "user", "content": user}]


def summarize(query: str, results: list[dict] | None = None,
              model: str | None = None,
              vodou_dir: Path = VODOU_DIR) -> dict:
    """Search (if results not supplied) then ask the local Ollama to answer.

    Returns ``{"answer": str, "model": str, "sources": [...]}``. Raises
    RuntimeError if the resolved endpoint is not loopback (defensive; resolve_
    ai_config already enforces it).
    """
    query = (query or "").strip()
    if results is None:
        results = search(query, vodou_dir=vodou_dir)
    cfg = resolve_ai_config(vodou_dir)
    endpoint, resolved_model = cfg["endpoint"], (model or cfg["model"])
    if not is_local_endpoint(endpoint):
        raise RuntimeError("AI endpoint is not loopback; refusing to send the "
                           "query off-machine.")
    payload = json.dumps({
        "model": resolved_model,
        "messages": build_summary_messages(query, results),
        "stream": False,
    }).encode("utf-8")
    data = _http_json(f"{endpoint}/api/chat", data=payload, timeout=120.0)
    answer = str(((data or {}).get("message") or {}).get("content", "")).strip()
    return {"answer": answer, "model": resolved_model, "sources": results}


# -- read-only profile data --------------------------------------------------

def read_bookmarks(vodou_dir: Path = VODOU_DIR) -> list[dict]:
    """Saved bookmarks as ``[{title, url}]`` (reuses Vodou's safe parser)."""
    import bookmarks  # GUI-free
    store = bookmarks.Bookmarks(Path(vodou_dir) / "bookmarks.json")
    return [{"title": b.title, "url": b.url} for b in store.all()]


def read_open_tabs() -> dict:
    """The last saved session's open tab URLs, or an empty snapshot.

    Reuses session.load_snapshot() because the session file is sealed/encrypted;
    it cannot be parsed without Vodou's own unseal. Returns
    ``{"urls": [...], "current": int}`` (empty when no session is saved).
    """
    import session  # GUI-free
    snap = session.load_snapshot()
    if not snap:
        return {"urls": [], "current": -1}
    urls, current = snap
    return {"urls": urls, "current": current}


# -- live control client (talks to a RUNNING Vodou) --------------------------
#
# Only works when Vodou is running with VODOU_ENABLE_CONTROL=1, which publishes
# ~/.vodou/control.json {port, token} for a loopback socket (see the app's
# remote_control.py). If that file is absent/stale, the tools report that control
# is unavailable rather than failing obscurely.

class ControlUnavailable(RuntimeError):
    """Vodou's loopback control surface isn't reachable (not enabled/running)."""


def read_control_info(vodou_dir: Path = VODOU_DIR) -> dict | None:
    info = _read_json(Path(vodou_dir) / "control.json")
    if not isinstance(info, dict) or "port" not in info or "token" not in info:
        return None
    return info


def build_control_request(token: str, cmd: str,
                          params: dict | None = None) -> bytes:
    return (json.dumps({"token": token, "cmd": cmd,
                        "params": params or {}}) + "\n").encode("utf-8")


def parse_control_response(line: bytes):
    """Return the result of a control reply, or raise. Raises RuntimeError on an
    ``ok:false`` reply, ValueError on malformed JSON."""
    resp = json.loads(line.decode("utf-8"))
    if not resp.get("ok"):
        raise RuntimeError(str(resp.get("error", "control error")))
    return resp.get("result")


def control_request(cmd: str, params: dict | None = None,
                    vodou_dir: Path = VODOU_DIR, timeout: float = 5.0):
    """Send one command to the running Vodou and return its result.

    Raises ControlUnavailable if control isn't enabled/running, or RuntimeError
    if the command was rejected.
    """
    info = read_control_info(vodou_dir)
    if not info:
        raise ControlUnavailable(
            "Vodou remote control is not available. Start Vodou with the "
            "environment variable VODOU_ENABLE_CONTROL=1 to enable it.")
    req = build_control_request(str(info["token"]), cmd, params)
    try:
        with socket.create_connection(("127.0.0.1", int(info["port"])),
                                      timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
    except OSError as exc:
        raise ControlUnavailable(
            "Vodou remote control is not reachable (is Vodou running with "
            f"VODOU_ENABLE_CONTROL=1?): {exc}") from exc
    return parse_control_response(buf.split(b"\n", 1)[0])


def vault_status(vault_file: Path | None = None) -> dict:
    """Non-secret status of the password vault: only whether it is configured.

    Deliberately returns NO entries and NO secrets — the vault is encrypted
    under a master password this server neither holds nor should handle.
    """
    if vault_file is None:
        import vault  # GUI-free; only for the default path
        vault_file = vault.VAULT_FILE
    return {"configured": Path(vault_file).exists()}
