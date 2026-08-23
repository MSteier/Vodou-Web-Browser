"""Tests for the Vodou MCP server backends (mcp_server/vodou_backends.py).

Targets the SDK-free, Qt-free logic: config resolution, the loopback guard,
SearXNG URL building + result normalization, the loopback-only TLS decision,
Ollama message building, and the read-only profile readers. No network and no
`mcp` SDK are required.

Run:  python tests/test_vodou_mcp.py
"""

import json
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "mcp_server"))

import vodou_backends as be  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


def fresh_dir():
    return Path(tempfile.mkdtemp())


# ---------------------------------------------------------------------------
print("loopback guard (is_local_endpoint)")

check("localhost is local", be.is_local_endpoint("http://localhost:11434"))
check("127.0.0.1 is local", be.is_local_endpoint("http://127.0.0.1:11434"))
check("127.0.0.2 (loopback range) is local",
      be.is_local_endpoint("http://127.0.0.2:11434"))
check("public IP is not local", not be.is_local_endpoint("http://8.8.8.8:11434"))
check("remote host is not local",
      not be.is_local_endpoint("http://evil.example.com:11434"))
check("spoofed loopback hostname is not local",
      not be.is_local_endpoint("http://127.0.0.1.example.net/"))
check("non-http scheme is not local",
      not be.is_local_endpoint("ftp://127.0.0.1/"))

# ---------------------------------------------------------------------------
print("\nSearXNG url + result normalization")

check("search url carries format=json",
      "format=json" in be.build_search_url("https://localhost/searxng", "cats"))
check("search url is under /search",
      be.build_search_url("https://localhost/searxng/", "cats")
      .startswith("https://localhost/searxng/search?"))
check("query is url-encoded",
      "q=a+b+%26+c" in be.build_search_url("https://x/searxng", "a b & c"))

payload = {"results": [
    {"title": "T1", "url": "https://a.example/1", "content": "snip1"},
    {"title": "T2", "url": "https://a.example/2", "content": "snip2"},
    {"title": "no-url", "url": "", "content": "dropped"},
]}
norm = be.normalize_results(payload, max_results=8)
check("results without a url are dropped", len(norm) == 2)
check("result fields normalized to title/url/snippet",
      norm[0] == {"title": "T1", "url": "https://a.example/1",
                  "snippet": "snip1"})
check("max_results caps the list",
      len(be.normalize_results(payload, max_results=1)) == 1)
check("empty payload -> empty list", be.normalize_results({}, 8) == [])

# ---------------------------------------------------------------------------
print("\nloopback-only TLS decision")

check("loopback https -> unverified context (self-signed localhost ok)",
      be._ssl_context_for("https://localhost/searxng") is not None)
check("loopback-ip https -> unverified context",
      be._ssl_context_for("https://127.0.0.1/searxng") is not None)
check("remote https -> normal verification (None)",
      be._ssl_context_for("https://example.com/searxng") is None)
check("plain http -> no context needed (None)",
      be._ssl_context_for("http://127.0.0.1:8081/searxng") is None)

# ---------------------------------------------------------------------------
print("\nconfig resolution")

d = fresh_dir()
check("searxng default when nothing configured",
      be.resolve_searxng_url(d, env={}) == be.DEFAULT_SEARXNG_URL)
check("searxng env override wins",
      be.resolve_searxng_url(d, env={"VODOU_SEARXNG_URL": "http://127.0.0.1:8081/"})
      == "http://127.0.0.1:8081")
(d / "config.json").write_text(json.dumps(
    {"searxng_url": "https://localhost/searxng"}), encoding="utf-8")
check("searxng config.json used when no env",
      be.resolve_searxng_url(d, env={}) == "https://localhost/searxng")

d2 = fresh_dir()
check("ai defaults when no ai_search.json",
      be.resolve_ai_config(d2)["endpoint"] == be.DEFAULT_OLLAMA_ENDPOINT)
(d2 / "ai_search.json").write_text(json.dumps(
    {"endpoint": "http://127.0.0.1:11434", "model": "mymodel"}),
    encoding="utf-8")
cfg = be.resolve_ai_config(d2)
check("ai endpoint/model read from file",
      cfg == {"endpoint": "http://127.0.0.1:11434", "model": "mymodel"})
(d2 / "ai_search.json").write_text(json.dumps(
    {"endpoint": "http://evil.example.com:11434", "model": "m"}),
    encoding="utf-8")
check("non-loopback ai endpoint is refused -> falls back to default",
      be.resolve_ai_config(d2)["endpoint"] == be.DEFAULT_OLLAMA_ENDPOINT)

# ---------------------------------------------------------------------------
print("\nOllama message building")

msgs = be.build_summary_messages("what is X?", norm)
check("messages are system + user", [m["role"] for m in msgs]
      == ["system", "user"])
check("system prompt insists on using only provided results",
      "ONLY" in msgs[0]["content"])
check("user message includes the question", "what is X?" in msgs[1]["content"])
check("user message includes numbered sources",
      "[1]" in msgs[1]["content"] and "https://a.example/1" in msgs[1]["content"])
check("no-results context is handled",
      "(no search results)" in be.build_summary_messages("q", [])[1]["content"])

# ---------------------------------------------------------------------------
print("\nread-only profile readers")

b = fresh_dir()
(b / "bookmarks.json").write_text(json.dumps([
    {"title": "Example", "url": "https://example.com/"},
    {"title": "Bad scheme", "url": "javascript:alert(1)"},  # unsafe -> dropped
]), encoding="utf-8")
marks = be.read_bookmarks(b)
check("safe bookmark is read",
      {"title": "Example", "url": "https://example.com/"} in marks)
check("unsafe bookmark url is filtered out",
      all(not m["url"].startswith("javascript:") for m in marks))

check("vault_status: absent file -> not configured",
      be.vault_status(fresh_dir() / "vault.dat") == {"configured": False})
vf = fresh_dir() / "vault.dat"
vf.write_text("x", encoding="utf-8")
check("vault_status: present file -> configured (no secrets returned)",
      be.vault_status(vf) == {"configured": True})

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL VODOU-MCP BACKEND TESTS PASSED")
