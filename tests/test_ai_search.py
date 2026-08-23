"""Tests for ai_search's pure/offline helpers: the search-results-page
recognizer, endpoint loopback enforcement, and prompt/message assembly.

Offline and deterministic — no Ollama, no network, no QApplication (QUrl is a
value type and needs none).

Run:  python tests/test_ai_search.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PyQt6.QtCore import QUrl  # noqa: E402

import ai_search as ai  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# --- is_search_results: loopback deployment (no searxng_host given) ---------
print("is_search_results — loopback only")
check("localhost /search -> True",
      ai.is_search_results(QUrl("http://localhost/search?q=cats")))
check("localhost /searxng/search -> True",
      ai.is_search_results(QUrl("http://localhost/searxng/search?q=cats")))
check("127.0.0.1 /search -> True",
      ai.is_search_results(QUrl("http://127.0.0.1/search?q=cats")))
check("wrong path -> False",
      not ai.is_search_results(QUrl("http://localhost/results?q=cats")))
check("remote host, no searxng_host given -> False", not ai.is_search_results(
    QUrl("http://host.docker.internal:8081/search?q=cats")))

# --- is_search_results: the bundled Docker deployment's real host -----------
# This is the case that was broken: SEARXNG_BASE there is
# http://host.docker.internal:8081, so the summary button never activated on
# an actual, successfully-loaded SearXNG results page.
print("\nis_search_results — Docker deployment (searxng_host passed)")
check("configured host's /search -> True", ai.is_search_results(
    QUrl("http://host.docker.internal:8081/search?q=cats"),
    "host.docker.internal"))
check("localhost still accepted alongside the configured host",
      ai.is_search_results(QUrl("http://localhost/search?q=cats"),
                            "host.docker.internal"))
check("an unrelated third-party host is still rejected",
      not ai.is_search_results(
          QUrl("http://evil.example/search?q=cats"), "host.docker.internal"))
check("configured host but wrong path -> False", not ai.is_search_results(
    QUrl("http://host.docker.internal:8081/"), "host.docker.internal"))
check("empty host -> False",
      not ai.is_search_results(QUrl("about:blank"), "host.docker.internal"))

# --- is_local_endpoint (Ask AI / summary must never leave the device) -------
print("\nis_local_endpoint")
check("127.0.0.1 accepted", ai.is_local_endpoint("http://127.0.0.1:11434"))
check("localhost accepted", ai.is_local_endpoint("http://localhost:11434"))
check("::1 accepted", ai.is_local_endpoint("http://[::1]:11434"))
check("remote host rejected",
      not ai.is_local_endpoint("http://example.com:11434"))
check("127.-prefixed hostname (not a literal) rejected", not ai.is_local_endpoint(
    "http://127.0.0.1.example.net:11434"))
check("non-http(s) scheme rejected",
      not ai.is_local_endpoint("file:///etc/passwd"))

# --- load_config: a non-local endpoint is refused, not merely warned about --
print("\nload_config endpoint enforcement")
import json  # noqa: E402
import tempfile  # noqa: E402
ai.CONFIG_FILE = Path(tempfile.mkdtemp()) / "ai_search.json"
ai.CONFIG_FILE.write_text(
    json.dumps({"endpoint": "http://evil.example:11434"}), encoding="utf-8")
cfg = ai.load_config()
check("a remote endpoint on disk is silently replaced with the default",
      cfg["endpoint"] == ai.DEFAULTS["endpoint"])
check("the rejection is flagged for the UI", cfg.get("endpoint_rejected") is True)

# --- split_reasoning ----------------------------------------------------------
print("\nsplit_reasoning")
check("closed <think> block is stripped",
      ai.split_reasoning("<think>hmm</think>answer")
      == ("answer", False))
check("unclosed <think> block -> still_thinking True",
      ai.split_reasoning("<think>still going")[1] is True)
check("no think block -> passthrough",
      ai.split_reasoning("plain answer") == ("plain answer", False))

print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL AI-SEARCH TESTS PASSED")
