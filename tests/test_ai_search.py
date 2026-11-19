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
from spoofcheck import SpoofVerdict  # noqa: E402

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

# --- build_site_safety_prompt: "Check this site" -----------------------------
print("\nbuild_site_safety_prompt")

clean_facts = {
    "url": "https://example.com/", "host": "example.com",
    "connection": "HTTPS (encrypted)", "cert_trusted": True,
    "spoof": None, "malicious": False, "bypassed_warning": False,
    "downloads": [],
}
clean = ai.build_site_safety_prompt(clean_facts)
check("clean site names the real host", "example.com" in clean)
check("clean site: rated No red flags found",
      "Vodou's rating: No red flags found" in clean)
check("clean site: no look-alike pattern detected, said plainly",
      "no look-alike/typosquat pattern" in clean)
check("clean site: not on the malicious list, said plainly",
      "is not on Vodou's local" in clean)
check("clean site: certificate trust is reported",
      "verified against the system trust store" in clean)
check("clean site: no downloads noted",
      "No downloads from this site" in clean)
check("the model is told its information is limited to what's listed",
      "no live web/reputation lookup" in clean)
check("the model is never told Vodou ran an antivirus scan",
      "antivirus scan" not in clean
      or "no antivirus scan" in clean)

spoofed_facts = {
    "url": "https://paypa1.com/login", "host": "paypa1.com",
    "connection": "HTTPS (encrypted)", "cert_trusted": False,
    "cert_trust_error": "self-signed certificate",
    "spoof": SpoofVerdict("typosquat", "paypa1.com", "paypal.com",
                          "Possible misspelled address",
                          "This address is one character away from "
                          "“paypal.com” and may be impersonating it."),
    "malicious": True, "bypassed_warning": True,
    "downloads": [("invoice.exe", ".exe"), ("readme.txt", None)],
}
spoofed = ai.build_site_safety_prompt(spoofed_facts)
check("spoofed site: rated Dangerous", "Vodou's rating: Dangerous" in spoofed)
check("spoofed site: the deceptive-address finding is included",
      "paypal.com" in spoofed and "impersonating" in spoofed)
check("spoofed site: the malicious-list hit is included",
      "reported phishing/malware list" in spoofed)
check("spoofed site: untrusted certificate is reported with its reason",
      "could not be verified (self-signed certificate)" in spoofed)
check("spoofed site: an earlier warning is disclosed as evidence",
      "showed a warning for this site" in spoofed)
check("spoofed site: the bypassed warning is not framed as the user's fault",
      "Continue anyway" not in spoofed)
check("spoofed site: the risky download is called out",
      "invoice.exe" in spoofed)
check("spoofed site: the harmless download raises no alarm",
      "readme.txt" not in spoofed)
check("a dangerous site lists its warning signs",
      "Warning signs Vodou found on this computer:" in spoofed)
check("a clean site says plainly there are no warning signs",
      "Warning signs Vodou found on this computer: none." in clean)
check("strongest evidence is listed first",
      spoofed.index("reported phishing") < spoofed.index("invoice.exe"))

no_cert_facts = {
    "url": "http://plain.example/", "host": "plain.example",
    "connection": "HTTP — NOT encrypted",
    "spoof": None, "malicious": False, "bypassed_warning": False,
    "downloads": [],
}
no_cert = ai.build_site_safety_prompt(no_cert_facts)
check("missing cert_trusted key is handled without raising",
      "example" in no_cert)
check("plain HTTP connection state is reported",
      "NOT encrypted" in no_cert)

# --- "Check this site" instructions and hidden system messages ---------------
print("\nsite-check instructions")
sysmsg = ai.SITE_CHECK_SYSTEM
check("model must use Vodou's rating as its verdict",
      "Use Vodou's rating as your verdict" in sysmsg)
check("model must not lower the rating", "Never lower it" in sysmsg)
check("model is told 'not flagged' isn't proof of safety",
      "not proof of safety" in sysmsg)
check("model must not comment on the user's choices",
      "Never comment on the user's own choices" in sysmsg)
check("a fixed reply format is required",
      "**Verdict: <rating>**" in sysmsg and "**What to do**" in sysmsg)

hist = [{"role": "system", "content": sysmsg},
        {"role": "user", "content": "q0"}]
hist += [{"role": "assistant" if i % 2 else "user", "content": f"m{i}"}
         for i in range(1, 40)]
msgs = ai.build_chat_messages(hist, {"max_turns": 6})
check("ASK_SYSTEM still comes first", msgs[0]["content"] == ai.ASK_SYSTEM)
check("the site-check instructions survive trimming a long chat",
      msgs[1]["content"] == sysmsg)
check("only the recent turns are kept",
      len(msgs) == 2 + 6 and msgs[-1]["content"] == "m39")

print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL AI-SEARCH TESTS PASSED")
