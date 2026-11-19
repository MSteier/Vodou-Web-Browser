"""On-device AI, via a local Ollama instance: search summaries, chat, and a
site-safety check.

Vodou uses a local SearXNG instance that queries upstream search engines. This
adds three optional, on-demand features, all produced **entirely locally** by
talking to Ollama over HTTP on 127.0.0.1:

  * **Summarize** the results on a SearXNG page.
  * **Ask** the model anything, as a normal multi-turn conversation.
  * **Check this site** — hands the model the current page's already-computed
    local safety signals (deceptive-address check, malicious-site list,
    certificate trust, this session's downloads from the same host) and lets
    it answer questions like "is this spoofed", "is it a scam", "will a
    download from here have malware" — see build_site_safety_prompt.

Inference runs locally. Optional Search web sends the latest typed question to
SearXNG and its upstream search engines, then gives the returned snippets to
local Ollama. The conversation and browser history are not sent to search.
Vodou never changes Ollama's models, config, or environment. With Search web
off, Ask mode sends only the conversation to Ollama. "Check this site" is a deliberate,
user-triggered exception: it attaches the current page's locally-computed
safety facts (never the page's actual content) to that one chat turn, and only
when the user explicitly asks for the check.

How it fits together:
  * Vodou reads the top results straight from the rendered SearXNG page (no
    SearXNG configuration needed), see RESULTS_JS.
  * It POSTs them, with the query, to Ollama's /api/chat and streams the reply
    into a side dock. Ask mode POSTs the conversation to the same endpoint.
  * Reasoning models (e.g. deepseek-r1) emit a <think>…</think> block first;
    that reasoning is hidden and only the final answer is shown.

`endpoint` must address this machine (localhost / 127.x / ::1). Anything else
is rejected and the default is used instead — see is_local_endpoint. The
on-device promise above is worth only as much as that check.

Config lives in ~/.vodou/ai_search.json (all keys optional):
  { "enabled": true, "endpoint": "http://127.0.0.1:11434",
    "model": "deepseek-r1:8b", "max_results": 6,
    "keep_alive": "5m", "temperature": 0.3, "max_turns": 12 }

`max_turns` caps how many past chat messages are resent with each question —
older turns drop off so a long conversation can't grow the prompt without
bound (and slow the model down).

`keep_alive` is passed straight to Ollama: it's how long Ollama keeps the model
resident after Vodou's request. A short value means Vodou's use frees VRAM soon
after, minimising any contention with your other local-LLM work.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from PyQt6.QtCore import QObject, QUrl, pyqtSignal
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest, QNetworkProxy

from ai_websearch import WebSearch, grounded_messages, source_footer

VODOU_DIR = Path.home() / ".vodou"
CONFIG_FILE = VODOU_DIR / "ai_search.json"

DEFAULTS = {
    "enabled": True,
    "endpoint": "http://127.0.0.1:11434",
    "model": "llama3.2:latest",
    "max_results": 6,
    "keep_alive": "5m",
    "temperature": 0.3,
    "max_turns": 12,
    "web_search": False,
    "web_search_url": "",
    "translate_language": "English",
}

# A full page can run well past what a local model's context window can
# usefully hold; this is a conservative cap, not an attempt at
# chunked/long-document translation (see translate_prompt).
TRANSLATE_MAX_CHARS = 8000


# Hosts the endpoint may point at. The whole promise of this module is that a
# question never leaves the machine, and `endpoint` is read from a plain JSON
# file — so a typo, a bad merge, or anything else that can write to the profile
# directory could silently redirect every typed question and search query to a
# remote server while the UI still says "on your device". Enforcing loopback
# here makes that promise something the code guarantees rather than documents.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def is_local_endpoint(endpoint: str) -> bool:
    """True if `endpoint` addresses this machine over plain HTTP(S).

    The numeric case is parsed as an address, never matched as a "127."
    prefix — a prefix test also accepts the hostname 127.0.0.1.example.net,
    which resolves wherever its owner points it.
    """
    url = QUrl(str(endpoint))
    if url.scheme() not in ("http", "https"):
        return False
    host = url.host().lower()
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False          # not an IP literal, and not a loopback name


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            cfg.update({k: data[k] for k in DEFAULTS if k in data})
    except (OSError, ValueError, TypeError):
        pass
    if not is_local_endpoint(cfg.get("endpoint", "")):
        cfg["endpoint"] = DEFAULTS["endpoint"]
        cfg["endpoint_rejected"] = True
    return cfg


def save_config(cfg: dict) -> None:
    try:
        VODOU_DIR.mkdir(parents=True, exist_ok=True)
        keep = {k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS}
        CONFIG_FILE.write_text(json.dumps(keep, indent=2), encoding="utf-8")
    except OSError:
        pass


def is_search_results(url: QUrl, searxng_host: str = "") -> bool:
    """True for a local SearXNG results page — the only place the summary
    button does anything.

    `searxng_host` should be the host of the *actually configured* SearXNG
    base URL (main.SEARXNG_BASE) — pass it from every call site. Without it,
    this only recognizes the two loopback names, which misses the bundled
    Docker deployment's default `http://host.docker.internal:8081` (or any
    other host VODOU_SEARXNG_URL/config.json points at): the summary button
    would silently never activate on the actual results page, even though
    SearXNG loaded and rendered fine. `searxng_host` is still checked against
    the URL rather than trusted blindly, so a page that merely matches
    "/search" on an unrelated host is never treated as a results page.
    """
    host = url.host()
    if not host or host not in (
            {"localhost", "127.0.0.1", searxng_host} if searxng_host
            else {"localhost", "127.0.0.1"}):
        return False
    return "/searxng/search" in url.path() or url.path().endswith("/search")


def query_from_url(url: QUrl) -> str:
    from PyQt6.QtCore import QUrlQuery
    # In a GET form query string a literal '+' means space (form-encoding);
    # swap it back before percent-decoding the rest.
    raw = QUrlQuery(url).queryItemValue(
        "q", QUrl.ComponentFormattingOption.FullyEncoded)
    raw = raw.replace("+", "%20")
    return QUrl.fromPercentEncoding(raw.encode("utf-8"))


# Pulls the top results out of the rendered SearXNG page. Runs in the page DOM
# (ApplicationWorld) and returns a list of {title, url, snippet}. %MAX% is
# substituted with the configured result cap before injection.
RESULTS_JS = r"""
(function () {
  var out = [];
  var seen = {};
  var nodes = document.querySelectorAll(
      '#results article.result, #urls article.result, article.result, .result');
  for (var i = 0; i < nodes.length && out.length < %MAX%; i++) {
    var el = nodes[i];
    var titleEl = el.querySelector('h3') ||
                  el.querySelector('a.url_header') ||
                  el.querySelector('a[href]');
    var linkEl = el.querySelector('a[href]');
    var snipEl = el.querySelector('.content') ||
                 el.querySelector('p.content') ||
                 el.querySelector('p');
    var title = titleEl ? (titleEl.innerText || '').trim() : '';
    var url = linkEl ? (linkEl.href || '') : '';
    var snip = snipEl ? (snipEl.innerText || '').trim() : '';
    if (!title && !snip) continue;
    if (url && seen[url]) continue;
    if (url) seen[url] = true;
    out.push({ title: title, url: url, snippet: snip });
  }
  return out;
})();
"""


def results_script(max_results: int) -> str:
    return RESULTS_JS.replace("%MAX%", str(int(max_results)))


def build_prompt(query: str, results: list[dict]) -> str:
    lines = [
        "You summarize web search results for a user, using only the "
        "information given.",
        "",
        f'The user searched for: "{query}"',
        "",
        f"Here are the top {len(results)} results (number, title, URL, "
        "snippet):",
        "",
    ]
    for i, r in enumerate(results, 1):
        lines.append(f"[{i}] {r.get('title', '').strip()}")
        if r.get("url"):
            lines.append(r["url"].strip())
        snip = r.get("snippet", "").strip()
        if snip:
            lines.append(snip)
        lines.append("")
    lines += [
        "Write a concise, neutral summary (about 3-6 sentences) that directly "
        "addresses the query using ONLY these snippets. Then give a short "
        "bulleted list of the most useful results as '- [n] one-line reason'. "
        "Cite claims with the result number in brackets, like [2]. If the "
        "snippets don't actually answer the query, say so plainly. Do not "
        "invent facts or URLs.",
    ]
    return "\n".join(lines)


def translate_prompt(text: str, target_language: str) -> str:
    """One-shot translate instruction for OllamaClient.translate. `text` is
    truncated to TRANSLATE_MAX_CHARS -- see that constant's comment."""
    truncated = text[:TRANSLATE_MAX_CHARS]
    lines = [
        f"Translate the following text into {target_language}. Output ONLY "
        "the translation, with no preamble, explanation, or quotation marks "
        "around it. Preserve the original paragraph breaks.",
        "",
        "---",
        truncated,
        "---",
    ]
    return "\n".join(lines)


# "Check this site" instructions, sent as a system message ahead of the
# facts. Small local models answer "is this safe?" badly when left to judge
# thin facts themselves: they hedge, invent details, or lecture. So Vodou
# rates the page with fixed rules (site_signals.rate) and the model's job is
# narrowed to explaining that rating, citing only the listed evidence, in a
# fixed shape that's easy to read at a glance. This message is kept out of
# the visible transcript (see main.BrowserWindow._render_ai_chat).
SITE_CHECK_SYSTEM = (
    "You are the safety explainer inside Vodou, a privacy browser. The user "
    "pressed \"Check this site\". Vodou has already examined the page on the "
    "user's own computer and rated it. Your job is to explain that rating "
    "to a non-technical person.\n\n"
    "Rules:\n"
    "1. Use Vodou's rating as your verdict, word for word. Never lower it. "
    "You may only raise it if the evidence plainly shows a scam.\n"
    "2. Base every statement on the evidence list. Don't invent anything: "
    "no domain age, owner, reviews, reputation, or what the page says.\n"
    "3. \"Not on the list\" and \"not flagged\" are not proof of safety. New "
    "scam sites appear every day. Say that once, briefly, when the rating "
    "is \"No red flags found\".\n"
    "4. Never comment on the user's own choices or what they may have known.\n"
    "5. Plain words, no jargon, no generic online-safety lecture.\n"
    "6. Vodou's checks are automated and can be wrong, so describe what the "
    "site appears to do, not what it definitely is or intends. Say \"this "
    "page may be trying to get your banking details\", not \"this page is "
    "stealing your banking details\"; say \"looks like\" or \"appears to\", "
    "not \"is a scam\". Stay clear and direct about what to do: careful "
    "wording must never make a likely-dangerous site sound harmless.\n\n"
    "Reply in exactly this format:\n"
    "**Verdict: <rating>**\n"
    "<one sentence saying what that means for the user>\n\n"
    "**Why**\n"
    "- <2 to 4 bullets, each restating one piece of evidence in plain words>\n\n"
    "**What to do**\n"
    "- <1 to 3 short, concrete steps>\n\n"
    "For Likely dangerous: tell them to leave the page, not to enter "
    "passwords, card numbers, or codes, and, if they already did, to change "
    "that password and contact their bank. For Looks suspicious: tell them "
    "to go to "
    "the real site by typing its address themselves instead of using this "
    "link. For No red flags found: say they can continue but should still "
    "type the address of important sites (bank, email) themselves.\n\n"
    "After this first answer, answer follow-up questions normally, still "
    "using only the evidence."
)


# Shown by Vodou itself under the first "Check this site" answer, so the
# caveat is always there even if the model leaves it out.
SITE_CHECK_NOTE = (
    "*Automated check by Vodou, run on this computer. It can be wrong in "
    "either direction: a safe site can trip a warning, and a brand-new scam "
    "can show no red flags. If something feels off, trust that and go to "
    "the real site by typing its address yourself.*"
)


def build_site_safety_prompt(facts: dict) -> str:
    """The visible user turn for "Check this site": Vodou's rule-based
    rating and the evidence behind it, followed by the question. Pairs with
    SITE_CHECK_SYSTEM. `facts` comes from main.BrowserWindow
    ._site_safety_facts (spoofcheck, Safe Browsing, the certificate probe,
    this session's downloads, plus site_signals' address and page findings).

    Every line is something Vodou checked locally. No page text is included:
    only fixed-vocabulary findings, so a scam page can't address the model.
    The model is never told Vodou checked something it didn't (no antivirus
    scan, no live reputation lookup)."""
    from site_signals import NO_RED_FLAGS as NO_RED_FLAGS_RATING, rate

    rating, signals = rate(facts)
    lines = [
        f"I'm on {facts['host']} ({facts['url']}). Is this site safe, or "
        "could it be a scam?",
        "",
        f"**Vodou's rating: {rating}**",
        "",
    ]
    warnings = [s.text for s in signals if s.weight != "info"]
    context = [s.text for s in signals if s.weight == "info"]
    if rating == NO_RED_FLAGS_RATING:
        lines.append("Warning signs Vodou found on this computer: none.")
        if warnings:
            lines += ["", "Minor notes (not a concern on their own):"]
            lines += [f"- {t}" for t in warnings]
    else:
        lines.append("Warning signs Vodou found on this computer:")
        lines += [f"- {t}" for t in warnings]
    if context:
        lines += ["", "For context:"] + [f"- {t}" for t in context]
    lines += ["", "Also checked, nothing wrong:"]
    ok = [f"- Connection: {facts['connection']}."]
    if facts.get("cert_trusted"):
        ok.append("- Certificate: verified against the system trust store.")
    if facts.get("spoof") is None:
        ok.append("- Address: no look-alike/typosquat pattern detected "
                  "against Vodou's known-brands list.")
    if not facts.get("malicious"):
        ok.append("- This host is not on Vodou's local "
                  "reported-phishing/malware list.")
    if not facts.get("downloads"):
        ok.append("- No downloads from this site this session.")
    lines += ok
    if facts.get("cert_check_skipped"):
        lines.append(f"- Certificate: not checked "
                     f"({facts['cert_check_skipped']}).")
    if facts.get("page_checked") is False:
        lines.append("- The page's contents couldn't be examined, so only "
                     "the address was checked.")
    lines += [
        "",
        "Not available: no antivirus scan of file contents, no live "
        "web/reputation lookup, no domain age or owner information.",
    ]
    return "\n".join(lines)


# Ask mode. Deliberately minimal: the model has no tools, no page access and no
# network, so the one thing worth insisting on is that it says when it doesn't
# know rather than inventing an answer the user can't easily check.
ASK_SYSTEM = (
    "You are a helpful assistant running locally inside Vodou, a privacy "
    "browser. Answer clearly and concisely, and use Markdown when it helps. "
    "You cannot browse the web, open pages, or see what the user is looking "
    "at — you only know what is in this conversation. If you are unsure or "
    "the answer may be out of date, say so plainly instead of guessing, and "
    "suggest what the user could search for."
)


def build_chat_messages(history: list[dict], cfg: dict) -> list[dict]:
    """Assemble the /api/chat payload for ask mode: the system prompt plus the
    last `max_turns` messages of `history` (oldest dropped first, so a long
    conversation doesn't grow the prompt without bound)."""
    try:
        limit = max(2, int(cfg.get("max_turns", DEFAULTS["max_turns"])))
    except (TypeError, ValueError):
        limit = DEFAULTS["max_turns"]
    valid = [m for m in history
             if isinstance(m, dict) and m.get("role") and m.get("content")]
    # Task-specific system messages (e.g. SITE_CHECK_SYSTEM) live in the
    # history so they stay with that conversation; hoist them so trimming a
    # long chat never drops them.
    extra = [m for m in valid if m["role"] == "system"]
    recent = [m for m in valid if m["role"] != "system"]
    return ([{"role": "system", "content": ASK_SYSTEM}] + extra
            + recent[-limit:])


_THINK_CLOSED = re.compile(r"<think>.*?</think>", re.DOTALL)


def split_reasoning(raw: str) -> tuple[str, bool]:
    """Return (visible_text, still_thinking). Closed <think>…</think> blocks
    are removed; an unclosed one means the model is still reasoning, so the
    visible text is whatever precedes it (usually empty)."""
    cleaned = _THINK_CLOSED.sub("", raw)
    idx = cleaned.find("<think>")
    if idx != -1:
        return cleaned[:idx].strip(), True
    return cleaned.strip(), False


class OllamaClient(QObject):
    """Streams a reply from a local Ollama model — a search summary
    (`summarize`) or a free-form conversation (`chat`). One request at a time:
    starting either cancels whatever was already running."""

    # full visible text so far (reasoning stripped)
    chunk = pyqtSignal(str)
    thinking = pyqtSignal(bool)     # True while inside the model's reasoning
    finished = pyqtSignal(str)      # final visible text
    failed = pyqtSignal(str)        # human-readable error
    status = pyqtSignal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._nam = QNetworkAccessManager(self)
        self._nam.setProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))
        self._search = WebSearch(self)
        self._search.finished.connect(self._searched)
        self._search.failed.connect(self._fail)
        self._sources = []
        self._reply: QNetworkReply | None = None
        self._raw = ""
        self._netbuf = b""
        self._got_content = False
        self._was_thinking = None

    @property
    def busy(self) -> bool:
        return self._reply is not None or self._search.busy

    @staticmethod
    def _endpoint(cfg: dict) -> str | None:
        """The endpoint to talk to, or None if it isn't on this machine.

        Checked again here, not just in load_config, because this is the line
        the bytes actually leave through — a cfg assembled anywhere else must
        not be able to route a question off-device.
        """
        endpoint = str(cfg.get("endpoint", DEFAULTS["endpoint"])).rstrip("/")
        return endpoint if is_local_endpoint(endpoint) else None

    def list_models(self, cfg: dict, callback) -> None:
        """Fetch the models installed in the local Ollama (GET /api/tags) and
        hand the callback a list of their names. Empty list on any failure —
        the picker simply keeps whatever it already had."""
        endpoint = self._endpoint(cfg)
        if endpoint is None:
            callback([])
            return
        reply = self._nam.get(QNetworkRequest(QUrl(endpoint + "/api/tags")))
        reply.finished.connect(lambda r=reply: self._on_models(r, callback))

    @staticmethod
    def _on_models(reply: QNetworkReply, callback) -> None:
        names: list[str] = []
        try:
            if reply.error() == QNetworkReply.NetworkError.NoError:
                data = json.loads(
                    bytes(reply.readAll()).decode("utf-8", "replace"))
                names = [m["name"] for m in data.get("models", [])
                         if isinstance(m, dict) and m.get("name")]
        except (ValueError, TypeError, KeyError):
            pass
        finally:
            reply.deleteLater()
        callback(names)

    def summarize(self, query: str, results: list[dict], cfg: dict) -> None:
        """Summarize search results — a one-shot request, no history."""
        self._start([{"role": "user",
                      "content": build_prompt(query, results)}], cfg)

    def translate(self, text: str, target_language: str, cfg: dict) -> None:
        """Translate `text` into `target_language` — a one-shot request, no
        history, same shape as summarize()."""
        self._start([{"role": "user",
                      "content": translate_prompt(text, target_language)}],
                     cfg)

    def chat(self, history: list[dict], cfg: dict, *, search_url=None) -> None:
        """Answer the conversation in `history` (a list of {role, content},
        ending with the user's newest question)."""
        if search_url and cfg.get("web_search"):
            self.cancel()
            if self._endpoint(cfg) is None:
                self.failed.emit("A local Ollama endpoint is required.")
                return
            messages = build_chat_messages(history, cfg)
            question = next((m['content'] for m in reversed(messages) if m['role'] == 'user'), '')
            self._search_pending = (messages, dict(cfg))
            self.status.emit("Searching the web through SearXNG…")
            self._search.start(question, search_url)
        else:
            self._start(build_chat_messages(history, cfg), cfg)

    def _searched(self, results):
        messages, cfg = self._search_pending
        self.status.emit("Answering with web results using your local model…")
        self._start(grounded_messages(messages, results), cfg)
        self._sources = results

    def _start(self, messages: list[dict], cfg: dict) -> None:
        self.cancel()
        self._raw = ""
        self._netbuf = b""
        self._got_content = False
        self._was_thinking = None

        endpoint = self._endpoint(cfg)
        if endpoint is None:
            self.failed.emit(
                "Refusing to send this off your device: the configured Ollama "
                "address is not on this machine. Local AI only ever talks to "
                "127.0.0.1 — fix \"endpoint\" in ai_search.json.")
            return
        req = QNetworkRequest(QUrl(endpoint + "/api/chat"))
        req.setAttribute(QNetworkRequest.Attribute.RedirectPolicyAttribute,
                         QNetworkRequest.RedirectPolicy.ManualRedirectPolicy)
        req.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader,
                      "application/json")
        body = json.dumps({
            "model": cfg.get("model", DEFAULTS["model"]),
            "messages": messages,
            "stream": True,
            "keep_alive": cfg.get("keep_alive", DEFAULTS["keep_alive"]),
            "options": {
                "temperature": float(cfg.get("temperature",
                                             DEFAULTS["temperature"]))},
        }).encode("utf-8")

        self._reply = self._nam.post(req, body)
        self._reply.readyRead.connect(self._on_ready)
        self._reply.finished.connect(self._on_finished)

    def cancel(self) -> None:
        self._search.cancel()
        self._sources = []
        if self._reply is not None:
            reply, self._reply = self._reply, None
            try:
                reply.readyRead.disconnect()
                reply.finished.disconnect()
            except TypeError:
                pass
            reply.abort()
            reply.deleteLater()

    # -- streaming -------------------------------------------------------

    def _on_ready(self) -> None:
        if self._reply is None:
            return
        self._netbuf += bytes(self._reply.readAll())
        while b"\n" in self._netbuf:
            line, self._netbuf = self._netbuf.split(b"\n", 1)
            line = line.strip()
            if line:
                self._handle_line(line)

    def _handle_line(self, line: bytes) -> None:
        try:
            obj = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            return
        if isinstance(obj, dict) and obj.get("error"):
            self._fail(str(obj["error"]))
            return
        piece = ""
        msg = obj.get("message") if isinstance(obj, dict) else None
        if isinstance(msg, dict):
            piece = msg.get("content", "") or ""
        elif isinstance(obj, dict):
            piece = obj.get("response", "") or ""   # /api/generate fallback
        if not piece:
            return
        self._got_content = True
        self._raw += piece
        visible, thinking = split_reasoning(self._raw)
        if thinking != self._was_thinking:
            self._was_thinking = thinking
            self.thinking.emit(thinking)
        self.chunk.emit(visible)

    def _on_finished(self) -> None:
        reply = self._reply
        if reply is None:
            return
        error = reply.error()
        code = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
        self._reply = None
        reply.deleteLater()
        if error != QNetworkReply.NetworkError.NoError and not self._got_content:
            self._fail(self._explain(error, reply.errorString()))
            return
        if not self._got_content or (code and not 200 <= code < 300):
            self._fail("Ollama returned no answer. Check the selected model and try again.")
            return
        visible, _ = split_reasoning(self._raw)
        if self._sources:
            visible += source_footer(self._sources)
        self.finished.emit(visible)

    def _fail(self, message: str) -> None:
        self.cancel()
        self.failed.emit(message)

    @staticmethod
    def _explain(error, fallback: str) -> str:
        C = QNetworkReply.NetworkError
        if error in (C.ConnectionRefusedError, C.HostNotFoundError,
                     C.RemoteHostClosedError):
            return ("Couldn't reach Ollama. Is it running? "
                    "(start it with `ollama serve`)")
        if error == C.OperationCanceledError:
            return "Cancelled."
        return fallback or "The request to Ollama failed."
