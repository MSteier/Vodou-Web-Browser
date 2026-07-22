"""On-device AI, via a local Ollama instance: search summaries, and chat.

Vodou's search already stays on your machine (a local SearXNG instance). This
adds two optional, on-demand features, both produced **entirely locally** by
talking to Ollama over HTTP on 127.0.0.1:

  * **Summarize** the results on a SearXNG page.
  * **Ask** the model anything, as a normal multi-turn conversation.

Nothing leaves the device: SearXNG is local, Ollama is local, and Vodou is only
a client of Ollama's HTTP API — it never changes Ollama's models, config, or
environment, so any other tools you run against Ollama keep working unchanged.
Ask mode sends *only what you type* — no page content, URL, or history is ever
attached to a question.

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
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest

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
}


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


def is_search_results(url: QUrl) -> bool:
    """True for a local SearXNG results page — the only place the summary
    button does anything."""
    if url.host() not in ("localhost", "127.0.0.1"):
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
    recent = [m for m in history
              if isinstance(m, dict) and m.get("role") and m.get("content")]
    return [{"role": "system", "content": ASK_SYSTEM}] + recent[-limit:]


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

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._nam = QNetworkAccessManager(self)
        self._reply: QNetworkReply | None = None
        self._raw = ""
        self._netbuf = b""
        self._got_content = False
        self._was_thinking = None

    @property
    def busy(self) -> bool:
        return self._reply is not None

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

    def chat(self, history: list[dict], cfg: dict) -> None:
        """Answer the conversation in `history` (a list of {role, content},
        ending with the user's newest question)."""
        self._start(build_chat_messages(history, cfg), cfg)

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
        self._reply = None
        reply.deleteLater()
        if error != QNetworkReply.NetworkError.NoError and not self._got_content:
            self._fail(self._explain(error, reply.errorString()))
            return
        visible, _ = split_reasoning(self._raw)
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
