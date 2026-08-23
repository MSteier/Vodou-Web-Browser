"""Loopback control surface for driving a RUNNING Vodou from local tools.

OFF by default; enabled with the environment variable ``VODOU_ENABLE_CONTROL=1``.
When enabled, Vodou opens a ``QTcpServer`` bound to ``127.0.0.1`` on an
OS-assigned port and writes that port plus a per-run random token to
``~/.vodou/control.json`` so a same-machine client (the Vodou MCP server) can
find it and authenticate. The wire protocol is newline-delimited JSON: a request
``{"token","cmd","params"}`` gets a reply ``{"ok":true,"result":...}`` or
``{"ok":false,"error":"..."}``.

Security model:
  * **Loopback bind only** — never reachable from the LAN.
  * **Per-run random token**, written to a file only readable on this machine;
    a request without it is rejected.
  * **A fixed, minimal command set** — open/navigate tabs and read blocking
    stats. No file, shell, vault, or arbitrary-eval access.
  * Because ``QTcpServer`` runs on the GUI thread's event loop, handlers touch
    the window directly — no cross-thread widget access.

``dispatch()`` is deliberately free of Qt/window internals beyond duck-typed
attribute access and injected ``url_factory`` / ``url_ok`` callables, so it can
be unit-tested against a fake window with no QApplication.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from PyQt6.QtCore import QObject
from PyQt6.QtNetwork import QHostAddress, QTcpServer

import blockstats

CONTROL_FILE = Path.home() / ".vodou" / "control.json"


class ControlError(Exception):
    """A control command failed for a client-visible reason (bad args, etc.)."""


def control_enabled() -> bool:
    """True when VODOU_ENABLE_CONTROL is set to something truthy."""
    return os.environ.get("VODOU_ENABLE_CONTROL", "").strip().lower() \
        not in ("", "0", "false", "no", "off")


def _period_for(key: str):
    for p in blockstats.PERIODS:
        if p.key == key:
            return p
    return blockstats.PERIODS[0]


def dispatch(window, cmd: str, params: dict | None, *,
             url_factory, url_ok) -> dict:
    """Execute one control command against ``window``.

    ``url_factory(text) -> QUrl`` builds a URL and ``url_ok(url) -> bool`` says
    whether it's an acceptable http(s) target; both are injected so this stays
    testable without Qt. Returns a JSON-serializable result, or raises
    ControlError for a client-visible failure.
    """
    params = params or {}
    if cmd == "ping":
        return {"pong": True}

    if cmd == "list_tabs":
        tabs = []
        for i, v in enumerate(window._views):
            tabs.append({
                "index": i,
                "url": v.url().toString(),
                "title": getattr(v, "_full_title", "") or v.url().host(),
                "current": v is window.current_view(),
            })
        return {"tabs": tabs}

    if cmd == "open_tab":
        u = url_factory(str(params.get("url", "")))
        if not url_ok(u):
            raise ControlError("invalid or non-http(s) url")
        window.add_tab(u)
        return {"opened": u.toString()}

    if cmd == "navigate":
        u = url_factory(str(params.get("url", "")))
        if not url_ok(u):
            raise ControlError("invalid or non-http(s) url")
        view = window.current_view()
        if view is None:
            raise ControlError("no active tab")
        view.setUrl(u)
        return {"navigated": u.toString()}

    if cmd == "blocking_stats":
        p = _period_for(str(params.get("period", "1h")))
        return {
            "period": p.key,
            "total": window.block_stats.total(p),
            "top_hosts": [{"host": h, "count": n}
                          for h, n in window.block_stats.top_hosts(p)],
        }

    raise ControlError(f"unknown command: {cmd}")


def write_control_file(port: int, token: str,
                       path: Path = CONTROL_FILE) -> None:
    """Publish ``{port, token}`` for the local client, owner-only where possible."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"port": port, "token": token}),
                    encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class ControlServer(QObject):
    """A loopback QTcpServer exposing the ``dispatch`` command set to a client."""

    def __init__(self, window, url_factory, url_ok, parent=None):
        super().__init__(parent)
        self._window = window
        self._url_factory = url_factory
        self._url_ok = url_ok
        self._server = QTcpServer(self)
        self._token = secrets.token_hex(16)

    def start(self) -> bool:
        """Listen on 127.0.0.1:<ephemeral> and publish the control file."""
        if not self._server.listen(QHostAddress(QHostAddress.SpecialAddress.LocalHost), 0):
            return False
        self._server.newConnection.connect(self._on_new_connection)
        write_control_file(self._server.serverPort(), self._token)
        return True

    @property
    def port(self) -> int:
        return self._server.serverPort()

    def _on_new_connection(self) -> None:
        while self._server.hasPendingConnections():
            sock = self._server.nextPendingConnection()
            buffer = bytearray()

            def on_ready(s=sock, b=buffer):
                b.extend(bytes(s.readAll()))
                while b"\n" in b:
                    line, _, rest = bytes(b).partition(b"\n")
                    b.clear()
                    b.extend(rest)
                    self._handle_line(s, line)

            sock.readyRead.connect(on_ready)
            sock.disconnected.connect(sock.deleteLater)

    def _handle_line(self, sock, line: bytes) -> None:
        try:
            msg = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._reply(sock, {"ok": False, "error": "bad json"})
        # Constant-time token check.
        if not secrets.compare_digest(str(msg.get("token", "")), self._token):
            return self._reply(sock, {"ok": False, "error": "unauthorized"})
        try:
            result = dispatch(self._window, str(msg.get("cmd", "")),
                              msg.get("params"),
                              url_factory=self._url_factory,
                              url_ok=self._url_ok)
            self._reply(sock, {"ok": True, "result": result})
        except ControlError as exc:
            self._reply(sock, {"ok": False, "error": str(exc)})
        except Exception:
            # Never leak internals to the socket.
            self._reply(sock, {"ok": False, "error": "internal error"})

    @staticmethod
    def _reply(sock, obj: dict) -> None:
        sock.write((json.dumps(obj) + "\n").encode("utf-8"))
        sock.flush()

    def stop(self) -> None:
        self._server.close()
        try:
            CONTROL_FILE.unlink(missing_ok=True)
        except OSError:
            pass
