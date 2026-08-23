"""Tests for the loopback control surface (remote_control.dispatch) and the MCP
client that talks to it (vodou_backends.control_request).

`dispatch` is exercised against a fake window with no QApplication; the client is
exercised against a tiny real loopback socket stub (no Qt, no running browser).

Run:  python tests/test_remote_control.py
"""

import json
import socket
import sys
import tempfile
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))                 # remote_control (repo root)
sys.path.insert(0, str(_ROOT / "mcp_server"))  # vodou_backends

import remote_control as rc  # noqa: E402
import vodou_backends as be  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


# --- fakes for dispatch (no Qt) --------------------------------------------

class FakeUrl:
    def __init__(self, s, scheme="https", host="example.com", valid=True):
        self._s, self._scheme, self._host, self._valid = s, scheme, host, valid

    def toString(self):
        return self._s

    def host(self):
        return self._host

    def isValid(self):
        return self._valid

    def scheme(self):
        return self._scheme


class FakeView:
    def __init__(self, url, title=""):
        self._u, self._full_title, self.loaded = url, title, None

    def url(self):
        return self._u

    def setUrl(self, u):
        self.loaded = u


class FakeStats:
    def total(self, period):
        return 42

    def top_hosts(self, period, limit=8):
        return [("ads.example", 30), ("track.example", 12)]


class FakeWindow:
    def __init__(self, views, active=None):
        self._views = views
        self._active = active if active is not None else (views[0] if views else None)
        self.block_stats = FakeStats()

    def current_view(self):
        return self._active

    def add_tab(self, u):
        v = FakeView(u)
        self._views.append(v)
        return v


def url_factory(text):
    scheme = text.split(":", 1)[0].lower() if ":" in text else ""
    return FakeUrl(text, scheme=scheme or "http", valid=bool(text))


def url_ok(u):
    return u.isValid() and u.scheme() in ("http", "https")


def dispatch(win, cmd, params=None):
    return rc.dispatch(win, cmd, params, url_factory=url_factory, url_ok=url_ok)


# ---------------------------------------------------------------------------
print("control_enabled (env gate)")

import os
_saved = os.environ.get("VODOU_ENABLE_CONTROL")
os.environ.pop("VODOU_ENABLE_CONTROL", None)
check("disabled when env unset", not rc.control_enabled())
os.environ["VODOU_ENABLE_CONTROL"] = "0"
check("disabled when env is 0", not rc.control_enabled())
os.environ["VODOU_ENABLE_CONTROL"] = "1"
check("enabled when env is 1", rc.control_enabled())
if _saved is None:
    os.environ.pop("VODOU_ENABLE_CONTROL", None)
else:
    os.environ["VODOU_ENABLE_CONTROL"] = _saved

# ---------------------------------------------------------------------------
print("\ndispatch commands")

win = FakeWindow([FakeView(FakeUrl("https://a.example/", host="a.example"),
                           "Alpha"),
                 FakeView(FakeUrl("https://b.example/", host="b.example"))])

check("ping", dispatch(win, "ping") == {"pong": True})

tabs = dispatch(win, "list_tabs")["tabs"]
check("list_tabs returns all tabs", len(tabs) == 2)
check("list_tabs marks the current tab",
      tabs[0]["current"] is True and tabs[1]["current"] is False)
check("list_tabs falls back to host when no title",
      tabs[1]["title"] == "b.example")

before = len(win._views)
res = dispatch(win, "open_tab", {"url": "https://new.example/x"})
check("open_tab adds a tab", len(win._views) == before + 1)
check("open_tab echoes the opened url", res["opened"] == "https://new.example/x")
check("open_tab rejects non-http(s)",
      raises(rc.ControlError,
             lambda: dispatch(win, "open_tab", {"url": "file:///etc/passwd"})))
check("open_tab rejects empty url",
      raises(rc.ControlError, lambda: dispatch(win, "open_tab", {"url": ""})))

res = dispatch(win, "navigate", {"url": "https://go.example/"})
check("navigate loads url in active tab",
      win.current_view().loaded.toString() == "https://go.example/")
check("navigate rejects javascript: urls",
      raises(rc.ControlError,
             lambda: dispatch(win, "navigate",
                              {"url": "javascript:alert(1)"})))
check("navigate errors with no active tab",
      raises(rc.ControlError,
             lambda: dispatch(FakeWindow([], active=None), "navigate",
                              {"url": "https://x.example/"})))

stats = dispatch(win, "blocking_stats", {"period": "1h"})
check("blocking_stats total", stats["total"] == 42)
check("blocking_stats top hosts",
      stats["top_hosts"][0] == {"host": "ads.example", "count": 30})
check("blocking_stats unknown period falls back to a valid one",
      dispatch(win, "blocking_stats", {"period": "nope"})["period"]
      in ("1h", "24h"))

check("unknown command raises",
      raises(rc.ControlError, lambda: dispatch(win, "frobnicate")))

# ---------------------------------------------------------------------------
print("\nMCP control client framing")

req = be.build_control_request("tok", "open_tab", {"url": "https://x/"})
parsed = json.loads(req.decode("utf-8"))
check("request carries token/cmd/params and a newline",
      req.endswith(b"\n") and parsed["token"] == "tok"
      and parsed["cmd"] == "open_tab" and parsed["params"]["url"] == "https://x/")
check("parse_control_response returns result on ok",
      be.parse_control_response(b'{"ok":true,"result":{"pong":true}}')
      == {"pong": True})
check("parse_control_response raises on ok:false",
      raises(RuntimeError,
             lambda: be.parse_control_response(b'{"ok":false,"error":"nope"}')))

# ---------------------------------------------------------------------------
print("\nMCP control client over a real loopback stub")


def _serve_once(sock, expect_token):
    conn, _ = sock.accept()
    with conn:
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        msg = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
        if msg.get("token") != expect_token:
            conn.sendall(b'{"ok":false,"error":"unauthorized"}\n')
        elif msg.get("cmd") == "ping":
            conn.sendall(b'{"ok":true,"result":{"pong":true}}\n')
        else:
            conn.sendall(b'{"ok":false,"error":"unknown"}\n')


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
port = srv.getsockname()[1]
t = threading.Thread(target=_serve_once, args=(srv, "secret-token"), daemon=True)
t.start()

d = Path(tempfile.mkdtemp())
(d / "control.json").write_text(json.dumps({"port": port, "token": "secret-token"}),
                                encoding="utf-8")
result = be.control_request("ping", vodou_dir=d, timeout=5.0)
check("control_request round-trips a result", result == {"pong": True})
srv.close()

# No control.json -> ControlUnavailable (control not enabled / not running).
check("control_request raises ControlUnavailable when not configured",
      raises(be.ControlUnavailable,
             lambda: be.control_request("ping", vodou_dir=Path(tempfile.mkdtemp()),
                                        timeout=2.0)))

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL REMOTE-CONTROL TESTS PASSED")
