"""Tests for the HTTP/SOCKS5 proxy feature.

Covers, without any network access or the real user profile:
  * building a QNetworkProxy from a saved config (types, SOCKS5 remote DNS),
  * proxy.json round-trip,
  * end-to-end routing — a real QWebEnginePage sent through a local fake proxy,
    whose arrival (captured locally, never forwarded) proves live routing,
  * the _on_proxy_auth credential logic: vault auto-fill, rejection-then-
    prompt, and the consecutive-failure cap that stops an auth loop.

The home directory is redirected to a throwaway temp dir BEFORE main is
imported, so the test never reads or writes the real ~/.vodou (the bug that
an earlier ad-hoc version of this test had). The Qt/WebEngine parts skip
cleanly if the engine can't initialize (e.g. a headless CI without it).

Run:  python tests/test_proxy.py
"""

import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

# Bail hard rather than hang forever if WebEngine wedges.
threading.Thread(
    target=lambda: (time.sleep(60), os._exit(3)), daemon=True).start()

# Isolate the home directory BEFORE importing main (which reads config from it).
_tmp_home = Path(tempfile.mkdtemp(prefix="vodou-proxy-test-"))
os.environ["USERPROFILE"] = str(_tmp_home)
os.environ["HOMEDRIVE"] = _tmp_home.drive or "C:"
os.environ["HOMEPATH"] = str(_tmp_home)[2:] if _tmp_home.drive else str(_tmp_home)
os.environ["HOME"] = str(_tmp_home)
os.environ["QT_QPA_PLATFORM"] = "offscreen"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PyQt6.QtNetwork import QNetworkProxy                        # noqa: E402
import main                                                      # noqa: E402

Type = QNetworkProxy.ProxyType
Cap = QNetworkProxy.Capability
_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# Guard: the isolated home must be in effect, or we'd risk the real profile.
assert str(main.PROXY_FILE).startswith(str(_tmp_home)), \
    "home isolation failed — refusing to run against the real profile"


# --- 1. QNetworkProxy construction (pure, no Qt app) ------------------------
print("QNetworkProxy construction")
check("disabled -> NoProxy",
      main._build_qnetwork_proxy({"enabled": False}).type() == Type.NoProxy)
check("no host -> NoProxy",
      main._build_qnetwork_proxy({"enabled": True, "host": ""}).type()
      == Type.NoProxy)

p = main._build_qnetwork_proxy(
    {"enabled": True, "type": "http", "host": "proxy.corp", "port": 8080})
check("http -> HttpProxy host/port",
      p.type() == Type.HttpProxy and p.hostName() == "proxy.corp"
      and p.port() == 8080)

p = main._build_qnetwork_proxy(
    {"enabled": True, "type": "socks5", "host": "127.0.0.1", "port": 9050,
     "remote_dns": True})
check("socks5 remote DNS -> HostNameLookupCapability set",
      p.type() == Type.Socks5Proxy
      and bool(p.capabilities() & Cap.HostNameLookupCapability))
p = main._build_qnetwork_proxy(
    {"enabled": True, "type": "socks5", "host": "127.0.0.1", "port": 9050,
     "remote_dns": False})
check("socks5 local DNS -> capability cleared",
      not (p.capabilities() & Cap.HostNameLookupCapability))

# --- 2. proxy.json round-trip -----------------------------------------------
print("\nproxy.json round-trip")
conf = {"enabled": True, "type": "socks5", "host": "10.0.0.1", "port": 1080,
        "username": "u", "remote_dns": True}
main.save_proxy_conf(conf)
check("save/load round-trips", main._load_proxy_conf() == conf)


# --- Qt-dependent phases ----------------------------------------------------
def start_fake_proxy():
    """A local listener that records the first request line of each connection
    and never forwards. Returns (port, captured_list)."""
    captured = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(1.0)
    port = srv.getsockname()[1]

    def serve():
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                conn.settimeout(2)
                data = conn.recv(4096)
                if data:
                    captured.append(data.decode("latin-1", "replace"))
            except OSError:
                pass
            finally:
                conn.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return port, captured, srv


try:
    from PyQt6.QtCore import QUrl                                 # noqa: E402
    from PyQt6.QtWidgets import QApplication                     # noqa: E402
    from PyQt6.QtWebEngineCore import QWebEnginePage             # noqa: E402
    app = QApplication.instance() or QApplication(sys.argv)
    _probe_page = QWebEnginePage()      # forces engine init; may raise if absent
except Exception as exc:  # noqa: BLE001
    print(f"\nSKIP: QtWebEngine unavailable in this environment ({exc})")
    if _failures:
        print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
        sys.exit(1)
    print("PROXY CONSTRUCTION/ROUND-TRIP TESTS PASSED (engine tests skipped)")
    sys.exit(0)


# --- 3. end-to-end routing through a local fake proxy (hermetic) ------------
print("\nend-to-end routing through a local proxy")
port, captured, srv = start_fake_proxy()
QNetworkProxy.setApplicationProxy(main._build_qnetwork_proxy(
    {"enabled": True, "type": "http", "host": "127.0.0.1", "port": port}))
page = QWebEnginePage()
page.load(QUrl("http://example.com/"))   # never forwarded; captured at proxy
deadline = time.time() + 20
while time.time() < deadline and not captured:
    app.processEvents()
    time.sleep(0.03)
srv.close()
first_line = captured[0].splitlines()[0] if captured else ""
print("    proxy saw:", first_line[:90] or "(nothing)")
check("QtWebEngine routed the request through the configured proxy",
      bool(captured) and "example.com" in captured[0])

# Back to direct so BrowserWindow construction below starts clean.
QNetworkProxy.setApplicationProxy(QNetworkProxy(Type.NoProxy))
main.save_proxy_conf({"enabled": False})


# --- 4. _on_proxy_auth credential logic -------------------------------------
print("\n_on_proxy_auth credential logic")
win = main.BrowserWindow()


class FakeAuth:
    def __init__(self, user=""):
        self._u, self._p = user, None
    def user(self):
        return self._u
    def setUser(self, u):
        self._u = u
    def setPassword(self, p):
        self._p = p


win.vault.create("master")
win.vault.set_proxy_credential("vaultuser", "vaultpass")
win._apply_proxy()                      # resets auth caches
a = FakeAuth()
win._on_proxy_auth(None, a, "proxy.example:8080")
check("auto-fills username/password from the unlocked vault",
      a._u == "vaultuser" and a._p == "vaultpass")

prompts = {"n": 0}
win._prompt_proxy_credentials = lambda host, rejected: (
    prompts.__setitem__("n", prompts["n"] + 1) or ("typed", "typed-pw"))
# Qt re-emits with the same user we just offered => that attempt was rejected.
a2 = FakeAuth(user="vaultuser")
win._on_proxy_auth(None, a2, "proxy.example:8080")
check("a rejected credential triggers a fresh prompt", prompts["n"] == 1)
check("uses the freshly prompted credential",
      a2._u == "typed" and a2._p == "typed-pw")

print("\nconsecutive-failure cap (no infinite auth loop)")
win._prompt_proxy_credentials = lambda host, rejected: ("typed", "typed-pw")
host = "loop.example:3128"
win._proxy_last_offered[host] = ("typed", "typed-pw")
gave_up = False
for _ in range(6):
    au = FakeAuth(user="typed")         # always "rejected"
    win._on_proxy_auth(None, au, host)
    win._proxy_last_offered[host] = ("typed", "typed-pw")
    if au._p is None:                   # handler returned without filling
        gave_up = True
        break
check("stops feeding credentials after repeated rejections", gave_up)

print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL PROXY TESTS PASSED")
