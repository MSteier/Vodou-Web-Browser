"""Regression checks for the seven accepted project-review fixes.

Run: python tests/test_review_regressions.py
Uses offscreen Qt, local sockets/pages and temporary files; no user profile.
"""
import csv
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Import WebEngine before constructing QApplication. Redirect all module-level
# profile paths while importing the app so these checks cannot touch real data.
PROFILE = tempfile.TemporaryDirectory(prefix="vodou-review-tests-")
with patch.object(Path, "home", return_value=Path(PROFILE.name)):
    import main
    import about
    import ai_search
    import autofill
    import cert_viewer
    import importers
    import remote_control
    from browser_instance import BrowserInstance
    from vault import Entry

from PyQt6.QtCore import QEvent, QUrl
from PyQt6.QtNetwork import QHostAddress, QNetworkProxy, QTcpSocket
from PyQt6.QtWebEngineCore import QWebEnginePage
from PyQt6.QtWidgets import QApplication

APP = QApplication.instance() or QApplication(["vodou-review-tests"])


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        APP.processEvents()
        if time.monotonic() >= deadline:
            raise AssertionError("Timed out waiting for Qt")
        time.sleep(0.005)


def js(page, code, world=main.APP_WORLD):
    results = []
    page.runJavaScript(code, world, results.append)
    wait_for(lambda: bool(results))
    return results[0]


def load_login(page, url="https://saved.example/login"):
    results = []
    page.loadFinished.connect(results.append)
    page.setHtml('<input autocomplete="username"><input type="password">', QUrl(url))
    wait_for(lambda: bool(results))
    page.loadFinished.disconnect(results.append)
    assert results[0]


class AutofillTests(unittest.TestCase):
    def test_renderer_rejects_replaced_document_and_wrong_url(self):
        page = QWebEnginePage()
        try:
            load_login(page)
            document = js(page, autofill.DOCUMENT_JS)
            script = autofill.build_fill_script("user", "review-secret",
                expected_url=document["url"], document_token=document["token"])
            self.assertEqual(js(page, script), "ok")
            self.assertEqual(js(page, "document.querySelector('[type=password]').value"),
                             "review-secret")
            # Even a reload of the same URL is a different document.
            load_login(page)
            self.assertNotEqual(js(page, autofill.DOCUMENT_JS)["token"], document["token"])
            self.assertEqual(js(page, script), "page-changed")
            self.assertEqual(js(page, "document.querySelector('[type=password]').value"), "")
            # Page-authored main-world properties cannot forge isolated state.
            js(page, "window.__vodouFillDocument=" + json.dumps(document["token"]), 0)
            self.assertEqual(js(page, script), "page-changed")
            load_login(page, "https://other.example/login")
            js(page, "window.__vodouFillDocument=" + json.dumps(document["token"]))
            self.assertEqual(js(page, script), "page-changed")
        finally:
            page.deleteLater()
            APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    def test_navigation_during_unlock_never_decrypts_password(self):
        page = Mock()
        view = SimpleNamespace(address=QUrl("https://saved.example/login"),
                               document_generation=1, page=lambda: page)
        view.url = lambda: view.address
        browser = SimpleNamespace(current_view=lambda: view, vault=Mock(),
                                  _on_fill_result=Mock())
        browser._fill_target_current = lambda *args: main.BrowserWindow._fill_target_current(browser, *args)
        def unlock():
            view.address = QUrl("https://other.example/login")
            view.document_generation += 1
            return True
        browser._unlock_vault = unlock
        main.BrowserWindow._fill_document(browser, view, page, view.url(), 1, "document-1")
        browser.vault.reveal.assert_not_called()
        page.runJavaScript.assert_not_called()
        browser._on_fill_result.assert_called_once_with("page-changed")

    def test_reload_while_choosing_login_never_decrypts(self):
        page = Mock()
        url = QUrl("https://saved.example/login")
        view = SimpleNamespace(document_generation=1, page=lambda: page, url=lambda: url)
        entry = Entry("saved.example", "user", "")
        vault = Mock()
        vault.entries_for_host.return_value = [(0, entry), (1, entry)]
        browser = SimpleNamespace(current_view=lambda: view, vault=vault,
                                  _unlock_vault=lambda: True, _on_fill_result=Mock())
        browser._fill_target_current = lambda *args: main.BrowserWindow._fill_target_current(browser, *args)
        picker = Mock(choice=(0, entry))
        def choose():
            view.document_generation += 1
            return True
        picker.exec.side_effect = choose
        with patch.object(main, "PickEntryDialog", return_value=picker):
            main.BrowserWindow._fill_document(browser, view, page, url, 1, "old")
        vault.reveal.assert_not_called()
        page.runJavaScript.assert_not_called()


class ProxyAndHistoryTests(unittest.TestCase):
    def test_proxy_blocks_certificate_connection_before_dns(self):
        previous = QNetworkProxy.applicationProxy()
        try:
            for kind in (QNetworkProxy.ProxyType.HttpProxy, QNetworkProxy.ProxyType.Socks5Proxy):
                QNetworkProxy.setApplicationProxy(QNetworkProxy(kind, "127.0.0.1", 9))
                with patch.object(cert_viewer.socket, "create_connection") as connect:
                    with self.assertRaises(cert_viewer.CertificateProxyUnsupported):
                        cert_viewer.fetch_certificate("saved.example")
                    connect.assert_not_called()
        finally:
            QNetworkProxy.setApplicationProxy(previous)

    def test_safety_prompt_reports_skipped_certificate(self):
        prompt = ai_search.build_site_safety_prompt({"url": "https://example.com",
            "host": "example.com", "connection": "HTTPS", "cert_check_skipped": "proxy active"})
        self.assertIn("not checked (proxy active)", prompt)

    def test_clear_history_includes_detached_and_closed_tabs(self):
        regular, detached = Mock(), Mock()
        browser = SimpleNamespace(profile=Mock(), cookie_keeper=Mock(), block_stats=Mock(),
            blocked_count=2, _refresh_shield=Mock(), _report_window=None,
            _views=[regular], _detached_windows=[SimpleNamespace(view=detached)],
            _closed_tabs=[("https://private.example", False)], statusBar=lambda: Mock())
        with patch.object(main.QMessageBox, "information"):
            main.BrowserWindow.clear_browsing_data(browser)
        regular.history().clear.assert_called_once()
        detached.history().clear.assert_called_once()
        self.assertEqual(browser._closed_tabs, [])


class CsvTests(unittest.TestCase):
    def test_export_import_round_trip_preserves_credentials(self):
        values = [" secret ", "'=literal", "'normal", "''=double", "=formula", " +formula",
                  "line1\nline2", "line1\r\nline2", "\tleading", " ", "päss🔒"]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "vault.csv"
            entries = [Entry("example.com", " user ", p, "note\nline") for p in values]
            importers.write_password_csv(path, entries)
            result, skipped = importers.parse_password_csv(path)
            self.assertEqual(skipped, 0)
            self.assertEqual([e.password for e in result], values)
            self.assertTrue(all(e.username == " user " and e.notes == "note\nline" for e in result))
            with path.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(rows[4]["password"], "'=formula")
            self.assertEqual(rows[1]["password"], "''=literal")

    def test_external_csv_is_never_unescaped_or_trimmed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "external.csv"
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["url", "username", "password"])
                w.writerow(["https://example.com", " user ", "'=original\r\n "])
            result, _ = importers.parse_password_csv(path)
            self.assertEqual(result[0].password, "'=original\r\n ")
            self.assertEqual(result[0].username, " user ")

    def test_overlong_or_invalid_password_is_not_silently_rewritten(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "invalid.csv"
            path.write_text("url,password\nhttps://example.com," + "x" * (importers.MAX_FIELD + 1))
            self.assertEqual(importers.parse_password_csv(path), ([], 1))
            path.write_bytes(b"url,password\nhttps://example.com,\xff")
            with self.assertRaises(OSError):
                importers.parse_password_csv(path)


class ControlTests(unittest.TestCase):
    def test_malformed_socket_messages_do_not_kill_server(self):
        server = remote_control.ControlServer(None, None, None)
        self.assertTrue(server._server.listen(QHostAddress("127.0.0.1"), 0))
        server._server.newConnection.connect(server._on_new_connection)
        def request(payload):
            sock = QTcpSocket()
            sock.connectToHost("127.0.0.1", server.port)
            self.assertTrue(sock.waitForConnected(1000))
            sock.write(payload + b"\n")
            sock.flush()
            wait_for(lambda: sock.bytesAvailable() > 0)
            result = json.loads(bytes(sock.readAll()))
            sock.abort()
            return result
        try:
            for payload in (b"[]", b"null", b"7", b"bad json", b'{"token":"\\u00e9"}',
                            b"[" * 1500 + b"]" * 1500):
                self.assertFalse(request(payload)["ok"])
            malformed = {"token": server._token, "cmd": "ping", "params": []}
            self.assertFalse(request(json.dumps(malformed).encode())["ok"])
            valid = {"token": server._token, "cmd": "ping"}
            self.assertEqual(request(json.dumps(valid).encode()), {"ok": True, "result": {"pong": True}})
        finally:
            server._server.close()
            server.deleteLater()
            APP.processEvents()


class InstanceTests(unittest.TestCase):
    def test_second_instance_forwards_without_owning_storage(self):
        with tempfile.TemporaryDirectory() as d:
            primary, second = BrowserInstance(Path(d) / ".vodou"), BrowserInstance(Path(d) / ".vodou")
            try:
                self.assertTrue(primary.acquire())
                primary.listen()
                self.assertFalse(second.acquire())
                received, errors = [], []
                primary.set_handler(received.append)
                def forward():
                    try:
                        second.forward("https://example.com/link")
                    except Exception as error:
                        errors.append(error)
                worker = threading.Thread(target=forward)
                worker.start()
                wait_for(lambda: not worker.is_alive(), timeout=8)
                worker.join()
                self.assertEqual(errors, [])
                self.assertEqual(received, ["https://example.com/link"])
                primary.close()
                self.assertTrue(second.acquire())
            finally:
                second.close()
                primary.close()

    def test_dead_owner_lock_is_recoverable(self):
        with tempfile.TemporaryDirectory() as d:
            code = ("import os,sys; from pathlib import Path; "
                    "from PyQt6.QtCore import QCoreApplication; "
                    "from browser_instance import BrowserInstance; "
                    "app=QCoreApplication(['lock-test']); "
                    "guard=BrowserInstance(Path(sys.argv[1])); "
                    "assert guard.acquire(); os._exit(0)")
            subprocess.run([sys.executable, "-c", code, str(Path(d) / ".vodou")], cwd=ROOT, check=True, timeout=10)
            guard = BrowserInstance(Path(d) / ".vodou")
            try:
                self.assertTrue(guard.acquire())
            finally:
                guard.close()

    def test_secondary_main_does_not_migrate_shred_or_open_vault(self):
        instance = Mock()
        instance.acquire.return_value = False
        with patch.object(main, "QApplication", return_value=Mock()), \
             patch.object(main, "BrowserInstance", return_value=instance), \
             patch.object(main, "migrate_config_dir") as migrate, \
             patch.object(main, "secure_config_dir") as secure, \
             patch.object(main, "shred_dir") as shred, \
             patch.object(main, "BrowserWindow") as window, \
             patch.object(main, "_startup_url_from_argv", return_value="https://example.com"):
            main.main()
        instance.forward.assert_called_once_with("https://example.com")
        migrate.assert_not_called()
        secure.assert_not_called()
        shred.assert_not_called()
        window.assert_not_called()
        instance.close.assert_called_once()

    def test_restart_is_deferred_until_shutdown(self):
        browser = SimpleNamespace(_write_session=Mock(), close=Mock())
        with patch.object(main, "mark_restart"), patch.object(main.QProcess, "startDetached") as start:
            main.BrowserWindow._restart_app(browser)
        start.assert_not_called()
        browser.close.assert_called_once()
        self.assertEqual(browser._relaunch_command[0], sys.executable)

    def test_profile_cleanup_finishes_before_restart_can_acquire_it(self):
        instance, app, window = Mock(), Mock(), Mock()
        instance.acquire.return_value = True
        instance.owned = True
        instance.close.side_effect = lambda: setattr(instance, "owned", False)
        app.exec.return_value = 0
        window._relaunch_command = (sys.executable, [], str(ROOT))
        def owned(*args):
            self.assertTrue(instance.owned)
        def restart(*args):
            self.assertFalse(instance.owned)
            return True, 1
        with patch.object(main, "QApplication", return_value=app), \
             patch.object(main, "BrowserInstance", return_value=instance), \
             patch.object(main, "migrate_config_dir", side_effect=owned), \
             patch.object(main, "secure_config_dir", side_effect=owned), \
             patch.object(main, "shred_dir", side_effect=owned) as shred, \
             patch.object(main, "_dispose_browser", side_effect=owned) as dispose, \
             patch.object(main, "apply_theme"), \
             patch.object(main, "BrowserWindow", return_value=window), \
             patch.object(main.QProcess, "startDetached", side_effect=restart) as start:
            with self.assertRaises(SystemExit) as result:
                main.main()
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(shred.call_count, 2)
        dispose.assert_called_once_with(window)
        start.assert_called_once_with(*window._relaunch_command)


class UpdateTests(unittest.TestCase):
    def test_general_update_uses_staging_dialog_not_live_pip(self):
        for outcome in ("current", "staged", "not_applied", "unavailable", "applying"):
            browser = SimpleNamespace(status=Mock(), _start_proc=Mock(), _note=Mock(),
                _note_already_current=Mock(), _start_definitions=Mock(),
                _open_qt_updater=Mock(return_value=SimpleNamespace(outcome=outcome)))
            about.AboutDialog._start_engine(browser)
            browser._open_qt_updater.assert_called_once()
            browser._start_proc.assert_not_called()
            self.assertEqual(browser._engine_status, outcome)
            self.assertEqual(browser._start_definitions.call_count, 0 if outcome == "applying" else 1)

if __name__ == "__main__":
    unittest.main(verbosity=2)
