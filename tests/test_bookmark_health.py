"""Real local HTTP/TLS, worker-thread responsiveness, and confirmed deletion."""
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PyQt6.QtCore import QThread, QTimer, Qt
from PyQt6.QtNetwork import QNetworkProxy
from PyQt6.QtWidgets import QApplication, QMessageBox
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from bookmark_health import HealthCheckWorker, HealthResult, _Batch
from bookmark_health_ui import BookmarkHealthDialog
from bookmarks import Bookmark, Bookmarks

APP = QApplication.instance() or QApplication([])
QNetworkProxy.setApplicationProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))


def spin(predicate, timeout=10):
    end = time.monotonic() + timeout
    while not predicate():
        APP.processEvents()
        if time.monotonic() > end:
            raise AssertionError('Timed out waiting for worker')
        time.sleep(.002)
    APP.processEvents()


class Handler(BaseHTTPRequestHandler):
    calls = Counter()
    lock = threading.Lock()
    active = maximum = 0

    def log_message(self, *args):
        pass

    def handle_check(self):
        with self.lock:
            type(self).calls[self.command, self.path] += 1
            type(self).active += 1
            type(self).maximum = max(self.active, self.maximum)
        try:
            if self.path.startswith('/slow'):
                time.sleep(.2)
            if self.path == '/reset' or (self.path == '/head-error' and self.command == 'HEAD'):
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            code = 200
            if self.path in ('/404','/503','/403'):
                code = int(self.path[1:])
            elif self.path in ('/405','/501','/bad-head') and self.command == 'HEAD':
                code = 404 if self.path == '/bad-head' else int(self.path[1:])
            elif self.path == '/loop':
                code = 302
            elif self.path == '/redirect':
                code = 301
            elif self.path == '/flaky':
                code = 503 if self.calls[self.command, self.path] < 2 else 200
            elif self.path == '/limited':
                code = 503
            self.send_response(code)
            self.send_header('Content-Length', '0')
            if code in (301,302):
                self.send_header('Location','/loop' if code == 302 else '/ok')
            if code == 503:
                self.send_header('Retry-After','1')
            self.end_headers()
        except (ConnectionError, OSError):
            pass
        finally:
            with self.lock:
                type(self).active -= 1

    do_HEAD = handle_check
    do_GET = handle_check


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def setUp(self):
        spin(lambda:Handler.active == 0)
        Handler.calls.clear(); Handler.maximum = 0

    def scan(self, paths, wait=10, **kwargs):
        worker = HealthCheckWorker([Bookmark(p, p if '://' in p else self.base+p) for p in paths],
                                   timeout=kwargs.pop('timeout',.8), **kwargs)
        results, errors, progress = [], [], []
        worker.result.connect(results.append)
        worker.failed.connect(errors.append)
        worker.progress.connect(lambda a,b:progress.append((a,b)))
        worker.start()
        try:
            spin(lambda:worker.isFinished(), timeout=wait)
            self.assertFalse(errors)
            self.assertEqual(len(results),len(paths))
            self.assertEqual(progress[-1],(len(paths),len(paths)))
        finally:
            worker.cancel(); worker.wait(); worker.deleteLater()
        return {r.title:r for r in results}

    def test_head_first_and_all_failed_heads_fall_back_to_get(self):
        results = self.scan(['/ok','/405','/501','/bad-head','/head-error'])
        self.assertTrue(all(r.ok for r in results.values()))
        self.assertEqual(Handler.calls['GET','/ok'],0)
        for path in ('/405','/501','/bad-head','/head-error'):
            self.assertEqual(results[path].method,'GET')
            self.assertGreaterEqual(Handler.calls['GET',path],1)

    def test_http_failures_are_broken_with_status_and_reason(self):
        # /503 is retried with backoff (see test_rate_limited_response_is_backed_off_*
        # below) before it's finally reported broken, so this needs a longer wait.
        results = self.scan(['/404','/403','/503'], wait=20)
        for path,result in results.items():
            self.assertFalse(result.ok)
            self.assertEqual(result.status_code,int(path[1:]))
            self.assertEqual(result.reason,'HTTP '+path[1:])
            self.assertEqual(result.method,'GET')

    def test_rate_limited_response_is_backed_off_and_retried_before_success(self):
        results = self.scan(['/flaky'])
        self.assertTrue(results['/flaky'].ok)
        self.assertEqual(results['/flaky'].method,'HEAD')
        # Backed off and retried on the same method rather than immediately
        # falling back to GET or being reported broken.
        self.assertEqual(Handler.calls['HEAD','/flaky'],2)
        self.assertEqual(Handler.calls['GET','/flaky'],0)

    def test_rate_limited_response_gives_up_after_max_attempts(self):
        results = self.scan(['/limited'], wait=20)
        result = results['/limited']
        self.assertFalse(result.ok)
        self.assertEqual(result.status_code,503)
        self.assertEqual(result.method,'GET')
        # 3 attempts on HEAD, then one GET fallback attempt.
        self.assertEqual(Handler.calls['HEAD','/limited'],3)
        self.assertEqual(Handler.calls['GET','/limited'],1)

    def test_invalid_url_is_reported_without_claiming_a_request_was_made(self):
        results = self.scan(['http://user:pass@example.invalid/','ftp://example.com/','http:///no-host'])
        for result in results.values():
            self.assertFalse(result.ok)
            self.assertEqual(result.method,'')
            self.assertEqual(result.reason,'Invalid URL or embedded credentials')

    def test_dns_refused_reset_and_redirect_loop(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0))
            refused = f'http://127.0.0.1:{reserved.getsockname()[1]}/'
        dns = 'http://vodou-bookmark-health-test.invalid/'
        results = self.scan([dns, refused, '/reset','/loop','/redirect'],timeout=2)
        self.assertEqual(results[dns].reason,'DNS resolution failed')
        # A local firewall can drop a closed-port connection instead of refusing it.
        self.assertTrue('Connection' in results[refused].reason or results[refused].reason == 'Timed out')
        self.assertIn('Connection',results['/reset'].reason)
        self.assertIn('Redirect',results['/loop'].reason)
        self.assertTrue(results['/redirect'].ok)
        self.assertTrue(all(not results[p].ok for p in (dns,refused,'/reset','/loop')))

    def test_timeout_and_slow_success_respect_setting(self):
        self.assertTrue(self.scan(['/slow'],timeout=.7)['/slow'].ok)
        result = self.scan(['/slow'],timeout=.05)['/slow']
        self.assertFalse(result.ok)
        self.assertEqual(result.reason,'Timed out')
        self.assertEqual(result.method,'GET')

    def test_concurrency_is_bounded_and_ui_keeps_ticking(self):
        beats, threads = [], []
        timer=QTimer(); timer.timeout.connect(lambda:beats.append(True)); timer.start(5)
        original=_Batch.request
        def observed(batch,*args):
            threads.append(QThread.currentThread() != APP.thread())
            return original(batch,*args)
        try:
            with patch.object(_Batch,'request',observed):
                results=self.scan([f'/slow?i={i}' for i in range(12)],concurrency=4,timeout=2)
        finally:
            timer.stop()
        self.assertTrue(all(r.ok for r in results.values()))
        self.assertGreater(Handler.maximum,1)
        self.assertLessEqual(Handler.maximum,4)
        self.assertGreater(len(beats),10)
        self.assertTrue(threads and all(threads))

    def test_untrusted_certificate_is_broken_without_disabling_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
            now=datetime.now(timezone.utc)
            cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name)
                  .public_key(key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
                  .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
                  .sign(key,hashes.SHA256()))
            cert_path=Path(directory)/'cert.pem'; key_path=Path(directory)/'key.pem'
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path,key_path)
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            try:
                url=f'https://127.0.0.1:{server.server_port}/'
                result=self.scan([url],timeout=2)[url]
                self.assertFalse(result.ok)
                self.assertIn('SSL error',result.reason)
            finally:
                server.shutdown(); server.server_close(); thread.join()

    def test_same_host_queue_does_not_use_up_timeout(self):
        results=self.scan([f'/slow?bulk={i}' for i in range(16)],concurrency=16,timeout=2)
        self.assertTrue(all(r.ok for r in results.values()))
        self.assertGreater(Handler.maximum,6)
        self.assertLessEqual(Handler.maximum,16)

    def test_cancel_and_empty_scan_finish_cleanly(self):
        self.assertEqual(self.scan([]),{})
        worker=HealthCheckWorker([Bookmark('slow',self.base+'/slow')]*30,concurrency=3)
        results=[]; worker.result.connect(results.append); worker.start()
        spin(lambda:Handler.active>0)
        worker.cancel()
        spin(lambda:worker.isFinished(),timeout=2)
        worker.wait(); worker.deleteLater()
        self.assertEqual(results,[])

    def test_dialog_scans_shows_progress_and_can_close_during_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Bookmarks(Path(directory)/'bookmarks.json')
            store.add('Good',self.base+'/ok'); store.add('Missing',self.base+'/404')
            dialog=BookmarkHealthDialog(store)
            dialog._start()
            spin(lambda:dialog.scanner is None)
            self.assertEqual((dialog.checked,dialog.total),(2,2))
            self.assertEqual(dialog.table.rowCount(),1)
            self.assertIn('Checked 2/2',dialog.status.text())
            store.add('Slow',self.base+'/slow')
            dialog._start()
            ended=[]
            dialog.scanner.finished.connect(lambda:ended.append(True))
            dialog.reject()
            spin(lambda:ended)
            self.assertEqual(len(store.all()),3)
            dialog.deleteLater()


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=Bookmarks(Path(self.tmp.name)/'bookmarks.json')
        self.store.add('Broken','https://example.com/dead')
        self.store.add('Good','https://example.com/ok')
        self.dialog=BookmarkHealthDialog(self.store)
        self.dialog._result(HealthResult('Good','https://example.com/ok',True,200,'HTTP 200'))
        self.dialog._result(HealthResult('Broken','https://example.com/dead',False,404,'HTTP 404'))

    def tearDown(self):
        self.dialog.reject(); self.dialog.deleteLater(); self.tmp.cleanup()

    def test_only_broken_rows_shown_and_nothing_selected_or_deleted(self):
        self.assertEqual(self.dialog.table.rowCount(),1)
        self.assertEqual(self.dialog.table.item(0,2).text(),'HTTP 404')
        self.assertEqual(self.dialog.table.item(0,0).checkState(),Qt.CheckState.Unchecked)
        self.dialog._remove()
        self.assertEqual(len(self.store.all()),2)

    def test_select_all_confirmation_deletes_from_real_store_and_results(self):
        self.dialog._select_all()
        with patch.object(QMessageBox,'exec',return_value=QMessageBox.StandardButton.No):
            self.dialog._remove()
        self.assertEqual(len(self.store.all()),2)
        with patch.object(QMessageBox,'exec',return_value=QMessageBox.StandardButton.Yes):
            self.dialog._remove()
        self.assertEqual([b.title for b in Bookmarks(self.store.path).all()],['Good'])
        self.assertEqual(self.dialog.table.rowCount(),0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
