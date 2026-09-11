"""Concurrent HEAD/GET bookmark health checks in a dedicated Qt worker thread.

Self-contained: no dependency on the local-AI review feature (bookmark_cleanup.py /
ai_search.py). Retry-after-aware backoff avoids the checker hammering a rate-limited
host and reporting live bookmarks as broken.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from threading import Event

from PyQt6.QtCore import QCoreApplication, QEvent, QEventLoop, QObject, QThread, QTimer, QUrl, Qt, pyqtSignal
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkProxy, QNetworkReply, QNetworkRequest

from bookmarks import Bookmark

DEFAULT_TIMEOUT_SECONDS = 8.0
DEFAULT_CONCURRENCY = 16
MAX_REDIRECTS = 5
RETRY_STATUS_CODES = (429, 503)
MAX_RETRY_ATTEMPTS = 3
RETRY_BASE_MS = 3000
MAX_RETRY_DELAY_MS = 60000


@dataclass(frozen=True)
class HealthResult:
    title: str
    url: str
    ok: bool
    status_code: int | None
    reason: str
    final_url: str = ""
    method: str = "HEAD"

    @property
    def bookmark(self):
        return Bookmark(self.title, self.url)


def failure_reason(code, error, *, timed_out=False, ssl_error=False):
    errors = QNetworkReply.NetworkError
    if timed_out or error == errors.TimeoutError:
        return "Timed out"
    if ssl_error or error == errors.SslHandshakeFailedError:
        return "SSL error: certificate verification or TLS handshake failed"
    if error == errors.TooManyRedirectsError:
        return "Redirect loop or too many redirects"
    if error == errors.InsecureRedirectError:
        return "Unsafe redirect from HTTPS to HTTP"
    if error == errors.HostNotFoundError:
        return "DNS resolution failed"
    if code is not None and code >= 400:
        return f"HTTP {code}"
    if error == errors.ConnectionRefusedError:
        return "Connection refused"
    if error == errors.RemoteHostClosedError:
        return "Connection reset or closed by server"
    if error != errors.NoError:
        return "Connection error: " + error.name
    return f"HTTP {code}" if code is not None else "No HTTP response"


def retry_after_ms(value: str) -> int:
    """Milliseconds a Retry-After header asks the client to wait; 0 if absent/unparsable."""
    try:
        seconds = int(value) if value.strip().isdigit() else (
            parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(seconds * 1000))
    except (ValueError, TypeError, OverflowError):
        return 0


class HealthCheckWorker(QThread):
    result = pyqtSignal(object)
    progress = pyqtSignal(int, int)
    failed = pyqtSignal(str)

    def __init__(self, bookmarks, parent=None, *, timeout=DEFAULT_TIMEOUT_SECONDS,
                 concurrency=DEFAULT_CONCURRENCY):
        super().__init__(parent)
        self.items = [Bookmark(b.title, b.url) for b in bookmarks]
        self.timeout_ms = max(1, min(120000, int(float(timeout) * 1000)))
        self.concurrency = max(1, min(64, int(concurrency)))
        self.cancelled = Event()
        self.proxy = QNetworkProxy(QNetworkProxy.applicationProxy())

    def cancel(self):
        self.cancelled.set()

    def shutdown(self):
        """Used only at application exit; network cancellation takes at most one poll."""
        self.cancel()
        self.wait()

    def run(self):
        # Construct and destroy every network object inside its owning thread.
        loop = QEventLoop()
        batch = None
        try:
            batch = _Batch(self, loop)
            QTimer.singleShot(0, batch.pump)
            loop.exec()
        except Exception as exc:
            self.failed.emit(f"Bookmark scan could not complete: {exc}")
        finally:
            if batch is not None:
                batch.stop()
                batch.deleteLater()
                QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


class _Batch(QObject):
    def __init__(self, worker, loop):
        super().__init__()
        self.worker, self.loop = worker, loop
        # One Qt client per slot avoids Qt's per-host connection queue consuming
        # a bookmark's timeout before its request can start. The pool is bounded.
        self.available = []
        for _ in range(min(worker.concurrency, len(worker.items))):
            manager = QNetworkAccessManager(self)
            manager.setProxy(worker.proxy)
            self.available.append(manager)
        self.active = {}
        self.next_index = self.checked = 0
        # Items that have started but not yet reported, including ones backing off
        # a retry outside of `active` — pump() must not finish while this is nonzero.
        self.pending = 0
        self.stopped = False
        self.poll = QTimer(self)
        self.poll.timeout.connect(self.check_cancel)
        self.poll.start(25)

    def check_cancel(self):
        if self.worker.cancelled.is_set():
            self.stop()
            self.loop.quit()

    def stop(self):
        self.stopped = True
        self.poll.stop()
        for state in list(self.active.values()):
            self.release(state['reply'])

    def release(self, reply):
        state = self.active.pop(id(reply))
        state['timer'].stop()
        state['timer'].deleteLater()
        # Unregister before abort: finished may be emitted synchronously.
        if reply.isRunning():
            reply.abort()
        reply.deleteLater()
        return state

    def pump(self):
        if self.stopped or self.worker.cancelled.is_set():
            self.check_cancel()
            return
        while len(self.active) < self.worker.concurrency and self.next_index < len(self.worker.items):
            bookmark = self.worker.items[self.next_index]
            self.next_index += 1
            url = QUrl(bookmark.url)
            if not url.isValid() or url.scheme() not in ('http', 'https') or not url.host() or url.userInfo():
                self.report(HealthResult(bookmark.title, bookmark.url, False, None,
                                         'Invalid URL or embedded credentials', method=''))
                continue
            self.pending += 1
            self.request(bookmark, 'HEAD')
        if not self.active and self.pending == 0 and self.next_index == len(self.worker.items):
            self.worker.progress.emit(self.checked, len(self.worker.items))
            self.loop.quit()

    def request(self, bookmark, method, manager=None, *, attempts=1):
        if self.stopped or self.worker.cancelled.is_set():
            if manager is not None:
                self.available.append(manager)
            return
        req = QNetworkRequest(QUrl(bookmark.url))
        req.setTransferTimeout(self.worker.timeout_ms)
        req.setMaximumRedirectsAllowed(MAX_REDIRECTS)
        req.setAttribute(QNetworkRequest.Attribute.RedirectPolicyAttribute,
                         QNetworkRequest.RedirectPolicy.NoLessSafeRedirectPolicy)
        for attr in (QNetworkRequest.Attribute.CookieLoadControlAttribute,
                     QNetworkRequest.Attribute.CookieSaveControlAttribute,
                     QNetworkRequest.Attribute.AuthenticationReuseAttribute):
            req.setAttribute(attr, QNetworkRequest.LoadControl.Manual)
        req.setRawHeader(b'User-Agent', b'Vodou-Bookmark-Checker/1.0')
        manager = manager or self.available.pop()
        reply = manager.head(req) if method == 'HEAD' else manager.get(req)
        reply.setReadBufferSize(16384)
        timer = QTimer(self)
        timer.setSingleShot(True)
        self.active[id(reply)] = dict(reply=reply, bookmark=bookmark, method=method, timer=timer, manager=manager,
                                  timed_out=False, ssl_error=False, headers_ready=False, attempts=attempts)
        # These callbacks belong to this worker's event loop, never a Python
        # lambda proxy queued to the GUI thread after the reply has been freed.
        direct = Qt.ConnectionType.DirectConnection
        timer.timeout.connect(lambda: self.timeout(reply), direct)
        reply.sslErrors.connect(lambda _: self.ssl_error(reply), direct)
        reply.metaDataChanged.connect(lambda: self.headers(reply), direct)
        reply.finished.connect(lambda: self.complete(reply), direct)
        timer.start(self.worker.timeout_ms)

    def ssl_error(self, reply):
        if id(reply) in self.active:
            self.active[id(reply)]['ssl_error'] = True
        # Qt rejects the connection normally; SSL errors are never ignored.

    def timeout(self, reply):
        if id(reply) in self.active:
            self.active[id(reply)]['timed_out'] = True
            reply.abort()

    def headers(self, reply):
        if id(reply) not in self.active or self.active[id(reply)]['method'] != 'GET':
            return
        code = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
        # A health check needs final response headers, not an entire download.
        if code is not None and (200 <= code < 300 or code >= 400):
            if not self.active[id(reply)]['headers_ready']:
                self.active[id(reply)]['headers_ready'] = True
                # Leave Qt's metadata callback before cancelling the download.
                QTimer.singleShot(0, lambda: self.complete(reply))

    def complete(self, reply):
        if id(reply) not in self.active:
            return
        code = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
        error = reply.error()
        final_url = reply.url().toString()
        retry_after = retry_after_ms(bytes(reply.rawHeader(b'Retry-After')).decode('ascii', 'replace'))
        state = self.release(reply)
        if self.stopped or self.worker.cancelled.is_set():
            self.check_cancel()
            return
        ok = (code is not None and 200 <= code < 400
              and error == QNetworkReply.NetworkError.NoError
              and not state['timed_out'] and not state['ssl_error'])
        # A rate-limited or overloaded server gets backed off and retried on the
        # same method rather than immediately counted as broken or re-hammered.
        if not ok and code in RETRY_STATUS_CODES and state['attempts'] < MAX_RETRY_ATTEMPTS:
            delay = max(RETRY_BASE_MS * state['attempts'], min(retry_after, MAX_RETRY_DELAY_MS))
            attempts, bookmark, method, manager = state['attempts'] + 1, state['bookmark'], state['method'], state['manager']
            QTimer.singleShot(delay, lambda: self.request(bookmark, method, manager, attempts=attempts))
            QTimer.singleShot(0, self.pump)
            return
        if not ok and state['method'] == 'HEAD':
            self.request(state['bookmark'], 'GET', state['manager'], attempts=state['attempts'])
            return
        self.available.append(state['manager'])
        self.pending -= 1
        bookmark = state['bookmark']
        reason = f'HTTP {code}' if ok else failure_reason(code, error,
                    timed_out=state['timed_out'], ssl_error=state['ssl_error'])
        self.report(HealthResult(bookmark.title, bookmark.url, ok, code, reason,
                                 final_url, state['method']))
        QTimer.singleShot(0, self.pump)

    def report(self, result):
        self.checked += 1
        self.worker.result.emit(result)
        self.worker.progress.emit(self.checked, len(self.worker.items))
