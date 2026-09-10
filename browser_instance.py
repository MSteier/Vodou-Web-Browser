"""One owner per profile, with same-user IPC for subsequent URL launches.

The lock lives beside the profile so it can be acquired before migration or
profile creation. It stays held through shutdown cleanup. IPC is separate
from the optional remote-control API and never exposes vault operations.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from PyQt6.QtCore import QObject, QLockFile, QTimer
from PyQt6.QtNetwork import QLocalServer, QLocalSocket

MAX_MESSAGE = 16 * 1024


class BrowserInstance(QObject):
    def __init__(self, profile_dir: Path, parent=None):
        super().__init__(parent)
        profile = profile_dir.resolve()
        identity = os.path.normcase(str(profile))
        self.name = "vodou-" + hashlib.sha256(identity.encode()).hexdigest()[:32]
        self.lock = QLockFile(str(profile.with_name(profile.name + ".instance.lock")))
        # A long-running browser is never stale just because time passed.
        # QLockFile still detects a dead owner PID and recovers crash locks.
        self.lock.setStaleLockTime(0)
        self.server = QLocalServer(self)
        self.server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
        self.server.newConnection.connect(self._connections)
        self._owns_lock = False
        self._handler = None
        self._pending: list[str] = []

    def acquire(self) -> bool:
        if self.lock.tryLock(0):
            self._owns_lock = True
            return True
        if self.lock.error() != QLockFile.LockError.LockFailedError:
            raise OSError("Cannot lock the Vodou profile. Check folder permissions.")
        return False

    def listen(self) -> None:
        if not self._owns_lock:
            raise RuntimeError("Profile ownership is required before listening.")
        # Only the lock owner may remove a stale socket from a crashed run.
        QLocalServer.removeServer(self.name)
        if not self.server.listen(self.name):
            raise OSError("Cannot start Vodou's local launcher connection.")

    def forward(self, url: str = "", timeout_ms: int = 5000) -> None:
        payload = (json.dumps({"url": url}) + "\n").encode()
        if len(payload) > MAX_MESSAGE:
            raise ValueError("The launch URL is too long.")
        deadline = time.monotonic() + timeout_ms / 1000
        sock = QLocalSocket()
        try:
            while time.monotonic() < deadline:
                sock.connectToServer(self.name)
                if sock.waitForConnected(250):
                    break
                sock.abort()
                time.sleep(0.05)
            else:
                raise OSError("Vodou is already running or starting. Try opening the link again.")
            sock.write(payload)
            remaining = max(1, int((deadline - time.monotonic()) * 1000))
            if not sock.waitForBytesWritten(remaining):
                raise OSError("Could not send the link to the running Vodou.")
            response = bytearray()
            while b"\n" not in response:
                remaining = int((deadline - time.monotonic()) * 1000)
                if remaining <= 0 or (not sock.bytesAvailable()
                                     and not sock.waitForReadyRead(remaining)):
                    raise OSError("The running Vodou has not accepted the link. Try again.")
                response.extend(bytes(sock.readAll()))
            if bytes(response) != b"ok\n":
                raise OSError("The running Vodou could not accept the link.")
        finally:
            sock.abort()

    def set_handler(self, handler) -> None:
        self._handler = handler
        pending, self._pending = self._pending, []
        for url in pending:
            handler(url)

    def _connections(self) -> None:
        while self.server.hasPendingConnections():
            sock = self.server.nextPendingConnection()
            sock.setReadBufferSize(MAX_MESSAGE + 1)
            buf = bytearray()
            timer = QTimer(sock)
            timer.setSingleShot(True)
            timer.timeout.connect(sock.abort)
            timer.start(5000)

            def ready(s=sock, b=buf):
                b.extend(bytes(s.readAll()))
                if len(b) > MAX_MESSAGE:
                    s.abort()
                    return
                if b"\n" not in b:
                    return
                reply = b"error\n"
                try:
                    data = json.loads(bytes(b).split(b"\n", 1)[0])
                    if not isinstance(data, dict) or not isinstance(data.get("url"), str):
                        raise ValueError("invalid launch request")
                    if self._handler is not None:
                        self._handler(data["url"])
                    elif len(self._pending) < 32:
                        self._pending.append(data["url"])
                    else:
                        raise ValueError("too many pending launches")
                    reply = b"ok\n"
                except Exception:
                    pass
                s.write(reply)
                s.flush()
                s.disconnectFromServer()

            sock.readyRead.connect(ready)
            sock.disconnected.connect(sock.deleteLater)
            if sock.bytesAvailable():
                ready()

    def close(self) -> None:
        self.server.close()
        if self._owns_lock:
            self.lock.unlock()
            self._owns_lock = False
