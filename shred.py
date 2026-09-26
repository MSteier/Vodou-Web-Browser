"""Best-effort secure deletion of on-disk browsing artifacts.

Plain deletion just unlinks a directory entry — the file's bytes stay on
disk and are trivially recoverable with an undelete tool. Shredding
overwrites the contents with random bytes (forced to disk with fsync)
before unlinking, so what a recovery tool finds is noise.

Honest limits: on SSDs, wear-leveling means an overwrite isn't guaranteed
to hit the same physical cells as the original data, and the filesystem may
keep old copies in its journal. The complete answer to that is full-disk
encryption (BitLocker/FileVault/LUKS); this shredder is defence in depth on
top, not a substitute.

Files locked by another process (e.g. the engine still shutting down) are
skipped silently — callers run the shred again at the next startup, which
catches anything a previous run couldn't remove.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

_CHUNK = 1024 * 1024  # overwrite in 1 MiB slices, never file-size buffers

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _OPEN_EXISTING = 3
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                             wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                             wintypes.HANDLE]
    _CreateFileW.restype = wintypes.HANDLE

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    class _ByHandleFileInfo(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    _GetFileInformationByHandle = _kernel32.GetFileInformationByHandle
    _GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInfo)]
    _GetFileInformationByHandle.restype = wintypes.BOOL


def _open_no_follow(path: Path):
    """Open `path` for read/write, atomically refusing to follow a symlink
    or junction planted at that path.

    A separate is_symlink()-then-open() has a TOCTOU gap: something with
    write access to the same directory could delete the file and replace it
    with a link between the check and the open, redirecting the overwrite
    onto an arbitrary target. Both branches below check-and-open in one OS
    call instead, so nothing can be swapped in between.

    Returns (file object, is_link). On the link branch the file object is
    None; the caller must not read/write it, only unlink the path itself.
    """
    if sys.platform == "win32":
        handle = _CreateFileW(
            str(path), _GENERIC_READ | _GENERIC_WRITE, 0, None,
            _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT, None)
        if handle == _INVALID_HANDLE_VALUE:
            # Raises the same errno-mapped OSError subclass (PermissionError,
            # FileNotFoundError, ...) a normal open() would, so callers can
            # still catch PermissionError specifically.
            raise ctypes.WinError(ctypes.get_last_error())
        info = _ByHandleFileInfo()
        if not _GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.get_last_error()
            _CloseHandle(handle)
            raise ctypes.WinError(error)
        if info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            _CloseHandle(handle)
            return None, True
        import msvcrt
        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        return os.fdopen(fd, "r+b"), False

    try:
        fd = os.open(str(path), os.O_RDWR | os.O_NOFOLLOW)
    except OSError as error:
        if error.errno == errno.ELOOP:
            return None, True
        raise
    return os.fdopen(fd, "r+b"), False


def _shred_file(path: Path) -> bool:
    """Overwrite one file with random bytes, then delete it."""
    for attempt in (1, 2):
        try:
            fh, is_link = _open_no_follow(path)
        except PermissionError:
            # read-only attribute blocks the open on Windows
            if attempt == 1:
                try:
                    os.chmod(path, 0o600)
                    continue
                except OSError:
                    return False
            return False
        except OSError:
            return False
        if is_link:
            # A symlink must be unlinked, never written through: doing so
            # would overwrite whatever it points at. Nothing Vodou writes
            # under the profile is a link, so one here was planted — and the
            # shredder is the last thing that should be turned into an
            # arbitrary-file-destruction primitive.
            try:
                path.unlink()
                return True
            except OSError:
                return False
        try:
            with fh:
                size = os.fstat(fh.fileno()).st_size
                remaining = size
                while remaining > 0:
                    step = min(remaining, _CHUNK)
                    fh.write(os.urandom(step))
                    remaining -= step
                fh.flush()
                os.fsync(fh.fileno())
            path.unlink()
            return True
        except PermissionError:
            if attempt == 1:
                try:  # read-only attribute blocks r+b on Windows
                    os.chmod(path, 0o600)
                except OSError:
                    return False
            else:
                return False
        except OSError:
            return False
    return False


def shred_dir(root: Path) -> bool:
    """Shred every file under root and remove the tree.

    Returns True when the tree is fully gone; False if anything was locked
    and left behind (to be retried on the next run). Never raises.
    """
    if not root.exists():
        return True
    clean = True
    # Bottom-up so each directory is empty (if all its files shredded) by
    # the time its rmdir runs.
    for current, _subdirs, files in os.walk(root, topdown=False):
        folder = Path(current)
        for name in files:
            if not _shred_file(folder / name):
                clean = False
        try:
            folder.rmdir()
        except OSError:
            clean = False
    return clean
