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

import os
from pathlib import Path

_CHUNK = 1024 * 1024  # overwrite in 1 MiB slices, never file-size buffers


def _shred_file(path: Path) -> bool:
    """Overwrite one file with random bytes, then delete it."""
    for attempt in (1, 2):
        try:
            size = path.stat().st_size
            if size:
                with open(path, "r+b") as fh:
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
