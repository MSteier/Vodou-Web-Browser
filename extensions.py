"""Real Chrome (Manifest V3) extension support, loaded via Qt WebEngine's
QWebEngineExtensionManager.

Unlike plugins.py's reviewed catalog, these run arbitrary third-party code
with broad page access -- Vodou does not review it. The UI this backs must
say so plainly before anything is added.

Persistence note: Vodou shreds its entire profile directory on every exit
and startup (see PROFILE_DIR/shred_dir in main.py), by design, for privacy.
Qt's "permanent" installExtension() stores extensions inside that same
profile directory, so it would get wiped right along with everything else.
Instead, this module only remembers *which local paths* to reload (outside
the shredded profile dir, same as plugins.json), and the caller re-calls the
explicitly-temporary loadExtension() for each one at every startup.

One-active-extension limit: loading a SECOND extension into the same
QWebEngineExtensionManager within one session was found to reliably crash
(observed via tests/manual_verify_extensions.py, PyQt6-WebEngine 6.11.0) --
regardless of whether the second one is valid, and regardless of timing
between the two loadExtension() calls. This looks like a genuine bug in
Qt WebEngine's brand-new (6.10) extension subsystem, not something fixable
from here. Until that's resolved upstream, at most one record may be
enabled at a time -- enforced below in add()/set_enabled() -- and
main.py's _apply_extensions() independently reconciles the live
QWebEngineExtensionManager state to match, unloading anything stale.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

EXTENSIONS_FILE = Path.home() / ".vodou" / "extensions.json"


@dataclass
class ExtensionRecord:
    id: str
    name: str
    source_path: str
    enabled: bool = True
    last_error: str = ""


class ExtensionStore:
    """Tracks which local extension paths the user added; persists metadata
    only (paths, names, enabled flags) -- never extension code itself."""

    def __init__(self, path: Path = EXTENSIONS_FILE):
        self.path = path
        self._records: dict[str, ExtensionRecord] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._records = {
                item["id"]: ExtensionRecord(**item)
                for item in data
                if isinstance(item, dict) and "id" in item and "source_path" in item
            }
        except (OSError, ValueError, TypeError):
            self._records = {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps([asdict(r) for r in self._records.values()]),
                encoding="utf-8",
            )
            tmp.replace(self.path)
        except OSError:
            pass

    def records(self) -> list[ExtensionRecord]:
        return list(self._records.values())

    def add(self, source_path: str, name: str) -> ExtensionRecord:
        record_id = source_path
        record = ExtensionRecord(id=record_id, name=name, source_path=source_path)
        self._records[record_id] = record
        self._deactivate_all_except(record_id)
        self._save()
        return record

    def remove(self, record_id: str) -> None:
        self._records.pop(record_id, None)
        self._save()

    def set_enabled(self, record_id: str, enabled: bool) -> None:
        record = self._records.get(record_id)
        if record is None:
            return
        record.enabled = enabled
        if enabled:
            self._deactivate_all_except(record_id)
        self._save()

    def _deactivate_all_except(self, record_id: str) -> None:
        """Enforces the one-active-extension limit (see module docstring):
        enabling any record disables every other one."""
        for other_id, other in self._records.items():
            if other_id != record_id:
                other.enabled = False

    def set_error(self, record_id: str, error: str) -> None:
        record = self._records.get(record_id)
        if record is None:
            return
        record.last_error = error
        self._save()

    def enabled_records(self) -> list[ExtensionRecord]:
        # Defensive: never return more than one, even if a pre-fix
        # extensions.json on disk somehow has several enabled=true records.
        enabled = [r for r in self._records.values() if r.enabled]
        return enabled[:1]
