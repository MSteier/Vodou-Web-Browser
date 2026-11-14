"""On/off switch for Claude's access to Vodou through the MCP server.

The switch is one tiny file, ``~/.vodou/mcp_enabled.json`` = ``{"enabled": bool}``.
Two separate processes share it:

  * the Vodou GUI WRITES it (Settings > Local AI > "Allow Claude (MCP) access");
  * the MCP server (mcp_server/vodou_mcp.py) READS it on every tool call.

Because the server re-reads it per call, flipping the switch takes effect
immediately: no Claude Desktop restart, and Claude's config is never touched.
The server keeps running either way; when off, every tool just refuses.

Pure standard library, no Qt, so both sides can import it.

Defaults:
  * file missing  -> ON  (keeps the behavior from before this switch existed)
  * file corrupt  -> OFF (fail closed: if we can't tell, don't hand out data)
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

STATE_FILE = Path.home() / ".vodou" / "mcp_enabled.json"

DISABLED_MESSAGE = (
    "Vodou MCP access is turned off. The user can turn it back on in Vodou: "
    "Settings > Local AI > Allow Claude (MCP) access.")


def is_enabled(path: Path = STATE_FILE) -> bool:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return True
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("enabled") is True


def set_enabled(on: bool, path: Path = STATE_FILE) -> None:
    """Save the switch atomically.

    Writes to a temp file in the same folder, then os.replace() swaps it in,
    so the MCP server can never read a half-written file mid-toggle.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".mcp_enabled.",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"enabled": bool(on)}, f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
