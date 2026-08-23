# Vodou MCP server

A local [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes Vodou's **private search** and **read-only profile data** to an MCP
client (Claude Desktop or Claude Code). It runs on your machine, over stdio —
nothing listens on the network.

## Tools

| Tool | What it does | Data source |
|------|--------------|-------------|
| `vodou_search(query, max_results=8)` | Private web search → `[{title, url, snippet}]` | your SearXNG |
| `vodou_ask(query, model="")` | Search **+** an answer from your **local** Ollama, with `[n]` citations | SearXNG + loopback Ollama |
| `vodou_bookmarks()` | Saved bookmarks `[{title, url}]` (read-only) | `~/.vodou/bookmarks.json` |
| `vodou_open_tabs()` | Last saved session's tab URLs (read-only) | `~/.vodou/session.json` |
| `vodou_vault_status()` | `{configured: bool}` — **only** whether a vault exists | `~/.vodou/vault.*` |

Everything stays on-device: search goes through your own SearXNG, and `vodou_ask`
refuses any Ollama endpoint that isn't loopback (the same guard Vodou enforces),
so a question never leaves the machine.

### Live control tools (only when Vodou is running with control enabled)

| Tool | What it does |
|------|--------------|
| `vodou_live_tabs()` | List the tabs open in the **running** browser |
| `vodou_open_url(url)` | Open an http(s) URL in a **new** tab |
| `vodou_navigate(url)` | Navigate the **active** tab to an http(s) URL |
| `vodou_live_blocking_stats(period)` | Live blocking totals + top hosts (`'1h'`/`'24h'`) |

These talk to a running Vodou over a **loopback** socket and are inert unless
Vodou was started with `VODOU_ENABLE_CONTROL=1` (see below); otherwise they
return `{ok: false, error: ...}`.

## Install

```sh
pip install -r mcp_server/requirements.txt      # the `mcp` SDK (1.x, FastMCP)
```

Use the **same Python** that has Vodou's own deps available (the server reuses
Vodou's GUI-free modules for bookmarks/session parsing). No `PYTHONPATH` is
needed — the server puts the repo on `sys.path` itself.

## Register with a client

**Claude Code:**

```sh
claude mcp add vodou -- python "C:/Users/Pacma/OneDrive/Desktop/Python Programs/privacy_browser/mcp_server/vodou_mcp.py"
```

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vodou": {
      "command": "python",
      "args": ["C:/Users/Pacma/OneDrive/Desktop/Python Programs/privacy_browser/mcp_server/vodou_mcp.py"]
    }
  }
}
```

Restart the client; the five `vodou_*` tools appear.

## Configuration

The server reads the same settings Vodou does:

- **SearXNG URL** — `VODOU_SEARXNG_URL` env var, else `~/.vodou/config.json`
  `{"searxng_url": "..."}`, else `https://localhost/searxng`. TLS verification is
  skipped **only** for a loopback host (a self-signed cert on `localhost` /
  `127.0.0.1`, where there is no meaningful MITM).
- **Ollama** — `~/.vodou/ai_search.json` `endpoint` / `model`, else
  `http://127.0.0.1:11434` / `llama3.2:latest`. A non-loopback `endpoint` is
  refused and the default is used instead.

## Live control — enabling it

The live-control tools require Vodou to be started with the control surface on:

```sh
# Windows (PowerShell):
$env:VODOU_ENABLE_CONTROL = "1"; pythonw main.py
# macOS / Linux:
VODOU_ENABLE_CONTROL=1 python main.py
```

When enabled, Vodou opens a `QTcpServer` bound to `127.0.0.1` on an OS-assigned
port and writes that port plus a **per-run random token** to
`~/.vodou/control.json`. The MCP server reads that file to reach the browser.
The socket is **loopback-only**, every request must carry the token, and the
command set is fixed (open/navigate tabs, read blocking stats) — no file, shell,
or vault access. The file is removed when Vodou closes. Leave
`VODOU_ENABLE_CONTROL` unset to keep the surface off entirely.

## Security notes / deliberate non-goals

- **No vault secrets.** The password vault is encrypted under a master password
  this server neither holds nor should handle, so only a non-secret
  "configured" flag is exposed — never entries or passwords.
- **Live control is off by default** and, when on, is loopback + token-gated
  with a minimal command set (see above). It never reads page contents, files,
  or credentials.
- No passwords are logged, echoed, or returned by any tool.

## Test

```sh
python tests/test_vodou_mcp.py     # backend logic, no network, no `mcp` SDK
```
