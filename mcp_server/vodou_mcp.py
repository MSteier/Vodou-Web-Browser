"""Vodou MCP server — exposes Vodou's private search and profile data to Claude.

A local, stdio MCP server (Claude Desktop / Claude Code). It surfaces:

  * vodou_search        — private web search via your own SearXNG
  * vodou_ask           — search + an answer from your LOCAL Ollama (never
                          leaves the machine)
  * vodou_bookmarks     — your saved bookmarks (read-only)
  * vodou_open_tabs     — URLs of the last saved browser session (read-only)
  * vodou_vault_status  — only whether a password vault exists (NO secrets)

Deliberately NOT exposed (see mcp_server/README.md):
  * password vault contents — encrypted under a master password this server
    must not hold;
  * live browser control and live blocking stats — those live in the running
    GUI process and need an in-app control surface that does not exist yet.

Run:  python mcp_server/vodou_mcp.py     (speaks MCP over stdio)
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import vodou_backends as be

mcp = FastMCP("vodou")


@mcp.tool()
def vodou_search(query: str, max_results: int = 8) -> list[dict]:
    """Search the web privately through the user's own SearXNG instance.

    Returns a list of {title, url, snippet}. Use this for fresh, factual
    lookups; nothing about the query is sent to a third-party search engine
    beyond what SearXNG itself federates.
    """
    return be.search(query, max_results=max_results)


@mcp.tool()
def vodou_ask(query: str, model: str = "") -> dict:
    """Answer a question using private search + the user's LOCAL Ollama model.

    Runs a SearXNG search, then asks the on-device Ollama to answer from those
    results with [n] citations. The AI endpoint is enforced to be loopback, so
    the question never leaves the machine. Returns {answer, model, sources}.
    """
    return be.summarize(query, model=(model or None))


@mcp.tool()
def vodou_bookmarks() -> list[dict]:
    """The user's saved Vodou bookmarks as [{title, url}] (read-only)."""
    return be.read_bookmarks()


@mcp.tool()
def vodou_open_tabs() -> dict:
    """URLs of the last saved browser session: {urls: [...], current: int}.

    Read-only; reflects the last persisted session, not necessarily a live
    running browser.
    """
    return be.read_open_tabs()


@mcp.tool()
def vodou_vault_status() -> dict:
    """Whether a password vault is configured: {configured: bool}.

    Returns NO entries and NO secrets — the vault is encrypted under a master
    password and its contents are intentionally not accessible here.
    """
    return be.vault_status()


if __name__ == "__main__":
    mcp.run()
