"""Importers for passwords (CSV) and bookmarks (Netscape HTML).

Password CSVs come from Chrome, Edge, Firefox, Brave, Bitwarden, etc. — all
slightly different, so columns are matched by header name rather than
position. Bookmark HTML is the "Netscape Bookmark File" format every browser
exports.

These parse untrusted files, so both are defensive: unknown columns are
ignored, malformed rows are skipped, and only http/https bookmark URLs are
kept (dropping javascript:, data:, place: and other exotic schemes).
"""

from __future__ import annotations

import csv
from html.parser import HTMLParser
from pathlib import Path

from bookmarks import Bookmark
from vault import Entry, normalize_site

# Bounds so a malicious CSV can't bloat the vault or a single field.
MAX_FIELD = 8192
MAX_ROWS = 100_000

# Header aliases -> canonical field. Matched case-insensitively.
_URL_KEYS = {"url", "login_uri", "website", "web site", "login url", "hostname"}
_USER_KEYS = {"username", "login_username", "user", "login", "email",
              "user name", "nickname"}
_PASS_KEYS = {"password", "login_password", "pass"}
_NOTE_KEYS = {"note", "notes", "comment", "comments"}


def _pick(row: dict[str, str], keys: set[str]) -> str:
    for header, value in row.items():
        if header and header.strip().lower() in keys and value:
            return value.strip()[:MAX_FIELD]
    return ""


def parse_password_csv(path: Path) -> tuple[list[Entry], int]:
    """Return (entries, skipped_count). Requires a password column."""
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return [], 0

    entries: list[Entry] = []
    skipped = 0
    for count, row in enumerate(reader):
        if count >= MAX_ROWS:
            break
        password = _pick(row, _PASS_KEYS)
        if not password:
            skipped += 1
            continue
        url = _pick(row, _URL_KEYS)
        site = normalize_site(url) if url else _pick(row, {"name", "title"})
        if not site:
            skipped += 1
            continue
        entries.append(Entry(
            site=site,
            username=_pick(row, _USER_KEYS),
            password=password,
            notes=_pick(row, _NOTE_KEYS)))
    return entries, skipped


def write_password_csv(path: Path, entries: list[Entry]) -> None:
    """Write entries to a CSV using the common Chrome/Edge column layout
    (name,url,username,password,note), so the file re-imports cleanly here or
    into another password manager.

    The passwords are written in PLAIN TEXT — this is an explicit export, and
    the caller is responsible for warning the user and for handling the file
    securely afterwards.
    """
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["name", "url", "username", "password", "note"])
        for e in entries:
            url = e.site if "://" in e.site else f"https://{e.site}"
            writer.writerow([e.site, url, e.username, e.password, e.notes])


class _BookmarkHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.bookmarks: list[Bookmark] = []
        self._href: str | None = None
        self._title_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href", "")
            if href and href.lower().startswith(("http://", "https://")):
                self._href = href
                self._title_parts = []

    def handle_data(self, data):
        if self._href is not None:
            self._title_parts.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            title = "".join(self._title_parts).strip()
            self.bookmarks.append(Bookmark(title=title or self._href,
                                           url=self._href))
            self._href = None
            self._title_parts = []


def parse_bookmarks_html(path: Path) -> list[Bookmark]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    parser = _BookmarkHTMLParser()
    parser.feed(text)
    # De-dupe within the file, preserving first-seen order.
    seen: set[str] = set()
    unique: list[Bookmark] = []
    for b in parser.bookmarks:
        if b.url not in seen:
            seen.add(b.url)
            unique.append(b)
    return unique
