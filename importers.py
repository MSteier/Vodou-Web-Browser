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
# Same idea for the bookmark side, which parses an equally untrusted file:
# without a cap, one crafted HTML file becomes an unbounded bookmarks.json
# (and an unbounded bookmarks bar to render on every startup).
MAX_BOOKMARKS = 20_000

# Header aliases -> canonical field. Matched case-insensitively.
_URL_KEYS = {"url", "login_uri", "website", "web site", "login url", "hostname"}
_USER_KEYS = {"username", "login_username", "user", "login", "email",
              "user name", "nickname"}
_PASS_KEYS = {"password", "login_password", "pass"}
_NOTE_KEYS = {"note", "notes", "comment", "comments"}


# Leading characters that make a spreadsheet treat a cell as a formula rather
# than text. Tab and CR count because Excel strips them before parsing.
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")
_ENCODING_COLUMN = "vodou_encoding"
_ENCODING_VERSION = "apostrophe-v1"


def _defuse_formula(value: str) -> str:
    """Escape formula cells and literal apostrophes, without losing data."""
    if (value.startswith(("'",) + _FORMULA_LEAD)
            or value.lstrip().startswith(_FORMULA_LEAD)):
        return "'" + value
    return value


def _refuse_formula(value: str) -> str:
    """Decode a cell ONLY in a row carrying our explicit encoding marker."""
    return value[1:] if value.startswith("'") else value


def _pick(row: dict[str, str], keys: set[str], *, encoded: bool = False) -> str:
    for header, value in row.items():
        if header and header.strip().lower() in keys and value:
            return _refuse_formula(value) if encoded else value
    return ""


def parse_password_csv(path: Path) -> tuple[list[Entry], int]:
    """Return (entries, skipped_count). Requires a password column."""
    entries: list[Entry] = []
    skipped = 0
    try:
        # newline='' preserves CR/LF inside quoted fields. Strict decoding
        # reports invalid input instead of silently altering a password.
        with Path(path).open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for count, row in enumerate(reader):
                if count >= MAX_ROWS:
                    break
                encoded = row.get(_ENCODING_COLUMN) == _ENCODING_VERSION
                pick = lambda keys: _pick(row, keys, encoded=encoded)
                password = pick(_PASS_KEYS)
                username = pick(_USER_KEYS)
                url = pick(_URL_KEYS)
                site = normalize_site(url or pick({"name", "title"}))
                notes = pick(_NOTE_KEYS)
                # Reject overlong rows rather than save truncated credentials.
                if (not password or not site or any(len(v) > MAX_FIELD
                        for v in (password, username, url, site, notes))):
                    skipped += 1
                    continue
                entries.append(Entry(site=site, username=username,
                                     password=password, notes=notes))
    except (UnicodeError, csv.Error) as error:
        raise OSError("Invalid CSV or UTF-8 encoding; no passwords were imported.") from error
    return entries, skipped


def write_password_csv(path: Path, entries: list[Entry]) -> None:
    """Write common login columns plus an explicit Vodou encoding marker.

    Formula escaping is reversible when importing here. Other tools must
    honor vodou_encoding to decode escaped values exactly.

    The passwords are written in PLAIN TEXT — this is an explicit export, and
    the caller is responsible for warning the user and for handling the file
    securely afterwards.
    """
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["name", "url", "username", "password", "note",
                         _ENCODING_COLUMN])
        for e in entries:
            url = e.site if "://" in e.site else f"https://{e.site}"
            writer.writerow([_defuse_formula(v) for v in
                             (e.site, url, e.username, e.password, e.notes)]
                            + [_ENCODING_VERSION])


class _BookmarkHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.bookmarks: list[Bookmark] = []
        self._href: str | None = None
        self._title_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a" and len(self.bookmarks) < MAX_BOOKMARKS:
            href = dict(attrs).get("href", "")
            # Bounded here as well as by bookmarks.MAX_URL, so an absurd href
            # is never even held in memory.
            if (href and len(href) <= MAX_FIELD
                    and href.lower().startswith(("http://", "https://"))):
                self._href = href
                self._title_parts = []

    def handle_data(self, data):
        # A title is a display label; cap the accumulated text so one <a> with
        # megabytes of body content can't be collected in full.
        if self._href is not None and len(self._title_parts) < 64:
            self._title_parts.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            title = "".join(self._title_parts).strip()[:MAX_FIELD]
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
