# Bundled spell-check dictionaries

Chromium's spellchecker is Hunspell-based and PyQt6-WebEngine ships **no**
dictionary files at all. Left to its own default, Chromium downloads a
missing dictionary from Google's component-update servers the first time a
language is enabled — a network call to a third party that would
contradict Vodou's no-phone-home design the moment someone turns spell
check on.

So these `.bdic` files are bundled directly instead, and `main.py` points
`QTWEBENGINE_DICTIONARIES_PATH` at this directory before `QApplication` is
created (see the `QTWEBENGINE_CHROMIUM_FLAGS` block in `main.py`). Spell
check then never touches the network, regardless of which bundled
language is enabled.

## Source

Pulled as-is from Chromium's own dependency repo:
<https://chromium.googlesource.com/chromium/deps/hunspell_dictionaries>,
the exact dictionaries Chrome itself ships. Filenames are untouched
(`<lang>-<REGION>-<major>-<minor>.bdic`) so Qt's own dictionary-file
lookup — which matches by the `<lang>-<REGION>` prefix — finds them
without renaming.

Only the languages Vodou's spell-check setting currently offers are
bundled:

| File | Language | Spell-check setting code |
|---|---|---|
| `en-US-10-2.bdic` | English (US) | `en-US` |
| `es-ES-3-0.bdic` | Spanish | `es-ES` |
| `fr-FR-3-0.bdic` | French | `fr-FR` |
| `de-DE-3-0.bdic` | German | `de-DE` |
| `pt-BR-3-0.bdic` | Portuguese (Brazil) | `pt-BR` |
| `pt-PT-3-0.bdic` | Portuguese (Portugal) | `pt-PT` |
| `ru-RU-3-0.bdic` | Russian | `ru-RU` |

Chromium's Hunspell-based spellchecker has no dictionaries at all for
Chinese, Japanese, or Arabic (CJK/Arabic morphology doesn't fit Hunspell's
word-list model) — that's why those three aren't in this list. They're
still fully supported by Vodou's page-translation feature, which is
model-based and has no such limitation.

## License

Covered by the upstream repo's `LICENSE` file (MPL 1.1 / GPL 2.0 / GPL 3.0
/ LGPL 2.1 / LGPL 3.0 tri-license), bundled here unmodified. Per-dictionary
copyright/attribution notices are in the matching `README_<lang>.txt`
file, also bundled unmodified from the same upstream repo.

## Updating

To add a language later: find its current filename at the URL above, add
it to this directory and the table, bundle its `README_<lang>.txt`, and
add its code to `spellcheck.AVAILABLE_LANGUAGES` — matching the bundled
file's `<lang>-<REGION>` prefix exactly.
