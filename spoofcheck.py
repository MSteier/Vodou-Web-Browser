"""Local, no-network detection of deceptive (spoofed) website addresses.

Three heuristics, all computed from the hostname alone — nothing is sent to
Google Safe Browsing or any external reputation service (that would leak every
site you visit):

  * homograph / look-alike  — the address uses confusable characters (Cyrillic
    'а', Greek 'ο', digit '1' for 'l', the ligature 'rn' for 'm', …) so that a
    "skeleton" of the domain collapses onto a well-known brand it is not.
  * mixed-script / punycode — a single domain label mixes writing systems
    (Latin + Cyrillic/Greek) or renders from punycode; almost always an attack.
  * typosquatting           — a near-miss ASCII spelling of a known brand
    within one edit (gooogle, faceook, paypa1).

Detection is heuristic and brand-list-bound: it protects a curated set of the
most-impersonated names, not the whole web, and errs toward silence over
false alarms. A companion helper (download_risk) classifies dangerous
executable downloads for the drive-by-download warning.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import PurePosixPath

# Sentinel host for the interstitial's own buttons. `.invalid` is reserved by
# RFC 6761 and can never resolve; the navigation handler intercepts it before
# any load, so these never touch the network.
SENTINEL_HOST = "vodou.invalid"
CONTINUE_URL = f"https://{SENTINEL_HOST}/continue"
BACK_URL = f"https://{SENTINEL_HOST}/back"


# Most-impersonated brands: registrable label -> canonical domain. Kept
# deliberately tight — every extra name widens the false-positive surface.
BRANDS: dict[str, str] = {
    # Big tech / accounts / mail
    "google": "google.com", "youtube": "youtube.com", "gmail": "gmail.com",
    "microsoft": "microsoft.com", "outlook": "outlook.com",
    "office": "office.com", "windows": "windows.com", "apple": "apple.com",
    "icloud": "icloud.com", "amazon": "amazon.com", "facebook": "facebook.com",
    "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "netflix": "netflix.com", "twitter": "twitter.com",
    "linkedin": "linkedin.com", "dropbox": "dropbox.com", "adobe": "adobe.com",
    "reddit": "reddit.com", "github": "github.com", "spotify": "spotify.com",
    "discord": "discord.com", "tiktok": "tiktok.com", "yahoo": "yahoo.com",
    "ebay": "ebay.com", "pinterest": "pinterest.com", "snapchat": "snapchat.com",
    # Payments / retail
    "paypal": "paypal.com", "stripe": "stripe.com", "walmart": "walmart.com",
    "target": "target.com", "bestbuy": "bestbuy.com", "alibaba": "alibaba.com",
    "aliexpress": "aliexpress.com",
    # Banks
    "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com",
    "chase": "chase.com", "citibank": "citibank.com",
    "capitalone": "capitalone.com", "usbank": "usbank.com",
    "barclays": "barclays.com", "santander": "santander.com",
    "hsbc": "hsbc.com",
    # Crypto (heavily phished)
    "coinbase": "coinbase.com", "binance": "binance.com",
    "kraken": "kraken.com", "metamask": "metamask.io",
    "blockchain": "blockchain.com", "ledger": "ledger.com",
    "trezor": "trezor.io", "bitfinex": "bitfinex.com",
}
_BRAND_LABELS = frozenset(BRANDS)

# Registrable-domain heuristic: common two-level public suffixes so that
# "paypal.co.uk" reduces to the label "paypal", not "co".
_TWO_LEVEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "co.jp", "co.nz",
    "co.za", "co.in", "co.kr", "com.au", "net.au", "org.au", "com.br",
    "com.mx", "com.sg", "com.hk", "com.tw", "com.cn", "com.tr",
})

# Confusable single characters -> their Latin skeleton. A pragmatic subset of
# the Unicode confusables data: the Cyrillic/Greek look-alikes and digit/letter
# swaps that actually show up in domain attacks.
_CONFUSABLES = {
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q",
    "ԝ": "w", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "г": "r",
    "п": "n", "л": "n",
    # Cyrillic uppercase
    "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c", "У": "y", "Х": "x",
    "І": "i", "Ј": "j", "К": "k", "М": "m", "Н": "h", "Т": "t", "В": "b",
    "Ѕ": "s", "Ԛ": "q", "Ԝ": "w",
    # Greek
    "ο": "o", "Ο": "o", "α": "a", "ρ": "p", "ε": "e", "ν": "v", "τ": "t",
    "υ": "u", "χ": "x", "κ": "k", "ι": "i", "Α": "a", "Β": "b", "Ε": "e",
    "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o",
    "Ρ": "p", "Τ": "t", "Χ": "x",
    # Digit / punctuation look-alikes
    "0": "o", "1": "l", "|": "l", "5": "s", "3": "e", "$": "s",
}


@dataclass(frozen=True)
class SpoofVerdict:
    kind: str            # "homograph" | "mixed_script" | "typosquat"
    display_host: str    # the real (decoded) host, shown to the user
    impersonated: str    # brand domain it resembles, or "" if none
    headline: str        # short interstitial title
    detail: str          # one-sentence explanation


def _is_ip_or_local(host: str) -> bool:
    if ":" in host:                      # IPv6
        return True
    if host in ("localhost",):
        return True
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts):
        return True                      # IPv4
    return "." not in host               # bare single label (intranet host)


def _registrable(host: str) -> tuple[str, str]:
    """Return (registrable_label, registrable_domain) using a small built-in
    suffix list. Heuristic, not a full public-suffix parse."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return labels[-3], ".".join(labels[-3:])
    if len(labels) >= 2:
        return labels[-2], ".".join(labels[-2:])
    return host, host


def _script_flags(label: str) -> tuple[bool, bool, bool]:
    has_latin = has_cyr = has_grk = False
    for ch in label:
        o = ord(ch)
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
            has_latin = True
        elif 0x0400 <= o <= 0x04FF:
            has_cyr = True
        elif 0x0370 <= o <= 0x03FF:
            has_grk = True
    return has_latin, has_cyr, has_grk


def _mixed_script(label: str) -> bool:
    return sum(_script_flags(label)) >= 2


def _ascii_form(host: str) -> str:
    """The punycode (ACE) form of a host, e.g. 'pаypal.com' (Cyrillic а) ->
    'xn--pypal-53d.com'. This is the un-fakeable spelling: two homographs that
    render identically have different punycode, so showing it lets the user
    actually tell a look-alike apart from the real domain."""
    out = []
    for lbl in host.split("."):
        if lbl.isascii():
            out.append(lbl)
        else:
            try:
                out.append("xn--" + lbl.encode("punycode").decode("ascii"))
            except (UnicodeError, ValueError):
                out.append(lbl)
    return ".".join(out)


def _skeleton(label: str) -> str:
    """Collapse confusable characters to a Latin skeleton for comparison."""
    out = "".join(_CONFUSABLES.get(ch, ch) for ch in label)
    # Multi-character look-alikes, applied after the single-char pass.
    out = out.replace("rn", "m").replace("vv", "w")
    return out


def _levenshtein_le(a: str, b: str, limit: int) -> int | None:
    """Edit distance between a and b, or None if it exceeds `limit`.

    Early-outs on the length gap and once a whole row is over the limit, so it
    stays cheap for the short strings (domain labels) it runs on."""
    if abs(len(a) - len(b)) > limit:
        return None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(v)
            best = min(best, v)
        if best > limit:
            return None
        prev = cur
    return prev[-1] if prev[-1] <= limit else None


def _nearest_brand(label: str) -> str | None:
    """Brand domain whose label is exactly one edit from `label` (and not
    equal). Restricted to brand labels of length >= 6 so short, word-like
    brands (apple, chase, ebay) don't false-match ordinary domains — those are
    still covered by the homograph/mixed-script checks."""
    for brand_label, domain in BRANDS.items():
        if len(brand_label) < 6 or label == brand_label:
            continue
        if _levenshtein_le(label, brand_label, 1) == 1:
            return domain
    return None


def inspect(host: str) -> SpoofVerdict | None:
    """Judge a hostname. Returns a verdict for a suspected spoof, else None."""
    if not host:
        return None
    host = host.strip().rstrip(".").lower()
    if _is_ip_or_local(host):
        return None

    labels = host.split(".")
    reg_label, reg_domain = _registrable(host)

    # The real thing is never a spoof of itself.
    if reg_label in _BRAND_LABELS and reg_domain == BRANDS[reg_label]:
        return None

    # 1. Mixed-script anywhere in the name (Latin fused with Cyrillic/Greek).
    for lbl in labels:
        if _mixed_script(lbl):
            brand = BRANDS.get(_skeleton(lbl))
            looks = (f" It reads like “{brand}”." if brand else "")
            return SpoofVerdict(
                "mixed_script", host, brand or "",
                "Mixed-alphabet address",
                "This address mixes characters from different alphabets to "
                "disguise its real spelling." + looks)

    # 2. Non-ASCII look-alike (homograph) of a brand: an internationalised
    #    label whose skeleton collapses onto a brand it is not.
    for lbl in labels:
        if not lbl.isascii():
            skel = _skeleton(lbl)
            brand = BRANDS.get(skel)
            if brand and reg_domain != brand:
                return SpoofVerdict(
                    "homograph", host, brand,
                    "Look-alike address",
                    f"This address uses look-alike letters to imitate "
                    f"“{brand}”.")

    # 3. ASCII homograph via digit/ligature swaps on the registrable label
    #    (paypa1 -> paypal, g00gle -> google, arnazon -> amazon).
    if reg_label.isascii():
        skel = _skeleton(reg_label)
        if skel != reg_label and skel in _BRAND_LABELS \
                and BRANDS[skel] != reg_domain:
            return SpoofVerdict(
                "homograph", host, BRANDS[skel],
                "Look-alike address",
                f"This address swaps in look-alike characters to imitate "
                f"“{BRANDS[skel]}”.")

        # 4. Typosquatting: a near-miss spelling of a brand.
        brand = _nearest_brand(reg_label)
        if brand:
            return SpoofVerdict(
                "typosquat", host, brand,
                "Possible misspelled address",
                f"This address is one character away from “{brand}” and may "
                f"be impersonating it.")

    return None


# -- interstitial page --------------------------------------------------------

def interstitial_html(verdict: SpoofVerdict, colors: dict) -> str:
    """Full-page warning shown in place of the blocked site. Self-contained
    (inline CSS, no network), and every piece of attacker-influenced text —
    the host and the brand — is HTML-escaped, never executed."""
    host = escape(verdict.display_host)
    detail = escape(verdict.detail)
    headline = escape(verdict.headline)
    ascii_host = _ascii_form(verdict.display_host)
    # When the address contains disguised (non-ASCII) characters, its punycode
    # differs and is the only spelling that can't be faked — show it so an
    # identical-looking look-alike is actually distinguishable.
    puny = ""
    if ascii_host != verdict.display_host:
        puny = (f'<div class="puny">true spelling: '
                f'{escape(ascii_host)}</div>')
    if verdict.impersonated:
        compare = (
            f'<div class="rows">'
            f'<div class="row"><span class="k">You may have wanted</span>'
            f'<span class="v good">{escape(verdict.impersonated)}</span></div>'
            f'<div class="row"><span class="k">This address is</span>'
            f'<span class="v bad">{host}</span></div>{puny}</div>')
    else:
        compare = f'<div class="single bad">{host}</div>{puny}'
    c = colors
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  html,body{{margin:0;height:100%;}}
  body{{background:{c['bg']};color:{c['text']};
    font-family:"Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;
    display:flex;align-items:center;justify-content:center;}}
  .card{{max-width:560px;margin:24px;padding:36px 40px;
    background:{c['surface']};border:1px solid {c['border']};
    border-radius:16px;box-shadow:0 18px 50px rgba(0,0,0,.35);}}
  .badge{{width:60px;height:60px;border-radius:50%;
    background:{c['danger']};color:{c['on_accent']};
    display:flex;align-items:center;justify-content:center;
    font-size:34px;margin-bottom:20px;}}
  h1{{font-size:22px;margin:0 0 10px;}}
  p{{font-size:15px;line-height:1.55;color:{c['muted']};margin:0 0 22px;}}
  .rows{{margin:0 0 26px;}}
  .row{{display:flex;justify-content:space-between;gap:16px;
    padding:11px 14px;border-radius:10px;background:{c['bg']};
    margin-bottom:8px;align-items:center;}}
  .k{{color:{c['muted']};font-size:13px;}}
  .v{{font-weight:600;font-family:"Cascadia Mono",Consolas,monospace;
    word-break:break-all;text-align:right;}}
  .good{{color:{c['ok']};}} .bad{{color:{c['danger']};}}
  .single{{padding:12px 14px;border-radius:10px;background:{c['bg']};
    font-weight:600;font-family:"Cascadia Mono",Consolas,monospace;
    word-break:break-all;margin:0 0 10px;}}
  .puny{{font-size:12.5px;color:{c['muted']};margin:2px 2px 26px;
    font-family:"Cascadia Mono",Consolas,monospace;word-break:break-all;}}
  .actions{{display:flex;gap:12px;}}
  a.btn{{flex:1;text-align:center;text-decoration:none;padding:12px 16px;
    border-radius:10px;font-size:15px;font-weight:600;}}
  a.safe{{background:{c['accent']};color:{c['on_accent']};}}
  a.risk{{background:transparent;color:{c['muted']};
    border:1px solid {c['border']};}}
</style></head><body>
  <div class="card">
    <div class="badge">&#9888;</div>
    <h1>{headline}</h1>
    <p>{detail} Sites like this are used to steal passwords and payment
       details or to deliver malware.</p>
    {compare}
    <div class="actions">
      <a class="btn safe" href="{BACK_URL}">Go back (safe)</a>
      <a class="btn risk" href="{CONTINUE_URL}">Continue anyway</a>
    </div>
  </div>
</body></html>"""


# -- drive-by download hardening ---------------------------------------------

# Extensions that can execute code / run installers on Windows. A page that
# hands you one of these — especially unprompted — is the classic drive-by.
_DANGEROUS_EXTS = frozenset({
    ".exe", ".scr", ".com", ".pif", ".msi", ".msp", ".mst", ".bat", ".cmd",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".jar", ".wsf", ".wsh",
    ".hta", ".cpl", ".dll", ".lnk", ".reg", ".inf", ".gadget", ".apk",
    ".appx", ".msix", ".dmg", ".pkg", ".deb", ".rpm", ".iso", ".img",
    ".vhd", ".vhdx", ".ade", ".adp", ".application", ".sct", ".scf",
})


def download_risk(filename: str) -> str | None:
    """Return the risky extension (e.g. '.exe') if this download can run code
    on the machine, else None. Used to escalate the download prompt."""
    ext = PurePosixPath(filename).suffix.lower()
    return ext if ext in _DANGEROUS_EXTS else None


# Windows-reserved device names (with or without an extension, any case).
_WIN_RESERVED = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
})

# Characters illegal in Windows filenames, or that open an NTFS alternate data
# stream (':') or a path component ('/', '\\').
_BAD_FILENAME_CHARS = frozenset('<>:"/\\|?*')


def safe_download_name(name: str) -> str:
    """Sanitise a server-suggested download filename to a safe basename.

    A `Content-Disposition` filename is attacker-controlled. `Path(name).name`
    strips directories but not the characters that let a crafted name hide an
    executable in an NTFS alternate data stream (`report.pdf:evil.exe`),
    collide with a reserved device name (`CON`, `NUL`, `COM1`…), or slip past
    an extension check with trailing dots/spaces (Windows ignores those). This
    removes all of that and always returns a non-empty, extension-preserving
    basename (so the drive-by executable check still sees the real suffix).
    """
    # Last path component under either separator, then drop illegal/control
    # characters (this also removes ':' — defusing ADS — and path separators).
    base = name.replace("\\", "/").split("/")[-1]
    cleaned = "".join(
        ch for ch in base
        if ch not in _BAD_FILENAME_CHARS and ord(ch) >= 0x20)
    # Windows silently drops trailing dots/spaces; strip them so a name can't
    # resolve to something other than what the extension check inspected.
    cleaned = cleaned.strip().rstrip(". ").strip()
    if not cleaned:
        return "download"
    # Reserved device name (bare or with an extension) -> prefix to neutralise.
    if cleaned.split(".", 1)[0].lower() in _WIN_RESERVED:
        cleaned = "_" + cleaned
    return cleaned[:255]
