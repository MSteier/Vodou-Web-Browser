"""Tests for the local deceptive-address check (spoofcheck.inspect).

Pure, no Qt, no network. Covers the brand + bait-word ("combosquat") check
added for prize-scam domains like zalopaywin.com, the existing heuristics it
must not disturb, and real brand-owned domains that must stay quiet.

Run:  python tests/test_spoofcheck.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import spoofcheck as sc  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


def kind(host):
    v = sc.inspect(host)
    return v.kind if v else None


# ---------------------------------------------------------------------------
print("brand + bait word -> flagged")

for host, brand in [
    ("zalopaywin.com", "zalopay.vn"),
    ("zalopaylucky.com", "zalopay.vn"),
    ("www.zalopay-win.com", "zalopay.vn"),
    ("paypal-login.com", "paypal.com"),
    ("secure-paypal.net", "paypal.com"),
    ("paypal-login-secure.com", "paypal.com"),
    ("coinbase-wallet-verify.io", "coinbase.com"),
    ("wellsfargo-support.com", "wellsfargo.com"),
    ("netflix-billing-update.com", "netflix.com"),
    ("metamask-airdrop.xyz", "metamask.io"),
    ("amazon-prize2026.top", "amazon.com"),
]:
    v = sc.inspect(host)
    check(f"{host} flagged as imitating {brand}",
          v is not None and v.kind == "brand_bait" and v.impersonated == brand)

# The address the user actually received (path/fragment never reach inspect).
check("zalopaywin.com headline is set",
      sc.inspect("zalopaywin.com").headline == "Suspicious brand address")

# ---------------------------------------------------------------------------
print("real brand domains and ordinary sites -> quiet")

for host in [
    "zalopay.vn", "www.zalopay.vn", "paypal.com", "www.paypal.com",
    "googleapis.com", "googleusercontent.com", "youtube-nocookie.com",
    "youtubekids.com", "microsoftonline.com", "amazonaws.com",
    "amazonpay.com", "githubusercontent.com", "paypalobjects.com",
    "dropboxusercontent.com", "cdninstagram.com", "whatsapp.net",
    "windowscentral.com", "officedepot.com", "outlookindia.com",
    "blockchain-news.com", "krakenimages.com", "targetwin.com",
    "applesupport.org", "chasewin.com",
    # brand-owned names found by scanning the top 100k domains
    "amazonservices.com", "redditgifts.com", "paypal-gifts.com",
    "misttechnologies.net", "vodou.misttechnologies.net",
    "wikipedia.org", "duckduckgo.com", "localhost", "192.168.1.10",
]:
    check(f"{host} not flagged", sc.inspect(host) is None)

# ---------------------------------------------------------------------------
print("existing heuristics unchanged")

check("paypa1.com is a homograph", kind("paypa1.com") == "homograph")
check("gooogle.com is a typosquat", kind("gooogle.com") == "typosquat")
check("Cyrillic-a paypal is mixed-script",
      kind("pаypal.com") == "mixed_script")
check("arnazon.com is a homograph", kind("arnazon.com") == "homograph")

# ---------------------------------------------------------------------------
print("bait-word splitter")

check("'loginsecure' splits into bait words", sc._only_bait("loginsecure"))
check("'win' is bait", sc._only_bait("win"))
check("'apis' is not bait", not sc._only_bait("apis"))
check("'online' is not bait", not sc._only_bait("online"))
check("empty remainder is not bait", not sc._only_bait(""))

# ---------------------------------------------------------------------------
print("interstitial escapes attacker text")

html = sc.interstitial_html(
    sc.SpoofVerdict("brand_bait", "<b>x</b>paypal-login.com", "paypal.com",
                    "Suspicious brand address", "d"),
    {k: "#000" for k in ("bg", "text", "surface", "border", "danger",
                         "on_accent", "muted", "ok", "accent")})
check("host is HTML-escaped", "<b>x</b>" not in html and "&lt;b&gt;" in html)

if _failures:
    print(f"\n{len(_failures)} failure(s)")
    sys.exit(1)
print("\nall spoofcheck tests passed")
