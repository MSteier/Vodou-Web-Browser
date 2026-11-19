"""Tests for "Check this site"'s local scam signals and rating
(site_signals.py).

Pure, no Qt, no network: address signals, page-snapshot signals (as
PAGE_SIGNALS_JS would return them), and the rule-based rating.

Run:  python tests/test_site_signals.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import site_signals as ss  # noqa: E402
from spoofcheck import inspect as spoof_inspect  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


def snap(**kw):
    base = {"title": "", "siteName": "", "headings": [], "text": "",
            "passwordFields": 0, "cardFields": 0, "formHosts": [],
            "linkExts": []}
    base.update(kw)
    return base


def facts(url, host, page=None, **kw):
    f = {"url": url, "host": host, "connection": "HTTPS (encrypted)",
         "cert_trusted": True, "spoof": spoof_inspect(host), "malicious": False,
         "bypassed_warning": False, "downloads": [],
         "url_signals": ss.url_signals(url, host),
         "page_signals": ss.page_signals(page, host)}
    f.update(kw)
    return f


def rating(f):
    return ss.rate(f)[0]


# ---------------------------------------------------------------------------
print("address signals")

u = ss.url_signals("https://paypal.com.account-check.top/x", "paypal.com.account-check.top")
check("brand in a subdomain is strong",
      any(s.weight == "strong" and "paypal.com" in s.text for s in u))
check("risky TLD is noted as weak",
      any(s.weight == "weak" and ".top" in s.text for s in u))
check("raw IP host is flagged",
      any("raw IP" in s.text for s in ss.url_signals("http://45.9.1.2/login", "45.9.1.2")))
check("long random link code is noted",
      any("random code" in s.text for s in ss.url_signals(
          "https://zalopaywin.com/hzcwCeXitkp/9GGncYBI1Hpx1lm1Ay3qa4eec7?ptf=ms",
          "zalopaywin.com")))
check("a plain real site has no address signals",
      ss.url_signals("https://www.paypal.com/signin", "www.paypal.com") == [])
check("the brand's own subdomain is not flagged",
      ss.url_signals("https://login.paypal.com/", "login.paypal.com") == [])

# ---------------------------------------------------------------------------
print("page signals")

ps = ss.page_signals(snap(title="ZaloPay - Nhận thưởng", passwordFields=1,
                          text="Chúc mừng! Bạn đã trúng thưởng. Claim your prize now."),
                     "zalopaywin.com")
check("page posing as a brand with a password field is strong",
      any(s.weight == "strong" and "zalopay.vn" in s.text for s in ps))
check("prize wording (Vietnamese and English) is found",
      any("prize/giveaway" in s.text and s.weight == "medium" for s in ps))
check("only fixed phrases are reported, never page text",
      all("Bạn đã" not in s.text for s in ps))

news = ss.page_signals(snap(title="PayPal stock jumps after earnings - Example News"),
                       "news.example.com")
check("a news page naming a brand without a login form is only weak",
      [s.weight for s in news] == ["weak"])

real = ss.page_signals(snap(title="Log in to your PayPal account", passwordFields=1),
                       "www.paypal.com")
check("the real brand's own login page raises nothing",
      [s.weight for s in real] == ["info"])

check("'purchase' is not read as the brand 'chase'",
      not any("chase" in s.text for s in ss.page_signals(
          snap(title="Complete your purchase", cardFields=1), "shop.example.com")))
check("'Wells Fargo' with a space still matches",
      any("wellsfargo.com" in s.text for s in ss.page_signals(
          snap(title="Wells Fargo Sign On", passwordFields=1), "wf-secure.xyz")))

off = ss.page_signals(snap(passwordFields=1, formHosts=["evil-collect.ru", "example.com"]),
                      "example.com")
check("a login form posting to another site is medium",
      any(s.weight == "medium" and "evil-collect.ru" in s.text for s in off))
check("a form posting to its own site is not flagged",
      not any("example.com" in s.text and "different site" in s.text for s in off))

check("installer links are noted",
      any(".apk" in s.text for s in ss.page_signals(snap(linkExts=[".apk", ".pdf"]), "x.com")))
check("a missing snapshot gives no page signals", ss.page_signals(None, "x.com") == [])

# ---------------------------------------------------------------------------
print("rating")

zalo = facts("https://zalopaywin.com/hzcwCeXitkp/9GGncYBI1Hpx1lm1Ay3qa4eec7",
             "zalopaywin.com",
             snap(title="ZaloPay", text="Congratulations! You have won a prize."))
check("the zalopaywin scam page is Dangerous", rating(zalo) == ss.DANGEROUS)
zalo_page_only = facts("https://zalo-gift.example/", "zalo-gift.example",
                       snap(title="ZaloPay", text="Congratulations! You have won."))
check("a page posing as a brand and announcing a prize is Dangerous even "
      "when the address itself looks harmless",
      rating(zalo_page_only) == ss.DANGEROUS)
check("a prize page that names no brand is only Suspicious",
      rating(facts("https://contest.example/", "contest.example",
                   snap(title="Contest", text="Congratulations, you won a prize!"))) == ss.SUSPICIOUS)

check("an ordinary site is No red flags found",
      rating(facts("https://example.com/", "example.com", snap(title="Example"))) == ss.NO_RED_FLAGS)
check("a real bank login is No red flags found",
      rating(facts("https://www.chase.com/", "www.chase.com",
                   snap(title="Chase Online", passwordFields=1))) == ss.NO_RED_FLAGS)
check("a news article about PayPal is not Dangerous",
      rating(facts("https://news.example.com/a", "news.example.com",
                   snap(title="PayPal earnings beat estimates"))) != ss.DANGEROUS)
check("a cheap TLD alone is not Suspicious",
      rating(facts("https://bakery.shop/", "bakery.shop", snap(title="Fresh bread"))) == ss.NO_RED_FLAGS)
check("a cheap TLD with a login form is Suspicious",
      rating(facts("https://portal.shop/", "portal.shop",
                   snap(title="Member login", passwordFields=1))) == ss.SUSPICIOUS)
check("a password form over plain HTTP is Dangerous",
      rating(facts("http://login.example.com/", "login.example.com",
                   snap(passwordFields=1), connection="HTTP — NOT encrypted")) == ss.DANGEROUS)
check("an untrusted certificate alone is Suspicious",
      rating(facts("https://x.example/", "x.example", snap(),
                   cert_trusted=False, cert_trust_error="expired")) == ss.SUSPICIOUS)
check("a malicious-list hit is Dangerous",
      rating(facts("https://bad.example/", "bad.example", malicious=True)) == ss.DANGEROUS)

r, sig = ss.rate(zalo)
check("strongest evidence comes first", sig[0].weight == "strong")

if _failures:
    print(f"\n{len(_failures)} failure(s)")
    sys.exit(1)
print("\nall site-signal tests passed")
