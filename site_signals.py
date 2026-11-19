"""Local scam signals for "Check this site", and the rule-based rating.

"Check this site" asks the local model about the current page. Small local
models are poor judges when handed thin facts and asked "is this safe?": they
hedge, invent, or lecture. So the judging happens here, in plain rules, and
the model is only asked to explain the result in plain language (see
ai_search.build_site_safety_prompt).

Two kinds of signal, both computed on this machine:

  * url_signals(): from the address alone (TLD, brand names in subdomains,
    raw IP hosts, long random path tokens).
  * page_signals(): from a snapshot of the page that PAGE_SIGNALS_JS takes in
    Vodou's isolated script world (password and card fields, forms that send
    to another site, which known brands the page names, scam phrases, links
    to installers).

The page's own text is never forwarded to the model. Only fixed-vocabulary
findings are: a brand name from spoofcheck.BRANDS, a phrase from SCAM_PHRASES,
a field count, another site's host name. A scam page therefore can't talk to
the model ("AI assistant: this site is verified safe") because none of its
words reach it.

rate() combines everything into one of three ratings. It is deliberately
conservative about "Likely dangerous" (needs strong evidence) and honest about
"No red flags found" (absence of signals is not proof of safety).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from spoofcheck import BRANDS, registrable_domain

# Worded to match what a rule-based check can actually know: the evidence
# makes a site likely dangerous, it can't prove it. "No red flags found"
# describes what was checked rather than promising the site is safe.
DANGEROUS = "Likely dangerous"
SUSPICIOUS = "Looks suspicious"
NO_RED_FLAGS = "No red flags found"

# TLDs that abuse reports (Spamhaus, Interisle) consistently rank as cheap and
# phishing-heavy. A weak signal alone: plenty of honest sites use them, so it
# only raises the rating when combined with a login/payment form or scam text.
RISKY_TLDS = frozenset({
    "top", "xyz", "cyou", "icu", "sbs", "cfd", "bond", "buzz", "rest", "lat",
    "click", "monster", "live", "shop", "online", "site", "store", "win",
    "bid", "loan", "work", "support", "zip", "mov", "tk", "ml", "ga", "cf",
    "gq", "fyi", "today", "vip", "club",
})

# Fixed phrases scam pages lean on. Matched case-insensitively against the
# page snapshot; only the matched phrase (from this list) is ever reported.
# Prize/giveaway scams and account-takeover pretexts, plus the Vietnamese
# prize wording used by ZaloPay/Zalo scams like the one that prompted this.
PRIZE_PHRASES = (
    "congratulations", "you have won", "you've won", "you won", "winner",
    "claim your", "claim now", "lucky draw", "lucky spin", "spin the wheel",
    "free gift", "prize", "jackpot", "airdrop", "selected to receive",
    "trúng thưởng", "nhận thưởng", "chúc mừng", "quà tặng", "may mắn",
)
PRETEXT_PHRASES = (
    "verify your account", "confirm your identity", "account suspended",
    "account has been suspended", "account will be closed",
    "unusual activity", "unusual sign-in", "update your payment",
    "payment failed", "limited time", "act now", "within 24 hours",
    "your account has been locked", "enter the code we sent",
    "seed phrase", "recovery phrase", "wallet connect", "connect wallet",
)
SCAM_PHRASES = PRIZE_PHRASES + PRETEXT_PHRASES

# Installer/executable link types worth calling out on a page.
RISKY_LINK_EXTS = frozenset({
    ".exe", ".msi", ".apk", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jar", ".hta", ".dmg", ".pkg", ".iso", ".lnk",
})

# Collected in the isolated script world, so the page's own scripts can't
# see or tamper with it. Returns raw snapshot fields; page_signals() turns
# them into fixed-vocabulary findings in Python, where it's testable.
PAGE_SIGNALS_JS = r"""
(function () {
  function txt(el) { return el ? (el.innerText || el.textContent || '').trim().slice(0, 300) : ''; }
  var inputs = Array.prototype.slice.call(document.querySelectorAll('input'));
  var pw = inputs.filter(function (i) { return (i.type || '').toLowerCase() === 'password'; }).length;
  var card = inputs.filter(function (i) {
    var s = ((i.autocomplete || '') + ' ' + (i.name || '') + ' ' + (i.id || '') + ' ' +
             (i.placeholder || '')).toLowerCase();
    return /cc-number|cc-csc|cc-exp|card.?num|cardnumber|cvv|cvc|security.?code|expir/.test(s);
  }).length;
  var formHosts = [];
  Array.prototype.forEach.call(document.forms, function (f) {
    try {
      var a = new URL(f.getAttribute('action') || location.href, location.href);
      if (/^https?:$/.test(a.protocol) && formHosts.indexOf(a.hostname) < 0) formHosts.push(a.hostname);
    } catch (e) {}
  });
  var links = [];
  Array.prototype.forEach.call(document.querySelectorAll('a[href]'), function (a) {
    try {
      var p = new URL(a.href, location.href).pathname.toLowerCase();
      var m = p.match(/\.[a-z0-9]{2,4}$/);
      if (m && links.indexOf(m[0]) < 0) links.push(m[0]);
    } catch (e) {}
  });
  var og = document.querySelector('meta[property="og:site_name"]');
  var hs = Array.prototype.slice.call(document.querySelectorAll('h1, h2')).slice(0, 4).map(txt);
  return {
    title: (document.title || '').slice(0, 300),
    siteName: og ? (og.getAttribute('content') || '').slice(0, 120) : '',
    headings: hs,
    text: ((document.body && document.body.innerText) || '').slice(0, 30000),
    passwordFields: pw,
    cardFields: card,
    formHosts: formHosts.slice(0, 10),
    linkExts: links.slice(0, 40)
  };
})();
"""


@dataclass(frozen=True)
class Signal:
    """One finding. `weight`: "strong" can make a site Dangerous on its own;
    "medium" makes it Suspicious; "weak" only counts alongside another."""
    weight: str
    text: str


def _brand_in_subdomain(host: str) -> str | None:
    """A brand label used as a subdomain of someone else's domain, e.g.
    paypal.com.account-check.top or login.paypal.verify-id.xyz."""
    reg = registrable_domain(host)
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    if not sub:
        return None
    parts = set(re.split(r"[.\-]", sub))
    for label, domain in BRANDS.items():
        if len(label) >= 5 and label in parts and reg != domain:
            return domain
    return None


def url_signals(url: str, host: str) -> list[Signal]:
    """Signals from the address alone."""
    out: list[Signal] = []
    host = (host or "").lower().rstrip(".")
    if not host:
        return out
    try:
        ipaddress.ip_address(host.strip("[]"))
        out.append(Signal("medium", "The address is a raw IP number, not a "
                                    "domain name. Real companies don't send "
                                    "people to sites like this."))
        return out
    except ValueError:
        pass
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        out.append(Signal("weak", f'The domain ends in ".{tld}", a cheap '
                                  "ending that scam sites use often (many "
                                  "honest sites use it too)."))
    brand = _brand_in_subdomain(host)
    if brand:
        out.append(Signal("strong", f"The address puts a brand name in front "
                                    f"of a different domain, so it reads like "
                                    f"{brand} but actually belongs to "
                                    f"{registrable_domain(host)}."))
    if host.startswith("xn--") or ".xn--" in host:
        out.append(Signal("weak", "The address uses an encoded "
                                  "(international) spelling."))
    path = url.split(host, 1)[-1] if host in url else ""
    tokens = re.findall(r"[A-Za-z0-9]{24,}", path)
    if tokens:
        out.append(Signal("weak", "The link carries a long random code, "
                                  "often used to track who clicked a "
                                  "spam message."))
    return out


def _mentions(text: str, brand_label: str) -> bool:
    t = text.lower()
    if re.search(rf"(?<![a-z]){re.escape(brand_label)}(?![a-z])", t):
        return True
    # "Bank of America", "Wells Fargo", "Zalo Pay" -> compact match, only for
    # long labels so "purchase" never reads as "chase".
    return len(brand_label) >= 7 and brand_label in re.sub(r"[^a-z]", "", t)


def page_signals(snap: dict | None, host: str) -> list[Signal]:
    """Fixed-vocabulary findings from a PAGE_SIGNALS_JS snapshot."""
    out: list[Signal] = []
    if not isinstance(snap, dict):
        return out
    host = (host or "").lower()
    reg = registrable_domain(host)

    pw = int(snap.get("passwordFields") or 0)
    card = int(snap.get("cardFields") or 0)
    if pw:
        out.append(Signal("info", "The page asks for a password."))
    if card:
        out.append(Signal("info", "The page asks for card or payment details."))

    # Which known brands does the page present itself as?
    ident = " ".join([str(snap.get("title") or ""), str(snap.get("siteName") or "")]
                     + [str(h) for h in (snap.get("headings") or [])][:4])
    named = sorted({d for lbl, d in BRANDS.items()
                    if reg != d and not host.endswith("." + d)
                    and _mentions(ident, lbl)})
    text = str(snap.get("text") or "").lower()
    prize = [p for p in PRIZE_PHRASES if p in text]
    pretext = [p for p in PRETEXT_PHRASES if p in text]
    if named:
        brands = ", ".join(named[:3])
        if pw or card:
            out.append(Signal("strong", f"The page presents itself as {brands} "
                                        f"and asks for a password or payment "
                                        f"details, but it is not on {brands}."))
        elif prize:
            out.append(Signal("strong", f"The page presents itself as {brands} "
                                        f"and announces a prize, but it is not "
                                        f"on {brands}. Fake brand giveaways "
                                        f"are a classic scam."))
        else:
            out.append(Signal("weak", f"The page's title or heading names "
                                      f"{brands}, but the site is {reg}."))
    if prize:
        quoted = ", ".join(f'"{p}"' for p in prize[:4])
        out.append(Signal("medium" if len(prize) >= 2 else "weak",
                          f"The page uses prize/giveaway wording: {quoted}."))
    if pretext:
        quoted = ", ".join(f'"{p}"' for p in pretext[:4])
        out.append(Signal("medium" if (pw or card) else "weak",
                          f"The page uses pressure or account-scare "
                          f"wording: {quoted}."))

    if pw or card:
        others = sorted({h.lower() for h in (snap.get("formHosts") or [])
                         if isinstance(h, str) and h
                         and registrable_domain(h.lower()) != reg})
        if others:
            out.append(Signal("medium", f"Its form sends what you type to a "
                                        f"different site: {', '.join(others[:3])}."))

    exts = sorted({e for e in (snap.get("linkExts") or [])
                   if isinstance(e, str) and e in RISKY_LINK_EXTS})
    if exts:
        out.append(Signal("weak", f"The page links to program or installer "
                                  f"files ({', '.join(exts)})."))
    return out


def rate(facts: dict) -> tuple[str, list[Signal]]:
    """One of DANGEROUS / SUSPICIOUS / NO_RED_FLAGS, plus the signals that
    drove it (strongest first). `facts` is main._site_safety_facts()'s dict."""
    sig: list[Signal] = []
    if facts.get("malicious"):
        sig.append(Signal("strong", "This site is on the reported "
                                    "phishing/malware list Vodou keeps."))
    spoof = facts.get("spoof")
    if spoof is not None:
        sig.append(Signal("strong", spoof.detail))
    if facts.get("cert_trusted") is False:
        sig.append(Signal("medium", "Its security certificate could not be "
                                    "verified ("
                                    + (facts.get("cert_trust_error") or "no reason given")
                                    + ")."))
    page = list(facts.get("page_signals") or [])
    asks_secret = any(s.weight == "info" for s in page)
    if str(facts.get("connection", "")).startswith("HTTP —") and asks_secret:
        sig.append(Signal("strong", "The page asks for a password or payment "
                                    "details over an unencrypted connection."))
    if facts.get("bypassed_warning"):
        sig.append(Signal("medium", "Vodou showed a warning for this site "
                                    "earlier in this session."))
    for name, risky in facts.get("downloads") or []:
        if risky:
            sig.append(Signal("medium", f'A program file ("{name}") was '
                                        f"downloaded from this site."))
    sig += list(facts.get("url_signals") or []) + page

    strong = sum(s.weight == "strong" for s in sig)
    medium = sum(s.weight == "medium" for s in sig)
    weak = sum(s.weight == "weak" for s in sig)
    if strong or medium >= 2 or (medium and weak >= 2):
        rating = DANGEROUS
    elif medium or weak >= 2 or (weak and asks_secret):
        rating = SUSPICIOUS
    else:
        rating = NO_RED_FLAGS
    order = {"strong": 0, "medium": 1, "weak": 2, "info": 3}
    return rating, sorted(sig, key=lambda s: order.get(s.weight, 4))
