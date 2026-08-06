"""Login autofill and credential capture via JavaScript injection.

Fill is always user-confirmed (toolbar button, Ctrl+Shift+F, or the offer
bar) — credentials are never injected without a click, so a hidden form on a
malicious page can't harvest them without you noticing.

Capture (for save/update-password prompts) runs in an isolated JavaScript
world and reports through console messages prefixed with a random per-session
token, so page scripts can neither tamper with the listener nor forge
messages. The page's host is always taken from the URL on the Python side —
never from JavaScript — so a page can only ever influence vault entries for
its own domain.

Field detection (the `_HELPERS` prelude shared by every script below) is
written to survive the ways real sign-in pages are built:

  * shadow DOM and same-origin iframes are pierced (plain querySelectorAll
    stops at the shadow boundary, so component-based logins were invisible);
  * visibility is judged by getClientRects()/computed style, not
    `offsetParent` — the latter is null for `position: fixed` elements, which
    made modal login overlays (Target, Google's dialogs) look hidden;
  * multi-step logins (Google, OpenAI: email first, password on a later
    screen) are handled — a page showing only an `autocomplete="username"`
    field is treated as a fillable login step, not skipped for lacking a
    password box.
"""

import json

# Shared field-detection helpers, injected at the top of every script's IIFE.
# Kept dependency-free and defensive (every cross-context access is wrapped)
# because it runs against arbitrary, sometimes hostile, page structures.
_HELPERS = r"""
    // All matching elements anywhere in the main frame, descending through
    // open shadow roots and same-origin iframes. Cross-origin frames throw on
    // access and are silently skipped, so we can never reach across origins.
    function _deepQuery(selector) {
        var out = [];
        function walk(root) {
            var matches;
            try { matches = root.querySelectorAll(selector); }
            catch (e) { return; }
            for (var i = 0; i < matches.length; i++) out.push(matches[i]);
            var all;
            try { all = root.querySelectorAll('*'); }
            catch (e) { return; }
            for (var j = 0; j < all.length; j++) {
                var el = all[j];
                if (el.shadowRoot) walk(el.shadowRoot);
                if (el.tagName === 'IFRAME' || el.tagName === 'FRAME') {
                    var doc = null;
                    try { doc = el.contentDocument; } catch (e) { doc = null; }
                    if (doc) walk(doc);
                }
            }
        }
        walk(document);
        return out;
    }

    // Genuinely on-screen and interactive. getClientRects() is empty for
    // display:none/detached nodes but non-empty for position:fixed ones,
    // unlike offsetParent.
    function _visible(el) {
        if (el.disabled || el.readOnly) return false;
        if (el.getClientRects().length === 0) return false;
        var view = (el.ownerDocument && el.ownerDocument.defaultView) || window;
        var s;
        try { s = view.getComputedStyle(el); } catch (e) { return true; }
        if (!s) return true;
        if (s.visibility === 'hidden' || s.display === 'none') return false;
        if (parseFloat(s.opacity) === 0) return false;
        return true;
    }

    function _isPw(el) {
        return (el.getAttribute('type') || '').toLowerCase() === 'password';
    }

    // A plausible username/email field (never a password, search, or button).
    function _isUserCand(el) {
        var t = (el.getAttribute('type') || 'text').toLowerCase();
        return t === 'text' || t === 'email' || t === 'tel' || t === '';
    }

    // Every visible input in the frame tree, in traversal (≈document) order.
    // Ordering by array index rather than compareDocumentPosition keeps the
    // "username precedes password" rule working across shadow/iframe walls,
    // where compareDocumentPosition reports DISCONNECTED.
    function _visibleInputs() {
        return _deepQuery('input').filter(_visible);
    }

    // Pick the username field for a login: prefer an explicit
    // autocomplete=username/email, else the last candidate before the
    // password (or the last candidate overall on a password-less step).
    function _pickUser(inputs, pwIndex) {
        var limit = pwIndex < 0 ? inputs.length : pwIndex;
        var cands = [];
        for (var i = 0; i < limit; i++) {
            if (_isUserCand(inputs[i])) cands.push(inputs[i]);
        }
        for (var j = 0; j < cands.length; j++) {
            var a = (cands[j].getAttribute('autocomplete') || '').toLowerCase();
            if (a === 'username' || a === 'email') return cands[j];
        }
        return cands.length ? cands[cands.length - 1] : null;
    }
"""


# Sets input values through the native setter and fires input/change events so
# React/Vue/Angular forms register the fill. Handles ordinary username+password
# forms, password-only pages (username already present/hidden), and the first
# screen of a multi-step login where only the username field is shown yet.
_FILL_JS = r"""
(function() {
    %(helpers)s
    function setVal(el, v) {
        var setter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value').set;
        setter.call(el, v);
        el.dispatchEvent(new Event('input',  {bubbles: true}));
        el.dispatchEvent(new Event('change', {bubbles: true}));
    }

    var inputs = _visibleInputs();
    var pw = null, pwIndex = -1;
    for (var i = 0; i < inputs.length; i++) {
        if (_isPw(inputs[i])) { pw = inputs[i]; pwIndex = i; break; }
    }
    var user = _pickUser(inputs, pwIndex);

    if (!pw) {
        // Multi-step login: no password box yet. Fill the username so the
        // page can advance to its password screen (where we'll offer again).
        if (user) { setVal(user, %(username)s); return 'username-only'; }
        return 'no-login-field';
    }
    if (user) setVal(user, %(username)s);
    setVal(pw, %(password)s);
    return user ? 'ok' : 'password-only';
})();
"""


def build_fill_script(username: str, password: str) -> str:
    return _FILL_JS % {
        "helpers": _HELPERS,
        "username": json.dumps(username),
        "password": json.dumps(password),
    }


# Reports what kind of login the page currently shows, so the caller can
# decide whether to offer autofill: 'password' (a password box is present),
# 'username' (a multi-step first screen — gated strictly on
# autocomplete=username so newsletter/search email boxes don't trigger it),
# or '' (nothing to offer). Empty string is falsy, so existing truthiness
# checks keep working.
PROBE_JS = r"""
(function() {
    %(helpers)s
    var inputs = _visibleInputs();
    for (var i = 0; i < inputs.length; i++) {
        if (_isPw(inputs[i])) return 'password';
    }
    for (var j = 0; j < inputs.length; j++) {
        var a = (inputs[j].getAttribute('autocomplete') || '').toLowerCase();
        if (a === 'username') return 'username';
    }
    return '';
})();
""" % {"helpers": _HELPERS}


# Snapshots login credentials at the moment a form is submitted (submit
# event, submit-button click, or Enter) and reports them via a token-prefixed
# console message. Deduplicates so the same values are only reported once.
_CAPTURE_JS = r"""
(function() {
    %(helpers)s
    var TOKEN = %(token)s;
    var last = "";

    function grab() {
        var inputs = _visibleInputs();
        var pw = null, pwIndex = -1;
        for (var i = 0; i < inputs.length; i++) {
            if (_isPw(inputs[i]) && inputs[i].value) {
                pw = inputs[i]; pwIndex = i; break;
            }
        }
        if (!pw) return;
        var user = "";
        for (var j = 0; j < pwIndex; j++) {
            if (_isUserCand(inputs[j]) && inputs[j].value) {
                user = inputs[j].value;
            }
        }
        var payload = JSON.stringify({u: user, p: pw.value});
        if (payload === last) return;
        last = payload;
        console.log(TOKEN + payload);
    }

    document.addEventListener('submit', grab, true);
    document.addEventListener('click', function(e) {
        var t = e.target;
        if (t && t.closest &&
                t.closest('button, input[type=submit], [role=button]'))
            grab();
    }, true);
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') grab();
    }, true);
})();
"""


def build_capture_script(token: str) -> str:
    return _CAPTURE_JS % {"helpers": _HELPERS, "token": json.dumps(token)}
