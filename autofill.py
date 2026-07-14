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
"""

import json

# Sets input values through the native setter and fires input/change events so
# React/Vue/Angular forms register the fill.
_FILL_JS = """
(function() {
    function setVal(el, v) {
        var setter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value').set;
        setter.call(el, v);
        el.dispatchEvent(new Event('input',  {bubbles: true}));
        el.dispatchEvent(new Event('change', {bubbles: true}));
    }
    function visible(el) {
        return el.offsetParent !== null && !el.disabled && !el.readOnly;
    }

    var pwFields = Array.prototype.filter.call(
        document.querySelectorAll('input[type=password]'), visible);
    if (pwFields.length === 0) return 'no-password-field';
    var pw = pwFields[0];

    var scope = pw.form || document;
    var candidates = Array.prototype.filter.call(
        scope.querySelectorAll(
            'input[type=text], input[type=email], input:not([type])'),
        visible);

    // username field = last text/email input that appears before the
    // password field in document order
    var user = null;
    for (var i = 0; i < candidates.length; i++) {
        var pos = pw.compareDocumentPosition(candidates[i]);
        if (pos & Node.DOCUMENT_POSITION_PRECEDING) user = candidates[i];
    }

    if (user) setVal(user, %(username)s);
    setVal(pw, %(password)s);
    return user ? 'ok' : 'password-only';
})();
"""


def build_fill_script(username: str, password: str) -> str:
    return _FILL_JS % {
        "username": json.dumps(username),
        "password": json.dumps(password),
    }


# True if the page currently shows a password field (used to decide whether
# to offer autofill at all).
PROBE_JS = "!!document.querySelector('input[type=password]')"


# Snapshots login credentials at the moment a form is submitted (submit
# event, submit-button click, or Enter) and reports them via a token-prefixed
# console message. Deduplicates so the same values are only reported once.
_CAPTURE_JS = """
(function() {
    var TOKEN = %(token)s;
    var last = "";

    function grab(scope) {
        if (!scope || !scope.querySelectorAll) scope = document;
        var pw = null;
        var pws = scope.querySelectorAll('input[type=password]');
        for (var i = 0; i < pws.length; i++) {
            if (pws[i].value) { pw = pws[i]; break; }
        }
        if (!pw) return;
        var form = pw.form || document;
        var user = null;
        var cands = form.querySelectorAll(
            'input[type=text], input[type=email], input:not([type])');
        for (var j = 0; j < cands.length; j++) {
            if (!cands[j].value) continue;
            var pos = pw.compareDocumentPosition(cands[j]);
            if (pos & Node.DOCUMENT_POSITION_PRECEDING) user = cands[j];
        }
        var payload = JSON.stringify(
            {u: user ? user.value : "", p: pw.value});
        if (payload === last) return;
        last = payload;
        console.log(TOKEN + payload);
    }

    document.addEventListener('submit', function(e) {
        grab(e.target);
    }, true);
    document.addEventListener('click', function(e) {
        var t = e.target;
        if (t && t.closest &&
                t.closest('button, input[type=submit], [role=button]'))
            grab(document);
    }, true);
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') grab(document);
    }, true);
})();
"""


def build_capture_script(token: str) -> str:
    return _CAPTURE_JS % {"token": json.dumps(token)}
