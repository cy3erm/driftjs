import re

_TAINT_SOURCE = re.compile(
    r"location\.(hash|search|href|pathname)|document\.(URL|documentURI|referrer|cookie)|window\.name",
)
_SINK = re.compile(
    r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write|\beval\s*\(|dangerouslySetInnerHTML|"
    r"insertAdjacentHTML|new\s+Function\s*\(",
)

_MSG_LISTENER = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]|onmessage\s*=")
_ORIGIN_CHECK = re.compile(r"\.origin\b")

_SAFE_HTTP = re.compile(r"http://(www\.w3\.org|schemas\.|localhost|127\.0\.0\.1|example\.(com|org)|.*\.local)", re.I)
_HTTP_URL = re.compile(r"""['"]http://[a-z0-9.\-]+""", re.I)

_SEC_CTX = re.compile(r"token|secret|password|passwd|otp|nonce|session|api[_-]?key|csrf|\bkey\b", re.I)

_CHECKS_SIMPLE = [
    ("high", "postMessage handler without origin check (possible DOM XSS / data leak)",
     lambda js: _MSG_LISTENER.search(js) and not _ORIGIN_CHECK.search(js)),
    ("high", "CORS allows any origin with credentials",
     lambda js: re.search(r"allow-origin['\"]?\s*[:=]\s*['\"]\*", js, re.I)
     and re.search(r"allow-credentials['\"]?\s*[:=]\s*['\"]?true", js, re.I)),
    ("high", "JWT 'alg: none' referenced (possible signature bypass)",
     lambda js: re.search(r"['\"]?alg['\"]?\s*[:=]\s*['\"]none['\"]", js, re.I)),
    ("medium", "Prototype pollution sink (__proto__ / constructor.prototype)",
     lambda js: re.search(r"__proto__|constructor\s*\[\s*['\"]prototype", js)),
    ("medium", "Weak/legacy crypto referenced (MD5/SHA1/DES/RC4)",
     lambda js: re.search(r"\b(MD5|SHA-?1|DES|RC4)\b", js)),
    ("medium", "Client-side authorization logic (bypassable in the browser)",
     lambda js: re.search(r"\.(isAdmin|is_admin|isAuthenticated|hasRole)\b|role\s*===?\s*['\"]admin", js)),
    ("low", "JWT decoded without verification",
     lambda js: re.search(r"jwt\.decode\s*\(", js) and not re.search(r"jwt\.verify\s*\(", js)),
]


def _has_insecure_http(js):
    for m in _HTTP_URL.finditer(js):
        if not _SAFE_HTTP.search(m.group(0)):
            return True
    return False


def _has_insecure_random(js):
    for line in js.splitlines():
        if "Math.random(" in line and _SEC_CTX.search(line):
            return True
    return False


def _has_dom_xss_chain(js):
    return bool(_TAINT_SOURCE.search(js) and _SINK.search(js))


def find_weaknesses(js):
    out = set()
    for sev, label, check in _CHECKS_SIMPLE:
        try:
            if check(js):
                out.add((sev, label))
        except Exception:
            continue
    if _has_dom_xss_chain(js):
        out.add(("high", "DOM XSS chain: untrusted source flows toward an HTML/JS sink"))
    if _has_insecure_random(js):
        out.add(("medium", "Math.random() used in a security context (not cryptographically safe)"))
    if _has_insecure_http(js):
        out.add(("low", "Insecure http:// URL (mixed content / MITM exposure)"))
    return out
