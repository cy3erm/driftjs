import re

NOTABLE_HEADER_PREFIX = "Custom header referenced: "

# Standard HTTP request/response header names (lowercased). When one of these
# shows up as an object key, it is a header, not a fuzzable request parameter.
STANDARD_HEADERS = frozenset({
    "a-im", "accept", "accept-charset", "accept-datetime", "accept-encoding",
    "accept-language", "accept-ranges", "access-control-allow-credentials",
    "access-control-allow-headers", "access-control-allow-methods",
    "access-control-allow-origin", "access-control-expose-headers",
    "access-control-max-age", "access-control-request-headers",
    "access-control-request-method", "age", "allow", "alt-svc", "authorization",
    "cache-control", "connection", "content-disposition", "content-encoding",
    "content-language", "content-length", "content-location", "content-md5",
    "content-range", "content-security-policy", "content-type", "cookie",
    "date", "dnt", "etag", "expect", "expires", "forwarded", "from", "host",
    "if-match", "if-modified-since", "if-none-match", "if-range",
    "if-unmodified-since", "keep-alive", "last-modified", "link", "location",
    "max-forwards", "origin", "p3p", "pragma", "proxy-authenticate",
    "proxy-authorization", "public-key-pins", "range", "referer",
    "referrer-policy", "retry-after", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    "sec-fetch-user", "server", "set-cookie", "strict-transport-security", "te",
    "timing-allow-origin", "tk", "trailer", "transfer-encoding", "upgrade",
    "upgrade-insecure-requests", "user-agent", "vary", "via", "warning",
    "www-authenticate", "x-content-type-options", "x-frame-options",
    "x-powered-by", "x-requested-with", "x-ua-compatible", "x-xss-protection",
})

# Single-word headers that are almost never legitimate request parameters, so
# they are safe to strip from params even when seen outside a headers block.
# Ambiguous words (date, location, origin, host, range, link, age) are omitted
# on purpose so a real param of that name survives.
UNAMBIGUOUS_HEADER_WORDS = frozenset({
    "authorization", "cookie", "referer", "connection", "pragma", "via",
    "warning", "dnt", "te", "trailer", "etag",
})

# Header names worth surfacing to the hunter: auth material, tenancy, and the
# request-routing headers that enable host-header / SSRF / method-override tricks.
INTERESTING_HEADERS = {
    "authorization": "auth material in transit",
    "x-api-key": "API key header",
    "x-auth-token": "auth token header",
    "x-access-token": "access token header",
    "x-csrf-token": "CSRF token header",
    "x-xsrf-token": "CSRF token header",
    "x-tenant-id": "tenant scoping (IDOR / tenant-isolation surface)",
    "x-tenant": "tenant scoping (IDOR / tenant-isolation surface)",
    "x-account-id": "account scoping (IDOR surface)",
    "x-org-id": "org scoping (IDOR surface)",
    "x-organization-id": "org scoping (IDOR surface)",
    "x-user-id": "user scoping (IDOR surface)",
    "x-forwarded-for": "client-IP spoof / ACL bypass surface",
    "x-forwarded-host": "host-header injection surface",
    "x-original-url": "URL-override routing surface",
    "x-rewrite-url": "URL-override routing surface",
    "x-override-url": "URL-override routing surface",
    "x-http-method-override": "HTTP method-override surface",
    "x-real-ip": "client-IP spoof surface",
    "x-debug": "debug toggle header",
    "x-debug-mode": "debug toggle header",
}

# A quoted object key immediately followed by a colon.
_QUOTED_KEY = re.compile(r"""['"]([A-Za-z][A-Za-z0-9_-]{1,60})['"]\s*:""")
# `headers:` / `headers =` / setHeaders / new Headers({...}) block openers.
_HEADERS_OPEN = re.compile(r"""(?:headers|setHeaders)\s*[:=]\s*\{|new\s+Headers\s*\(\s*\{""", re.I)


def is_header(name: str) -> bool:
    n = name.strip().lower()
    return (n in STANDARD_HEADERS
            or n in INTERESTING_HEADERS
            or n.startswith(("x-", "sec-", "access-control-")))


def _matching_brace(js: str, open_idx: int) -> int:
    depth = 0
    quote = ""
    i = open_idx
    n = len(js)
    while i < n:
        c = js[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(js)


def find_header_keys(js: str) -> set:
    """
    Collect header names declared in `headers: { ... }` / `new Headers({...})`
    blocks. Every quoted key inside such a block is a header regardless of how
    it is spelled, which is what lets us keep X-Accept, Content-Type, custom
    x-* names, etc. out of the parameter results.
    """
    found = set()
    for m in _HEADERS_OPEN.finditer(js):
        brace = js.find("{", m.start())
        if brace == -1:
            continue
        end = _matching_brace(js, brace)
        block = js[brace:end]
        for km in _QUOTED_KEY.finditer(block):
            found.add(km.group(1).lower())
    return found


def find_interesting_headers(js: str) -> set:
    """Return (header, why) pairs for security-relevant headers seen anywhere."""
    keys = find_header_keys(js)
    # Also catch interesting headers referenced outside an obvious block, e.g.
    # req.setRequestHeader('X-Api-Key', ...) or 'x-tenant-id': tok elsewhere.
    for m in _QUOTED_KEY.finditer(js):
        name = m.group(1).lower()
        if name in INTERESTING_HEADERS:
            keys.add(name)
    return {(h, INTERESTING_HEADERS[h]) for h in keys if h in INTERESTING_HEADERS}
