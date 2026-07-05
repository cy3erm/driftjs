import re

INTERESTING_PARAMS = {
    "redirect", "redirect_uri", "redirecturl", "url", "next", "return", "returnurl",
    "continue", "dest", "destination", "callback", "cb", "goto", "target",
    "debug", "test", "admin", "role", "isadmin", "token", "access_token", "key",
    "apikey", "api_key", "auth", "password", "passwd", "secret", "file", "path",
    "template", "id", "user", "userid", "account", "email", "cmd", "exec", "query",
}

_INTERESTING_PATH = re.compile(r"""(?ix)
    /(admin|internal|debug|test|staging|dev|private|secret|graphql|graphiql|
      api/v?\d|actuator|swagger|openapi|api-docs|redoc|rapidoc|\.git|backup|
      upload|download|delete|export|import|config|\.env|env|token|oauth|sso|
      saml|webhook|callback|proxy|health|metrics|debug|status|\.json)
""")

_SINKS = [
    ("innerHTML", re.compile(r"\.innerHTML\s*=")),
    ("outerHTML", re.compile(r"\.outerHTML\s*=")),
    ("document.write", re.compile(r"\bdocument\.write(ln)?\s*\(")),
    ("eval", re.compile(r"\beval\s*\(")),
    ("setTimeout(string)", re.compile(r"\bsetTimeout\s*\(\s*['\"]")),
    ("Function constructor", re.compile(r"\bnew\s+Function\s*\(")),
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML")),
    ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(")),
    ("location assignment", re.compile(r"\blocation\s*(\.href)?\s*=")),
    ("jQuery html()", re.compile(r"\$\([^)]*\)\.html\s*\(")),
    ("postMessage", re.compile(r"\.postMessage\s*\(")),
]

_SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

_CLOUD = [
    ("S3 bucket", re.compile(r"\b[a-z0-9.\-]+\.s3([.-][a-z0-9-]+)?\.amazonaws\.com\b", re.I)),
    ("S3 bucket", re.compile(r"\bs3://[a-z0-9.\-]{3,}\b", re.I)),
    ("S3 bucket", re.compile(r"(?<![a-z0-9.\-])s3([.-][a-z0-9-]+)?\.amazonaws\.com/[a-z0-9.\-]{3,}", re.I)),
    ("GCS bucket", re.compile(r"\bstorage\.googleapis\.com/[a-z0-9.\-_]{3,}\b", re.I)),
    ("GCS bucket", re.compile(r"\b[a-z0-9.\-_]+\.storage\.googleapis\.com\b", re.I)),
    ("Azure blob", re.compile(r"\b[a-z0-9]{3,24}\.blob\.core\.windows\.net\b", re.I)),
    ("DigitalOcean Space", re.compile(r"\b[a-z0-9.\-]+\.[a-z0-9-]+\.digitaloceanspaces\.com\b", re.I)),
    ("Firebase Storage", re.compile(r"\b[a-z0-9.\-]+\.firebasestorage\.app\b", re.I)),
]

_NOTABLE = [
    ("Cloud metadata / SSRF target (169.254.169.254)", re.compile(r"\b169\.254\.169\.254\b")),
    ("GCP metadata / SSRF target", re.compile(r"\bmetadata\.google\.internal\b", re.I)),
    ("localhost reference", re.compile(r"https?://(localhost|127\.0\.0\.1)\b", re.I)),
    ("Hardcoded Bearer token", re.compile(r"[Aa]uthorization['\"]?\s*[:=]\s*['\"]Bearer\s+[A-Za-z0-9._\-]{10,}")),
    ("localStorage auth/token access", re.compile(r"(local|session)Storage\.getItem\(\s*['\"][^'\"]*(token|auth|jwt|session|key)", re.I)),
    ("GraphQL introspection query", re.compile(r"__schema|IntrospectionQuery|__type", re.I)),
    ("Basic auth header", re.compile(r"[Aa]uthorization['\"]?\s*[:=]\s*['\"]Basic\s+[A-Za-z0-9+/=]{8,}")),
    ("Debug flag enabled", re.compile(r"\bdebug['\"]?\s*[:=]\s*(true|1)\b", re.I)),
]


def interesting_params(params):
    return {p for p in params if p.lower() in INTERESTING_PARAMS}


def interesting_endpoints(endpoints):
    return {e for e in endpoints if _INTERESTING_PATH.search(e)}


def find_sinks(js):
    out = set()
    for label, rx in _SINKS:
        if rx.search(js):
            out.add(label)
    return out


def find_sourcemaps(js, base=""):
    return {m.group(1).strip() for m in _SOURCEMAP.finditer(js)}


def find_cloud_assets(js):
    out = set()
    for label, rx in _CLOUD:
        for m in rx.finditer(js):
            out.add((label, m.group(0)))
    return out


def find_notable(js):
    out = set()
    for label, rx in _NOTABLE:
        if rx.search(js):
            out.add(label)
    return out


_DEV_COMMENT = re.compile(
    r"""(?ix)
    (?://|/\*|\#)\s*
    ((?:todo|fixme|hack|xxx|bug|note|hardcoded|hard-coded|temporary|temp\s|remove\s|
      do\s+not\s|dont\s|don't\s|insecure|vulnerab|backdoor|debug|test\s+only|
      password|passwd|secret|api[_-]?key|internal\s+only|deprecated)
     [^\n\r*]{0,120})
    """)

_INTERNAL_HOST = re.compile(
    r"""(?ix)
    \b(
      (?:[a-z0-9-]+\.)+
      (?:internal|intranet|corp|staging|prod|preprod)
      (?:\.[a-z]{2,})?
    |
      (?:[a-z0-9-]+\.)+(?:local|lan)\b(?![.\w])
    |
      (?:[a-z0-9-]+\.)+(?:test|dev|qa|uat)\.[a-z]{2,}
    )
    \b
    """)

_METHOD_TAIL = re.compile(r"\.(test|dev)\b\s*[.(]|\bprototype\.|\.bind\b|\.call\b|\.apply\b")

_PRIVATE_IP = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")

_WEBSOCKET = re.compile(r"\bwss?://[a-z0-9.\-]+(?::[0-9]+)?(?:/[^\s'\"<>]*)?", re.I)


def find_dev_comments(js):
    out = set()
    for m in _DEV_COMMENT.finditer(js):
        note = m.group(1).strip().rstrip("*/").strip()
        if 3 <= len(note) <= 130:
            out.add(note)
    return out


def find_internal_hosts(js):
    out = set()
    for m in _INTERNAL_HOST.finditer(js):
        h = m.group(1).lower()
        if h.endswith((".w3.org",)) or "example" in h:
            continue

        tail = js[m.end():m.end() + 8]
        if _METHOD_TAIL.match("." + h.split(".")[-1] + tail) or ".prototype." in h or h.endswith((".bind", ".call", ".apply")):
            continue
        if tail[:1] in ("(", "."):
            continue
        out.add(h)
    for m in _PRIVATE_IP.finditer(js):
        out.add(m.group(1))
    return out


def find_websockets(js):
    return {m.group(0) for m in _WEBSOCKET.finditer(js)}
