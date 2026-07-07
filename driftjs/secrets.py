import re

_RULES = [
    ("AWS Access Key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("Firebase Database", re.compile(r"\bhttps://[a-z0-9-]+\.firebaseio\.com\b", re.I)),
    ("Firebase API Key", re.compile(r"\bapiKey['\"]?\s*[:=]\s*['\"]AIza[0-9A-Za-z\-_]{35}['\"]")),
    ("Stripe Live Key", re.compile(r"\b(sk|pk)_live_[0-9A-Za-z]{24,}\b")),
    ("Stripe Test Key", re.compile(r"\b(sk|pk)_test_[0-9A-Za-z]{24,}\b")),
    ("Algolia API Key", re.compile(r"\balgolia[._-]?api[._-]?key['\"]?\s*[:=]\s*['\"][0-9a-f]{32}['\"]", re.I)),
    ("Mapbox Token", re.compile(r"\bpk\.eyJ[0-9A-Za-z\-_]+\.[0-9A-Za-z\-_]+\b")),
    ("Sentry DSN", re.compile(r"\bhttps://[0-9a-f]{32}@[0-9a-z.-]+/[0-9]+\b", re.I)),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_/]+")),
    ("GitHub Token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")),
    ("Twilio SID", re.compile(r"\bAC[0-9a-f]{32}\b")),
    ("SendGrid Key", re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b")),
    ("JWT", re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b")),
    ("Private Key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Cloudinary URL", re.compile(r"\bcloudinary://[0-9]{15}:[0-9A-Za-z\-_]+@[0-9A-Za-z]+\b")),
    ("Basic Auth in URL", re.compile(r"\bhttps?://[^\s:@/]+:[^\s:@/]+@[^\s/]+", re.I)),
    ("Heroku API Key", re.compile(r"\bheroku['\"]?\s*[:=]\s*['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", re.I)),
    ("Mailgun Key", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("PayPal/Braintree Token", re.compile(r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b")),
    ("Square Token", re.compile(r"\b(sq0atp|sq0csp)-[0-9A-Za-z\-_]{22,}\b")),
    ("Shopify Token", re.compile(r"\bshp(at|ca|pa|ss)_[0-9a-fA-F]{32}\b")),
    ("GitLab Token", re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b")),
    ("npm Token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    ("Facebook Access Token", re.compile(r"\bEAACEdEose0cBA[0-9A-Za-z]+\b")),
    ("Datadog API Key", re.compile(r"\bdd[a-z]?_[0-9a-f]{32}\b", re.I)),
    ("Segment Write Key", re.compile(r"\bsegment[._-]?write[._-]?key['\"]?\s*[:=]\s*['\"][0-9A-Za-z]{32}['\"]", re.I)),
    ("OpenAI Key", re.compile(r"\bsk-(proj-)?[0-9A-Za-z_-]{20,}T3BlbkFJ[0-9A-Za-z_-]{20,}\b")),
    ("Anthropic Key", re.compile(r"\bsk-ant-[0-9A-Za-z_-]{20,}\b")),
    ("Discord Bot Token", re.compile(r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b")),
    ("Discord Webhook", re.compile(r"https://(canary\.|ptb\.)?discord(app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z_-]+")),
    ("Telegram Bot Token", re.compile(r"\b[0-9]{8,10}:AA[0-9A-Za-z_-]{33}\b")),
    ("Cloudflare API Token", re.compile(r"\bcloudflare[._-]?api[._-]?token['\"]?\s*[:=]\s*['\"][0-9A-Za-z_-]{40}['\"]", re.I)),
    ("DigitalOcean Token", re.compile(r"\bdop_v1_[0-9a-f]{64}\b")),
    ("GitHub Fine-grained Token", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    ("Linear API Key", re.compile(r"\blin_api_[0-9A-Za-z]{40}\b")),
    ("Notion Token", re.compile(r"\b(secret_|ntn_)[0-9A-Za-z]{36,}\b")),
    ("Airtable Key", re.compile(r"\b(key[0-9A-Za-z]{14}|pat[0-9A-Za-z]{14}\.[0-9a-f]{64})\b")),
    ("HubSpot Key", re.compile(r"\bpat-(na|eu)1-[0-9a-f-]{36,}\b")),
    ("New Relic Key", re.compile(r"\bNRAK-[0-9A-Z]{27}\b")),
    ("Postmark Token", re.compile(r"\bpostmark[._-]?token['\"]?\s*[:=]\s*['\"][0-9a-f-]{36}['\"]", re.I)),
    ("Dropbox Token", re.compile(r"\bsl\.[0-9A-Za-z_-]{130,}\b")),
    ("Figma Token", re.compile(r"\bfig[dhoru]_[0-9A-Za-z_-]{40,}\b")),
    ("reCAPTCHA Secret", re.compile(r"\b6L[0-9A-Za-z_-]{6}_[0-9A-Za-z_-]{27}\b")),
    ("RapidAPI Key", re.compile(r"\bx-rapidapi-key['\"]?\s*[:=]\s*['\"][0-9A-Za-z]{50}['\"]", re.I)),
    ("Pusher Key", re.compile(r"\bpusher[._-]?(app[._-]?)?secret['\"]?\s*[:=]\s*['\"][0-9a-f]{20}['\"]", re.I)),
    ("Supabase Key", re.compile(r"\bsb(p|s)_[0-9a-f]{40}\b")),
    ("PlanetScale Token", re.compile(r"\bpscale_(tkn|pw)_[0-9A-Za-z_.-]{32,}\b")),
    ("Doppler Token", re.compile(r"\bdp\.(pt|st|ct|sa)\.[0-9A-Za-z]{40,}\b")),
    ("Vercel Token", re.compile(r"\bvercel[._-]?token['\"]?\s*[:=]\s*['\"][0-9A-Za-z]{24}['\"]", re.I)),
    ("Grafana Token", re.compile(r"\bglc_[0-9A-Za-z_+/=]{32,}\b")),
    ("Atlassian Token", re.compile(r"\bATATT3[0-9A-Za-z_=-]{180,}\b")),
    ("Twitch Client Secret", re.compile(r"\btwitch[._-]?client[._-]?secret['\"]?\s*[:=]\s*['\"][0-9a-z]{30}['\"]", re.I)),
    ("Razorpay Key", re.compile(r"\brzp_(live|test)_[0-9A-Za-z]{14}\b")),
]

_PLACEHOLDER = re.compile(r"(?i)(example|xxx+|your[_-]?|placeholder|dummy|test1234|sample|foobar|changeme|<[^>]+>|123456789)")

_GENERIC = re.compile(
    r"""(?ix)
    (api[_-]?key|secret[_-]?key|secret|token|password|passwd|access[_-]?key|
     client[_-]?secret|auth[_-]?token|private[_-]?key)
    ['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-+/=.]{20,100})['"]
    """)

_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def _redact(value):
    v = value.strip().strip("'\"")
    if len(v) <= 10:
        return v[:2] + "*" * (len(v) - 2)
    return f"{v[:6]}...{v[-4:]} ({len(v)} chars)"


def _shannon(s):
    if not s:
        return 0.0
    import math
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


_GENERIC_STOPWORDS = re.compile(
    r"(?i)(a11y|aria|width|height|default|config|enabled|disabled|label|tooltip|"
    r"placeholder|keyword|undefined|function|element|component|onclick|onchange|"
    r"transform|translate|animation|gradient|background|transition)")


def _looks_generic_secret(v):
    if _PLACEHOLDER.search(v) or _GENERIC_STOPWORDS.search(v):
        return False
    if v.startswith("http") or v.count("/") > 1 or v.count(".") > 3:
        return False
    if not (any(c.isdigit() for c in v) and any(c.isalpha() for c in v)):
        return False
    if "_" in v or "-" in v:

        parts = re.split(r"[_-]", v)
        if sum(1 for p in parts if p.isalpha() and len(p) >= 3) >= 2:
            return False
    return _shannon(v) >= 4.2


def _scan_named(text):
    found = set()
    raws = set()
    for line in text.splitlines():
        if len(line) > 8000:
            continue
        for label, rx in _RULES:
            for m in rx.finditer(line):
                raw = m.group(0)
                if _PLACEHOLDER.search(raw):
                    continue
                found.add((label, _redact(raw)))
                raws.add(raw)
    return found, raws


def find_secrets(js):
    out, raws = _scan_named(js)


    for m in _GENERIC.finditer(js):
        val = m.group(2)
        if val in raws or any(val in r for r in raws):
            continue
        if _looks_generic_secret(val):
            out.add(("Generic high-entropy secret", _redact(val)))


    for m in _B64.finditer(js):
        blob = m.group(0)
        if len(blob) > 4000:
            continue
        try:
            import base64
            decoded = base64.b64decode(blob + "===", validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        if not decoded or not decoded.isprintable():
            continue
        nested, _ = _scan_named(decoded)
        for label, red in nested:
            out.add((f"{label} (base64-encoded)", red))

    return out
