import re

_API = re.compile(r"/(api|graphql|graphiql|rest|internal|gateway|rpc)s?(?:/|$|\?)", re.I)
_VERSION = re.compile(r"/v\d+(?:/|$|\?)", re.I)

_SENSITIVE_VERB = re.compile(
    r"/(admin|internal|transfer|payout|refund|withdraw|delete|remove|export|import|"
    r"upload|invite|approve|grant|revoke|impersonate|sudo|config|password|passwd|"
    r"reset|token|secret|credential|oauth|sso|saml|webhook|billing|payment|charge|"
    r"apikey|api[_-]?key|role|permission|acl|actuator)s?(?:/|$|\?|\{)", re.I)

_ID_PARAM = frozenset({
    "id", "userid", "user_id", "user", "account", "accountid", "account_id",
    "uuid", "guid", "orderid", "order_id", "customerid", "customer_id",
    "invoiceid", "invoice_id", "docid", "fileid", "file_id", "objectid",
    "recordid", "pid", "uid", "gid", "tid", "teamid", "team_id", "orgid", "org_id",
})
_REDIRECTISH = frozenset({
    "redirect", "redirect_uri", "redirecturl", "url", "next", "return", "returnurl",
    "continue", "dest", "destination", "callback", "cb", "goto", "target",
})
_FILEISH = frozenset({
    "file", "path", "template", "filename", "filepath", "document", "doc", "page",
})


def _query_params(endpoint):
    _, _, query = endpoint.partition("?")
    if not query:
        return set()
    return {p for p in query.split("&") if p}


def score_endpoint(endpoint):
    reasons = []
    score = 0
    path = endpoint.partition("?")[0]
    qparams = {p.lower() for p in _query_params(endpoint)}

    if _API.search(path) or _VERSION.search(path):
        score += 2
        reasons.append("API route")

    m = _SENSITIVE_VERB.search(path)
    if m:
        score += 3
        reasons.append(f"sensitive action ({m.group(1).lower()})")

    id_params = sorted(qparams & _ID_PARAM)
    if id_params:
        score += 3
        reasons.append(f"IDOR surface (param {', '.join(id_params)})")
    elif "{id}" in path or "{uuid}" in path:
        score += 2
        reasons.append("IDOR surface (id in path)")

    red = sorted(qparams & _REDIRECTISH)
    if red:
        score += 2
        reasons.append(f"open-redirect/SSRF param ({', '.join(red)})")

    fil = sorted(qparams & _FILEISH)
    if fil:
        score += 2
        reasons.append(f"path/file param ({', '.join(fil)})")

    return score, reasons


def rank_endpoints(endpoints):
    ranked = []
    for e in endpoints:
        score, reasons = score_endpoint(e)
        if score > 0:
            ranked.append((score, e, reasons))
    ranked.sort(key=lambda r: (-r[0], r[1]))
    return ranked


def age_str(seconds):
    if seconds < 0:
        seconds = 0
    if seconds < 3600:
        return f"{max(1, seconds // 60)}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"
