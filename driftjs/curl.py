from urllib.parse import urlparse

from .headers import NOTABLE_HEADER_PREFIX
from .probe import _fill_placeholders, _to_url


def _placeholder_for(key):
    if "api-key" in key or "apikey" in key:
        return "$API_KEY"
    if "auth" in key or "token" in key:
        return "$TOKEN"
    return "FUZZ"


def headers_from_notable(notable):
    out = []
    seen = set()
    for n in sorted(notable):
        if n.startswith(NOTABLE_HEADER_PREFIX):
            name = n[len(NOTABLE_HEADER_PREFIX):].split(" (")[0].strip()
            key = name.lower()
            if key and key not in seen:
                seen.add(key)
                out.append((name, _placeholder_for(key)))
    auth_signal = any(
        "Bearer token" in n or "Basic auth" in n
        or "localstorage auth" in n.lower() for n in notable
    )
    if auth_signal and "authorization" not in seen:
        out.append(("Authorization", "Bearer $TOKEN"))
    return out


def _fuzz_query(endpoint):
    _, _, query = endpoint.partition("?")
    parts = [p for p in query.split("&") if p]
    if not parts:
        return ""
    return "?" + "&".join(f"{p}=FUZZ" for p in parts)


def curl_for(base_url, endpoint, headers):
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "https"
    host = parsed.netloc
    path = endpoint.partition("?")[0]
    url = _fill_placeholders(_to_url(path, scheme, host)) + _fuzz_query(endpoint)
    lines = [f"curl -s -X GET '{url}'"]
    for name, value in headers:
        lines.append(f"  -H '{name}: {value}'")
    return " \\\n".join(lines)
