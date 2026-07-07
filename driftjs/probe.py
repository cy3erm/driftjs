import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

_UA = "driftjs (recon)"

_PLACEHOLDER_SAMPLE = {
    "{id}": "1",
    "{uuid}": "00000000-0000-0000-0000-000000000000",
    "{hash}": "0" * 32,
    "{var}": "1",
}


def host_of(url):
    return urlparse(url).netloc.lower()


def in_scope(url, scope):
    h = host_of(url)
    if not h:
        return False
    return any(h == s or h.endswith("." + s) for s in scope)


def _fill_placeholders(path):
    for ph, sample in _PLACEHOLDER_SAMPLE.items():
        path = path.replace(ph, sample)
    return path


def _to_url(endpoint, scheme, host):
    ep = endpoint.split("?")[0]
    if ep.startswith("http"):
        return ep
    if not ep.startswith("/"):
        ep = "/" + ep
    return f"{scheme}://{host}{ep}"


def probe_one(url, timeout=10):
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, method=method, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if e.code in (405, 501) and method == "HEAD":
                continue
            return e.code
        except Exception:
            return None
    return None


def probe(base_url, endpoints, scope, delay=0.5, limit=150):
    scheme = urlparse(base_url).scheme or "https"
    host = host_of(base_url)
    results = []
    probed = 0
    for ep in endpoints:
        url = _to_url(ep, scheme, host)
        if not in_scope(url, scope):
            results.append((ep, url, "skipped (out of scope)"))
            continue
        if probed >= limit:
            results.append((ep, url, "skipped (limit)"))
            continue
        status = probe_one(_fill_placeholders(url))
        results.append((ep, url, status))
        probed += 1
        time.sleep(delay)
    return results


def classify(status):
    if not isinstance(status, int):
        return "other"
    if status in (200, 201, 202, 204):
        return "live"
    if status in (301, 302, 303, 307, 308):
        return "redirect"
    if status in (401, 403):
        return "protected"
    if status == 404:
        return "notfound"
    return "other"
