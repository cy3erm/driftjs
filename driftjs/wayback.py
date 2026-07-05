import json
import urllib.parse
import urllib.request

from .extract import Extraction, extract

CDX = "http://web.archive.org/cdx/search/cdx"
SNAPSHOT = "http://web.archive.org/web/{ts}id_/{url}"
_UA = "driftjs (recon differ)"


def _get(url: str, timeout: int = 45) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def archived_js_urls(domain: str, limit: int = 40) -> list[tuple[str, str]]:
    q = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "filter": ["statuscode:200", "mimetype:.*javascript.*"],
        "collapse": "urlkey",
        "limit": str(limit * 3),
    }
    cdx_url = f"{CDX}?{urllib.parse.urlencode(q, doseq=True)}"
    raw = ""
    for attempt in range(2):
        try:
            raw = _get(cdx_url, timeout=45)
            break
        except Exception:
            if attempt == 1:
                raise
    rows = json.loads(raw) if raw.strip() else []
    out: list[tuple[str, str]] = []
    for row in rows[1:]:
        ts, original = row[0], row[1]
        mimetype = row[3] if len(row) > 3 else ""
        if original.split("?")[0].endswith(".js") or "javascript" in mimetype:
            out.append((ts, original))
        if len(out) >= limit:
            break
    return out


def fetch_archived(timestamp: str, original: str, timeout: int = 30) -> str:
    return _get(SNAPSHOT.format(ts=timestamp, url=original), timeout)


def historical_endpoints(domain: str, limit: int = 40) -> Extraction:
    ex = Extraction()
    for ts, original in archived_js_urls(domain, limit):
        try:
            ex.merge(extract(fetch_archived(ts, original)))
        except Exception:
            continue
    return ex
