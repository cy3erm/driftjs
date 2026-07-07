import json
import urllib.request
from urllib.parse import urljoin

_UA = "driftjs (recon)"


def _get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def parse_sourcemap(raw):
    data = json.loads(raw)
    sources = data.get("sources", []) or []
    contents = data.get("sourcesContent") or []
    pairs = []
    for i, src in enumerate(sources):
        if not src:
            continue
        content = contents[i] if i < len(contents) else None
        pairs.append((src, content))
    return pairs


def recover(js_url, ref, timeout=20):
    if ref.startswith("data:"):
        return [], []
    map_url = urljoin(js_url, ref)
    raw = _get(map_url, timeout)
    return parse_sourcemap(raw)


def clean_source_path(p):
    p = p.split("?")[0]
    for prefix in ("webpack://", "webpack:///", "webpack-internal:///", "rollup://"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p.lstrip("./")
