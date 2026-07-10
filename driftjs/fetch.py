import gzip
import os
import re
import urllib.request
import zlib
from urllib.parse import urljoin

_SCRIPT_SRC = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.I)
_LINK_TAG = re.compile(r"<link\b[^>]*>", re.I)
_HREF = re.compile(r"""href=['"]([^'"]+)['"]""", re.I)
_DYN_IMPORT = re.compile(r"""import\(\s*['"]([^'"]+?\.m?js(?:\?[^'"]*)?)['"]\s*\)""", re.I)
_UA = "driftjs (recon differ)"
_MAX_BYTES = 8_000_000


def _decode_body(raw, encoding=""):
    enc = (encoding or "").lower()
    if enc == "gzip" or raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    elif enc == "deflate":
        try:
            raw = zlib.decompress(raw)
        except Exception:
            try:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            except Exception:
                pass
    return raw.decode("utf-8", "ignore")


def _get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(_MAX_BYTES)
        enc = r.headers.get("Content-Encoding", "")
    return _decode_body(raw, enc)


def _is_js(u):
    return u.split("?")[0].lower().endswith((".js", ".mjs"))


def _script_urls(page_url, html):
    urls = []
    for src in _SCRIPT_SRC.findall(html):
        urls.append(urljoin(page_url, src))
    for tag in _LINK_TAG.findall(html):
        if "modulepreload" in tag.lower():
            m = _HREF.search(tag)
            if m:
                urls.append(urljoin(page_url, m.group(1)))
    for imp in _DYN_IMPORT.findall(html):
        urls.append(urljoin(page_url, imp))
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def gather_js(target):
    if os.path.exists(target):
        with open(target, "r", encoding="utf-8", errors="ignore") as f:
            return [(target, f.read())]

    if not re.match(r"^https?://", target):
        target = "https://" + target

    if _is_js(target):
        return [(target, _get(target))]

    html = _get(target)
    out = []
    for u in _script_urls(target, html):
        if _is_js(u):
            try:
                out.append((u, _get(u)))
            except Exception:
                continue
    out.append((target + " (inline)", html))
    return out
