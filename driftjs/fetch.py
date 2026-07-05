import os
import re
import urllib.request
from urllib.parse import urljoin

_SCRIPT_SRC = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.I)
_UA = "driftjs (recon differ)"


def _get(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def _script_urls(page_url: str, html: str) -> list[str]:
    urls = []
    for src in _SCRIPT_SRC.findall(html):
        urls.append(urljoin(page_url, src))
    return urls


def gather_js(target: str) -> list[tuple[str, str]]:

    if os.path.exists(target):
        with open(target, "r", encoding="utf-8", errors="ignore") as f:
            return [(target, f.read())]


    if target.split("?")[0].endswith(".js"):
        return [(target, _get(target))]


    html = _get(target)
    out: list[tuple[str, str]] = []
    for u in _script_urls(target, html):
        if u.split("?")[0].endswith(".js"):
            try:
                out.append((u, _get(u)))
            except Exception:
                continue

    out.append((target + " (inline)", html))
    return out
