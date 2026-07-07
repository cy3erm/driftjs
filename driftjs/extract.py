import re
from dataclasses import dataclass, field


_PATH = re.compile(r"""['"`](/(?!/)[a-zA-Z0-9_\-./${}:]{1,120}(?:\?[a-zA-Z0-9_\-=&%.]{0,120})?)['"`]""")

_URL = re.compile(r"""['"`](https?://[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9_\-./${}:]{0,120})?(?:\?[a-zA-Z0-9_\-=&%.]{0,120})?)['"`]""")

_CALL = re.compile(r"""(?:fetch|axios\.\w+|\.(?:get|post|put|patch|delete)|open)\s*\(\s*['"`]([^'"`]{1,200})['"`]""")

_PARAM = re.compile(r"""[?&]([a-zA-Z_][a-zA-Z0-9_]{0,40})=""")
_PARAM_KEY = re.compile(r"""[{,]\s*['"`]?([a-zA-Z_][a-zA-Z0-9_]{1,40})['"`]?\s*:""")

_KEY_STOP = frozenset({
    "children", "classname", "style", "key", "ref", "default", "__typename",
    "type", "props", "state", "context", "width", "height", "margin", "padding",
    "color", "background", "border", "display", "position", "class", "id",
    "onclick", "onchange", "onsubmit", "value", "label", "title", "name",
})


_ASSET = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js|mjs|map|woff2?|ttf|eot|mp[34]|pdf)(\?|$)", re.I)
_STATIC_JSON = re.compile(r"/(manifest|asset-manifest|browserconfig|site\.web)\S*\.json(\?|$)|\.min\.json(\?|$)", re.I)
_NOISE = re.compile(r"^/+$|^//|^/[.*]|[<>^\\]|application/|text/|image/|charset")
_PLACEHOLDER_SEG = re.compile(r"\{(id|var|hash|uuid)\}")


_THIRD_PARTY = re.compile(r"""(?ix)
    doubleclick|googlesyndication|googleadservices|google-analytics|googletagmanager|
    gstatic|googleapis|adsystem|adservice|/adsbygoogle|/pagead|/show_ads|/gen_204|
    facebook\.|fbcdn|connect\.facebook|/fbevents|
    cloudflare|cloudfront|jsdelivr|unpkg|cdnjs|bootstrapcdn|jquery\.com|
    hotjar|mixpanel|segment\.|sentry|newrelic|nr-data|
    twitter\.|x\.com/i/|tiktok|snapchat|criteo|taboola|outbrain|
    recaptcha|gravatar|/slotcar_library
""")


@dataclass
class Extraction:
    endpoints: set = field(default_factory=set)
    params: set = field(default_factory=set)
    secrets: set = field(default_factory=set)
    sinks: set = field(default_factory=set)
    sourcemaps: set = field(default_factory=set)
    cloud: set = field(default_factory=set)
    notable: set = field(default_factory=set)
    weaknesses: set = field(default_factory=set)
    libraries: set = field(default_factory=set)
    comments: set = field(default_factory=set)
    internal_hosts: set = field(default_factory=set)
    websockets: set = field(default_factory=set)
    source_files: set = field(default_factory=set)

    def merge(self, other: "Extraction") -> None:
        self.endpoints |= other.endpoints
        self.params |= other.params
        self.secrets |= other.secrets
        self.sinks |= other.sinks
        self.sourcemaps |= other.sourcemaps
        self.cloud |= other.cloud
        self.notable |= other.notable
        self.weaknesses |= other.weaknesses
        self.libraries |= other.libraries
        self.comments |= other.comments
        self.internal_hosts |= other.internal_hosts
        self.websockets |= other.websockets
        self.source_files |= other.source_files


_SEG_NUM = re.compile(r"/\d+(?=/|$)")
_SEG_UUID = re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", re.I)
_SEG_HASH = re.compile(r"/[0-9a-f]{16,}(?=/|$)", re.I)
_SEG_TMPL = re.compile(r"/\$\{[^}]+\}|/:[a-zA-Z_]+|/\{[^}]+\}")


def _normalize_path(path: str) -> str:
    path = _SEG_TMPL.sub("/{var}", path)
    path = _SEG_UUID.sub("/{uuid}", path)
    path = _SEG_HASH.sub("/{hash}", path)
    path = _SEG_NUM.sub("/{id}", path)
    return path


def _clean_endpoint(e: str) -> tuple[str, set[str]] | None:
    e = e.strip().split("#")[0]
    if not e:
        return None
    if _ASSET.search(e) or _STATIC_JSON.search(e) or _THIRD_PARTY.search(e):
        return None
    path, _, query = e.partition("?")
    params = set(_PARAM.findall("?" + query)) if query else set()


    norm = _normalize_path(path)
    probe = _PLACEHOLDER_SEG.sub("x", norm)
    if _NOISE.search(probe) or "{" in probe or "}" in probe:
        return None

    if not e.startswith("http"):
        segs = [s for s in norm.strip("/").split("/") if s]
        if not segs:
            return None
        if len(segs) == 1 and not re.fullmatch(r"[A-Za-z][A-Za-z0-9._{}-]{2,}", segs[0]):
            return None

    if params:
        norm = f"{norm}?{'&'.join(sorted(params))}"
    return norm, params


def extract(js: str) -> Extraction:
    out = Extraction()
    for rx in (_PATH, _URL, _CALL):
        for m in rx.finditer(js):
            cleaned = _clean_endpoint(m.group(1))
            if cleaned:
                endpoint, params = cleaned
                out.endpoints.add(endpoint)
                out.params |= params
    out.params = {p for p in out.params if not (p.isupper() and len(p) > 6)}


    for m in _PARAM_KEY.finditer(js):
        k = m.group(1)
        if len(k) >= 3 and k.lower() not in _KEY_STOP and re.fullmatch(r"[a-z][a-zA-Z0-9_]{2,}", k):
            out.params.add(k)

    from .secrets import find_secrets
    from .analyze import (find_sinks, find_sourcemaps, find_cloud_assets, find_notable,
                          find_dev_comments, find_internal_hosts, find_websockets)
    from .weaknesses import find_weaknesses
    from .libraries import find_libraries
    out.secrets = find_secrets(js)
    out.sinks = find_sinks(js)
    out.sourcemaps = find_sourcemaps(js)
    out.cloud = find_cloud_assets(js)
    out.notable = find_notable(js)
    out.weaknesses = find_weaknesses(js)
    out.libraries = find_libraries(js)
    out.comments = find_dev_comments(js)
    out.internal_hosts = find_internal_hosts(js)
    out.websockets = find_websockets(js)
    return out
