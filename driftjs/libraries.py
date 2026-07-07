import re

_LIB_PATTERNS = [
    ("jQuery", re.compile(r"jQuery\s+JavaScript\s+Library\s+v?([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("jQuery", re.compile(r"jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I)),
    ("jQuery", re.compile(r"jquery['\"]?\s*[:=]\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("lodash", re.compile(r"lodash[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I)),
    ("lodash", re.compile(r"lodash\s+([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("AngularJS", re.compile(r"angular\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("AngularJS", re.compile(r"angular[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I)),
    ("Bootstrap", re.compile(r"[Bb]ootstrap\s+v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("Handlebars", re.compile(r"[Hh]andlebars[.-]?v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("Moment.js", re.compile(r"moment[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I)),
    ("DOMPurify", re.compile(r"DOMPurify[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
]


_VULN_BELOW = {
    "jQuery": ("3.5.0", "XSS in htmlPrefilter (CVE-2020-11022/11023)"),
    "lodash": ("4.17.21", "prototype pollution (CVE-2019-10744 and related)"),
    "Bootstrap": ("3.4.1", "XSS in data-target / tooltip (CVE-2019-8331 and related)"),
    "Handlebars": ("4.7.7", "prototype pollution / RCE in older releases"),
    "DOMPurify": ("2.4.2", "sanitizer bypass in older releases"),
}


def _ver_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0,)


def find_libraries(js):
    out = set()
    seen = set()
    for name, rx in _LIB_PATTERNS:
        for m in rx.finditer(js):
            version = m.group(1)
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            note = ""
            if name in _VULN_BELOW:
                threshold, desc = _VULN_BELOW[name]
                if _ver_tuple(version) < _ver_tuple(threshold):
                    note = desc
            out.add((name, version, note))
    return out
