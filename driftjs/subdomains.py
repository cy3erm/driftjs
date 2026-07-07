import json
import time
import urllib.parse
import urllib.request

_CRT = "https://crt.sh/?q={q}&output=json"
_UA = "driftjs (recon)"


def _get(url, timeout=45):
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def _parse(raw, domain):
    out = set()
    try:
        rows = json.loads(raw)
    except Exception:
        return out
    for row in rows:
        for field in (row.get("name_value", ""), row.get("common_name", "")):
            for name in str(field).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if (name == domain or name.endswith("." + domain)) and "@" not in name and "*" not in name and " " not in name:
                    out.add(name)
    return out


def enumerate_subdomains(domain, timeout=45, retries=2):
    domain = domain.strip().lower().lstrip("*.")
    found = set()
    for q in (f"%.{domain}", domain):
        raw = ""
        for attempt in range(retries):
            try:
                raw = _get(_CRT.format(q=urllib.parse.quote(q)), timeout=timeout)
                break
            except Exception:
                if attempt < retries - 1:
                    time.sleep(2)
        if raw.strip():
            found |= _parse(raw, domain)
    found.add(domain)
    return sorted(found)
