import json
import urllib.request

_OSV = "https://api.osv.dev/v1/query"
_UA = "driftjs (recon)"

_NPM_NAME = {
    "jQuery": "jquery",
    "lodash": "lodash",
    "AngularJS": "angular",
    "Bootstrap": "bootstrap",
    "Handlebars": "handlebars",
    "Moment.js": "moment",
    "DOMPurify": "dompurify",
}


def _post(url, payload, timeout=20):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "ignore"))


def parse_vulns(resp):
    out = []
    for v in resp.get("vulns", []):
        vid = v.get("id", "")
        aliases = v.get("aliases", []) or []
        cve = next((a for a in aliases if a.startswith("CVE-")), vid)
        summary = (v.get("summary") or v.get("details") or "").strip().split("\n")[0][:140]
        ds = v.get("database_specific") or {}
        sev = ds.get("severity", "") or ""
        out.append((cve, summary, sev))
    return out


def lookup_cves(lib_name, version, timeout=20):
    pkg = _NPM_NAME.get(lib_name)
    if not pkg:
        return []
    resp = _post(_OSV, {"package": {"name": pkg, "ecosystem": "npm"}, "version": version}, timeout)
    return parse_vulns(resp)
