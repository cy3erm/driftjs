import argparse
import json as _json
import os
import sys

from .extract import Extraction, extract
from .fetch import gather_js
from .snapshot import diff, load_latest, save_snapshot
from .analyze import interesting_params, interesting_endpoints

DEFAULT_STATE = os.path.expanduser("~/.driftjs")


def _c(s, code):
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s


def _short(label):
    lab = label.split("?")[0]
    if "(inline)" in label:
        return "(inline)"
    base = lab.rstrip("/").split("/")[-1]
    return base or lab


def _key(cat, item):
    if cat == "secrets":
        return item[1]
    if cat == "cloud":
        return item[1]
    if cat == "libraries":
        return f"{item[0]} {item[1]}"
    if cat == "weaknesses":
        return item[1]
    return item


_TRACKED = ["endpoints", "params", "secrets", "cloud", "notable", "weaknesses",
            "sinks", "sourcemaps", "libraries", "comments", "internal_hosts",
            "websockets", "source_files"]


def _record(origins, ex, src):
    for cat in _TRACKED:
        for item in getattr(ex, cat):
            origins.setdefault((cat, _key(cat, item)), set()).add(src)


def _src(origins, cat, item):
    files = origins.get((cat, _key(cat, item)))
    if not files:
        return ""
    files = sorted(files)
    if len(files) == 1:
        return _c(f"  \u2190 {files[0]}", "90")
    return _c(f"  \u2190 {files[0]} +{len(files) - 1}", "90")


def run(target, state_dir, label=None, wayback=False, as_json=False, wordlist=None,
        probe=False, scope=None, probe_delay=0.5, compact=False, maps=False):
    key = label or target
    if not as_json and not compact:
        print(f"[*] gathering JS for {target}")
    try:
        sources = gather_js(target)
    except Exception as e:
        if compact:
            print(_c(f"[-] {target}: unreachable", "90"))
            return None
        sys.exit(f"[!] could not fetch {target}: {e}")

    current = Extraction()
    origins = {}
    for src_label, js in sources:
        ex = extract(js)
        current.merge(ex)
        _record(origins, ex, _short(src_label))

    if maps:
        _recover_maps(sources, current, as_json or compact, origins)

    previous = load_latest(state_dir, key)
    d = diff(previous, current)
    save_snapshot(state_dir, key, current)

    if wordlist:
        _write_wordlist(wordlist, current)

    if as_json:
        _emit_json(target, current, d, origins)
        return None

    if compact:
        hot = interesting_endpoints(current.endpoints)
        flags = []
        if current.secrets:
            flags.append(_c(f"{len(current.secrets)} secret", "31;1"))
        if current.cloud:
            flags.append(_c(f"{len(current.cloud)} cloud", "31"))
        if hot:
            flags.append(_c(f"{len(hot)} interesting", "33"))
        if d.new_endpoints and not d.first_run:
            flags.append(_c(f"{len(d.new_endpoints)} new", "32"))
        tail = ("  " + " · ".join(flags)) if flags else ""
        print(f"[+] {len(current.endpoints)} endpoints{tail}")
        return {"endpoints": len(current.endpoints), "secrets": len(current.secrets),
                "cloud": len(current.cloud), "interesting": len(hot)}

    print(f"[*] {len(sources)} source(s), {len(current.endpoints)} endpoints, "
          f"{len(current.params)} params, {len(current.secrets)} secrets")

    if current.secrets:
        print(_c(f"\n[!] {len(current.secrets)} SECRET(s) in JS:", "31;1"))
        for label_, red in sorted(current.secrets):
            print(_c(f"    ! {label_}: {red}", "31") + _src(origins, "secrets", (label_, red)))

    if current.cloud:
        print(_c(f"\n[!] {len(current.cloud)} cloud asset(s) (check for misconfig/public access):", "31"))
        for label_, ref in sorted(current.cloud):
            print(_c(f"    ! {label_}: {ref}", "31") + _src(origins, "cloud", (label_, ref)))

    if current.notable:
        print(_c(f"\n[*] {len(current.notable)} notable signal(s):", "35;1"))
        for n in sorted(current.notable):
            print(_c(f"    * {n}", "35") + _src(origins, "notable", n))

    if current.weaknesses:
        order = {"high": 0, "medium": 1, "low": 2}
        rows = sorted(current.weaknesses, key=lambda w: order.get(w[0], 3))
        print(_c(f"\n[!] {len(rows)} potential weakness(es) — leads to verify, not confirmed bugs:", "31;1"))
        color = {"high": "31;1", "medium": "33", "low": "90"}
        for sev, label in rows:
            print(_c(f"    [{sev.upper()}] {label}", color.get(sev, "37")) + _src(origins, "weaknesses", (sev, label)))

    if current.libraries:
        vuln = [x for x in current.libraries if x[2]]
        print(_c(f"\n[*] {len(current.libraries)} library/versions detected:", "36"))
        for name, ver, note in sorted(current.libraries):
            if note:
                print(_c(f"    ! {name} {ver} — {note}", "31;1") + _src(origins, "libraries", (name, ver, note)))
            else:
                print(_c(f"    · {name} {ver}", "36") + _src(origins, "libraries", (name, ver, note)))
        if vuln:
            print(_c(f"    ({len(vuln)} with known-vulnerable version(s))", "31"))

    if current.internal_hosts:
        print(_c(f"\n[*] {len(current.internal_hosts)} internal host/IP(s) referenced:", "33"))
        for h in sorted(current.internal_hosts):
            print(_c(f"    > {h}", "33") + _src(origins, "internal_hosts", h))

    if current.websockets:
        print(_c(f"\n[*] {len(current.websockets)} websocket endpoint(s):", "36"))
        for w in sorted(current.websockets):
            print(_c(f"    ~ {w}", "36") + _src(origins, "websockets", w))

    if current.comments:
        print(_c(f"\n[*] {len(current.comments)} developer comment(s) of interest:", "35"))
        for c in sorted(current.comments)[:25]:
            print(_c(f"    // {c}", "35"))

    hot_e = interesting_endpoints(current.endpoints)
    if hot_e:
        print(_c(f"\n[*] {len(hot_e)} interesting endpoint(s):", "33;1"))
        for e in sorted(hot_e):
            print(_c(f"    > {e}", "33") + _src(origins, "endpoints", e))

    hot_p = interesting_params(current.params)
    if hot_p:
        print(_c("\n[*] interesting param(s): " + ", ".join(sorted(hot_p)), "33"))

    if current.sinks:
        print(_c("\n[*] DOM XSS sink(s) present: " + ", ".join(sorted(current.sinks)), "35"))

    if current.sourcemaps:
        print(_c(f"\n[*] {len(current.sourcemaps)} source map(s) referenced (original source may be recoverable):", "36"))
        for sm in sorted(current.sourcemaps):
            print(_c(f"    ~ {sm}", "36") + _src(origins, "sourcemaps", sm))

    if d.first_run:
        print(_c(f"\n[=] baseline recorded — {d.total_endpoints} endpoints. run again later to see what's new.", "36"))
    else:
        if d.new_endpoints:
            print(_c(f"\n[+] {len(d.new_endpoints)} NEW endpoint(s) since last run:", "32;1"))
            for e in d.new_endpoints:
                print(_c(f"    + {e}", "32"))
        if d.new_secrets:
            print(_c(f"\n[+] {len(d.new_secrets)} NEW secret(s) since last run:", "31;1"))
            for label_, red in d.new_secrets:
                print(_c(f"    + {label_}: {red}", "31"))
        if d.new_params:
            print(_c("\n[+] new param(s): " + ", ".join(d.new_params[:20]), "32"))
        if d.gone_endpoints:
            print(_c(f"\n[-] {len(d.gone_endpoints)} endpoint(s) disappeared:", "90"))
            for e in d.gone_endpoints[:20]:
                print(_c(f"    - {e}", "90"))
        if not (d.new_endpoints or d.new_params or d.new_secrets):
            print("\n[=] no changes since last run.")

    print(f"\n[=] snapshot saved. tracked target: {key}")

    ghosts = []
    if wayback:
        ghosts = _run_wayback(target, current)

    if probe:
        _run_probe(target, current, d, ghosts, scope or [], probe_delay)


def _recover_maps(sources, current, quiet, origins):
    from .sourcemap import recover, clean_source_path
    from .analyze import find_sourcemaps
    recovered_count = 0
    for js_url, js in sources:
        for ref in find_sourcemaps(js):
            try:
                paths, contents = recover(js_url, ref)
            except Exception:
                continue
            for p in paths:
                current.source_files.add(clean_source_path(p))
            for idx, code in enumerate(contents):
                ex = extract(code)
                current.merge(ex)
                origin = clean_source_path(paths[idx]) if idx < len(paths) else _short(js_url) + ".map"
                _record(origins, ex, origin)
                recovered_count += 1
    if not quiet and current.source_files:
        print(_c(f"\n[*] recovered {len(current.source_files)} original source file(s) from source maps"
                 f" ({recovered_count} with full content re-scanned):", "36;1"))
        for p in sorted(current.source_files)[:40]:
            print(_c(f"    ~ {p}", "36"))


def _write_wordlist(path, ex):
    words = set()
    for e in ex.endpoints:
        for seg in e.strip("/").split("/"):
            seg = seg.split("?")[0]
            if seg and "{" not in seg and seg.isascii():
                words.add(seg)
    words |= ex.params
    with open(path, "w") as f:
        f.write("\n".join(sorted(words)) + "\n")
    if sys.stdout.isatty():
        print(_c(f"[=] wrote {len(words)} words to {path}", "36"))


def _emit_json(target, ex, d, origins):
    src_map = {f"{cat}:{val}": sorted(files) for (cat, val), files in origins.items()}
    print(_json.dumps({
        "target": target,
        "endpoints": sorted(ex.endpoints),
        "params": sorted(ex.params),
        "interesting_endpoints": sorted(interesting_endpoints(ex.endpoints)),
        "interesting_params": sorted(interesting_params(ex.params)),
        "secrets": sorted(list(s) for s in ex.secrets),
        "cloud": sorted(list(c) for c in ex.cloud),
        "notable": sorted(ex.notable),
        "weaknesses": sorted(list(w) for w in ex.weaknesses),
        "libraries": sorted(list(x) for x in ex.libraries),
        "comments": sorted(ex.comments),
        "internal_hosts": sorted(ex.internal_hosts),
        "websockets": sorted(ex.websockets),
        "source_files": sorted(ex.source_files),
        "sinks": sorted(ex.sinks),
        "sourcemaps": sorted(ex.sourcemaps),
        "sources": src_map,
        "new_endpoints": d.new_endpoints,
        "new_secrets": [list(s) for s in d.new_secrets],
        "first_run": d.first_run,
    }, indent=2))


def _run_wayback(target, current):
    from urllib.parse import urlparse
    from .wayback import historical_endpoints
    domain = urlparse(target).netloc or target.split("/")[0]
    if not domain or "." not in domain:
        print(_c("\n[!] --wayback needs a domain/URL target (skipped).", "33"))
        return
    print(_c(f"\n[*] pulling archived JS for {domain} from the Wayback Machine...", "36"))
    try:
        hist = historical_endpoints(domain)
    except Exception as e:
        print(_c(f"[!] wayback lookup failed: {e}", "33"))
        return
    ghosts = sorted(hist.endpoints - current.endpoints)
    if ghosts:
        print(_c(f"\n[G] {len(ghosts)} GHOST endpoint(s) — in old builds, gone from current JS:", "35;1"))
        for e in ghosts:
            print(_c(f"    ~ {e}", "35"))
        print(_c("    (these may still respond. test only what you're authorized to.)", "90"))
    else:
        print("\n[=] no ghost endpoints found in archived JS.")
    return ghosts


def _run_probe(target, current, d, ghosts, scope, delay):
    from urllib.parse import urlparse
    from .probe import probe, classify

    host = urlparse(target).netloc
    if not host:
        print(_c("\n[!] --probe needs a URL target with a host (skipped).", "33"))
        return


    allow = set(scope) | {host.lower()}


    candidates = set(interesting_endpoints(current.endpoints))
    candidates |= set(d.new_endpoints)
    candidates |= set(ghosts)
    candidates = sorted(candidates)
    if not candidates:
        print("\n[=] nothing to probe.")
        return

    print(_c(f"\n[!] ACTIVE: probing {len(candidates)} endpoint(s) against {sorted(allow)} "
             f"(HEAD/GET, {delay}s apart). Authorized targets only.", "31;1"))

    results = probe(target, candidates, allow, delay=delay)
    buckets = {"live": [], "redirect": [], "protected": [], "notfound": [], "other": [], "skipped": []}
    for ep, url, status in results:
        if isinstance(status, str):
            buckets["skipped"].append((ep, url, status))
        else:
            buckets[classify(status)].append((ep, url, status))

    def show(name, code, note):
        rows = buckets[name]
        if rows:
            print(_c(f"\n[{note}] {len(rows)} {name}:", code))
            for ep, url, status in rows:
                ghost_tag = "  (ghost!)" if ep in ghosts else ""
                print(_c(f"    {status}  {url}{ghost_tag}", code))

    show("live", "32;1", "+")
    show("redirect", "36", "~")
    show("protected", "33", "*")
    show("other", "90", "?")
    live_ghosts = [r for r in buckets["live"] if r[0] in ghosts]
    if live_ghosts:
        print(_c(f"\n[!!] {len(live_ghosts)} DELETED endpoint(s) still live — high value:", "31;1"))
        for ep, url, status in live_ghosts:
            print(_c(f"    {status}  {url}", "31;1"))


def _scan_targets(targets, args):
    from .banner import print_banner
    many = len(targets) > 1
    if not args.json:
        print_banner()
        if many:
            print(f"[*] scanning {len(targets)} target(s)\n")
    hits = []
    for t in targets:
        if many and not args.json:
            print(_c(f"── {t} " + "─" * max(0, 50 - len(t)), "36"))
        try:
            summary = run(t, args.state, args.label, args.wayback, args.json, args.wordlist,
                          args.probe, args.scope, args.probe_delay, compact=many, maps=args.maps)
        except SystemExit as e:
            if many:
                print(_c(f"[!] {t}: {e}", "33"))
                continue
            raise
        if many and summary:
            hits.append((t, summary))
    if many and not args.json:
        _rollup(hits)


def _rollup(hits):
    print(_c("\n" + "=" * 60, "36"))
    print(_c("ROLLUP", "36;1"))
    with_secrets = [(t, s) for t, s in hits if s["secrets"]]
    with_interesting = [(t, s) for t, s in hits if s["interesting"]]
    if with_secrets:
        print(_c(f"\n[!] {len(with_secrets)} host(s) with secrets:", "31;1"))
        for t, s in with_secrets:
            print(_c(f"    ! {t}  ({s['secrets']} secret(s))", "31"))
    if with_interesting:
        print(_c(f"\n[*] {len(with_interesting)} host(s) with interesting endpoints:", "33"))
        for t, s in with_interesting:
            print(_c(f"    > {t}  ({s['interesting']} interesting)", "33"))
    total_ep = sum(s["endpoints"] for _, s in hits)
    print(f"\n[=] {len(hits)} host(s) scanned, {total_ep} endpoints total.")


def _targets_from_args(args):
    if args.list:
        with open(args.list) as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    t = args.target
    if t and t.startswith("*."):
        from .subdomains import enumerate_subdomains
        domain = t[2:]
        print(_c(f"[*] enumerating subdomains of {domain} via crt.sh...", "36"))
        try:
            subs = enumerate_subdomains(domain)
        except Exception as e:
            sys.exit(f"[!] subdomain enumeration failed: {e}")
        if args.sub_limit:
            subs = subs[:args.sub_limit]
        print(_c(f"[*] {len(subs)} subdomain(s) found\n", "36"))
        return [f"https://{s}" for s in subs]
    return [t]


def main():
    p = argparse.ArgumentParser(prog="driftjs",
                                description="Surface endpoints, secrets, and attack surface from a target's JS, and diff what's new over time.")
    p.add_argument("target", nargs="?", help="page URL, .js URL, *.domain.com for subdomains, or a file path with --local")
    p.add_argument("--local", action="store_true", help="treat target as a local file")
    p.add_argument("--list", metavar="FILE", help="scan many targets from a file (one per line)")
    p.add_argument("--sub-limit", type=int, default=50, help="max subdomains to scan in *.domain mode")
    p.add_argument("--wayback", action="store_true",
                   help="also pull archived JS and surface endpoints gone from the current build")
    p.add_argument("--maps", action="store_true",
                   help="fetch referenced source maps and recover original source (endpoints, secrets, comments)")
    p.add_argument("--json", action="store_true", help="output JSON (for piping into other tools)")
    p.add_argument("--wordlist", metavar="FILE", help="write discovered paths+params to a wordlist file")
    p.add_argument("--probe", action="store_true",
                   help="ACTIVE: send HEAD/GET requests to check which endpoints are live (authorized targets only)")
    p.add_argument("--scope", action="append", default=[], metavar="HOST",
                   help="host allowed for probing (repeatable); the target host is always in scope")
    p.add_argument("--probe-delay", type=float, default=0.5, help="seconds between probe requests")
    p.add_argument("--label", help="name to track this target under (defaults to the target)")
    p.add_argument("--state", default=DEFAULT_STATE, help="where snapshots live")
    p.add_argument("--all", action="store_true",
                   help="turn on all passive features at once (--wayback --maps). does NOT enable --probe, since that sends live requests")
    args = p.parse_args()

    if args.all:
        args.wayback = True
        args.maps = True

    if not args.target and not args.list:
        from .banner import print_banner
        print_banner()
        p.print_help()
        sys.exit(0)

    if args.local:
        from .banner import print_banner
        if not args.json:
            print_banner()
        run(args.target, args.state, args.label, args.wayback, args.json, args.wordlist,
            args.probe, args.scope, args.probe_delay, maps=args.maps)
        return

    targets = _targets_from_args(args)
    _scan_targets(targets, args)


if __name__ == "__main__":
    main()
