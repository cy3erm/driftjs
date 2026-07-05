
from driftjs.extract import extract, _clean_endpoint
from driftjs.secrets import find_secrets
from driftjs.analyze import interesting_params, interesting_endpoints, find_sinks, find_sourcemaps
from driftjs.snapshot import diff

# assembled so no complete key literal sits in the file (avoids push-protection)
FAKE_STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dcabcd"


# ---- endpoint extraction + normalization ----

def test_extracts_basic_endpoints():
    ex = extract('fetch("/api/v1/users"); axios.get("/admin/login");')
    assert "/api/v1/users" in ex.endpoints
    assert "/admin/login" in ex.endpoints


def test_normalizes_ids_and_hashes():
    ex = extract('fetch("/api/users/123"); fetch("/files/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");')
    assert "/api/users/{id}" in ex.endpoints
    assert any("{hash}" in e for e in ex.endpoints)


def test_rejects_single_char_junk():
    for junk in ["/I", "/v", "/L", "/", "//"]:
        assert _clean_endpoint(junk) is None, f"junk survived: {junk}"


def test_keeps_real_single_segment_routes():
    for good in ["/login", "/graphql", "/api", "/dashboard"]:
        assert _clean_endpoint(good) is not None, f"real route dropped: {good}"


def test_filters_third_party_ads_noise():
    junk = ('fetch("/adsbygoogle"); fetch("/show_ads_impl"); '
            'fetch("https://pagead2.googlesyndication.com/pagead/ping"); '
            'fetch("https://googleads.g.doubleclick.net/x");')
    assert len(extract(junk).endpoints) == 0


def test_strips_query_values_keeps_keys():
    ex = extract('fetch("/search?q=hello&page=1")')
    ep = next(iter(ex.endpoints))
    assert "hello" not in ep and "page" in ep
    assert "q" in ex.params and "page" in ex.params


# ---- secret detection ----

def test_detects_stripe_and_aws():
    s = find_secrets(f'k="{FAKE_STRIPE}"; a="AKIAIOSFODNN7ABCD123"')
    labels = {label for label, _ in s}
    assert "Stripe Live Key" in labels
    assert "AWS Access Key" in labels


def test_secrets_are_redacted():
    s = find_secrets(f'k="{FAKE_STRIPE}"')
    _, redacted = next(iter(s))
    assert "4eC39HqLyjWDarjtT1zdp7dc" not in redacted


def test_placeholder_secrets_ignored():
    assert len(find_secrets('key="AKIAEXAMPLE1234567890"; k2="your-api-key-here"')) == 0


def test_detects_jwt_and_private_key():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456"
    assert any(l == "JWT" for l, _ in find_secrets(f'token="{jwt}"'))
    assert any(l == "Private Key" for l, _ in find_secrets("-----BEGIN RSA PRIVATE KEY-----"))


# ---- interesting classification ----

def test_interesting_params():
    hot = interesting_params({"redirect", "q", "debug", "color", "admin"})
    assert hot == {"redirect", "debug", "admin"}


def test_interesting_endpoints():
    hot = interesting_endpoints({"/api/v1/admin/x", "/home", "/graphql", "/about", "/internal/y"})
    assert "/api/v1/admin/x" in hot and "/graphql" in hot and "/internal/y" in hot
    assert "/home" not in hot and "/about" not in hot


# ---- DOM XSS sinks ----

def test_finds_dom_xss_sinks():
    sinks = find_sinks('el.innerHTML = x; eval(y); document.write(z); node.dangerouslySetInnerHTML = q;')
    assert "innerHTML" in sinks and "eval" in sinks
    assert "document.write" in sinks and "dangerouslySetInnerHTML" in sinks


def test_no_sinks_in_clean_code():
    assert len(find_sinks('const x = 1; function f(){ return x + 1; }')) == 0


# ---- source maps ----

def test_finds_sourcemap():
    sm = find_sourcemaps("//# sourceMappingURL=app.min.js.map\nconst x=1;")
    assert "app.min.js.map" in sm


# ---- diff ----

def test_diff_first_run_and_new():
    a = extract('fetch("/api/v1/a")')
    d1 = diff(None, a)
    assert d1.first_run and "/api/v1/a" in d1.new_endpoints
    b = extract('fetch("/api/v1/a"); fetch("/api/v1/b")')
    d2 = diff(a, b)
    assert d2.new_endpoints == ["/api/v1/b"] and not d2.first_run


def test_diff_ignores_changed_ids():
    a = extract('fetch("/users/1")')
    b = extract('fetch("/users/999")')
    d = diff(a, b)
    assert d.new_endpoints == []


def test_diff_surfaces_new_secret():
    a = extract('const x = 1;')
    b = extract(f'k="{FAKE_STRIPE}"')
    d = diff(a, b)
    assert any(l == "Stripe Live Key" for l, _ in d.new_secrets)


# ---- cloud assets ----

def test_finds_s3_bucket():
    from driftjs.analyze import find_cloud_assets
    c = find_cloud_assets('url = "https://my-app-uploads.s3.amazonaws.com/x.png"')
    assert any(label == "S3 bucket" for label, _ in c)


def test_finds_gcs_and_azure():
    from driftjs.analyze import find_cloud_assets
    c = find_cloud_assets('a="https://storage.googleapis.com/my-bucket/f"; b="https://acct123.blob.core.windows.net/c"')
    labels = {label for label, _ in c}
    assert "GCS bucket" in labels and "Azure blob" in labels


# ---- notable signals ----

def test_finds_ssrf_metadata_hint():
    from driftjs.analyze import find_notable
    n = find_notable('fetch("http://169.254.169.254/latest/meta-data/")')
    assert any("169.254.169.254" in x for x in n)


def test_finds_localstorage_token_access():
    from driftjs.analyze import find_notable
    n = find_notable('const t = localStorage.getItem("authToken");')
    assert any("localStorage" in x for x in n)


def test_finds_graphql_introspection():
    from driftjs.analyze import find_notable
    n = find_notable('const q = "query IntrospectionQuery { __schema { types { name } } }"')
    assert any("introspection" in x.lower() or "GraphQL" in x for x in n)


def test_swagger_endpoint_is_interesting():
    hot = interesting_endpoints({"/swagger/index.html", "/api-docs", "/home"})
    assert "/swagger/index.html" in hot and "/api-docs" in hot and "/home" not in hot


# ---- probing (scope enforcement is safety-critical) ----

def test_probe_scope_enforcement():
    from driftjs.probe import in_scope
    scope = {"target.com"}
    assert in_scope("https://target.com/api", scope)
    assert in_scope("https://sub.target.com/api", scope)      # subdomain in scope
    assert not in_scope("https://evil.com/api", scope)        # different host blocked
    assert not in_scope("https://nottarget.com/api", scope)   # suffix trick blocked


def test_probe_skips_out_of_scope(monkeypatch):
    import driftjs.probe as P
    calls = []
    monkeypatch.setattr(P, "probe_one", lambda url, timeout=10: calls.append(url) or 200)
    results = P.probe("https://target.com", ["/in", "https://evil.com/out"], {"target.com"}, delay=0)
    statuses = {ep: status for ep, url, status in results}
    assert statuses["/in"] == 200
    assert "out of scope" in str(statuses["https://evil.com/out"])
    # evil.com must NOT have been probed
    assert all("evil.com" not in c for c in calls)


def test_probe_fills_placeholders(monkeypatch):
    import driftjs.probe as P
    seen = []
    monkeypatch.setattr(P, "probe_one", lambda url, timeout=10: seen.append(url) or 200)
    P.probe("https://target.com", ["/users/{id}"], {"target.com"}, delay=0)
    assert seen == ["https://target.com/users/1"]   # {id} substituted, not sent literally


def test_probe_classify():
    from driftjs.probe import classify
    assert classify(200) == "live"
    assert classify(302) == "redirect"
    assert classify(403) == "protected"
    assert classify(404) == "notfound"
    assert classify(None) == "other"


# ---- subdomain enumeration (crt.sh) ----

def test_subdomain_parse(monkeypatch):
    import driftjs.subdomains as S
    fake = ('[{"name_value": "api.target.com\\nwww.target.com", "common_name": "target.com"},'
            '{"name_value": "*.staging.target.com", "common_name": "admin.target.com"},'
            '{"name_value": "mail.target.com", "common_name": "other.com"}]')
    monkeypatch.setattr(S, "_get", lambda url, timeout=45: fake)
    subs = S.enumerate_subdomains("target.com")
    assert "api.target.com" in subs and "www.target.com" in subs
    assert "admin.target.com" in subs
    assert "staging.target.com" in subs        # wildcard stripped
    assert "target.com" in subs                # apex included
    assert "other.com" not in subs             # out-of-domain dropped
    assert not any("*" in s for s in subs)


def test_subdomain_handles_empty(monkeypatch):
    import driftjs.subdomains as S
    monkeypatch.setattr(S, "_get", lambda url, timeout=45: "")
    subs = S.enumerate_subdomains("target.com")
    assert subs == ["target.com"]              # graceful: just the apex


# ---- weakness indicators (leads, not confirmed vulns) ----

def test_weaknesses_flag_vuln_patterns():
    from driftjs.weaknesses import find_weaknesses
    vuln = ("window.addEventListener('message', function(e){ handle(e.data); });"
            "el.innerHTML = location.hash;"
            "if (user.isAdmin) { adminPanel(); }"
            "const h = MD5(pw);"
            "const p = obj['__proto__'];")
    labels = " ".join(l for _, l in find_weaknesses(vuln))
    assert "postMessage" in labels
    assert "DOM XSS" in labels
    assert "authorization" in labels
    assert "crypto" in labels
    assert "Prototype" in labels


def test_weaknesses_no_false_positives_on_clean_code():
    from driftjs.weaknesses import find_weaknesses
    clean = ("function add(a,b){return a+b;}"
             "const items = data.map(x => x.name);"
             "fetch('https://api.example.com/u').then(r => r.json());"
             "window.addEventListener('message', function(e){ if(e.origin===T) go(e.data); });"
             "const id = crypto.randomUUID();")
    assert find_weaknesses(clean) == set()


def test_weaknesses_severity_present():
    from driftjs.weaknesses import find_weaknesses
    w = find_weaknesses("el.innerHTML = location.hash;")
    assert all(sev in ("high", "medium", "low") for sev, _ in w)


def test_dom_xss_chain_needs_both_source_and_sink():
    from driftjs.weaknesses import find_weaknesses
    # sink alone, no untrusted source -> no chain flagged
    only_sink = find_weaknesses("el.innerHTML = staticString;")
    assert not any("DOM XSS chain" in l for _, l in only_sink)


# ---- expanded secret detection ----

def test_detects_new_providers():
    from driftjs.secrets import find_secrets
    # keys assembled from fragments so no complete literal sits in the file (push-protection)
    openai = "sk-" + "proj-" + "Xk92mNp4Qr7sT1vWy3zBcD5" + "T3Blbk" + "FJ" + "Xk92mNp4Qr7sT1vWy3zBcD5"
    cases = {
        "OpenAI Key": f'k="{openai}"',
        "DigitalOcean Token": 'k="dop_v1_' + "3f" * 32 + '"',
        "Anthropic Key": 'k="sk-' + 'ant-Xk92mNp4Qr7sT1vWy3zBcD5eF8"',
        "Razorpay Key": 'k="rzp_' + 'live_Xk92mNp4Qr7sT1"',
    }
    for expected, code in cases.items():
        labels = {l for l, _ in find_secrets(code)}
        assert expected in labels, f"missed {expected}"


def test_generic_entropy_catches_unknown_key():
    from driftjs.secrets import find_secrets
    s = find_secrets('const apiKey = "aG9F8kL2mN4pQ7rS9tU1vW3xY5zB6cD8";')
    assert any("Generic" in l for l, _ in s)


def test_generic_entropy_ignores_normal_words():
    from driftjs.secrets import find_secrets
    s = find_secrets('const label = "getUserProfileData"; const btn = "submitButtonElement";')
    assert s == set()


def test_base64_encoded_secret_decoded():
    from driftjs.secrets import find_secrets
    import base64
    enc = base64.b64encode(b"AKIAIOSFODNN7ABCD123").decode()
    labels = {l for l, _ in find_secrets(f'const b = "{enc}";')}
    assert any("base64-encoded" in l for l in labels)


# ---- vulnerable library detection ----

def test_detects_vulnerable_library():
    from driftjs.libraries import find_libraries
    libs = find_libraries("/*! jQuery JavaScript Library v1.7.2 */ lodash-4.17.10.min.js")
    assert any(n == "jQuery" and note for n, v, note in libs)
    assert any(n == "lodash" and note for n, v, note in libs)


def test_modern_library_not_flagged_vulnerable():
    from driftjs.libraries import find_libraries
    libs = find_libraries("jquery-3.7.1.min.js")
    assert all(not note for _, _, note in libs)


# ---- dev comments ----

def test_dev_comments():
    from driftjs.analyze import find_dev_comments
    c = find_dev_comments("// TODO: fix the auth bypass\n// hardcoded password\n/* FIXME insecure */")
    assert any("auth" in x.lower() for x in c)
    assert any("hardcoded" in x.lower() for x in c)


def test_dev_comments_ignore_normal_comments():
    from driftjs.analyze import find_dev_comments
    c = find_dev_comments("// initialize the component\n// render the list")
    assert c == set()


# ---- internal hosts + private IPs ----

def test_internal_hosts_and_private_ips():
    from driftjs.analyze import find_internal_hosts
    h = find_internal_hosts('u="http://api.r1.internal/x"; s="db.staging.corp"; ip="10.0.1.5"; p="192.168.1.1"')
    assert "10.0.1.5" in h and "192.168.1.1" in h
    assert any("internal" in x for x in h)


def test_internal_hosts_ignore_js_method_calls():
    from driftjs.analyze import find_internal_hosts
    # .test() / .prototype.test / .bind are JS, not hostnames
    junk = "if(pattern.test(x)){} regexp.prototype.test.bind(y); a.test(b); t.hostname.test(z)"
    h = find_internal_hosts(junk)
    assert not any(x.endswith(".test") for x in h)


# ---- websockets ----

def test_websockets():
    from driftjs.analyze import find_websockets
    w = find_websockets('new WebSocket("wss://realtime.target.com/socket")')
    assert any("realtime.target.com" in x for x in w)


# ---- source-map recovery ----

def test_sourcemap_parse_and_rescan():
    from driftjs.sourcemap import parse_sourcemap, clean_source_path
    from driftjs.extract import extract
    import json
    stripe = "sk_" + "live_" + "realKeyFromOriginalSource1234abcd"
    sm = json.dumps({
        "version": 3,
        "sources": ["webpack:///src/api/admin.js", "webpack:///src/utils/auth.js"],
        "sourcesContent": [
            'fetch("/api/v1/admin/secretPanel"); // TODO: add authz check',
            f'const STRIPE = "{stripe}";',
        ],
    })
    sources, contents = parse_sourcemap(sm)
    assert clean_source_path(sources[0]) == "src/api/admin.js"
    merged = extract(contents[0])
    merged.merge(extract(contents[1]))
    assert "/api/v1/admin/secretPanel" in merged.endpoints
    assert any("Stripe" in l for l, _ in merged.secrets)
    assert any("authz" in c or "TODO" in c for c in merged.comments)


def test_sourcemap_handles_no_content():
    from driftjs.sourcemap import parse_sourcemap
    import json
    sources, contents = parse_sourcemap(json.dumps({"version": 3, "sources": ["a.js"]}))
    assert sources == ["a.js"] and contents == []


# ---- source attribution ----

def test_source_attribution_tracks_origin_file():
    import driftjs.cli as cli
    from driftjs.extract import extract
    cur = cli.Extraction()
    origins = {}
    for js, lbl in [('fetch("/api/admin/x")', "app.main.js"),
                    ('fetch("/api/v2/graphql")', "app.chunk.js")]:
        ex = extract(js)
        cur.merge(ex)
        cli._record(origins, ex, lbl)
    assert origins[("endpoints", "/api/admin/x")] == {"app.main.js"}
    assert origins[("endpoints", "/api/v2/graphql")] == {"app.chunk.js"}


def test_source_shows_multiple_files():
    import driftjs.cli as cli
    from driftjs.extract import extract
    origins = {}
    for lbl in ["a.js", "b.js"]:
        cli._record(origins, extract('fetch("/shared/api")'), lbl)
    suffix = cli._src(origins, "endpoints", "/shared/api")
    assert "a.js" in suffix and "+1" in suffix
