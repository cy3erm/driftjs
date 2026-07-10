"""
Human explanations for each weakness lead. driftjs is detection-only: these
findings are starting points, so each entry says why the pattern matters and
how to confirm whether it is actually exploitable. Keyed by the exact label
string emitted in weaknesses.find_weaknesses so nothing here changes the
snapshot/diff data shape.
"""

WEAKNESS_INFO = {
    "postMessage handler without origin check (possible DOM XSS / data leak)": {
        "why": "A message listener that never checks event.origin will act on "
               "messages from any site. An attacker page can postMessage into "
               "this window to drive privileged actions or exfiltrate data.",
        "verify": "Find the addEventListener('message', ...) handler and trace "
                  "event.data into a sink or a state change. Host a page that "
                  "frames/opens the target and posts a crafted message.",
    },
    "CORS allows any origin with credentials": {
        "why": "Access-Control-Allow-Origin: * combined with credentials lets "
               "any origin read authenticated responses, leaking user data "
               "cross-site.",
        "verify": "Send a request with an Origin header of your domain and check "
                  "whether the response reflects it in ACAO alongside "
                  "Allow-Credentials: true.",
    },
    "JWT 'alg: none' referenced (possible signature bypass)": {
        "why": "If the server honors the 'none' algorithm, a token's signature "
               "can be stripped and claims forged, bypassing authentication.",
        "verify": "Take a valid token, set the header alg to none, drop the "
                  "signature segment, and replay it against an authenticated "
                  "endpoint.",
    },
    "Prototype pollution sink (__proto__ / constructor.prototype)": {
        "why": "Writing attacker-controlled keys into __proto__ or "
               "constructor.prototype can pollute Object.prototype, corrupting "
               "app logic and sometimes escalating to XSS or RCE.",
        "verify": "Find the merge/clone/query-parse routine and try a key like "
                  "__proto__[polluted]=1, then check whether ({}).polluted is set.",
    },
    "Weak/legacy crypto referenced (MD5/SHA1/DES/RC4)": {
        "why": "MD5/SHA1 are collision-prone and DES/RC4 are broken. Using them "
               "for signing, tokens, or password handling weakens those controls.",
        "verify": "Confirm the algorithm is used in a security context (token, "
                  "signature, password) rather than a non-security checksum.",
    },
    "Client-side authorization logic (bypassable in the browser)": {
        "why": "Role/permission checks like isAdmin performed in the browser can "
               "be flipped by the user. If the server trusts them, access "
               "control is bypassable.",
        "verify": "Toggle the flag in memory or tamper the response, then confirm "
                  "the server still enforces the restriction on the raw API call.",
    },
    "JWT decoded without verification": {
        "why": "jwt.decode without a matching verify reads claims without "
               "checking the signature, so forged tokens may be trusted.",
        "verify": "Check whether the decoded claims drive a trust decision with "
                  "no server-side verify step behind it.",
    },
    "DOM XSS chain: untrusted source flows toward an HTML/JS sink": {
        "why": "A tainted source (location.hash, document.referrer, window.name, "
               "etc.) reaching innerHTML/eval/document.write can execute "
               "attacker-controlled script in the victim's session.",
        "verify": "Trace the specific source into the sink; if no encoding sits "
                  "between them, craft a URL/fragment payload and confirm "
                  "execution.",
    },
    "Math.random() used in a security context (not cryptographically safe)": {
        "why": "Math.random is predictable. Using it for tokens, IDs, OTPs, or "
               "nonces lets an attacker predict or brute-force those values.",
        "verify": "Confirm the random value is used as a secret/identifier, then "
                  "test whether outputs are predictable from observed values.",
    },
    "Insecure http:// URL (mixed content / MITM exposure)": {
        "why": "Loading resources or calling APIs over plain http exposes them to "
               "interception and tampering on the network path.",
        "verify": "Confirm the http URL is a real request (not a namespace/schema "
                  "string) and that no upgrade to https happens before use.",
    },
}


def explain(label: str) -> dict | None:
    return WEAKNESS_INFO.get(label)
