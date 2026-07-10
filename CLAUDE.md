# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`driftjs` is a bug-bounty recon tool that extracts attack surface (endpoints, secrets, params, cloud assets, source maps, DOM sinks, libraries, internal hosts, websockets) from a target's JavaScript, snapshots it, and **diffs what changed since the last run**. First run is a baseline; every run after surfaces what's new — the untested surface.

Despite the name, this is a **Python** project (3.10+), stdlib only, **zero runtime dependencies**. The `js` refers to what it scans, not what it's written in.

Passive by default (downloads JS a browser could already fetch). The only feature that sends requests to the target is `--probe`, which is opt-in and scope-guarded.

## Commands

```bash
# after ANY edit, always run all three (this is the required gate):
python -m compileall driftjs && python -m pytest -q && python -m pyflakes driftjs

python -m pytest -q tests/test_driftjs.py::test_extracts_basic_endpoints   # single test
python -m driftjs https://target.com    # run without installing
pipx install -e .                   # install as the `driftjs` CLI entry point
```

CI (`.github/workflows/ci.yml`) runs `pyflakes driftjs` then `pytest -q` across Python 3.10/3.11/3.12. Both must pass — **CI fails on any pyflakes output at all**.

## Hard rules (do not violate)

- **Zero runtime dependencies.** Never add a pip package to core — stdlib only.
- **No comments or docstrings.** They get stripped before commit; write self-explanatory code instead.
- **Every new detector needs two tests**: one proving it fires on the real pattern, and one proving it stays **silent** on clean/benign code. Detection must stay low false-positive — no exceptions.
- **Fake credentials in tests are assembled from fragments, never written whole**: `stripe = "sk_" + "live_" + "..."` then f-stringed into the scanned code. Before any commit, `grep -rn '"sk_live_' tests/` must be empty (GitHub push protection blocks whole secrets).
- **Findings are "leads to verify," never "confirmed bugs."** Keep that framing in all output and reports.
- **`--probe` is the only active feature**: opt-in and scope-gated. Never loosen the scope check or make it default-on.
- **Commit messages and PR descriptions never mention AI or tooling.** Keep them clean.

## Architecture

The pipeline is: **fetch JS → extract findings → diff against last snapshot → render**. The orchestration lives in `cli.py:run()`.

**`fetch.py`** — `gather_js(target)` returns a list of `(label, js_source)` pairs. Resolves a page URL to its `<script src>`, `modulepreload`, and dynamic `import()` bundles and downloads each; also handles a direct `.js` URL, a local file path, and appends the page's inline HTML as a pseudo-source. 8 MB cap per file.

**`extract.py`** — the core. `extract(js) -> Extraction`. `Extraction` is a dataclass of ~15 `set` fields (endpoints, params, secrets, sinks, cloud, notable, weaknesses, libraries, comments, internal_hosts, websockets, sourcemaps, source_files, graphql_ops, routes) with a `.merge()`. Endpoint extraction is regex-based (`_PATH`, `_URL`, `_CALL`) followed by heavy **noise filtering** (`_clean_endpoint`): drops static assets, third-party ad/analytics hosts, and junk single-char segments. **Path normalization** collapses IDs/hashes/UUIDs/templates to `{id}`/`{hash}`/`{uuid}`/`{var}` so `/users/1` and `/users/2` are one route — this is what keeps the diff quiet. `extract()` delegates each finding category to a specialized module (below) and assembles the result.

**Detection modules** (each is a `find_*` function returning a set, intentionally small and data-driven — add detections here):
- `secrets.py` — `find_secrets`, ~60 credential patterns plus entropy-based and base64-decoded detection
- `analyze.py` — sinks, sourcemaps, cloud assets, notable signals, dev comments, internal hosts, websockets, plus `interesting_params`/`interesting_endpoints` allowlists used at render time
- `weaknesses.py` — graded (high/medium/low) insecure-pattern leads (DOM XSS chains, `postMessage` w/o origin check, weak crypto, `alg:none`, etc.)
- `libraries.py` — JS library + version fingerprinting and known-vulnerable flags
- `graphql.py` — named GraphQL operations (`query`/`mutation`/`subscription` + PascalCase name); anchored so `db.query()`/`MutationObserver` don't match
- `routes.py` — client-side route paths, **gated behind a router fingerprint** (react-router/vue-router/angular) so nothing is mined from non-router bundles — the key false-positive control
- `headers.py` — distinguishes real HTTP header names from fuzzable params (so headers don't leak in as fake params) and surfaces security-relevant headers as signals
- `explain.py` — `explain(label)` maps a weakness to a plain-English "why it matters" + "how to verify"

**`snapshot.py`** — persistence and diffing. Snapshots are JSON under `~/.driftjs/<sha256(target)[:12]>/`, with `latest.json` plus timestamped history (collision-safe `-N` suffix within the same second). `load_latest` / `save_snapshot` / `diff`. A separate `seen.json` (`load_seen`/`update_seen`) tracks per-endpoint **first-seen** timestamps against a `baseline_ts` anchor — an endpoint is "fresh" only if its first-seen is strictly after the baseline, so nothing is falsely flagged fresh on the first run. The category list `_DIFF_CATS` must stay in sync with `Extraction`'s fields and with the `_TRACKED` list in `cli.py` when adding a new finding category.

**Triage layer** — `rank.py` scores each endpoint by hunt-value (API route, sensitive action, IDOR/redirect/file params) and returns sorted `(score, endpoint, reasons)`; `curl.py` turns the top endpoints into ready-to-fire `curl` PoCs (fills path placeholders, `FUZZ`es params, attaches discovered auth/tenant headers as `$TOKEN`/`FUZZ` placeholders). Both are **non-asserting** — ranking/PoCs are leads, never bug claims, which keeps them false-positive-free by construction. Surfaced via `--rank` / `--curl`; `ranked`/`fresh_endpoints`/`first_seen` are always included in `--json`. `curl.py` reads header names back out of `notable` via the shared `NOTABLE_HEADER_PREFIX` constant in `headers.py` — keep that constant the single source of truth on both the write (`extract.py`) and read (`curl.py`) side.

**Optional/lazy features** (imported lazily inside `cli.py` so the fast path stays dependency-light): `sourcemap.py` (`--maps`, recovers original source and re-scans it), `wayback.py` (`--wayback`, archived "ghost" endpoints), `subdomains.py` (`*.domain.com` via crt.sh), `probe.py` (`--probe`), `cve.py` (`--cve`, live OSV lookup), `report.py` (`--html`), `watch.py` (`--watch`/`--webhook`), `rank.py` (`--rank`), `curl.py` (`--curl`), `banner.py`.

**Source attribution** — `cli.py` maintains an `origins` dict mapping each `(category, key)` finding to the JS file(s) it came from, rendered inline as `← app.abc123.js` and in `--json` as a `sources` map.

## Conventions and gotchas

- **When adding a finding category**, update all of: the `Extraction` dataclass + `merge()` (`extract.py`), `_TRACKED` (`cli.py`), `_DIFF_CATS` and the load/save payloads (`snapshot.py`), the JSON builder `_build_json` and the `_print_since_last` labels (`cli.py`), and add a test.
- Output uses raw ANSI codes via `_c(s, code)`, which no-ops when stdout isn't a TTY — don't hardcode escape sequences elsewhere.
- `--probe` scope safety is load-bearing: it only ever requests the target host plus hosts explicitly added with `--scope`, uses HEAD/GET only, and rate-limits. Do not loosen this.
- Detection modules favor many small, obvious literal entries over cleverness — match that style so entries stay auditable.
- `demo/app.v1.js` and `demo/app.v2.js` are a before/after pair for demonstrating the diff.
- Version is a single source of truth in `driftjs/__init__.py` (`__version__`), read dynamically by `pyproject.toml`.
