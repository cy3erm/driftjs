# Changelog

All notable changes to driftjs. Versions follow [semantic versioning](https://semver.org/).

## [1.4.0]

### Added
- **GraphQL operation extraction.** Named `query` / `mutation` / `subscription` operations are pulled from bundles (including `gql` template literals). Mutations are highlighted as higher-value surface. Router/DOM lookalikes (`db.query(...)`, `new MutationObserver(...)`) are ignored.
- **Client-side route mining.** React Router / Vue Router / Angular route paths are extracted — including admin routes that are gated only in the browser. Extraction is gated behind a router fingerprint, so route paths are never guessed from non-router bundles.
- Both categories are diffed over time (new operations / new routes since last run), tracked for source attribution, included in `--json`, and rendered in the HTML report.

### Fixed
- Router config keys (`path`, `element`, `loader`, `lazy`, …) no longer leak into the fuzzable-parameter list. A real `?path=` query parameter still surfaces.

## [1.3.0]

### Added
- **`--rank`** — ranks endpoints by likely bug value (API route, sensitive action, IDOR / open-redirect / file params) and shows the reasons. Ordering only; never asserts a bug.
- **`--curl`** — prints ready-to-run curl PoCs for the top-ranked endpoints, filling path placeholders, `FUZZ`-ing params, and attaching discovered auth/tenant headers as `$TOKEN` / `FUZZ` placeholders.
- **First-seen tracking** — interesting endpoints are tagged `(new, seen Nd ago)` once they appear after the baseline, so freshly-shipped (least-tested) surface stands out. Anchored to a per-target baseline so nothing is falsely flagged fresh on the first run.
- `ranked`, `fresh_endpoints`, and `first_seen` are now always present in `--json`.

## [1.2.1]

### Fixed
- Crash when `--wayback` and `--probe` were used together and the Wayback lookup failed or the target had no domain (`set(None)`); the wayback step now always returns a list.
- Header blocks containing a `}` inside a string value were truncated, leaking later header names into the parameter list. The brace matcher is now string-aware.
- History snapshots taken within the same second no longer overwrite each other.
- Gzip/deflate-compressed responses are now decompressed instead of decoding to garbage.
