# Conformance

Normative conformance harness for [guard-core-rs](https://github.com/rennf93/guard-core-rs)
against the guard-core spec 4.1.0 fixture corpus. Mirrors the Go port layout
(`guard-core-go/conformance/`): the corpus is vendored byte-identical and a
native runner compares each case per the rules in `specs/fixtures/README.md`
of the reference repo.

## Layout

```
conformance/
├── README.md                      this file: knob mapping, drift semantics
├── pattern_ledger.toml            pattern translation ledger (as_is / translated / residual)
├── xfail_baseline.toml            honest expected-fail manifest for the current engine
└── guard-core-spec-4.1.0/
    ├── CORPUS.md                  vendored corpus provenance + sha256 manifest
    └── cases/                     byte-identical copy of guard-core specs/fixtures/cases/
        ├── index.json
        └── (12 suite files, 184 cases, 0 baselined xfails)
```

Runner code lives in the `guard-core-conformance` workspace crate
(`crates/guard-core-conformance/`); the vendored corpus and manifests stay
here so the paths match the Go port precedent.

## Running

```bash
cargo test -p guard-core-conformance --test conformance -- --nocapture   # conformance gate
cargo test -p guard-core-conformance --test ledger_integrity -- --nocapture  # ledger integrity
```

## Runner semantics

1. Loads `cases/index.json` and aborts unless `spec_version == 4.1.0`
   (suite files are also checked against the index version and case counts).
2. Runs every case through the Rust detect equivalent under the recorded
   `config_knobs` (see mapping below), with the index `fixed_ip`
   (`203.0.113.7`; the detect stage does not use IP data).
3. Compares `is_threat`, `threat_score` (6-decimal floats), `original_length`,
   `processed_length` (code-point counts, mandatory), `detection_method`, and
   `threats` as an order-insensitive multiset keyed on the canonical entry
   content. `execution_time` is dropped recursively before comparing.

Threat `position` fields (`suspicious_patterns` entries) are compared natively
against corpus expectations: they are Unicode code-point indices into the
analyzed content, matching the Python reference (`semantic.py` emits
`match.start()` on the processed `str`). The engine finds matches on bytes
internally and converts byte offsets to code-point indices at its result
boundary (`SuspiciousPattern.position`), so the runner performs no conversion
of its own.

### Detect equivalent (current engine state)

The Rust engine currently ports preprocessing (`preprocessor`), regex
compilation (`compiler`), and semantic analysis (`semantic`); the 4.x
pattern-table scan stages (processed / raw / decoded-path-traversal /
url-decoded / short-base64 views) have no Rust counterpart yet. The detect
equivalent therefore runs:

1. `preprocessor::preprocess(content, max_truncate_bytes, preserve_attack_patterns)`
2. `semantic::analyze` on the processed content sliced to `max_content_length`
   code points (mirrors the reference: semantic analysis runs on the processed
   content, raw content only feeds the binary check, which is not ported yet)
3. semantic threats emitted exactly like the reference: per attack type with
   `probability >= semantic_threshold` while `score > semantic_threshold`, else
   the `suspicious` fallback carrying `threat_score`
4. `is_threat = regex_anomaly >= threat_score_threshold || semantic threats
   non-empty`, with `regex_anomaly = 0.0` while the pattern stage is absent
5. `detection_method = "enhanced"`, lengths as code-point counts

### Config knob mapping

| Corpus knob | Recorded | Rust mapping |
|---|---|---|
| `detection_max_content_length` | 10000 | semantic-analysis slice budget (code points) |
| `detection_max_body_inspect_bytes` | 262144 | `preprocess` truncation budget (the reference truncates at this limit, not at `max_content_length`) |
| `detection_preserve_attack_patterns` | true | `preprocess` attack-region-preserving truncation flag |
| `detection_semantic_threshold` | 0.7 | semantic threat gate and per-type probability gate |
| `detection_threat_score_threshold` | 1.0 | `is_threat` regex-anomaly threshold (honored in the formula; regex stage currently contributes 0.0) |
| `detection_compiler_timeout` | 2.0 | unmapped: the `regex` crate is finite-automata based, no per-scan timeout exists |
| `detection_max_tracked_patterns` | 1000 | unmapped: closest counterpart is `PatternCache` LRU capacity, but the detect path compiles no tracked patterns yet |
| `detection_anomaly_threshold` | 3.0 | unmapped: `PerformanceMonitor` is not ported |
| `detection_slow_pattern_threshold` | 0.1 | unmapped: `PerformanceMonitor` is not ported |
| `detection_monitor_history_size` | 1000 | unmapped: `PerformanceMonitor` is not ported |
| `detection_anomaly_emission_cooldown` | 60.0 | unmapped: `PerformanceMonitor` is not ported |
| `detection_min_samples_for_anomaly` | 30 | unmapped: `PerformanceMonitor` is not ported |

Missing or mistyped mappable knobs abort the runner. Unmapped knobs are
reported in `Knobs::unmapped` with reasons (see `src/knobs.rs`).

### Expected-fail baseline and drift semantics

The engine is behind the 4.x reference, so `xfail_baseline.toml` records the
failing case ids honestly (generated from a real run, never hand-written
expectations). The gate is fail-closed:

- failing case **not** in the baseline: gate fails (unbaselined failure, includes regressions of previously-passing cases)
- baselined case that **passes**: gate fails (stale baseline; remove the entry)
- failing case **in** the baseline: tolerated as `xfail`
- executed case set must cover the corpus: a not-run, unbaselined case fails the gate

The four-way report (`passed / failed / xfail / not_run`) is printed per suite
with case ids under `--nocapture`. Fail-closed drift evaluation is unit-tested
in `src/report.rs` with synthetic results; normative comparison is unit-tested
in `src/compare.rs`.

## Pattern translation ledger

`pattern_ledger.toml` classifies every distinct regex pattern that fires in
the vendored corpus, exactly once, in one of:

- `as_is`: compiles unchanged with the `regex` crate (47 patterns)
- `translated`: recorded, corpus-verified translation (3 patterns, all
  `\Z` -> `\z`, Python's absolute-end anchor); the integrity test reproduces
  the recorded `(match, position)` evidence from the corpus cases. The test
  runs the translated regex directly, so it converts the `regex` crate's byte
  spans to code-point indices when checking recorded positions (the same
  boundary conversion the engine performs)
- `residual`: uses constructs the RE2-family `regex` crate rejects (21
  patterns: lookbehind/lookahead, one backreference). No translation is
  attempted.

`tests/ledger_integrity.rs` enforces full coverage (any corpus pattern missing
from the ledger fails the test), compilation of as-is and translated sources,
corpus verification of translations, and rejection of residual patterns.

**Open decision, deliberately not made here:** whether the engine stays
ledger-only (stdlib `regex`, residuals unmatched) or adds `fancy-regex` for
the residual set. The residual section of the ledger is the decision input;
nothing in this repo depends on either outcome.
