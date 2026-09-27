# Usage

## The detect pipeline

`guard_core_rs::detect::detect` is the top-level entry point: the spec 4.1.0
`SusPatternsManager.detect` equivalent. It preprocesses the content, runs the
reference scan views, applies semantic analysis, and scores the result.

```rust
use guard_core_rs::detect::{self, DetectConfig};

let config = DetectConfig {
    max_content_length: 10_000,
    max_full_scan_bytes: 262_144,
    preserve_attack_patterns: true,
    semantic_threshold: 0.7,
    threat_score_threshold: 1.0,
};

let verdict = detect::detect(
    "<script>alert(1)</script>",
    "query_param",
    &config,
);

assert!(verdict.is_threat);
assert!(verdict.threat_score >= config.threat_score_threshold);
```

## Request contexts

The second argument is the request context the content came from. The engine
normalizes it to one of the known contexts and uses it to select the pattern
view filters, mirroring the reference `SusPatternsManager`:

| Context | Typical source |
|---|---|
| `query_param` | A query string parameter value |
| `header` | A request header value |
| `url_path` | The URL path |
| `request_body` | The request body |
| `unknown` | Anything else (relaxes view filtering) |

Scan one content slice per source: adapters pass the path, each query
parameter value, each header value, and the body separately.

## The verdict

`DetectVerdict` carries the full result:

| Field | Meaning |
|---|---|
| `is_threat` | `sum(regex weights) >= threat_score_threshold` or any semantic threat |
| `threat_score` | `min(max(regex anomaly, semantic max), 1.0)` when a threat exists, else `0.0` |
| `threats` | One entry per threat: `Threat::Regex(RegexThreat)` or `Threat::Semantic(SemanticThreat)` |
| `original_length` | Code-point length of the input |
| `processed_length` | Code-point length after preprocessing |

Positions in threat payloads are Unicode code-point indices, not byte
offsets, matching Python `str` index semantics.

## Scanning a request (adapter wiring)

The engine has no HTTP dependency. A middleware translates native request
content into engine inputs and turns a threat verdict into a block response:

```rust
fn scan_request(path: &str, query_values: &[String], body: &str, config: &DetectConfig) -> bool {
    if detect::detect(path, "url_path", config).is_threat {
        return true;
    }
    for value in query_values {
        if detect::detect(value, "query_param", config).is_threat {
            return true;
        }
    }
    !body.is_empty() && detect::detect(body, "request_body", config).is_threat
}
```

!!! note
    For production wiring prefer the adapter crates
    ([tower-guard-rs](https://github.com/rennf93/tower-guard-rs),
    axum-guard-rs, actix-guard-rs, rocket-guard-rs): they handle body
    buffering, caps, and response translation. The
    [`examples/`](https://github.com/rennf93/guard-core-rs/tree/master/examples)
    directory shows this wiring over hyper.

## Standalone use of the building blocks

The pipeline stages are public on their own:

```rust
use guard_core_rs::preprocessor;
use guard_core_rs::semantic::{self, AttackKeywords, AttackStructures};

let clean = preprocessor::preprocess("<scr\u{200B}ipt>alert(1)</script>", 10_000, true);
let analysis = semantic::analyze(&clean, &AttackKeywords::default(), &AttackStructures::default());
let score = semantic::get_threat_score(&analysis);
```

`compiler` adds regex compilation with an LRU pattern cache and
`validate_pattern_safety` (a ReDoS-construct deny list); the `regex` crate is
RE2-like and linear-time, so catastrophic backtracking is structurally absent.

## Conformance

The `guard-core-conformance` crate runs the vendored spec 4.1.0 corpus
through the Rust pipeline and compares `is_threat`, `threat_score`,
lengths, detection method, and the threat multiset:

```sh
cargo test -p guard-core-conformance -- --nocapture
# conformance gate: N passed, N failed, N xfail, N not_run (spec 4.1.0)
```

Drift handling is fail-closed: unbaselined failures and stale xfails both
fail the gate.
