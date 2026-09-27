# guard-core-rs

`guard-core-rs` is the Rust port of the
[guard-core](https://github.com/rennf93/guard-core) detection engine: the
framework-agnostic, CPU-bound core of the Guard ecosystem. It is a cargo
workspace that implements the full 4.x detect pipeline (content
preprocessing, the pattern-table scan stage, semantic analysis, and regex
pattern detection) plus the pipeline-side surfaces the adapters consume
(rate limiting, IP bans, geo country rules, cloud provider checks, security
headers, events, responses), with a spec 4.1.0 conformance harness.

The detect stage passes the vendored spec 4.1.0 corpus (184 cases, zero
xfail) and the pipeline gate replays the five spec 4.1.0 pipeline suites
(security headers, CORS, the response-side `process_response` pass with the
behavior-rule engine, the suspicious-activity `400` answer, and the route
`ip_whitelist`/`ip_blacklist` gate included, zero xfail); the remaining
parity gaps are pipeline-side (distributed Redis rate limiting, the
reference-vocabulary event bus) and are listed in the configuration guide's
honesty section rather than hidden.

## What it provides

- Content preprocessing: unicode NFKC normalization with lookalike folding,
  a 7-round decoding pipeline (URL decoding, HTML entities, `\xNN`, `\uNNNN`,
  base64 candidates, SQL comment stripping), null-byte removal, and
  attack-preserving truncation
- Semantic analysis: token extraction, Shannon entropy, encoding layer
  detection, attack probability scoring, obfuscation detection, code
  injection risk, and aggregate threat scoring
- Regex pattern compilation with LRU caching and ReDoS safety validation
- The `detect` pipeline: the spec 4.1.0 `SusPatternsManager.detect`
  equivalent, with reference view passes and scoring semantics
- A conformance harness pinning behavior against the vendored spec 4.1.0
  corpus (184 detect cases across 12 suites, zero baselined xfail)

## Ecosystem position

```text
guard-core (Python)           <- Reference implementation, spec owner
├── guard-core-rs (this repo) <- Rust port: detection engine
│   ├── tower-guard-rs        <- Adapter: tower middleware
│   ├── axum-guard-rs         <- Adapter: axum middleware
│   ├── actix-guard-rs        <- Adapter: actix-web middleware
│   └── rocket-guard-rs       <- Adapter: rocket fairing
├── guard-core-go             <- Go port
└── guard-core-ts             <- TypeScript port
```

The engine is pure, synchronous, and I/O-free: no network, no filesystem, no
tokio, no framework crates. Framework integration happens in the adapter
repositories above; each adapter translates native request content into
engine inputs, runs `detect`, and translates a threat verdict into a native
block response. The `examples/` directory shows that wiring over hyper.

## Crates

| Crate | Purpose |
|---|---|
| `guard-core-rs` | Facade crate (published name): re-exports the engine modules |
| `guard-core-engine` | The detection engine itself |
| `guard-core-python` | PyO3 bindings exposing the detection sections to Python |
| `guard-core-conformance` | Conformance gate, pattern ledger, xfail baseline |
| `guard-core-benchmark` | Criterion benches |

## Installation

The crate is not on crates.io yet. Depend on it via git:

```toml
[dependencies]
guard-core-rs = { git = "https://github.com/rennf93/guard-core-rs" }
```

Requires Rust 1.92 or later (edition 2024).

## Quick start

```rust
use guard_core_rs::detect::{self, DetectConfig};

let config = DetectConfig {
    max_content_length: 10_000,
    max_full_scan_bytes: 262_144,
    preserve_attack_patterns: true,
    semantic_threshold: 0.7,
    threat_score_threshold: 1.0,
};

let verdict = detect::detect("<script>alert(1)</script>", "query_param", &config);
assert!(verdict.is_threat);
```

## Next steps

- [Usage](usage.md) - the detection pipeline, contexts, and verdict shape
- [Configuration](configuration.md) - every `DetectConfig` knob, and what the
  engine does not implement yet
