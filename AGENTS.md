# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

guard-core-rs is the Rust port of the [guard-core](https://github.com/Guard-Core/guard-core) detection engine: the framework-agnostic, CPU-bound core of the Guard ecosystem. It is a cargo workspace of five crates: the engine implements the full 4.x detect pipeline (pattern compilation, content preprocessing, the pattern-table scan stage, semantic analysis) plus the pipeline-side surfaces the adapters consume (rate limiting, IP bans, geo country rules, cloud provider checks, security headers, the event bus, responses), and the conformance harness pins the detect stage to the vendored spec 4.1.0 corpus. Documented divergences from the Python engine live in the CHANGELOG's "Known differences from Python" section; do not claim full parity beyond what that list and the corpus gate prove.

- **Repository**: https://github.com/Guard-Core/guard-core-rs
- **Language**: Rust, edition 2024, MSRV 1.92
- **License**: MIT OR Apache-2.0
- **Version**: 4.1.0 (all workspace crates; mirrors guard-core 4.1.0)
- **Reference implementation**: guard-core (Python), spec 4.1.0
- **Status**: work in progress. Read [Current Status](#current-status) before writing any code or docs here.

## Ecosystem Position

```
guard-core (Python)           <- Reference implementation, spec owner (specs/01-14), corpus source
├── guard-core-rs (this repo) <- Rust port: detection engine + conformance harness
│   ├── tower-guard-rs        <- Adapter (v1.1.0 on crates.io)
│   ├── axum-guard-rs         <- Adapter (v1.1.0 on crates.io)
│   ├── actix-guard-rs        <- Adapter (v1.1.0 on crates.io)
│   └── rocket-guard-rs       <- Adapter (v1.1.0 on crates.io)
├── guard-core-go             <- Go port (precedent for the conformance layout)
└── guard-core-ts             <- TypeScript port
```

Per `specs/impl/rs.md` in the reference repo, the engine crate serves two consumers:

1. **Native Rust middleware**: the engine behind the four adapter crates (all released at v1.1.0).
2. **Embeddable engine**: PyO3 bindings (`guard-core-python`) exposing the detection sections to Python. The binding surface mirrors only the detection sections (04-06); it is NOT a guard-core replacement and MUST NOT be documented as one.

Ports target **spec 4.1.0**. The conformance corpus is vendored byte-identical from the reference repo with a sha256 manifest, so every behavioral claim can be checked against a pinned, shared fixture set.

## Boundary Rules

- **`guard-core-engine` MUST stay framework-free and I/O-free**: no network, no filesystem access at runtime, no tokio, no async runtime, no framework crates (actix-web, axum, rocket, tower, hyper). Pure, synchronous, CPU-bound functions only.
- **No panics across the FFI boundary or the public API**: engine malfunctions return typed errors; the fail-closed rule of the reference repo's `conformance.md` applies.
- **`guard-core-python` (PyO3) exposes detection sections 04-06 only** (`04-detection`, `05-content-pipeline`, `06-suspatterns` in the reference repo's `specs/`). Handlers, config, Redis, IP intelligence, rate limiting, and responses are out of scope. Publish only in lockstep with the engine crate (PyO3 ABI coupling).
- **`guard-core-rs` (facade crate)** is the home for config (section 02), pipeline (section 03), and handler-side modules (sections 07-12): it re-exports the engine stages (`compiler`, `preprocessor`, `semantic`, `detect`, `detection_exclusions`) and hosts the pipeline-side modules the adapters use (`tower` stage plumbing, `events`, `geo`, `cloud_provider`, `responses`, `headers_auth`, `user_agent`, `redact`, `logging`, `request_limits`).
- **Adapter crates wire framework types to the engine and contain no security logic.**
- **Never edit files under `conformance/guard-core-spec-4.1.0/`**: the corpus is vendored byte-identical from the reference repo and protected by a sha256 manifest in `CORPUS.md`. Behavior changes happen in the engine, not the fixtures.

## Current Status

Honest state of the port. Verify rather than trust; numbers below were read from the repo (corpus `index.json`, `conformance/xfail_baseline.toml`, crate sources).

### Implemented (guard-core-engine)

- **`compiler`**: regex compilation with `(?im)` flags, LRU-backed `PatternCache` (capacity clamped to 1..=5000), `validate_pattern_safety` (ReDoS-construct deny list), `batch_compile`. 7 inline tests.
- **`preprocessor`**: NFKC normalization with lookalike folding, whitespace collapsing, null-byte removal, a 7-round decoding pipeline (URL decoding, HTML entities, `\xNN`, `\uNNNN`, base64 candidates behind a printable-ASCII gate, SQL comment stripping), attack-region extraction, attack-preserving truncation. 14 inline tests.
- **`semantic`**: token extraction, Shannon entropy, encoding-layer detection, attack probability scoring, obfuscation detection, code-injection risk, aggregate threat scoring. 14 inline tests.
- **`guard-core-python`**: 10 PyO3 functions (`preprocess`, `normalize_unicode`, `decode_common_encodings`, `analyze`, `get_threat_score`, `calculate_entropy`, `detect_encoding_layers`, `detect_obfuscation`, `validate_pattern_safety`, `batch_threat_scores` with the GIL released). Functions only, no classes.
- **`guard-core-benchmark`**: 4 criterion suites (`compiler`, `detection_engine`, `preprocessor`, `semantic`).
- **CI**: format check, clippy with `-D warnings`, workspace tests, MSRV 1.92 job, `cargo audit`, `cargo deny`, docs build with warnings as errors, libfuzzer smoke, conformance gate.

### Conformance

- Vendored spec 4.1.0 corpus (`conformance/guard-core-spec-4.1.0/`, regenerated at engine 4.3.2, `engine_commit 5895798` per `cases/index.json`): **22 suites, 375 cases**, of which the runner consumes the 13 `kind: detect` suites (**193 cases**, `cost_bodies` included), the 5 `kind: pipeline` suites (35 cases), and `safety_gates` (94 cases); `event_stream` (39) and `redis_interop` (14) are not consumed by the Rust runner yet (no event-bus capture seam, no Redis driver), documented in `conformance/guard-core-spec-4.1.0/CORPUS.md`.
- **Pattern translation ledger** (`conformance/pattern_ledger.toml`): every corpus pattern must compile as-is or have a recorded, corpus-verified translation; anything else fails CI.
- **xfail baseline** (`conformance/xfail_baseline.toml`): **6 baselined cases** (the `safety_gates` cost-verdict class: reference Python-re timing facts, not Rust divergences). The engine runs the full 4.x detect pipeline (pattern table across the scan views) and passes the detect corpus; the gates report **193 passed / 0 xfail** (detect), **35 passed / 0 xfail** (pipeline), and **88 passed / 6 xfail** (safety_gates) with zero drift.
- Drift handling is **fail-closed**: an unbaselined failure fails the gate, a baselined-but-passing (stale) xfail fails the gate, and an unbaselined not-run case fails the gate.

### Not yet implemented

- Config, pipeline, and handler parity gaps versus the reference (opt-in vs default-on stage wiring, `passive_mode`, endpoint/decorator/geo rate-limit tiers, the suspicious-activity response shape, Redis-distributed rate limiting) are recorded here rather than silently absorbed.
- `PerformanceMonitor` and the monitoring knobs (`detection_compiler_timeout`, `detection_anomaly_threshold`, `detection_slow_pattern_threshold`, `detection_monitor_history_size`, `detection_anomaly_emission_cooldown`, `detection_min_samples_for_anomaly`, `detection_max_tracked_patterns`) are recorded as unmapped with reasons in the knob mapping.

## Quick Start

```bash
git clone https://github.com/Guard-Core/guard-core-rs
cd guard-core-rs
cargo build --workspace --exclude guard-core-python
cargo test --workspace --exclude guard-core-python
```

Using the facade crate (from the `guard-core-rs` doctest; API is unstable at 0.0.1):

```rust
use guard_core_rs::preprocessor;
use guard_core_rs::semantic::{self, AttackKeywords, AttackStructures};

let raw = "<scr\u{200B}ipt>alert(1)</script>";
let clean = preprocessor::preprocess(raw, 10_000, true);

let result = semantic::analyze(&clean, &AttackKeywords::default(), &AttackStructures::default());
let score = semantic::get_threat_score(&result);
assert!(score > 0.0);
```

There is no checked-in Python packaging config for `guard-core-python` yet (PyO3 cdylib, `abi3-py310`); it is currently exercised from source, not from a published wheel.

## Development Commands

There is no Makefile or justfile. `.github/workflows/ci.yml` and `.pre-commit-config.yaml` are the source of truth; every command below is copied from them.
```bash
# Documentation site (docs.yml builds strict and deploys on master)
pip install mkdocs-material && mkdocs build --strict

# Example apps (workspace members; see examples/*/README.md for the full smoke assertions)
cargo build -p guard-core-rs-simple-app -p guard-core-rs-advanced-app
docker compose -f examples/simple_app/docker-compose.yml up --build -d --wait
docker compose -f examples/advanced_app/docker-compose.yml up --build -d --wait
```


```bash
# Format check (CI gate)
cargo fmt --all -- --check

# Lint (CI gate; clippy::all is deny, nursery + pedantic are warn)
cargo clippy --workspace --all-targets --exclude guard-core-python -- -D warnings

# Unit + integration tests (CI gate)
cargo test --workspace --exclude guard-core-python

# Conformance gate (spec 4.1.0); prints "conformance gate: N passed, N failed, N xfail, N not_run"
cargo test -p guard-core-conformance --test conformance -- --nocapture

# Ledger integrity: every corpus pattern is as-is, translated, or residual, exactly one state
cargo test -p guard-core-conformance --test ledger_integrity -- --nocapture

# Docs build with warnings as errors (CI gate)
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude guard-core-python --no-deps --all-features

# MSRV check (CI runs this on toolchain 1.92.0)
cargo check --workspace --exclude guard-core-python --all-targets

# Supply-chain (CI gate)
cargo audit
cargo deny check

# Benchmarks (criterion)
cargo bench -p guard-core-benchmark

# Fuzz smoke (requires nightly; three targets: fuzz_preprocess, fuzz_semantic, fuzz_compiler)
cargo +nightly fuzz build
cargo +nightly fuzz run fuzz_preprocess -- -max_total_time=60
```

`guard-core-python` is excluded from the clippy/test/doc jobs because it is a PyO3 `extension-module` cdylib; note that no CI job currently compiles it. Pre-commit (`pre-commit run --all-files`) runs rustfmt, clippy autofix, tests, zizmor, prettier, taplo, and a pygrep hook that forbids outer `#[allow(...)]` attributes outside tests and fuzz code.

## Project Structure

```
guard-core-rs/
├── Cargo.toml                  # workspace: members = ["crates/*", "examples/*"], exclude = ["fuzz"], resolver = "3"
├── Cargo.lock
├── crates/
│   ├── guard-core-rs/          # facade crate (published name): re-exports engine modules
│   ├── guard-core-engine/      # detection engine: compiler.rs, detect.rs, preprocessor.rs, patterns/, semantic/
│   ├── guard-core-python/      # PyO3 bindings (cdylib, Python module name: guard_core_rs)
│   ├── guard-core-benchmark/   # criterion benches (4 suites, harness = false)
│   └── guard-core-conformance/ # conformance runner (gate + ledger integrity tests)
├── examples/
│   ├── simple_app/             # minimal hyper service: guard shim + router (main.rs, Dockerfile, docker-compose.yml, README.md)
│   └── advanced_app/           # env-driven DetectConfig + route-scoped guard strictness (/admin tree)
├── docs/                       # mkdocs-material site sources: index.md, usage.md, configuration.md
├── conformance/                # vendored spec 4.1.0 corpus, pattern_ledger.toml, xfail_baseline.toml
├── fuzz/                       # libfuzzer targets: fuzz_preprocess, fuzz_semantic, fuzz_compiler
├── scripts/                    # pin-actions.sh (pinact), benches/ (Python-vs-Rust comparison)
├── .github/workflows/          # ci.yml, fuzz.yml, live-smoke.yml, docs.yml, ecosystem-gate.yml, release.yml,
│                               # greetings.yml, issue-link.yml, labeler.yml, stale.yml, summary.yml, sync-labels.yml
├── mkdocs.yml                  # mkdocs-material site definition (docs/ sources; site/ is gitignored)
├── rust-toolchain.toml         # channel = stable, components = clippy + rustfmt
├── rustfmt.toml, clippy.toml, deny.toml
└── CHANGELOG.md                # [Unreleased] + "Known differences from Python"
```

## Actions

The workflow set mirrors the engine-class standard (guard-core-go): `ci.yml` (fmt/clippy/test, MSRV, security audit, rustdoc), `fuzz.yml`, `live-smoke.yml` (dockerized compose runs of both example apps with curl assertions of real engine behavior), `docs.yml` (mkdocs-material strict build + gh-deploy to Pages on master), `ecosystem-gate.yml` (matrix over the four Rust adapters, each tested against this engine master via the sibling path-dependency override), `release.yml` (v* tag gate: fmt/clippy/test on stable + MSRV 1.92, conformance gate, tag/version consistency; publishing is manual and owner-gated), plus the community set (`greetings.yml`, `issue-link.yml`, `labeler.yml`, `stale.yml`, `summary.yml`, `sync-labels.yml`). All third-party actions are SHA-pinned.

## Technology Stack

- **Rust**: edition 2024, MSRV 1.92, toolchain channel `stable` with clippy + rustfmt components.
- **Engine dependencies** (workspace-pinned): `regex 1.12.4` (RE2-like, linear time, no backtracking), `lru 0.18.0`, `html-escape 0.2.13`, `percent-encoding 2.3.2`, `unicode-normalization 0.1.25`.
- **Conformance dependencies**: `serde 1.0.228`, `serde_json 1.0.145`, `toml 0.9.11`.
- **Bindings**: `pyo3 0.29.0` with `extension-module` and `abi3-py310` (Python 3.10+ ABI).
- **Benchmarks**: `criterion 0.8.2` (default features off). **Fuzzing**: `libfuzzer-sys 0.4` on nightly.
- **Supply chain**: `cargo-audit`, `cargo-deny` (license allow-list, yanked = deny, unknown sources = deny), SHA-pinned GitHub Actions (via `scripts/pin-actions.sh`).

The RE2-like `regex` crate is a structural advantage: section 04's catastrophic-backtracking class is absent, so the ReDoS arbiter reduces mostly to `validate_pattern_safety`. The cost is that corpus patterns using lookaround or backreferences need ledger translations.

## Testing & Conformance

- **Unit tests**: 55 inline `#[test]` functions (engine: compiler 7, preprocessor 14, semantic 14; conformance: 20), plus 1 doctest in the facade crate. All tests are inline `#[cfg(test)]` modules; there is no shared test-utility crate.
- **Conformance gate**: runs every `kind: detect` corpus case through the full Rust detect pipeline (preprocess, pattern-table scan, semantic analysis under recorded config knobs), compares `is_threat`, `threat_score` (floats rounded to 6 decimals), `original_length` and `processed_length` (code-point counts), `detection_method`, and `threats` as an order-insensitive multiset. `execution_time` is dropped. The authoritative result is the printed line `conformance gate: N passed, N failed, N xfail, N not_run (spec 4.1.0)`.
- **Knob mapping**: 5 detection knobs are mapped (`detection_max_content_length`, `detection_max_body_inspect_bytes`, `detection_preserve_attack_patterns`, `detection_semantic_threshold`, `detection_threat_score_threshold`); 7 are recorded as unmapped with reasons (e.g. `PerformanceMonitor is not ported`).
- **Ledger integrity tests**: full coverage, exactly-one-state per pattern, as-is compilation, translated patterns reproducing corpus evidence, residual rejection.
- **Positions are Unicode code-point indices**, not byte offsets, in all public results and bindings (the engine matches on bytes internally and converts). Keep it that way; the corpus expects Python `match.start()` semantics on `str`.
- **Benchmarks**: `cargo bench -p guard-core-benchmark`; `scripts/benches/bench.py` compares the Rust engine against the Python `guard_core.detection_engine` (recorded results in `scripts/benches/BENCHMARKS.md`).
- **Fuzzing**: three libfuzzer targets feed arbitrary strings into `preprocess`, semantic analysis, and `compile`, asserting no panics.

## Code Quality Standards

- **Lints** (declared per crate in `[lints]`): `unsafe_code = "forbid"`, `clippy::all = "deny"`, `clippy::nursery = "warn"`, `clippy::pedantic = "warn"`. Allowed: `cast_possible_truncation`, `cast_precision_loss`, `missing_errors_doc`, `missing_panics_doc`, `module_name_repetitions`.
- **Formatting**: `rustfmt.toml` sets max width 100, `imports_granularity = "Item"`, `group_imports = "StdExternalCrate"`, doc-comment formatting and comment wrapping on. `clippy.toml` mirrors the thresholds.
- **Docs**: rustdoc warnings are errors in CI (`RUSTDOCFLAGS="-D warnings"`).
- **No outer `#[allow(...)]`** in non-test, non-fuzz code; a pre-commit pygrep hook rejects it.
- **cargo-deny**: licenses limited to MIT, Apache-2.0 (incl. LLVM-exception variant), BSD-3-Clause, ISC, Unicode-3.0, Zlib; yanked crates denied; wildcard versions denied; unknown registries/git sources denied.
- **GitHub Actions are SHA-pinned**; run `scripts/pin-actions.sh` after editing workflows.

## Best Practices

1. **Keep the engine pure**: CPU-bound, synchronous, no I/O, no tokio. If a change needs I/O or async, it belongs in the facade crate or an adapter, behind the boundary rules above.
2. **Run the gates before committing**: fmt, clippy, tests (pre-commit runs them for you). Match the CI commands exactly, including `--exclude guard-core-python`.
3. **Conformance honesty**: an engine change that flips a corpus case must come with a ledger or xfail update and a written reason. Never weaken the gate; it is fail-closed by design (stale xfails fail too).
4. **Never edit the vendored corpus**; behavior changes go in the engine. Re-vendoring is a deliberate act that updates `CORPUS.md` and its sha256 manifest.
5. **Code-point positions, not byte offsets**, in every public result, binding, and comparison.
6. **Keep the CHANGELOG's "Known differences from Python" section current** when introducing a divergence (entropy over bytes, context-window widths, base64 detector breadth, etc.).
7. **Use conventional commits** (`feat:`, `fix:`, `docs:`), matching existing history. No AI attribution in commit messages.
8. **Document status honestly**: this is a 0.0.1 port. Say what exists and what does not; never imply parity with the Python engine.

## Related Projects

- [guard-core](https://github.com/Guard-Core/guard-core): Python reference implementation, spec owner (`specs/01-14`), and conformance corpus source.
- [guard-core-go](https://github.com/Guard-Core/guard-core-go): Go port; precedent for the conformance directory layout.
- [guard-core-ts](https://github.com/Guard-Core/guard-core-ts): TypeScript port.
- [fastapi-guard](https://github.com/Guard-Core/fastapi-guard), flaskapi-guard, djapi-guard, tornadoapi-guard: Python framework adapters.
- Rust adapters (released at v1.1.0): [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs), [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs), [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs), [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs).
