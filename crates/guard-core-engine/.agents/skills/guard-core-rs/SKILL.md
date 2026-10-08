---
name: guard-core-rs
description: Use when working in the guard-core-rs Rust workspace (github.com/Guard-Core/guard-core-rs): porting Python guard-core detection behavior (spec 4.0.2 sections 04-06) to Rust, editing guard-core-engine compiler/preprocessor/semantic code, running or interpreting the spec 4.0.2 conformance gate, updating conformance/pattern_ledger.toml or conformance/xfail_baseline.toml, extending the PyO3 bindings in guard-core-python, adding criterion benches or libfuzzer targets, or answering status questions about what the Rust port does and does not implement. Covers CI-verified cargo commands, boundary rules (engine has no I/O and no tokio; PyO3 binds detection sections 04-06 only), and honest limitations (no 4.x pattern-table scan stage yet; baseline 39 pass / 124 xfail).
---

# guard-core-rs

Rust port of the guard-core detection engine (spec 4.0.2). Pre-1.0 work in progress: the CPU-bound detection pipeline exists, the 4.x pattern-table scan stage and all I/O layers do not.

## Quick Reference

```bash
cargo fmt --all -- --check                                                # format gate
cargo clippy --workspace --all-targets --exclude guard-core-python -- -D warnings  # lint gate
cargo test --workspace --exclude guard-core-python                        # test gate
cargo test -p guard-core-conformance --test conformance -- --nocapture    # conformance gate
cargo test -p guard-core-conformance --test ledger_integrity -- --nocapture  # ledger integrity
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude guard-core-python --no-deps --all-features
cargo bench -p guard-core-benchmark                                       # criterion
cargo +nightly fuzz run fuzz_preprocess -- -max_total_time=60             # fuzz (nightly)
```

## Installation

Not published in usable form: the facade crate `guard-core-rs` is version 0.0.1 and the project is a work in progress. Clone the repository:

```bash
git clone https://github.com/Guard-Core/guard-core-rs
cd guard-core-rs
```

## Setup

- Toolchain: `rust-toolchain.toml` pins channel `stable` with clippy + rustfmt. Nightly is only needed for libfuzzer. MSRV 1.92, edition 2024.
- No Makefile or justfile: `.github/workflows/ci.yml` and `.pre-commit-config.yaml` are the source of truth for commands. `pre-commit run --all-files` runs fmt, clippy autofix, tests, zizmor, prettier, taplo, and the forbidden-`#[allow]` hook.
- Always exclude `guard-core-python` from workspace-wide cargo commands (see Footguns).

## Workspace Layout

```
crates/
├── guard-core-rs/          # facade crate: re-exports engine modules (public crate name)
├── guard-core-engine/      # detection engine: compiler.rs, preprocessor.rs, semantic/
├── guard-core-python/      # PyO3 bindings (cdylib, Python module guard_core_rs, abi3-py310)
├── guard-core-benchmark/   # criterion benches: compiler, detection_engine, preprocessor, semantic
└── guard-core-conformance/ # conformance runner (on feat/conformance-ledger until merged)
conformance/                # vendored spec 4.0.2 corpus, pattern_ledger.toml, xfail_baseline.toml
fuzz/                       # libfuzzer targets: fuzz_preprocess, fuzz_semantic, fuzz_compiler
```

The engine implements: regex compilation with an LRU `PatternCache` and ReDoS-safety validation, a 7-round preprocessing pipeline (NFKC + lookalikes, URL/HTML/hex/unicode/base64 decoding, SQL comment stripping, attack-region-preserving truncation), and semantic analysis (tokens, entropy, encoding layers, attack probability, obfuscation, threat score).

## Conformance Gate

- Corpus: 163 cases across 11 suites, vendored byte-identical from the Python reference repo at pinned commit, sha256-manifested. Never edit corpus files.
- Pattern ledger: every corpus pattern compiles as-is (47) or has a recorded translation (3); the remaining 20 are residual. A pattern with neither state fails CI.
- xfail baseline: 124 cases baselined with reasons. With zero drift the gate prints `conformance gate: 39 passed, 124 xfail` (163 total).
- Drift is fail-closed: unbaselined failures, stale (now-passing) xfails, and unbaselined not-run cases all fail the gate.
- An engine change that flips a corpus case requires a ledger or xfail update with a written reason in the same change.

## Boundary Rules

- `guard-core-engine`: no I/O, no filesystem at runtime, no tokio, no async runtime, no framework crates. Pure synchronous CPU-bound functions; typed errors, no panics in public APIs.
- `guard-core-python` binds detection sections 04-06 only (detection, content pipeline, suspatterns). It is an embeddable engine, not a guard-core replacement.
- The `guard-core-rs` facade will hold config/pipeline/handlers (sections 02-03, 07-12); today it only re-exports `compiler`, `preprocessor`, `semantic`.
- Adapter crates (tower/axum/actix/rocket-guard-rs) hold all framework glue and no security logic.

## Footguns

- **`--exclude guard-core-python` is mandatory** on workspace clippy/test/doc commands: it is a PyO3 `extension-module` cdylib and the CI jobs skip it (no CI job compiles it today).
- **Positions are Unicode code-point indices, not byte offsets**, in `SuspiciousPattern.position` and binding results; the engine converts internally. Corpus comparisons expect Python `match.start()` semantics.
- **Never edit `conformance/guard-core-spec-4.0.2/`**: vendored byte-identical with a sha256 manifest in `CORPUS.md`.
- **Stale xfails fail the gate**: if you make a baselined case pass, remove it from `xfail_baseline.toml` in the same PR.
- **The pattern-table scan stage does not exist**: the conformance detect equivalent hardcodes `regex_anomaly = 0.0` and relies on semantic analysis. Do not claim regex-threat parity.
- `PatternCache` capacity is clamped to 1..=5000; `compile` always adds `(?im)` flags; `validate_pattern_safety` is a ReDoS-construct deny list, not a formal guarantee.
- Content limits are internal constants (`MAX_CONTENT_LENGTH` 50_000, `MAX_TOKENS` 1000, scan length 10_000); do not assume unbounded input.
- GitHub Actions must stay SHA-pinned (`scripts/pin-actions.sh`); a pre-commit hook forbids outer `#[allow(...)]` outside tests and fuzz.

## Related Projects

- [guard-core](https://github.com/Guard-Core/guard-core): Python reference implementation, spec owner, corpus source.
- [guard-core-go](https://github.com/Guard-Core/guard-core-go): Go port, conformance layout precedent. [guard-core-ts](https://github.com/Guard-Core/guard-core-ts): TypeScript port.
- Adapters (scaffolds): [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs), [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs), [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs), [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs).
- [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) and the other Python framework adapters.
