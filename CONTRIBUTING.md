# Contributing to Guard Core Rust

Thanks for considering a contribution to Guard Core Rust, part of the Guard ecosystem (guard-core-rs follows the conventions of the Python baseline: guard-core and fastapi-guard).

## Development Setup

Requirements:

- Rust 1.92 (MSRV, what CI gates on) or newer; rustup recommended
- A Python 3 interpreter (the workspace ships the guard-core-python pyo3 bindings crate)

## Build and test (workspace; the guard-core-python bindings crate is excluded, exactly like CI)

```bash
cargo build --workspace --exclude guard-core-python
cargo test --workspace --exclude guard-core-python
```

## Quality Gates

Run before pushing (CI enforces the same checks):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --exclude guard-core-python -- -D warnings
cargo test --workspace --exclude guard-core-python
cargo install cargo-audit --locked && cargo audit
cargo install cargo-deny --locked && cargo deny check
```

The conformance suite (`cargo test -p guard-core-conformance`) pins engine behavior to the detection spec; keep it green.

## Pull Requests

- Every PR closes an open issue ("Delivers issue: #N") or carries the `no-issue` label (chores and dependency bumps).
- Keep the CI green; one clean push per PR is preferred.
- Commit messages: lowercase, imperative, conventional style (`fix(scope): ...`, `feat(scope): ...`, `ci(scope): ...`). No attribution trailers.

## Security

Never open public issues for security vulnerabilities. Follow SECURITY.md and report via GitHub security advisories.

## Questions

Open a GitHub Discussion in this repository or ask in the Guard Discord (#help).
