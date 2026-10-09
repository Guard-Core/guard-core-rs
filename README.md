<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Rust port of the [guard-core](https://github.com/Guard-Core/guard-core) detection engine. The workspace ships two published crates:</strong>
</p>

<p align="center">
    <a href="https://crates.io/crates/guard-core-rs">
        <img src="https://img.shields.io/crates/v/guard-core-rs?color=0080ff" alt="Crates.io version">
    </a>
    <a href="https://guard-core.github.io/guard-core-rs/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-rs/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/guard-core-rs/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-rs/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-core-rs/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-rs/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/guard-core-rs/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-core-rs/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/guard-core-rs/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-rs/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/guard-core-rs/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/guard-core-rs?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Rust-DEA584.svg?style=flat&logo=rust&logoColor=white" alt="Rust">
    <a href="https://crates.io/crates/guard-core-rs">
        <img src="https://img.shields.io/crates/d/guard-core-rs" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/guard-core-rs/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---

## Status

Production port of the Python engine, tracked against guard-core 4.1.x with a conformance corpus (spec 4.1.0, 184 detect cases, zero xfail). Used by the Rust adapters: [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs), [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs), [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs), and [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs).

Docs: https://guard-core.github.io/guard-core-rs/

## Install

```sh
cargo add guard-core-engine
```

Note on registry resolution: the 4.1.0 dists of `guard-core-engine` and `guard-core-rs` are currently yanked on crates.io, so a plain registry install resolves 4.0.4. The 4.1.0 line is restored at the synchronized 4.2.0 train; until then the adapters and CI compile the engine from the sibling checkouts via path dependencies.

## Links

- Python reference: https://github.com/Guard-Core/guard-core
- TypeScript port: https://github.com/Guard-Core/guard-core-ts
- Adapters: [tower](https://github.com/Guard-Core/tower-guard-rs), [axum](https://github.com/Guard-Core/axum-guard-rs), [actix-web](https://github.com/Guard-Core/actix-guard-rs), [rocket](https://github.com/Guard-Core/rocket-guard-rs)
- Telemetry: [guard-agent-rs](https://github.com/Guard-Core/guard-agent-rs)
- Cloud platform: https://app.guard-core.com

## License

Dual-licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.
