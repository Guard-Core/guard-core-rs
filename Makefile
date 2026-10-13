.PHONY: install test lint fix bump-version clean

# Install the workspace (all member crates except the PyO3 bindings,
# which need a Python interpreter and are exercised in CI)
install:
	cargo build --workspace --exclude guard-core-python

# Run the test suite (conformance gate, binary-noise honesty tests, units)
test:
	cargo test --workspace --exclude guard-core-python

# Lint: format check + clippy with warnings denied (mirrors CI)
lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --exclude guard-core-python -- -D warnings
	cargo clippy -p guard-core-python --all-targets --all-features -- -D warnings

# Auto-fix formatting and clippy suggestions where possible
fix:
	cargo fmt --all
	cargo clippy --workspace --all-targets --exclude guard-core-python --fix --allow-dirty

# Bump the version train across all workspace crates:
#   make bump-version VERSION=4.0.5
bump-version:
ifndef VERSION
	$(error VERSION is required. Usage: make bump-version VERSION=x.y.z)
endif
	python3 .github/scripts/bump_version.py $(VERSION)

# Clean build artifacts
clean:
	cargo clean
