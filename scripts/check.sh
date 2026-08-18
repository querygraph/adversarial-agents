#!/bin/sh
# Acceptance: the in-process matrix, the Rust compile-fail suite, and the
# TypeSec sibling crates. The container-engine modes (opa, cerbos) and the
# HTTP provider emulators are exercised by `docker compose run --rm bench`,
# which needs the Docker network and is not part of this host-only script.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
typesec_dir=$(CDPATH= cd -- "$repo_dir/../typesec" && pwd)

cd "$repo_dir"
uv sync --extra frameworks --extra test
python3 scripts/build_opa_data.py
uv run pytest
uv run agentgym --mode default --json >/dev/null
uv run agentgym --explain >/dev/null
cargo test --manifest-path rust/Cargo.toml
cargo test --manifest-path "$typesec_dir/Cargo.toml" -p typesec-python
cargo test --manifest-path "$typesec_dir/Cargo.toml" -p typesec-integrations
uv build
