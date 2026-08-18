#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
typesec_dir=$(CDPATH= cd -- "$repo_dir/../typesec" && pwd)

cd "$repo_dir"
uv sync --extra frameworks --extra test
uv run pytest
uv run agentgym --framework pydantic-ai --mode typesec --json >/dev/null
cargo test --manifest-path rust/Cargo.toml
cargo test --manifest-path "$typesec_dir/Cargo.toml" -p typesec-python
cargo test --manifest-path "$typesec_dir/Cargo.toml" -p typesec-integrations
uv build
