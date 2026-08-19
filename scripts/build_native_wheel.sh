#!/bin/sh
# Build the exact Rust companion wheel from this checkout. The native crate
# depends only on published, exact TypeSec components and carries Cargo.lock;
# no sibling repositories or hidden path dependencies are involved.
set -eu

MATURIN_VERSION=1.14.1

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repo_dir/dist"}
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
build_python=$(uv python find 3.13)

uvx --from "maturin==$MATURIN_VERSION" maturin build \
    --locked \
    --release \
    --interpreter "$build_python" \
    --manifest-path "$repo_dir/native/Cargo.toml" \
    --out "$output_dir"

"$build_python" - "$output_dir" <<'PY'
import hashlib
import pathlib
import sys

wheels = sorted(pathlib.Path(sys.argv[1]).glob("querygraph_agentgym_native-0.3.0-*.whl"))
if len(wheels) != 1:
    raise SystemExit(f"expected exactly one native 0.3.0 wheel, found {wheels}")
wheel = wheels[0]
digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
print(f"{digest}  {wheel}")
PY
