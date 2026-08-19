#!/bin/sh
# Release acceptance gate. Every dependency comes from a committed lock, the
# generated policy must already be current, and protected-score regressions
# make the command fail.
set -eu
export OTEL_SDK_DISABLED=true

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$repo_dir"
uv lock --check
uv sync --frozen --extra typesec --extra test
uv run python scripts/build_opa_data.py --check
uv run python scripts/build_cerbos_policies.py --check
uv run pytest
uv run agentgym --framework pydantic-ai --mode typesec --check --require-fail-closed
cargo test --locked --manifest-path rust/Cargo.toml
cargo test --locked --manifest-path native/Cargo.toml
uv build --wheel --no-build-isolation
scripts/build_native_wheel.sh dist

# Prove the portable wheel imports its packaged fixtures with neither this
# checkout nor the optional Rust companion on sys.path.
wheel=$(find "$repo_dir/dist" -maxdepth 1 -name 'querygraph_agentgym-*.whl' -print | sort | tail -n 1)
test -n "$wheel"
wheel_env=$(mktemp -d "${TMPDIR:-/tmp}/agentgym-wheel.XXXXXX")
cleanup() {
    case "$wheel_env" in
        "${TMPDIR:-/tmp}/agentgym-wheel."*) rm -rf -- "$wheel_env" ;;
        *) printf '%s\n' "refusing to remove unexpected path: $wheel_env" >&2 ;;
    esac
}
trap cleanup EXIT INT TERM
uv venv --python 3.13 "$wheel_env"
uv pip install --python "$wheel_env/bin/python" "$wheel"
(
    cd "$wheel_env"
    env -u PYTHONPATH "$wheel_env/bin/python" - <<'PY'
import importlib.util

import agentgym.cli
from agentgym.typesec_native import gate
from agentgym.world import WORLD

assert WORLD.policy_digest and WORLD.rbac_grants
assert importlib.util.find_spec("agentgym_native") is None
try:
    gate()
except RuntimeError as error:
    assert "querygraph-agentgym-native" in str(error)
else:
    raise AssertionError("protected mode did not fail without its companion")
PY
    env -u PYTHONPATH "$wheel_env/bin/agentgym" \
        --framework pydantic-ai --mode native --json > native-report.json
    "$wheel_env/bin/python" - <<'PY'
import json

with open("native-report.json") as stream:
    report = json.load(stream)
assert report["scores"][0]["mode"] == "native"
assert report["scores"][0]["utility"] == 100.0
PY
)

uv pip install --python "$wheel_env/bin/python" --no-index \
    --find-links "$repo_dir/dist" 'querygraph-agentgym[typesec]==0.3.0'
(cd "$wheel_env" && env -u PYTHONPATH "$wheel_env/bin/python" -c \
    'from agentgym_native import AgentGymGate; from agentgym.typesec_native import gate; assert isinstance(gate(), AgentGymGate)')

git diff --exit-code -- policy/opa/data.json policy/cerbos/resource_policies \
    uv.lock native/Cargo.lock rust/Cargo.lock
