#!/bin/sh
# One image, several roles: the benchmark matrix, the test suites, and the
# deterministic provider emulators, selected by the first argument.
set -eu

cd /work/adversarial-agents

case "${1:-benchmark}" in
  benchmark)
    shift || true
    exec uv run agentgym "$@"
    ;;
  test)
    uv run pytest
    exec cargo test --manifest-path rust/Cargo.toml
    ;;
  workos)
    exec uv run python -m agentgym.wire.workos_server
    ;;
  arcade)
    exec uv run python -m agentgym.wire.arcade_server
    ;;
  shell)
    exec /bin/bash
    ;;
  *)
    exec "$@"
    ;;
esac
