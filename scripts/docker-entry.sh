#!/bin/sh
# One image, several roles: the benchmark matrix, the test suites, and the
# deterministic provider emulators, selected by the first argument. The image
# installs into a plain venv (typesec from a prebuilt wheel), so the venv's
# own entry points are invoked directly rather than through `uv run`, which
# would try to re-sync against the editable typesec source.
set -eu

cd /work/adversarial-agents
VENV=/work/adversarial-agents/.venv/bin

case "${1:-benchmark}" in
  benchmark)
    shift || true
    exec "${VENV}/agentgym" "$@"
    ;;
  test)
    exec "${VENV}/pytest"
    ;;
  workos)
    exec "${VENV}/python" -m agentgym.wire.workos_server
    ;;
  arcade)
    exec "${VENV}/python" -m agentgym.wire.arcade_server
    ;;
  shell)
    exec /bin/bash
    ;;
  *)
    exec "$@"
    ;;
esac
