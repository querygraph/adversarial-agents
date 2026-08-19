"""Private control metadata shared by provider clients and emulators."""

from __future__ import annotations

from collections.abc import Mapping

FAULT_HEADER = "X-AgentGym-Fault"
CLEAR_FAULT = "none"


def request_fault(
    headers: Mapping[str, str],
    *,
    default: str | None,
    allowed: frozenset[str],
) -> str | None:
    """Resolve a request-scoped fault without mutating the server emulator.

    Header names are compared case-insensitively because ``urllib`` and the
    stdlib HTTP server are free to normalize their capitalization.
    """
    marker: str | None = None
    present = False
    for key, value in headers.items():
        if key.lower() == FAULT_HEADER.lower():
            marker = value
            present = True
            break
    fault = default if not present else (None if marker == CLEAR_FAULT else marker)
    if fault is not None and fault not in allowed:
        raise ValueError(f"unknown AgentGym fault {fault!r}")
    return fault
