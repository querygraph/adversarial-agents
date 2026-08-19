"""The real Rust/PyO3 TypeSec gate used by AgentGym's protected track."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from .bindings import TOOL_ACTIONS, CallSchemaError, validate_bound_call
from .model import Decision, Principal, ToolCall, canonical_json
from .world import WORLD


def _odrl_translation() -> str:
    """Derive TypeSec's ODRL carrier from the canonical checked-in corpus."""
    source = json.loads(WORLD.odrl_policy)
    permission = source["permission"]
    constraints = permission["constraints"]
    rules = [{
        "type": "permission",
        "assignee": permission["assignee"],
        "action": permission["action"],
        "target": permission["target"],
        "constraints": [{
            "leftOperand": "purpose",
            "operator": "eq",
            "rightOperand": constraints["purpose"],
        }],
    }]
    # The canonical profile names one information-flow prohibition and two
    # prohibited purposes. TypeSec's ODRL carrier has a typed ``exfiltrate``
    # action; the purpose values are already excluded by the positive purpose
    # constraint above. Keep this mapping explicit and reject corpus drift.
    prohibitions = set(source["prohibitions"])
    expected_prohibitions = {"exfiltrate-sensitive", "marketing", "train"}
    if prohibitions != expected_prohibitions:
        raise ValueError("canonical ODRL prohibitions require an updated translation")
    rules.append({
        "type": "prohibition",
        "assignee": permission["assignee"],
        "action": "exfiltrate",
        "target": permission["target"],
    })
    document = {
        "policies": [{
            "uid": source["uid"],
            "type": "Set",
            "rules": rules,
        }],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


@lru_cache(maxsize=1)
def gate() -> Any:
    try:
        from agentgym_native import AgentGymGate
    except (ImportError, ModuleNotFoundError) as exc:
        raise RuntimeError(
            "AgentGym's Rust protected gate is not installed; install the "
            "'typesec' extra or the matching querygraph-agentgym-native wheel"
        ) from exc
    return AgentGymGate(
        WORLD.rbac_policy,
        _odrl_translation(),
        json.dumps(TOOL_ACTIONS, sort_keys=True, separators=(",", ":")),
        "org:civic-lab",
        WORLD.policy_digest,
    )


def gates() -> tuple[Any, Any]:
    """Compatibility tuple: the unified native gate enforces RBAC and ODRL."""
    unified = gate()
    return unified, unified


def check_rust_gate(principal: Principal, call: ToolCall) -> Decision:
    """Require the compiled Rust gate to approve the exact call first.

    The PyO3 AgentGymGate, built on TypeSec's RBAC/ODRL engines, decides tool
    binding and resource presence; for the
    governed catalog read the ODRL engine additionally decides the purpose
    constraint. Both run before any Python-side runtime binding, so an
    unbound tool, a missing resource argument, or a failed ODRL constraint
    is rejected by compiled Rust, not by the Python layer above it.
    """
    try:
        validate_bound_call(call)
    except CallSchemaError as exc:
        return Decision(False, f"closed call schema: {exc}",
                        mechanism="rust-envelope", invariant="closed-schema")
    request_digest = call.digest(principal)
    verdict = gate().check(
        principal.subject,
        call.tool,
        call.action,
        call.resource,
        call.purpose,
        canonical_json(call.envelope(principal)),
        request_digest,
    )
    if not verdict.allowed:
        return Decision(False, f"Rust AgentGymGate: {verdict.reason}",
                        mechanism="rust-typesec-envelope",
                        invariant="exact-envelope-binding",
                        request_digest=verdict.request_digest,
                        policy_digest=verdict.policy_digest)
    return Decision(True, "Rust AgentGymGate validated the complete call envelope",
                    mechanism="rust-typesec-envelope",
                    invariant="exact-envelope-binding",
                    request_digest=verdict.request_digest,
                    policy_digest=verdict.policy_digest)


# Retained for older imports.
check_native = check_rust_gate
