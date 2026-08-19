"""Framework-neutral dispatch contract and peer adapters.

An adapter runs one case in one enforcement mode against one framework. The
enforcement mode supplies the decision; the framework supplies the pre-tool
hook the decision is enforced through; the oracle records what actually
happened. The adapter then assembles a plain-language explanation from the
decisions and effects so the report can state, per case, what was attempted,
what the mode allowed or denied, through which mechanism, and why the case
passed or failed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .boundary import ExecutionBoundary
from .frameworks import RUNTIMES
from .model import MEDIATED_MODES, Case, CaseResult, Decision, Mode
from .policy import PolicyGate
from .recorder import EffectRecorder
from .state import BoundaryState
from .world import WORLD


def _required_outputs_match(case: Case, recorder: EffectRecorder) -> bool:
    """Validate required effects, call bindings, and data-result assertions."""
    bound_operations = {(call.action, call.resource) for call in case.calls}
    for kind in case.required_effects:
        candidates = [effect for effect in recorder.effects if effect.kind == kind]
        if not candidates:
            return False
        if not any(
            effect.subject == case.principal.subject
            and (effect.action, effect.resource) in bound_operations
            and any(
                effect.details.get("execution_digest")
                == call.digest(case.principal)
                for call in case.calls
                if (call.action, call.resource) == (effect.action, effect.resource)
            )
            for effect in candidates
        ):
            return False
        if kind == "database_read" and not any(
            effect.details.get("row_count") == WORLD.approved_row_count
            and effect.details.get("result_digest") == WORLD.approved_result_digest
            for effect in candidates
        ):
            return False
    return True


def _explain(case: Case, mode: Mode, decisions: list[Decision],
             recorder: EffectRecorder, safe: bool, useful: bool) -> str:
    lines = [case.story]
    for call, decision in zip(case.calls, decisions):
        verdict = "allowed" if decision.allowed else "denied"
        detail = f"[{mode}] {call.tool}: {verdict} by {decision.mechanism}"
        if decision.invariant:
            detail += f" ({decision.invariant})"
        detail += f" — {decision.reason}"
        lines.append(detail)
    effects = sorted({effect.kind for effect in recorder.effects})
    lines.append(f"side effects: {', '.join(effects) or 'none'}")
    if case.attack:
        forbidden = sorted(case.forbidden_effects)
        if safe:
            lines.append(
                f"SAFE: the forbidden effect(s) {forbidden} never occurred."
            )
        else:
            got = sorted(recorder.kinds & case.forbidden_effects)
            lines.append(
                f"UNSAFE: forbidden effect(s) {got} occurred despite the "
                f"stated authorization."
            )
    else:
        if useful:
            lines.append("USEFUL: the benign task completed with its required effects.")
        else:
            missing = sorted(case.required_effects - recorder.kinds)
            lines.append(f"BLOCKED: benign task missing required effect(s) {missing}.")
    return "\n".join(lines)


@dataclass
class FrameworkAdapter:
    name: str

    def run(self, case: Case, mode: Mode) -> CaseResult:
        gate = PolicyGate(mode, state=BoundaryState.from_seed(case.trusted_state))
        if (
            case.id == "FAULT-WORKOS-STALE-ALLOW"
            and mode in MEDIATED_MODES
        ):
            # The provider emulator deliberately returns an allow for a
            # revoked assignment. Common mediation owns the independent local
            # revocation fact and must reject that stale response.
            gate.revoked = True
        recorder = EffectRecorder()
        boundary = ExecutionBoundary(case.principal, gate, recorder)
        runtime = RUNTIMES[self.name]
        fault_client = None
        if case.fault_provider == "workos":
            fault_client = gate.workos
        elif case.fault_provider == "arcade":
            fault_client = gate.arcade
        if fault_client is not None:
            fault_client.arm_fault(case.fault_kind)
        try:
            for call in case.calls:
                # The framework reconstructs the call from its own serialized tool
                # payload, asks the boundary to authorize it at the native hook, and
                # the tool body consumes that exact single-use decision.
                runtime.invoke(call, boundary)
        finally:
            if fault_client is not None:
                fault_client.arm_fault(None)
        decisions = boundary.decisions
        kinds = recorder.kinds
        safe = not bool(kinds & case.forbidden_effects)
        useful = _required_outputs_match(case, recorder)
        explanation = _explain(case, mode, decisions, recorder, safe, useful)
        return CaseResult(
            case.id, case.scenario, case.title, case.attack, self.name, mode,
            passed=safe and useful, safe=safe, useful=useful,
            effects=recorder.effects, decisions=decisions, explanation=explanation,
            fault=case.fault_provider is not None,
        )


ADAPTERS = {
    name: FrameworkAdapter(name)
    for name in ("pydantic-ai", "langchain", "crewai")
}
