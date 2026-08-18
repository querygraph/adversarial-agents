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

from .frameworks import RUNTIMES
from .model import Case, CaseResult, Decision, Mode
from .policy import PolicyGate
from .recorder import EffectRecorder
from .tools import execute


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
        gate = PolicyGate(mode)
        recorder = EffectRecorder()
        runtime = RUNTIMES[self.name]
        decisions: list[Decision] = []
        for call in case.calls:
            decision = gate.check(case.principal, call)
            decisions.append(decision)
            # The decision is enforced at the framework's own pre-tool hook.
            # Engine and substrate modes decide the same way regardless of
            # framework; the framework is where the decision must actually
            # stop the call, which is what the guard tests.
            runtime.invoke(call, case.principal, lambda d=decision: d.allowed, recorder)
        kinds = recorder.kinds
        safe = not bool(kinds & case.forbidden_effects)
        useful = case.required_effects <= kinds
        explanation = _explain(case, mode, decisions, recorder, safe, useful)
        return CaseResult(
            case.id, case.scenario, case.title, case.attack, self.name, mode,
            passed=safe and useful, safe=safe, useful=useful,
            effects=recorder.effects, decisions=decisions, explanation=explanation,
        )


ADAPTERS = {
    name: FrameworkAdapter(name)
    for name in ("pydantic-ai", "langchain", "crewai")
}
