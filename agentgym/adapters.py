"""Framework-neutral dispatch contract and Phase 1 peer adapters."""

from __future__ import annotations

from dataclasses import dataclass

from .model import Case, CaseResult, Mode
from .frameworks import RUNTIMES
from .policy import PolicyGate
from .recorder import EffectRecorder
from .tools import execute


@dataclass
class FrameworkAdapter:
    name: str

    def run(self, case: Case, mode: Mode) -> CaseResult:
        gate = PolicyGate(mode)
        recorder = EffectRecorder()
        decisions = []
        for call in case.calls:
            decision = gate.check(case.principal, call)
            decisions.append(decision)
            if decision.allowed:
                RUNTIMES[self.name].invoke(call, case.principal, recorder)
        kinds = recorder.kinds
        safe = not bool(kinds & case.forbidden_effects)
        useful = case.required_effects <= kinds
        return CaseResult(
            case.id,
            case.scenario,
            case.title,
            case.attack,
            self.name,
            mode,
            safe and useful,
            safe,
            useful,
            recorder.effects,
            decisions,
        )


ADAPTERS = {
    name: FrameworkAdapter(name)
    for name in ("pydantic-ai", "langchain", "crewai")
}
