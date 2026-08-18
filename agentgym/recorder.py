"""Observable side effects are the benchmark ground truth."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Effect, Principal, ToolCall


@dataclass
class EffectRecorder:
    effects: list[Effect] = field(default_factory=list)

    def record(self, kind: str, principal: Principal, call: ToolCall, **details: object) -> None:
        self.effects.append(
            Effect(kind, principal.subject, call.action, call.resource, dict(details))
        )

    @property
    def kinds(self) -> set[str]:
        return {effect.kind for effect in self.effects}

