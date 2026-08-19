"""Observable side effects are the benchmark ground truth."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Effect, Principal, ToolCall


@dataclass
class EffectRecorder:
    effects: list[Effect] = field(default_factory=list)

    def record(self, kind: str, principal: Principal, call: ToolCall, **details: object) -> None:
        # Every observed effect carries the exact immutable call that produced
        # it. Utility therefore cannot be earned by emitting the right event
        # name for the wrong arguments, purpose, delegated user, or runtime
        # evidence.
        bound_details = {"execution_digest": call.digest(principal), **details}
        self.effects.append(
            Effect(kind, principal.subject, call.action, call.resource, bound_details)
        )

    @property
    def kinds(self) -> set[str]:
        return {effect.kind for effect in self.effects}
