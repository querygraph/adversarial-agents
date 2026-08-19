"""Seeded exact-call mutations for execution-boundary adversarial tests."""

from __future__ import annotations

import random
from dataclasses import dataclass

from .model import ToolCall, thaw_json


@dataclass(frozen=True)
class CallMutation:
    dimension: str
    call: ToolCall


def mutate_call(call: ToolCall, *, seed: int = 0) -> tuple[CallMutation, ...]:
    """Return deterministic one-field mutations of every bound call dimension."""
    args = thaw_json(call.args)
    args["__agentgym_mutation"] = seed
    runtime = thaw_json(call.runtime)
    runtime["__agentgym_mutation"] = seed
    values = [
        CallMutation("action", ToolCall(
            call.tool, f"{call.action}:mutated", call.resource, call.args,
            call.purpose, call.delegated_user, call.runtime,
        )),
        CallMutation("resource", ToolCall(
            call.tool, call.action, f"{call.resource}:mutated", call.args,
            call.purpose, call.delegated_user, call.runtime,
        )),
        CallMutation("arguments", ToolCall(
            call.tool, call.action, call.resource, args,
            call.purpose, call.delegated_user, call.runtime,
        )),
        CallMutation("purpose", ToolCall(
            call.tool, call.action, call.resource, call.args,
            f"{call.purpose or 'none'}:mutated", call.delegated_user, call.runtime,
        )),
        CallMutation("delegated-user", ToolCall(
            call.tool, call.action, call.resource, call.args,
            call.purpose, "user:attacker@example.invalid", call.runtime,
        )),
        CallMutation("runtime", ToolCall(
            call.tool, call.action, call.resource, call.args,
            call.purpose, call.delegated_user, runtime,
        )),
    ]
    random.Random(seed).shuffle(values)
    return tuple(values)

