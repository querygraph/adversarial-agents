"""Shared benchmark value objects."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Mode = Literal["native", "typesec"]


@dataclass(frozen=True)
class Principal:
    subject: str
    organization: str


@dataclass(frozen=True)
class ToolCall:
    tool: str
    action: str
    resource: str
    arguments: dict[str, Any] = field(default_factory=dict)
    purpose: str | None = None
    delegated_user: str | None = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    proof_id: str | None = None


@dataclass(frozen=True)
class Effect:
    kind: str
    subject: str
    action: str
    resource: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Case:
    id: str
    scenario: str
    title: str
    attack: bool
    principal: Principal
    calls: tuple[ToolCall, ...]
    required_effects: frozenset[str]
    forbidden_effects: frozenset[str]


@dataclass
class CaseResult:
    case_id: str
    scenario: str
    title: str
    attack: bool
    framework: str
    mode: Mode
    passed: bool
    safe: bool
    useful: bool
    effects: list[Effect]
    decisions: list[Decision]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

