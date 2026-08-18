"""Shared benchmark value objects.

The central structural distinction is between ``args`` and ``runtime`` on a
:class:`ToolCall`. ``args`` is the canonical request a framework integration
possesses at dispatch time: the model-proposed arguments plus verified
request fields. Every enforcement mode receives it. ``runtime`` holds facts
that only materialize at or after execution — the approval store's hash for
this call, the data-plane sensitivity label of content entering a channel,
receipt-chain and outbox state, branch capability usage. A stateless
decision-point engine is never shown ``runtime``, because in a real
integration the application would have to maintain and correctly bind that
state itself — which is precisely the enforcement problem under test. A
substrate that mediates execution (the TypeSec mode) checks ``runtime``
facts through the mechanism that owns each of them, and the oracle reads
both to record what actually happened.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Mode = Literal["native", "opa", "cerbos", "typesec"]

MODES: tuple[Mode, ...] = ("native", "opa", "cerbos", "typesec")


@dataclass(frozen=True)
class Principal:
    subject: str
    organization: str


@dataclass(frozen=True)
class ToolCall:
    tool: str
    action: str
    resource: str
    args: dict[str, Any] = field(default_factory=dict)
    purpose: str | None = None
    delegated_user: str | None = None
    runtime: dict[str, Any] = field(default_factory=dict)

    def request(self, principal: Principal) -> dict[str, Any]:
        """The canonical authorization request visible at dispatch time."""
        return {
            "subject": principal.subject,
            "organization": principal.organization,
            "tool": self.tool,
            "action": self.action,
            "resource": self.resource,
            "purpose": self.purpose,
            "delegated_user": self.delegated_user,
            "args": dict(self.args),
        }


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    proof_id: str | None = None
    # Which enforcement mechanism produced the decision (e.g. "rust-toolgate",
    # "opa", "workos-fga", "secure-value-label") and which invariant it
    # protected. Both feed the per-case explanation in the report.
    mechanism: str = "unspecified"
    invariant: str | None = None


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
    # One-paragraph story of what the case does and, for attacks, what the
    # adversary is trying to smuggle across which boundary.
    story: str = ""


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
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
