"""Shared benchmark value objects.

The central structural distinction is between ``args`` and ``runtime`` on a
:class:`ToolCall`. ``args`` is the canonical request a framework integration
possesses at dispatch time: the model-proposed arguments plus verified
request fields. Every enforcement mode receives it. ``runtime`` holds facts
that only materialize at or after execution — the approval store's hash for
this call, the data-plane sensitivity label of content entering a channel,
receipt-chain and outbox state, branch capability usage. A stateless
raw decision-point profile is not shown ``runtime``. The mediated OPA,
Cerbos, and TypeSec profiles all receive it through the same application
state machines, making mediation architecture an explicit benchmark axis.
The oracle reads both surfaces to record what actually happened.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass, field
from types import MappingProxyType
from typing import Any, Literal, TypeAlias, Union

Mode = Literal[
    "native",
    "workos",
    "arcade",
    "opa",
    "cerbos",
    "opa-mediated",
    "cerbos-mediated",
    "typesec",
]

MODES: tuple[Mode, ...] = (
    "native", "workos", "arcade", "opa", "cerbos",
    "opa-mediated", "cerbos-mediated", "typesec",
)
IN_PROCESS_MODES: tuple[Mode, ...] = ("native", "workos", "arcade", "typesec")
SERVICE_MODES: tuple[Mode, ...] = (
    "opa", "cerbos", "opa-mediated", "cerbos-mediated",
)
MEDIATED_MODES: frozenset[Mode] = frozenset(
    {"opa-mediated", "cerbos-mediated", "typesec"}
)

JsonScalar: TypeAlias = str | int | float | bool | None
FrozenJson: TypeAlias = Union[JsonScalar, tuple["FrozenJson", ...], "FrozenDict"]


class FrozenDict(Mapping[str, FrozenJson]):
    """A recursively immutable, JSON-compatible mapping.

    ``dataclass(frozen=True)`` only prevents replacing an attribute; it does not
    freeze a dictionary stored in that attribute. A ``dict`` subclass is also
    insufficient because ``dict.__setitem__(value, ...)`` bypasses Python-level
    overrides. This wrapper retains only a read-only mapping proxy and is not a
    ``dict``, so even base-class descriptor attacks fail.
    """

    __slots__ = ("_data",)

    def __init__(self, value: Mapping[str, FrozenJson]) -> None:
        object.__setattr__(self, "_data", MappingProxyType(dict(value)))

    def __getitem__(self, key: str) -> FrozenJson:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"FrozenDict({dict(self._data)!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Mapping) and dict(self.items()) == dict(other.items())

    @staticmethod
    def _immutable(*_args: object, **_kwargs: object) -> None:
        raise TypeError("security-relevant call data is immutable")

    __setattr__ = _immutable
    __delattr__ = _immutable
    __setitem__ = _immutable
    __delitem__ = _immutable


def freeze_json(value: Any, *, path: str = "$") -> FrozenJson:
    """Validate and recursively freeze one JSON value.

    Security envelopes reject Python-only objects, non-string object keys, and
    non-finite numbers so all participants hash exactly the same JSON document.
    """
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} must not contain NaN or infinity")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, FrozenJson] = {}
        keys = tuple(value)
        for key in keys:
            if not isinstance(key, str):
                raise TypeError(f"{path} object keys must be strings")
        for key in sorted(keys):
            frozen[key] = freeze_json(value[key], path=f"{path}.{key}")
        return FrozenDict(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(
            freeze_json(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        )
    if isinstance(value, (set, frozenset)):
        raise TypeError(f"{path} contains non-JSON value {type(value).__name__}")
    raise TypeError(f"{path} contains non-JSON value {type(value).__name__}")


def thaw_json(value: FrozenJson | Any) -> Any:
    """Return ordinary JSON containers for SDK and report serialization."""
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """Serialize JSON with one stable, cross-process representation."""
    return json.dumps(
        thaw_json(value), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    )


@dataclass(frozen=True)
class Principal:
    subject: str
    organization: str

    def __post_init__(self) -> None:
        for name in ("subject", "organization"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")


@dataclass(frozen=True)
class ToolCall:
    tool: str
    action: str
    resource: str
    args: Mapping[str, Any] = field(default_factory=dict)
    purpose: str | None = None
    delegated_user: str | None = None
    runtime: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tool", "action", "resource"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if self.purpose is not None and not isinstance(self.purpose, str):
            raise TypeError("purpose must be a string or None")
        if self.delegated_user is not None and not isinstance(self.delegated_user, str):
            raise TypeError("delegated_user must be a string or None")
        if not isinstance(self.args, Mapping):
            raise TypeError("args must be a JSON object")
        if not isinstance(self.runtime, Mapping):
            raise TypeError("runtime must be a JSON object")
        object.__setattr__(self, "args", freeze_json(self.args, path="$.args"))
        object.__setattr__(self, "runtime", freeze_json(self.runtime, path="$.runtime"))

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
            "args": thaw_json(self.args),
        }

    def envelope(self, principal: Principal) -> dict[str, Any]:
        """The complete immutable request consumed at the effect boundary."""
        return {
            **self.request(principal),
            "runtime": thaw_json(self.runtime),
        }

    def digest(self, principal: Principal) -> str:
        """SHA-256 of the complete canonical execution envelope."""
        return hashlib.sha256(canonical_json(self.envelope(principal)).encode()).hexdigest()

    def request_digest(self, principal: Principal) -> str:
        """SHA-256 of only the request-plane fields visible to raw PDPs."""
        return hashlib.sha256(canonical_json(self.request(principal)).encode()).hexdigest()


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
    # Digest of what the deciding policy component actually observed. Raw
    # provider/PDP profiles carry the request-plane digest; mediated profiles
    # carry the complete execution-envelope digest.
    request_digest: str | None = None
    # The application boundary always pins the complete call even when a raw
    # PDP saw fewer facts. This prevents TOCTOU without inflating PDP binding.
    execution_digest: str | None = None
    policy_digest: str | None = None
    evidence_verified: bool = False


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
    fault_provider: Literal["workos", "arcade"] | None = None
    fault_kind: str | None = None
    # Empty means every mode. Fault trials use this to avoid attributing a
    # provider outage to a mode that never contacts that provider.
    applicable_modes: frozenset[Mode] = frozenset()
    # Trusted execution-service seed material is benchmark setup, not part of
    # the model/framework ToolCall payload.  Stateful scenarios use this to
    # provision an isolated approval store, receipt ledger, or branch
    # capability registry before the untrusted call is dispatched.
    trusted_state: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.trusted_state, Mapping):
            raise TypeError("trusted_state must be a JSON object")
        object.__setattr__(
            self,
            "trusted_state",
            freeze_json(self.trusted_state, path="$.trusted_state"),
        )


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
    fault: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
