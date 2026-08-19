"""Single-use authorization boundary between framework hooks and effects."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .model import Decision, Principal, ToolCall
from .permits import PermitError, issue_local_execution_permit
from .policy import PolicyGate
from .recorder import EffectRecorder
from .state import BoundaryState
from .tools import _apply_effects


class BoundaryDenied(PermissionError):
    """A framework reached the effect boundary without an exact valid permit."""


@dataclass
class ExecutionBoundary:
    """Authorize, consume, and revalidate one exact tool call.

    Framework hooks call :meth:`authorize` on the call reconstructed from their
    own wire payload.  The tool body can then call :meth:`execute` exactly once.
    The policy gate verifies the full-call digest and, for TypeSec, the
    authenticated receipt and compiled Rust envelope a second time.
    """

    principal: Principal
    gate: PolicyGate
    recorder: EffectRecorder
    decisions: list[Decision] = field(default_factory=list)
    _pending: dict[str, list[tuple[Decision, object]]] = field(
        default_factory=dict, init=False,
    )
    state: BoundaryState = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Real PolicyGate instances own isolated state. Lightweight framework
        # test gates receive an empty bundle without changing their contract.
        candidate = getattr(self.gate, "state", None)
        self.state = candidate if isinstance(candidate, BoundaryState) else BoundaryState()

    def authorize(self, call: ToolCall) -> bool:
        decision = self.gate.check(self.principal, call)
        self.decisions.append(decision)
        if decision.allowed:
            digest = call.digest(self.principal)
            issue = getattr(self.gate, "issue_execution_permit", None)
            try:
                if callable(issue):
                    permit = issue(self.principal, call, decision)
                else:
                    # Lightweight test gates still exercise exact-call, expiry,
                    # and single-use semantics without requiring the optional
                    # protected-track extension.
                    permit = issue_local_execution_permit(
                        request_digest=digest,
                        policy_digest=decision.policy_digest or "",
                        issued_at=0.0,
                        expires_at=60.0,
                    )
            except PermitError as exc:
                self.decisions[-1] = replace(
                    decision,
                    allowed=False,
                    reason=f"execution permit issuance failed closed: {exc}",
                    mechanism="execution-permit",
                    invariant="fail-closed",
                    proof_id=None,
                    evidence_verified=False,
                )
                return False
            self._pending.setdefault(digest, []).append((decision, permit))
        return decision.allowed

    def execute(self, call: ToolCall) -> None:
        digest = call.digest(self.principal)
        pending = self._pending.get(digest)
        if not pending:
            raise BoundaryDenied("no unspent decision exists for this exact call")
        decision, permit = pending.pop(0)
        if not pending:
            self._pending.pop(digest, None)
        if not self.gate.verify_execution(self.principal, call, decision):
            raise BoundaryDenied("execution receipt failed exact-call verification")
        try:
            _apply_effects(
                call,
                self.principal,
                self.recorder,
                self.state,
                permit,
                policy_digest=decision.policy_digest or "",
                now=float(getattr(self.gate, "evaluation_time", 0.0)),
            )
        except PermitError as exc:
            raise BoundaryDenied("execution permit was rejected by the effect boundary") from exc

    @property
    def unspent_permits(self) -> int:
        return sum(len(decisions) for decisions in self._pending.values())
