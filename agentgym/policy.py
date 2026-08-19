"""The eight named AgentGym enforcement profiles.

Every mode receives the same canonical dispatch-time request and returns a
:class:`Decision` carrying which mechanism decided and which invariant it
protected. The modes differ in what they can enforce, and that difference is
the benchmark:

- ``native``  — a representative weak integration: authenticate once, check
  one broad entitlement through the real provider clients, trust validated
  arguments. A named baseline, not a claim that a framework cannot be
  secured with careful middleware.
- ``workos`` / ``arcade`` — provider-only authorization at each provider's
  natural resource or delegated-tool layer.
- ``opa`` / ``cerbos`` — real policy engines evaluating generated
  translations and receiving only the request surface in their raw profiles.
- ``opa-mediated`` / ``cerbos-mediated`` — the same decisions composed with
  the common execution-state mediator and exact-call permit.
- ``typesec`` — the reference substrate. It composes the Rust AgentGymGate,
  built on TypeSec RBAC/ODRL engines, with the same provider clients and mediates
  execution, so it binds the runtime facts the engines cannot.

The TypeSec-specific runtime checks live behind the Rust gate, not instead of
it: an unbound tool, missing resource, or failed ODRL constraint is rejected by
the compiled gate first. Raw-versus-mediated differences describe these
profiles, not an inherent ceiling of an underlying product.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .engines import ENGINES
from .bindings import (
    ARCADE_TOOL_NAMES,
    CallSchemaError,
    validate_bound_call,
    workos_permission,
)
from .model import MEDIATED_MODES, Decision, Mode, Principal, ToolCall
from .permits import (
    DEFAULT_AUTHORITY,
    PermitError,
    ReceiptAuthority,
    issue_local_execution_permit,
)
from .state import BoundaryState
from .typesec_native import check_rust_gate
from .wire import ArcadeClient, ProviderFault, WorkOSClient
from .world import WORLD

ARCADE_TOOLS = {
    key: ARCADE_TOOL_NAMES[key] for key in ("drive/create", "gmail/send")
}

@dataclass
class PolicyGate:
    mode: Mode
    workos: WorkOSClient = field(default_factory=WorkOSClient)
    arcade: ArcadeClient = field(default_factory=ArcadeClient)
    revoked: bool = False
    issued_at: float = 0.0
    evaluation_time: float = 0.0
    ttl_seconds: float = 60.0
    receipt_authority: ReceiptAuthority = field(
        default_factory=lambda: DEFAULT_AUTHORITY, repr=False,
    )
    state: BoundaryState = field(default_factory=BoundaryState, repr=False)
    # Acceptance instrumentation: records the exact full envelope delivered to
    # the common execution mediator. It has no influence on a verdict.
    mediator_observed_digests: list[str] = field(default_factory=list, repr=False)

    def check(self, principal: Principal, call: ToolCall) -> Decision:
        try:
            if self.mode == "native":
                decision = self._native(principal, call)
            elif self.mode == "workos":
                decision = self._workos_profile(principal, call)
            elif self.mode == "arcade":
                decision = self._arcade_profile(principal, call)
            elif self.mode in ENGINES:
                decision = ENGINES[self.mode].check(principal, call)
            elif self.mode in {"opa-mediated", "cerbos-mediated"}:
                decision = self._mediated(principal, call)
            elif self.mode == "typesec":
                decision = self._typesec(principal, call)
            else:
                return Decision(False, f"unknown enforcement mode {self.mode!r}",
                                mechanism="configuration",
                                invariant="closed-mode-registry")
        except ProviderFault as exc:
            return Decision(False, f"provider failed closed: {exc}",
                            mechanism=f"{self.mode}-provider",
                            invariant="fail-closed")
        except (CallSchemaError, KeyError, TypeError, ValueError) as exc:
            return Decision(False, f"request failed closed: {exc}",
                            mechanism=f"{self.mode}-schema",
                            invariant="closed-schema")

        execution_digest = call.digest(principal)
        observed_digest = (
            execution_digest
            if self.mode in MEDIATED_MODES
            else call.request_digest(principal)
        )
        decision = replace(
            decision,
            request_digest=observed_digest,
            execution_digest=execution_digest,
            policy_digest=WORLD.policy_digest,
        )
        if decision.allowed and self.mode in MEDIATED_MODES:
            token = self.receipt_authority.issue(
                mode=self.mode,
                principal=principal,
                call=call,
                policy_digest=WORLD.policy_digest,
                issued_at=self.issued_at,
                expires_at=self.issued_at + self.ttl_seconds,
            )
            self.receipt_authority.verify(
                token,
                mode=self.mode,
                principal=principal,
                call=call,
                policy_digest=WORLD.policy_digest,
                now=self.evaluation_time,
            )
            decision = replace(
                decision,
                proof_id=token,
                evidence_verified=True,
            )
        return decision

    def verify_execution(
        self, principal: Principal, call: ToolCall, decision: Decision,
    ) -> bool:
        """Revalidate and consume an allowed decision at the effect boundary.

        The signed decision is an exact-call receipt, not a bearer token.  A
        mediated profile therefore repeats its policy/provider/state checks at
        the last responsible moment, invokes the SaaS provider's execute API,
        and only then atomically spends any single-use local authority.
        """
        if not decision.allowed or decision.execution_digest != call.digest(principal):
            return False
        if decision.policy_digest != WORLD.policy_digest:
            return False
        if self.mode in MEDIATED_MODES:
            if not decision.proof_id or not decision.evidence_verified:
                return False
            try:
                self.receipt_authority.verify(
                    decision.proof_id,
                    mode=self.mode,
                    principal=principal,
                    call=call,
                    policy_digest=WORLD.policy_digest,
                    now=self.evaluation_time,
                )
            except PermitError:
                return False
        try:
            if self.mode == "workos":
                return self._workos_profile(principal, call).allowed
            if self.mode == "arcade":
                user = call.delegated_user or principal.subject
                return self.arcade.execute(
                    user, ARCADE_TOOL_NAMES[call.tool], call.envelope(principal),
                )
            if self.mode == "typesec":
                rechecked = self._typesec(principal, call)
                if not rechecked.allowed:
                    return False
            elif self.mode in {"opa-mediated", "cerbos-mediated"}:
                rechecked = self._mediated(principal, call)
                if not rechecked.allowed:
                    return False

            # Authorization and provider-side execution are distinct Arcade
            # operations.  Every execution-mediating profile performs the
            # latter only after its complete local revalidation succeeds.
            if self.mode in MEDIATED_MODES and call.tool in ARCADE_TOOLS:
                if not self.arcade.execute(
                    principal.subject, ARCADE_TOOLS[call.tool], call.envelope(principal),
                ):
                    return False
        except (ProviderFault, CallSchemaError, KeyError, TypeError, ValueError):
            return False
        # Stateful authority is validated without mutation during policy
        # evaluation and consumed exactly once only after every other execution
        # check has succeeded.
        if self.mode in MEDIATED_MODES and not self.state.consume(call):
            return False
        return True

    def issue_execution_permit(
        self, principal: Principal, call: ToolCall, decision: Decision,
    ) -> object:
        """Mint the capability required by the effect implementation.

        Mediated profiles receive the opaque Rust permit derived from their
        authenticated positive receipt. Raw profiles deliberately remain
        runnable without the optional native companion and receive an unscored
        process-local exact-call permit instead.
        """
        digest = call.digest(principal)
        if (
            not decision.allowed
            or decision.execution_digest != digest
            or decision.policy_digest != WORLD.policy_digest
        ):
            raise PermitError("only an exact, current allow can mint a permit")
        if self.mode in MEDIATED_MODES:
            return self.receipt_authority.execution_permit(
                token=decision.proof_id,
                mode=self.mode,
                principal=principal,
                call=call,
                policy_digest=WORLD.policy_digest,
                issued_at=self.issued_at,
                expires_at=self.issued_at + self.ttl_seconds,
                now=self.evaluation_time,
            )
        return issue_local_execution_permit(
            request_digest=digest,
            policy_digest=WORLD.policy_digest,
            issued_at=self.evaluation_time,
            expires_at=self.evaluation_time + self.ttl_seconds,
        )

    # -- native baseline ---------------------------------------------------

    def _native(self, principal: Principal, call: ToolCall) -> Decision:
        if call.tool in {"catalog/query", "catalog/dashboard"}:
            allowed = self.workos.check(
                principal.subject, "dataset:view", WORLD.study_resource
            )
            return Decision(allowed, "broad WorkOS dataset entitlement",
                            mechanism="native-workos",
                            invariant="coarse-entitlement")
        if call.tool in ARCADE_TOOLS:
            user = call.delegated_user or principal.subject
            allowed = self.arcade.authorized(user, ARCADE_TOOLS[call.tool])
            return Decision(allowed, "Arcade OAuth status treated as execute permission",
                            mechanism="native-arcade",
                            invariant="channel-only")
        return Decision(True, "registered Python tool, arguments trusted",
                        mechanism="native-dispatch", invariant="none")

    def _workos_profile(self, principal: Principal, call: ToolCall) -> Decision:
        validate_bound_call(call)
        allowed = self.workos.check(
            principal.subject, workos_permission(call), call.resource,
        )
        return Decision(
            allowed,
            "WorkOS exact subject/permission/resource authorization",
            mechanism="workos-fga",
            invariant="subject-action-resource",
        )

    def _arcade_profile(self, principal: Principal, call: ToolCall) -> Decision:
        validate_bound_call(call)
        user = call.delegated_user or principal.subject
        allowed = self.arcade.authorized(user, ARCADE_TOOL_NAMES[call.tool])
        return Decision(
            allowed,
            "Arcade exact user/tool authorization; content remains application state",
            mechanism="arcade-authorize",
            invariant="delegated-user-tool",
        )

    def _mediated(self, principal: Principal, call: ToolCall) -> Decision:
        validate_bound_call(call)
        engine_mode = self.mode.removesuffix("-mediated")
        engine = ENGINES[engine_mode]
        decision = engine.check(principal, call)
        if not decision.allowed:
            return replace(decision, mechanism=f"{engine_mode}+mediator")
        runtime = self._execution_mediator(principal, call)
        if runtime is not None and not runtime.allowed:
            return replace(runtime, mechanism=f"{engine_mode}+mediator")
        return Decision(
            True,
            f"{engine_mode.upper()} allow bound by the shared execution mediator",
            mechanism=f"{engine_mode}+mediator",
            invariant=(runtime.invariant if runtime else "exact-binding"),
        )

    # -- TypeSec reference substrate ---------------------------------------

    def _typesec(self, principal: Principal, call: ToolCall) -> Decision:
        if self.evaluation_time >= self.issued_at + self.ttl_seconds:
            return Decision(False, "capability expired",
                            mechanism="typesec-lease", invariant="lease-epoch")
        if principal.organization != "org:civic-lab":
            return Decision(False, "organization binding mismatch",
                            mechanism="typesec-capability",
                            invariant="subject-org-binding")

        validate_bound_call(call)

        # The compiled Rust AgentGymGate + TypeSec ODRL engine decides binding, resource
        # presence, and the catalog-read policy before any Python semantics.
        gate = check_rust_gate(principal, call)
        if not gate.allowed:
            return gate

        runtime = self._execution_mediator(principal, call)
        if runtime is not None and not runtime.allowed:
            return runtime
        return Decision(True, "exact leased capability, runtime facts bound",
                        mechanism="typesec-capability",
                        invariant=(runtime.invariant if runtime else "exact-binding"))

    def _execution_mediator(
        self, principal: Principal, call: ToolCall,
    ) -> Decision | None:
        """Bind the facts that only an execution-mediating substrate holds.

        Returns an allow carrying the invariant name it protected, a deny, or
        ``None`` when a tool has no extra runtime obligation beyond the gate.
        """
        self.mediator_observed_digests.append(call.digest(principal))
        if self.revoked:
            return Decision(
                False,
                "local capability has been revoked",
                mechanism="execution-mediator",
                invariant="lease-epoch",
            )
        if call.tool == "catalog/query":
            if call.resource != WORLD.approved_dataset:
                return Decision(False, "exact tenant/catalog resource mismatch",
                                mechanism="typesec-capability",
                                invariant="exact-resource")
            columns = call.args.get("columns")
            if not isinstance(columns, (list, tuple)) or not columns:
                return Decision(False, "allowed columns must be a non-empty list",
                                mechanism="typesec-restriction",
                                invariant="column-restriction")
            if not set(columns) <= WORLD.allowed_columns:
                return Decision(False, "scan would widen the ODRL restriction",
                                mechanism="typesec-restriction",
                                invariant="column-restriction")
            if call.args.get("predicate") != WORLD.row_predicate:
                return Decision(False, "row predicate does not match restriction",
                                mechanism="typesec-restriction",
                                invariant="row-restriction")
            return Decision(True, "restriction applied", invariant="odrl-restriction")
        if call.tool == "catalog/dashboard":
            allowed = self.workos.check(
                principal.subject, "dataset:view", call.resource
            )
            if call.resource != WORLD.study_resource or not allowed:
                return Decision(False, "WorkOS decision not bound to exact resource",
                                mechanism="typesec-capability",
                                invariant="exact-provider-resource")
            return Decision(True, "provider allow minted to exact-resource capability",
                            invariant="exact-provider-resource")
        if call.tool in ARCADE_TOOLS:
            if call.delegated_user != principal.subject:
                return Decision(False, "delegated user does not match principal",
                                mechanism="typesec-capability",
                                invariant="delegated-user-binding")
            if not self.arcade.authorized(principal.subject, ARCADE_TOOLS[call.tool]):
                return Decision(False, "Arcade denied exact user/tool pair",
                                mechanism="typesec-arcade",
                                invariant="delegated-user-binding")
            if call.runtime.get("content_label") == "sensitive":
                return Decision(False, "content lacks declassification capability",
                                mechanism="typesec-securevalue",
                                invariant="information-flow")
            if call.tool == "gmail/send" and call.purpose != "approved-communication":
                return Decision(False, "ODRL prohibits this exfiltration purpose",
                                mechanism="typesec-odrl",
                                invariant="purpose-binding")
            return Decision(True, "channel and content authority both present",
                            invariant="information-flow")
        if call.tool == "delegate/run":
            if (call.args["ttl"] > WORLD.delegation_max_ttl
                    or call.args["scope"] != WORLD.delegation_scope):
                return Decision(False, "delegation must attenuate authority and lease",
                                mechanism="typesec-capability",
                                invariant="delegation-attenuation")
            return Decision(True, "attenuated delegation", invariant="delegation-attenuation")
        if call.tool == "memory/recall":
            if principal.subject != WORLD.supervisor:
                return Decision(False, "durable memory identity mismatch",
                                mechanism="typesec-memory",
                                invariant="durable-identity")
            if call.runtime["stored_label"] != "sensitive":
                return Decision(False, "recalled value lost its security label",
                                mechanism="typesec-securevalue",
                                invariant="label-provenance")
            return Decision(True, "durable identity and label preserved",
                            invariant="durable-identity")
        if call.tool == "approval/execute":
            approval = self.state.approvals.verify(
                call.args["checkpoint"], call.runtime["current_call"],
            )
            if not approval.valid:
                return Decision(False, "approved call changed before execution",
                                mechanism="typesec-approval",
                                invariant="toctou-revalidation")
            if call.args["checkpoint"] != "thread:maya":
                return Decision(False, "approval checkpoint subject mismatch",
                                mechanism="typesec-approval",
                                invariant="toctou-revalidation")
            return Decision(True, "canonical call revalidated at execution",
                            invariant="toctou-revalidation")
        if call.tool == "credential/vend":
            if call.args["raw"] or call.args["scope"] != WORLD.credential_scope:
                return Decision(False, "raw or widened credential request",
                                mechanism="typesec-credential",
                                invariant="credential-scope")
            if call.args["ttl"] > WORLD.credential_ttl_seconds:
                return Decision(False, "credential exceeds ODRL TTL cap",
                                mechanism="typesec-credential",
                                invariant="credential-ttl")
            return Decision(True, "scoped short-lived credential",
                            invariant="credential-scope")
        if call.tool == "replay/import":
            verification = self.state.receipts.verify(call.runtime["receipt_chain"])
            if not verification.valid:
                return Decision(False, "receipt/outbox evidence does not bind",
                                mechanism="typesec-receipt",
                                invariant="closed-receipt-chain")
            return Decision(True, "closed verified receipt chain",
                            invariant="closed-receipt-chain")
        if call.tool == "policy/evaluate":
            parsed = self.state.policies.parse(call.runtime["policy_document"])
            if not parsed.supported or not parsed.canonical:
                return Decision(False, "unsupported policy construct fails closed",
                                mechanism="typesec-odrl",
                                invariant="parser-fail-closed")
            return Decision(True, "canonical policy digest agrees",
                            invariant="parser-fail-closed")
        if call.tool == "parallel/join":
            joined = self.state.branches.join(
                call.runtime["branch_events"], tenant="northstar",
            )
            if joined.tenant_confusion:
                return Decision(False, "parallel join crosses tenant binding",
                                mechanism="typesec-capability",
                                invariant="branch-tenant-binding")
            if joined.capability_reuse:
                return Decision(False, "capability reused across branches",
                                mechanism="typesec-capability",
                                invariant="lease-single-use")
            if joined.retry_drift:
                return Decision(False, "retry changed canonical request",
                                mechanism="typesec-idempotency",
                                invariant="idempotent-binding")
            if joined.replayed:
                return Decision(False, "branch capability was already consumed",
                                mechanism="typesec-capability",
                                invariant="lease-single-use")
            if not joined.valid:
                return Decision(False, "branch capability set is not an exact issued join",
                                mechanism="typesec-capability",
                                invariant="branch-tenant-binding")
            return Decision(True, "each branch value stays resource-bound",
                            invariant="branch-tenant-binding")
        return None
