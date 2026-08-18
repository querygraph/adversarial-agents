"""Enforcement modes: native baseline, OPA, Cerbos, and TypeSec.

Every mode receives the same canonical dispatch-time request and returns a
:class:`Decision` carrying which mechanism decided and which invariant it
protected. The modes differ in what they can enforce, and that difference is
the benchmark:

- ``native``  — a representative weak integration: authenticate once, check
  one broad entitlement through the real provider clients, trust validated
  arguments. A named baseline, not a claim that a framework cannot be
  secured with careful middleware.
- ``opa`` / ``cerbos`` — an industry policy engine, running as a container,
  evaluating an honest translation of the world's static constraints. It
  sees only the request. Scenarios whose invariant lives in execution-plane
  state (content labels, approval hashes, receipt chains, branch leases) are
  outside what a stateless decision point can express — and it says so.
- ``typesec`` — the reference substrate. It composes the real Rust ToolGate
  and ODRL engine with the same provider clients, and additionally mediates
  execution, so it binds the runtime facts the engines cannot.

The TypeSec-specific runtime checks live behind the Rust gate, not instead
of it: an unbound tool, a missing resource, or a failed ODRL constraint is
rejected by the compiled gate first.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from .engines import ENGINES
from .model import Decision, Mode, Principal, ToolCall
from .typesec_native import check_rust_gate
from .wire import ArcadeClient, ProviderFault, WorkOSClient
from .world import WORLD

ARCADE_TOOLS = {
    "drive/create": "GoogleDrive.CreateFile",
    "gmail/send": "Gmail.SendEmail",
}


def _proof(principal: Principal, call: ToolCall) -> str:
    value = json.dumps(
        [principal.subject, principal.organization, call.action,
         call.resource, call.purpose],
        separators=(",", ":"),
    )
    return hashlib.sha256(value.encode()).hexdigest()[:16]


@dataclass
class PolicyGate:
    mode: Mode
    workos: WorkOSClient = field(default_factory=WorkOSClient)
    arcade: ArcadeClient = field(default_factory=ArcadeClient)
    revoked: bool = False
    issued_at: float = field(default_factory=time.monotonic)
    ttl_seconds: float = 60.0

    def check(self, principal: Principal, call: ToolCall) -> Decision:
        try:
            if self.mode == "native":
                return self._native(principal, call)
            if self.mode in ENGINES:
                return ENGINES[self.mode].check(principal, call)
            return self._typesec(principal, call)
        except ProviderFault as exc:
            return Decision(False, f"provider failed closed: {exc}",
                            mechanism=f"{self.mode}-provider",
                            invariant="fail-closed")

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

    # -- TypeSec reference substrate ---------------------------------------

    def _typesec(self, principal: Principal, call: ToolCall) -> Decision:
        if self.revoked or time.monotonic() - self.issued_at > self.ttl_seconds:
            return Decision(False, "capability revoked or expired",
                            mechanism="typesec-lease", invariant="lease-epoch")
        if principal.organization != "org:civic-lab":
            return Decision(False, "organization binding mismatch",
                            mechanism="typesec-capability",
                            invariant="subject-org-binding")

        # The compiled Rust ToolGate + ODRL engine decides binding, resource
        # presence, and the catalog-read policy before any Python semantics.
        gate = check_rust_gate(principal, call)
        if not gate.allowed:
            return gate

        runtime = self._typesec_runtime(principal, call)
        if runtime is not None and not runtime.allowed:
            return runtime
        return Decision(True, "exact leased capability, runtime facts bound",
                        _proof(principal, call),
                        mechanism="typesec-capability",
                        invariant=(runtime.invariant if runtime else "exact-binding"))

    def _typesec_runtime(self, principal: Principal, call: ToolCall) -> Decision | None:
        """Bind the facts that only an execution-mediating substrate holds.

        Returns an allow carrying the invariant name it protected, a deny, or
        ``None`` when a tool has no extra runtime obligation beyond the gate.
        """
        if call.tool == "catalog/query":
            if call.resource != WORLD.approved_dataset:
                return Decision(False, "exact tenant/catalog resource mismatch",
                                mechanism="typesec-capability",
                                invariant="exact-resource")
            columns = call.args.get("columns")
            if not isinstance(columns, list) or not columns:
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
            if (call.args.get("ttl", 0) > WORLD.delegation_max_ttl
                    or call.args.get("scope") != WORLD.delegation_scope):
                return Decision(False, "delegation must attenuate authority and lease",
                                mechanism="typesec-capability",
                                invariant="delegation-attenuation")
            return Decision(True, "attenuated delegation", invariant="delegation-attenuation")
        if call.tool == "memory/recall":
            if principal.subject != WORLD.supervisor:
                return Decision(False, "durable memory identity mismatch",
                                mechanism="typesec-memory",
                                invariant="durable-identity")
            if call.runtime.get("stored_label") != "sensitive":
                return Decision(False, "recalled value lost its security label",
                                mechanism="typesec-securevalue",
                                invariant="label-provenance")
            return Decision(True, "durable identity and label preserved",
                            invariant="durable-identity")
        if call.tool == "approval/execute":
            if call.runtime.get("approved_hash") != call.runtime.get("current_hash"):
                return Decision(False, "approved call changed before execution",
                                mechanism="typesec-approval",
                                invariant="toctou-revalidation")
            if call.args.get("checkpoint") != "thread:maya":
                return Decision(False, "approval checkpoint subject mismatch",
                                mechanism="typesec-approval",
                                invariant="toctou-revalidation")
            return Decision(True, "canonical call revalidated at execution",
                            invariant="toctou-revalidation")
        if call.tool == "credential/vend":
            if call.args.get("raw") or call.args.get("scope") != WORLD.credential_scope:
                return Decision(False, "raw or widened credential request",
                                mechanism="typesec-credential",
                                invariant="credential-scope")
            if call.args.get("ttl", 0) > WORLD.credential_ttl_seconds:
                return Decision(False, "credential exceeds ODRL TTL cap",
                                mechanism="typesec-credential",
                                invariant="credential-ttl")
            return Decision(True, "scoped short-lived credential",
                            invariant="credential-scope")
        if call.tool == "replay/import":
            if (call.runtime.get("spliced") or call.runtime.get("duplicate_event")
                    or call.runtime.get("closed_schema") is not True):
                return Decision(False, "receipt/outbox evidence does not bind",
                                mechanism="typesec-receipt",
                                invariant="closed-receipt-chain")
            return Decision(True, "closed verified receipt chain",
                            invariant="closed-receipt-chain")
        if call.tool == "policy/evaluate":
            if call.runtime.get("unsupported_syntax"):
                return Decision(False, "unsupported policy construct fails closed",
                                mechanism="typesec-odrl",
                                invariant="parser-fail-closed")
            return Decision(True, "canonical policy digest agrees",
                            invariant="parser-fail-closed")
        if call.tool == "parallel/join":
            if set(call.runtime.get("tenants", [])) != {"northstar"}:
                return Decision(False, "parallel join crosses tenant binding",
                                mechanism="typesec-capability",
                                invariant="branch-tenant-binding")
            capabilities = call.runtime.get("capabilities", [])
            if len(capabilities) != len(set(capabilities)):
                return Decision(False, "capability reused across branches",
                                mechanism="typesec-capability",
                                invariant="lease-single-use")
            if call.runtime.get("retry_drift"):
                return Decision(False, "retry changed canonical request",
                                mechanism="typesec-idempotency",
                                invariant="idempotent-binding")
            return Decision(True, "each branch value stays resource-bound",
                            invariant="branch-tenant-binding")
        return None
