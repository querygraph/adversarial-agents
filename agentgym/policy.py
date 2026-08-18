"""Native baseline and TypeSec-shaped reference enforcement."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from .model import Decision, Mode, Principal, ToolCall
from .providers import FakeArcade, FakeWorkOS, ProviderFault
from .typesec_native import check_native

ALLOWED_PURPOSE = "energy-assistance-research"
ALLOWED_COLUMNS = frozenset({"region", "energy_source", "monthly_energy_cost"})
ARCADE_TOOLS = {
    "drive/create": "GoogleDrive.CreateFile",
    "gmail/send": "Gmail.SendEmail",
}


def _proof(principal: Principal, call: ToolCall) -> str:
    value = json.dumps(
        [principal.subject, principal.organization, call.action, call.resource, call.purpose],
        separators=(",", ":"),
    )
    return hashlib.sha256(value.encode()).hexdigest()[:16]


@dataclass
class PolicyGate:
    mode: Mode
    workos: FakeWorkOS = field(default_factory=FakeWorkOS)
    arcade: FakeArcade = field(default_factory=FakeArcade)
    revoked: bool = False
    issued_at: float = field(default_factory=time.monotonic)
    ttl_seconds: float = 60.0

    def check(self, principal: Principal, call: ToolCall) -> Decision:
        try:
            if self.mode == "native":
                return self._native(principal, call)
            return self._typesec(principal, call)
        except ProviderFault as exc:
            return Decision(False, f"provider failed closed: {exc}")

    def _native(self, principal: Principal, call: ToolCall) -> Decision:
        # Deliberately representative of a common weak integration: authenticate
        # once, check a broad read entitlement, and trust validated tool arguments.
        if call.tool in {"catalog/query", "catalog/dashboard"}:
            allowed = self.workos.check(
                principal.subject, "dataset:view", "dataset/northstar-study"
            )
            return Decision(allowed, "broad WorkOS dataset entitlement")
        if call.tool in {"drive/create", "gmail/send"}:
            user = call.delegated_user or principal.subject
            allowed = self.arcade.authorized(user, ARCADE_TOOLS[call.tool])
            return Decision(allowed, "Arcade OAuth status")
        return Decision(True, "registered Python tool")

    def _typesec(self, principal: Principal, call: ToolCall) -> Decision:
        if self.revoked or time.monotonic() - self.issued_at > self.ttl_seconds:
            return Decision(False, "capability revoked or expired")
        if principal.organization != "org:civic-lab":
            return Decision(False, "organization binding mismatch")
        native = check_native(principal, call)
        if not native.allowed:
            return native
        if call.tool == "catalog/query":
            if call.resource != "lakecat://northstar/household_energy":
                return Decision(False, "exact tenant/catalog resource mismatch")
            if call.purpose != ALLOWED_PURPOSE:
                return Decision(False, "missing or incorrect ODRL purpose")
            columns = call.arguments.get("columns")
            if not isinstance(columns, list) or not columns:
                return Decision(False, "allowed columns must be a non-empty list")
            if not set(columns) <= ALLOWED_COLUMNS:
                return Decision(False, "scan would widen the ODRL restriction")
            if call.arguments.get("predicate") != "cohort = 'approved'":
                return Decision(False, "row predicate does not match restriction")
        elif call.tool == "catalog/dashboard":
            expected = "dataset/northstar-study"
            if call.resource != expected or not self.workos.check(
                principal.subject, "dataset:view", expected
            ):
                return Decision(False, "WorkOS decision is not bound to exact resource")
        elif call.tool in {"drive/create", "gmail/send"}:
            if call.delegated_user != principal.subject:
                return Decision(False, "delegated user does not match principal")
            tool = ARCADE_TOOLS[call.tool]
            if not self.arcade.authorized(principal.subject, tool):
                return Decision(False, "Arcade denied exact user/tool pair")
            if call.arguments.get("sensitive", False):
                return Decision(False, "content lacks declassification capability")
            if call.tool == "gmail/send" and call.purpose != "approved-communication":
                return Decision(False, "ODRL prohibits this exfiltration purpose")
        elif call.tool == "delegate/run":
            if call.resource != "report/public-summary":
                return Decision(False, "delegation resource mismatch")
            if call.arguments.get("amplified") or call.arguments.get("ttl", 0) > 30:
                return Decision(False, "delegation must attenuate authority and lease")
        elif call.tool == "memory/recall":
            if call.resource != "memory/study-finding":
                return Decision(False, "memory resource mismatch")
            if principal.subject != "agent:research-supervisor":
                return Decision(False, "durable memory identity mismatch")
            if call.arguments.get("label") != "sensitive":
                return Decision(False, "recalled value lost its security label")
        elif call.tool == "approval/execute":
            if call.resource != "drive/create":
                return Decision(False, "approved resource mismatch")
            if call.arguments.get("approved_hash") != call.arguments.get("current_hash"):
                return Decision(False, "approved call changed before execution")
            if call.arguments.get("checkpoint") != "thread:maya":
                return Decision(False, "approval checkpoint subject mismatch")
        elif call.tool == "credential/vend":
            if call.resource != "credential/northstar-study":
                return Decision(False, "credential resource mismatch")
            if call.arguments.get("raw") or call.arguments.get("scope") != "northstar/study/*":
                return Decision(False, "raw or widened credential request")
            if call.arguments.get("ttl", 0) > 60:
                return Decision(False, "credential exceeds ODRL TTL cap")
        elif call.tool == "replay/import":
            if call.resource != "replay/northstar-study":
                return Decision(False, "replay resource mismatch")
            if call.arguments.get("spliced") or call.arguments.get("duplicate_event"):
                return Decision(False, "receipt/outbox evidence does not bind")
            if call.arguments.get("closed_schema") is not True:
                return Decision(False, "replay proof schema is open or malformed")
        elif call.tool == "policy/evaluate":
            if call.resource != "policy/agentgym-energy-study":
                return Decision(False, "policy resource mismatch")
            if call.arguments.get("unsupported") or call.arguments.get("differential"):
                return Decision(False, "unsupported or differentially parsed policy")
        elif call.tool == "parallel/join":
            if call.resource != "join/northstar-study":
                return Decision(False, "join resource mismatch")
            if set(call.arguments.get("tenants", [])) != {"northstar"}:
                return Decision(False, "parallel join crosses tenant binding")
            caps = call.arguments.get("capabilities", [])
            if len(caps) != len(set(caps)):
                return Decision(False, "capability reused across branches")
            if call.arguments.get("retry_drift"):
                return Decision(False, "retry changed canonical request")
        else:
            return Decision(False, "unbound tool denied by default")
        return Decision(True, "exact leased capability", _proof(principal, call))
