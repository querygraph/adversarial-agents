"""Canonical tool/action bindings and closed request-shape validation."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .model import ToolCall

TOOL_ACTIONS: dict[str, str] = {
    "catalog/query": "read",
    "catalog/dashboard": "dataset:view",
    "drive/create": "execute",
    "gmail/send": "execute",
    "delegate/run": "delegate",
    "memory/recall": "read",
    "approval/execute": "execute",
    "credential/vend": "read",
    "replay/import": "write",
    "policy/evaluate": "read",
    "parallel/join": "read",
}

ARCADE_TOOL_NAMES: dict[str, str] = {
    "catalog/query": "AgentGym.CatalogQuery",
    "catalog/dashboard": "AgentGym.CatalogDashboard",
    "drive/create": "GoogleDrive.CreateFile",
    "gmail/send": "Gmail.SendEmail",
    "delegate/run": "AgentGym.DelegateRun",
    "memory/recall": "AgentGym.MemoryRecall",
    "approval/execute": "AgentGym.ApprovalExecute",
    "credential/vend": "AgentGym.CredentialVend",
    "replay/import": "AgentGym.ReplayImport",
    "policy/evaluate": "AgentGym.PolicyEvaluate",
    "parallel/join": "AgentGym.ParallelJoin",
}


def workos_permission(call: ToolCall) -> str:
    # Provider namespace projected mechanically from the canonical RBAC
    # action; the underlying grant tuple is authored only once.
    return f"agentgym:{call.action}"


class CallSchemaError(ValueError):
    """A security-relevant call is missing, unknown, or incorrectly typed."""


def _closed(mapping: Mapping[str, Any], required: set[str], *, where: str,
            optional: set[str] | None = None) -> None:
    optional = optional or set()
    missing = required - set(mapping)
    unknown = set(mapping) - required - optional
    if missing:
        raise CallSchemaError(f"{where} missing required field(s): {sorted(missing)}")
    if unknown:
        raise CallSchemaError(f"{where} contains unknown field(s): {sorted(unknown)}")


def _string(value: Any, *, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise CallSchemaError(f"{where} must be a non-empty string")
    return value


def _boolean(value: Any, *, where: str) -> bool:
    if type(value) is not bool:
        raise CallSchemaError(f"{where} must be a boolean")
    return value


def _ttl(value: Any, *, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CallSchemaError(f"{where} must be a finite non-negative number")
    if not math.isfinite(value) or value < 0:
        raise CallSchemaError(f"{where} must be a finite non-negative number")
    return float(value)


def _strings(value: Any, *, where: str, nonempty: bool = True) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise CallSchemaError(f"{where} must be an array of strings")
    result = tuple(_string(item, where=f"{where}[]") for item in value)
    if nonempty and not result:
        raise CallSchemaError(f"{where} must not be empty")
    return result


def _array(value: Any, *, where: str, nonempty: bool = True) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise CallSchemaError(f"{where} must be an array")
    result = tuple(value)
    if nonempty and not result:
        raise CallSchemaError(f"{where} must not be empty")
    return result


def _integer(value: Any, *, where: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CallSchemaError(f"{where} must be an integer >= {minimum}")
    return value


def _sha256(value: Any, *, where: str) -> str:
    encoded = _string(value, where=where)
    if (
        not encoded.startswith("sha256:")
        or len(encoded) != 71
        or any(character not in "0123456789abcdef" for character in encoded[7:])
    ):
        raise CallSchemaError(f"{where} must be a sha256:<lowercase-hex> digest")
    return encoded


def _approval_call(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise CallSchemaError("current approved call must be an object")
    _closed(
        value,
        {"tool", "action", "resource", "args", "purpose", "delegated_user", "runtime"},
        where="current approved call",
    )
    _string(value["tool"], where="current approved call tool")
    _string(value["action"], where="current approved call action")
    _string(value["resource"], where="current approved call resource")
    _string(value["purpose"], where="current approved call purpose")
    _string(value["delegated_user"], where="current approved call delegated user")
    args = value["args"]
    runtime = value["runtime"]
    if not isinstance(args, Mapping) or not isinstance(runtime, Mapping):
        raise CallSchemaError("current approved call args/runtime must be objects")
    _closed(args, {"filename", "content_digest"}, where="current approved call args")
    _string(args["filename"], where="current approved call filename")
    _sha256(args["content_digest"], where="current approved call content digest")
    _closed(runtime, {"content_label"}, where="current approved call runtime")
    label = _string(runtime["content_label"], where="current approved call label")
    if label not in {"public", "sensitive"}:
        raise CallSchemaError("current approved call label is unknown")


def _receipt_chain(value: Any) -> None:
    events = _array(value, where="receipt chain")
    fields = {"event_id", "kind", "payload_hash", "previous", "schema", "digest"}
    for index, event in enumerate(events):
        where = f"receipt chain[{index}]"
        if not isinstance(event, Mapping):
            raise CallSchemaError(f"{where} must be an object")
        _closed(event, fields, where=where)
        _string(event["event_id"], where=f"{where}.event_id")
        kind = _string(event["kind"], where=f"{where}.kind")
        if kind not in {"authorization", "scan", "outbox"}:
            raise CallSchemaError(f"{where}.kind is unknown")
        _sha256(event["payload_hash"], where=f"{where}.payload_hash")
        previous = _string(event["previous"], where=f"{where}.previous")
        if previous != "genesis":
            _sha256(previous, where=f"{where}.previous")
        if event["schema"] != "agentgym.receipt/v1":
            raise CallSchemaError(f"{where}.schema is unsupported")
        _sha256(event["digest"], where=f"{where}.digest")


def _branch_events(value: Any) -> None:
    events = _array(value, where="branch events")
    fields = {"branch_id", "tenant", "capability", "attempt", "request_digest"}
    for index, event in enumerate(events):
        where = f"branch events[{index}]"
        if not isinstance(event, Mapping):
            raise CallSchemaError(f"{where} must be an object")
        _closed(event, fields, where=where)
        for name in ("branch_id", "tenant", "capability"):
            _string(event[name], where=f"{where}.{name}")
        _integer(event["attempt"], where=f"{where}.attempt", minimum=1)
        _sha256(event["request_digest"], where=f"{where}.request_digest")


def validate_bound_call(call: ToolCall) -> None:
    """Validate the closed schema shared by protected and mediated tracks.

    This function validates shape and types only.  Values that are validly
    encoded but exceed authority (a broad scope, sensitive label, or replay)
    remain policy decisions and are intentionally not rejected here.
    """
    expected_action = TOOL_ACTIONS.get(call.tool)
    if expected_action is None:
        raise CallSchemaError(f"tool {call.tool!r} has no registered binding")
    if call.action != expected_action:
        raise CallSchemaError(
            f"action binding mismatch: {call.tool!r} requires {expected_action!r}"
        )

    args = call.args
    runtime = call.runtime
    if call.tool == "catalog/query":
        _closed(args, {"columns", "predicate"}, where="query arguments")
        _closed(runtime, set(), where="query runtime")
        _strings(args["columns"], where="query columns")
        _string(args["predicate"], where="query predicate")
        _string(call.purpose, where="query purpose")
    elif call.tool == "catalog/dashboard":
        _closed(args, set(), where="dashboard arguments")
        _closed(runtime, set(), where="dashboard runtime")
    elif call.tool in {"drive/create", "gmail/send"}:
        _closed(args, set(), where="SaaS arguments")
        _closed(runtime, {"content_label"}, where="SaaS runtime")
        label = _string(runtime["content_label"], where="content label")
        if label not in {"public", "sensitive"}:
            raise CallSchemaError("content label is unknown")
        _string(call.delegated_user, where="delegated user")
        if call.tool == "gmail/send":
            _string(call.purpose, where="email purpose")
    elif call.tool == "delegate/run":
        _closed(args, {"ttl", "scope"}, where="delegation arguments")
        _closed(runtime, set(), where="delegation runtime")
        _ttl(args["ttl"], where="delegation ttl")
        _string(args["scope"], where="delegation scope")
    elif call.tool == "memory/recall":
        _closed(args, {"namespace"}, where="memory arguments")
        _closed(runtime, {"stored_label"}, where="memory runtime")
        _string(args["namespace"], where="memory namespace")
        label = _string(runtime["stored_label"], where="stored label")
        if label not in {"public", "sensitive"}:
            raise CallSchemaError("stored label is unknown")
    elif call.tool == "approval/execute":
        _closed(args, {"checkpoint"}, where="approval arguments")
        _closed(runtime, {"current_call"}, where="approval runtime")
        _string(args["checkpoint"], where="approval checkpoint")
        _approval_call(runtime["current_call"])
    elif call.tool == "credential/vend":
        _closed(args, {"raw", "scope", "ttl"}, where="credential arguments")
        _closed(runtime, set(), where="credential runtime")
        _boolean(args["raw"], where="raw credential flag")
        _string(args["scope"], where="credential scope")
        _ttl(args["ttl"], where="credential ttl")
    elif call.tool == "replay/import":
        _closed(args, set(), where="replay arguments")
        _closed(runtime, {"receipt_chain"}, where="replay runtime")
        _receipt_chain(runtime["receipt_chain"])
    elif call.tool == "policy/evaluate":
        _closed(args, set(), where="policy arguments")
        _closed(runtime, {"policy_document"}, where="policy runtime")
        if not isinstance(runtime["policy_document"], Mapping):
            raise CallSchemaError("policy document must be an object")
    elif call.tool == "parallel/join":
        _closed(args, set(), where="parallel arguments")
        _closed(runtime, {"branch_events"}, where="parallel runtime")
        _branch_events(runtime["branch_events"])
