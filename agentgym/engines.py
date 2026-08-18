"""HTTP clients for the competitor policy engines.

OPA and Cerbos run as real containers (see docker-compose.yml) evaluating
policies translated as faithfully as their languages allow from the same
world model the benchmark uses everywhere. Each client sends the canonical
dispatch-time request — never runtime facts — and fails closed on any
transport, timeout, or malformed-response fault, exactly as the provider
integrations do.

Engine endpoints (overridable for compose vs. host runs):

- ``AGENTGYM_OPA_URL``    default ``http://localhost:8181``
- ``AGENTGYM_CERBOS_URL`` default ``http://localhost:3592``
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .model import Decision, Principal, ToolCall

TIMEOUT_SECONDS = 5.0

# The resource "kind" Cerbos policies are organized around, per tool.
CERBOS_KIND = {
    "catalog/query": "dataset",
    "catalog/dashboard": "dashboard",
    "drive/create": "saas_channel",
    "gmail/send": "saas_channel",
    "delegate/run": "delegation",
    "memory/recall": "memory",
    "approval/execute": "approval",
    "credential/vend": "credential",
    "replay/import": "replay",
    "policy/evaluate": "policy_corpus",
    "parallel/join": "parallel_join",
}


def _post(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode())


class OpaEngine:
    """Open Policy Agent: ``POST /v1/data/agentgym/decision``.

    An absent ``result`` (undefined decision) is a deny — OPA omits the key
    when no rule matched, and treating that as anything but deny would be a
    fail-open integration.
    """

    mode = "opa"

    def __init__(self) -> None:
        self.url = os.environ.get("AGENTGYM_OPA_URL", "http://localhost:8181")

    def check(self, principal: Principal, call: ToolCall) -> Decision:
        try:
            body = _post(
                f"{self.url}/v1/data/agentgym/decision",
                {"input": call.request(principal)},
            )
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return Decision(False, f"OPA unavailable, failing closed: {exc}",
                            mechanism="opa")
        result = body.get("result")
        if not isinstance(result, dict):
            return Decision(False, "OPA decision undefined; deny by default",
                            mechanism="opa")
        return Decision(
            bool(result.get("allow")),
            str(result.get("reason", "no reason returned")),
            proof_id=result.get("proof_id"),
            mechanism="opa",
            invariant=result.get("invariant"),
        )


class CerbosEngine:
    """Cerbos: ``POST /api/check/resources`` with principal/resource attrs."""

    mode = "cerbos"

    def __init__(self) -> None:
        self.url = os.environ.get("AGENTGYM_CERBOS_URL", "http://localhost:3592")

    def check(self, principal: Principal, call: ToolCall) -> Decision:
        kind = CERBOS_KIND.get(call.tool)
        if kind is None:
            return Decision(False, f"no Cerbos resource kind bound for {call.tool}",
                            mechanism="cerbos", invariant="unknown-tool-deny")
        request = {
            "requestId": f"agentgym-{call.tool}",
            "principal": {
                "id": principal.subject,
                "roles": ["user"],
                "attr": {"organization": principal.organization},
            },
            "resources": [{
                "resource": {
                    "kind": kind,
                    "id": call.resource,
                    "attr": {
                        "tool": call.tool,
                        "purpose": call.purpose or "",
                        "delegated_user": call.delegated_user or "",
                        "args": dict(call.args),
                    },
                },
                "actions": [call.action],
            }],
        }
        try:
            body = _post(f"{self.url}/api/check/resources", request)
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return Decision(False, f"Cerbos unavailable, failing closed: {exc}",
                            mechanism="cerbos")
        results = body.get("results") or []
        if not results:
            return Decision(False, "Cerbos returned no resource result; deny",
                            mechanism="cerbos")
        actions = results[0].get("actions") or {}
        effect = actions.get(call.action)
        allowed = effect == "EFFECT_ALLOW"
        return Decision(
            allowed,
            f"Cerbos {effect or 'EFFECT_DENY'} for {call.action} on {kind}",
            proof_id=body.get("cerbosCallId"),
            mechanism="cerbos",
        )


ENGINES = {engine.mode: engine for engine in (OpaEngine(), CerbosEngine())}
