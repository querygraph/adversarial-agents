"""HTTP clients for the competitor policy engines.

OPA and Cerbos run as real containers (see docker-compose.yml) evaluating
generated translations of the canonical corpus. Each raw client sends the
canonical dispatch-time request and fails closed on transport, timeout, or
malformed-response faults. Separately named mediated profiles compose an
engine allow with the common execution-state mediator.

Engine endpoints (overridable for compose vs. host runs):

- ``AGENTGYM_OPA_URL``    default ``http://localhost:8181``
- ``AGENTGYM_CERBOS_URL`` default ``http://localhost:3592``
"""

from __future__ import annotations

import http.client
import json
import os
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


def _post(url: str, payload: dict) -> object:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode())


def _malformed(engine: str, detail: str) -> Decision:
    return Decision(
        False,
        f"{engine} malformed response, failing closed: {detail}",
        mechanism=engine.lower(),
        invariant="fail-closed",
    )


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
        except (OSError, http.client.HTTPException, ValueError) as exc:
            return Decision(False, f"OPA unavailable, failing closed: {exc}",
                            mechanism="opa")
        if not isinstance(body, dict):
            return _malformed("OPA", "top level must be an object")
        result = body.get("result")
        if not isinstance(result, dict):
            return Decision(False, "OPA decision undefined; deny by default",
                            mechanism="opa")
        allow = result.get("allow")
        if not isinstance(allow, bool):
            return _malformed("OPA", "result.allow must be a boolean")
        reason = result.get("reason", "no reason returned")
        proof_id = result.get("proof_id")
        invariant = result.get("invariant")
        if not isinstance(reason, str):
            return _malformed("OPA", "result.reason must be a string")
        if proof_id is not None and not isinstance(proof_id, str):
            return _malformed("OPA", "result.proof_id must be a string or null")
        if invariant is not None and not isinstance(invariant, str):
            return _malformed("OPA", "result.invariant must be a string or null")
        return Decision(
            allow,
            reason,
            proof_id=proof_id,
            mechanism="opa",
            invariant=invariant,
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
        except (OSError, http.client.HTTPException, ValueError) as exc:
            return Decision(False, f"Cerbos unavailable, failing closed: {exc}",
                            mechanism="cerbos")
        if not isinstance(body, dict):
            return _malformed("Cerbos", "top level must be an object")
        results = body.get("results")
        if results is None:
            results = []
        if not isinstance(results, list):
            return _malformed("Cerbos", "results must be an array")
        if not results:
            return Decision(False, "Cerbos returned no resource result; deny",
                            mechanism="cerbos")
        if len(results) != 1 or not isinstance(results[0], dict):
            return _malformed("Cerbos", "expected exactly one resource result object")
        actions = results[0].get("actions")
        if actions is None:
            actions = {}
        if not isinstance(actions, dict):
            return _malformed("Cerbos", "result.actions must be an object")
        effect = actions.get(call.action)
        if effect is not None and not isinstance(effect, str):
            return _malformed("Cerbos", "action effect must be a string")
        if effect not in {None, "EFFECT_ALLOW", "EFFECT_DENY"}:
            return _malformed("Cerbos", f"unknown action effect {effect!r}")
        call_id = body.get("cerbosCallId")
        if call_id is not None and not isinstance(call_id, str):
            return _malformed("Cerbos", "cerbosCallId must be a string or null")
        allowed = effect == "EFFECT_ALLOW"
        return Decision(
            allowed,
            f"Cerbos {effect or 'EFFECT_DENY'} for {call.action} on {kind}",
            # ``cerbosCallId`` is volatile transport telemetry, not a
            # verifiable authorization proof. Keeping it out of the canonical
            # result makes identical benchmark runs byte-stable.
            proof_id=None,
            mechanism="cerbos",
        )


ENGINES = {engine.mode: engine for engine in (OpaEngine(), CerbosEngine())}
