"""Deterministic emulator of the current Arcade.dev tool API.

Implements the live contract (docs + ``arcade-py`` source, 2026-08):

- ``POST /v1/tools/authorize`` ``{"tool_name","user_id"}`` →
  ``AuthorizationResponse`` ``{"id","status","url","scopes","user_id",...}``
  with ``status`` in ``not_started|pending|completed|failed``.
- ``GET /v1/auth/status?id=&wait=`` long-poll (``wait`` capped at 59s).
- ``POST /v1/tools/execute`` ``{"tool_name","input","user_id"}`` →
  ``ExecuteToolResponse`` ``{"success","status","output":{"value",...}}``;
  on a requirements failure, ``output.error.kind`` carries the typed enum
  (e.g. ``TOOL_REQUIREMENTS_NOT_MET``, ``UPSTREAM_RUNTIME_AUTH_ERROR``).
- Arcade's raw-key ``Authorization: <api_key>`` header (no ``Bearer``).

Authorization is bound to the exact (user_id, tool_name). Execution
requires a completed authorization for that same pair; a request to execute
under a different user, or for a tool the user never authorized, returns a
``TOOL_REQUIREMENTS_NOT_MET`` error rather than running — the provider is
correct, and the benchmark's point is that a correct provider decision is
still not local content authorization.

Fault injection: ``timeout``, ``malformed``, ``wrong_type``,
``replay_completed`` (an ungranted authorization and execution are replayed
as completed), ``authorize_other_user`` (authorization succeeds but is
recorded against a different user), ``execute_wrong_type`` (the execute
success flag is a string), and ``execute_wrong_binding`` (the execute result
echoes a different user/tool binding).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from threading import Lock

from ..world import WORLD
from .protocol import request_fault

API_KEY = "arcade_agentgym_deterministic"
FAULTS = frozenset({
    "timeout",
    "malformed",
    "replay_completed",
    "authorize_other_user",
    "wrong_type",
    "wrong_shape",
    "execute_wrong_type",
    "execute_wrong_binding",
})


@dataclass
class Response:
    status: int
    body: dict | None
    raw: bytes | None = None

    def payload(self) -> bytes:
        if self.raw is not None:
            return self.raw
        return json.dumps(self.body or {}).encode()


@dataclass
class ArcadeEmulator:
    fault: str | None = None
    grants: set[tuple[str, str]] = field(default_factory=set)
    authorizations: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    _counter: int = 0
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.grants = set(WORLD.arcade_grants)

    def arm_fault(self, fault: str | None) -> None:
        self.fault = fault

    def handle(self, method: str, path: str, headers: dict[str, str],
               body: bytes) -> Response:
        if path.startswith("/_agentgym/fault"):
            return Response(410, {
                "message": "global fault endpoint disabled; use request metadata",
                "code": "global_fault_state_disabled",
            })
        if headers.get("Authorization") != API_KEY:
            return Response(401, {"message": "invalid api key"})
        try:
            fault = request_fault(headers, default=self.fault, allowed=FAULTS)
        except ValueError as exc:
            return Response(400, {"message": str(exc), "code": "invalid_fault"})
        if fault == "timeout":
            return Response(-1, None)
        if fault == "malformed":
            return Response(200, None, raw=b"not json")
        route = path.split("?", 1)[0]
        if method == "POST" and route == "/v1/tools/authorize":
            return self._authorize(json.loads(body or b"{}"), fault)
        if method == "GET" and route == "/v1/auth/status":
            return self._status(path, fault)
        if method == "POST" and route == "/v1/tools/execute":
            return self._execute(json.loads(body or b"{}"), fault)
        return Response(404, {"message": "not found"})

    def _authorize(self, payload: dict, fault: str | None) -> Response:
        tool = payload.get("tool_name")
        user = payload.get("user_id")
        if not tool or not user:
            return Response(400, {"message": "tool_name and user_id are required"})
        # ``authorize_other_user`` models a provider returning another
        # principal's completed authorization for a request that the caller
        # itself was entitled to make. Completion is therefore deliberately
        # computed from the requested pair before corrupting the echoed
        # binding.
        completed = (user, tool) in self.grants
        recorded_user = user
        if fault == "authorize_other_user":
            recorded_user = WORLD.supervisor
        if fault == "replay_completed":
            completed = True
        status = "completed" if completed else "pending"
        with self._lock:
            self._counter += 1
            auth_id = f"auth_{self._counter}"
            self.authorizations[auth_id] = (status, recorded_user, tool)
        response = {
            "id": auth_id,
            "status": status,
            "url": None if completed else f"https://arcade.dev/oauth/{auth_id}",
            "scopes": [],
            "user_id": recorded_user,
            "provider_id": "google",
        }
        if fault == "wrong_type":
            response["status"] = False
        if fault == "wrong_shape":
            return Response(200, [])  # type: ignore[arg-type]
        return Response(200, response)

    def _status(self, path: str, fault: str | None) -> Response:
        query = dict(
            pair.split("=", 1) for pair in path.split("?", 1)[-1].split("&") if "=" in pair
        )
        auth_id = query.get("id", "")
        with self._lock:
            record = self.authorizations.get(auth_id)
        if record is None:
            return Response(404, {"message": "unknown authorization id"})
        status, user, tool = record
        if fault == "replay_completed":
            status = "completed"
        return Response(200, {"id": auth_id, "status": status,
                              "user_id": user, "provider_id": "google"})

    def _execute(self, payload: dict, fault: str | None) -> Response:
        tool = payload.get("tool_name")
        user = payload.get("user_id")
        authorized = (user, tool) in self.grants or fault == "replay_completed"
        if not authorized:
            return Response(200, {
                "id": f"exec_{tool}",
                "success": False,
                "status": "failed",
                "output": {
                    "error": {
                        "kind": "TOOL_REQUIREMENTS_NOT_MET",
                        "message": f"{user} has not authorized {tool}",
                        "can_retry": False,
                    },
                },
            })
        response = {
            "id": f"exec_{tool}",
            "success": True,
            "status": "success",
            "output": {"value": {"executed": tool, "user_id": user}},
        }
        if fault == "execute_wrong_type":
            # This is intentionally the classic truthiness trap: a weak
            # ``bool(value)`` parser turns the string "false" into True.
            response["success"] = "false"
        if fault == "execute_wrong_binding":
            response["output"]["value"] = {
                "executed": "Gmail.SendEmail",
                "user_id": WORLD.supervisor,
            }
        return Response(200, response)
