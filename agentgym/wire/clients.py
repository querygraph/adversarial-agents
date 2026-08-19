"""Clients that speak the emulated provider contracts.

By default a client talks to an in-process emulator instance (fast, used by
the unit suite). Point ``AGENTGYM_WORKOS_URL`` / ``AGENTGYM_ARCADE_URL`` at
the compose services and the same client issues real HTTP requests to the
emulator servers, exercising the actual wire path in the Docker matrix. The
request and response shapes are identical either way, so the enforcement
code above the client cannot tell which transport served it.

Any transport failure, timeout, non-2xx status, or unparseable body raises
:class:`ProviderFault`, which every enforcement mode converts to a
fail-closed deny.
"""

from __future__ import annotations

import http.client
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .arcade import API_KEY as ARCADE_KEY
from .arcade import ArcadeEmulator
from .protocol import CLEAR_FAULT, FAULT_HEADER
from .workos import API_KEY as WORKOS_KEY
from .workos import MEMBERSHIPS, WorkOSEmulator

CLIENT_TIMEOUT = 3.0
_FAULT_UNSET = object()


class ProviderFault(RuntimeError):
    """A deterministic malformed, unavailable, or timed-out provider response."""


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field {key!r}")
        value[key] = item
    return value


def _http(method: str, url: str, headers: dict[str, str],
          body: dict | None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=CLIENT_TIMEOUT) as response:
            parsed = json.loads(
                response.read().decode(), object_pairs_hook=_json_object,
            )
    except urllib.error.HTTPError as exc:
        raise ProviderFault(f"HTTP {exc.code}") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise ProviderFault(f"transport error: {exc}") from exc
    except ValueError as exc:
        raise ProviderFault(f"malformed response: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProviderFault("malformed response: top level must be an object")
    return parsed


def _response_object(value: object, provider: str) -> dict:
    if not isinstance(value, dict):
        raise ProviderFault(f"malformed {provider} response: expected an object")
    return value


def _required_bool(body: dict, field: str, provider: str) -> bool:
    value = body.get(field)
    if not isinstance(value, bool):
        raise ProviderFault(
            f"malformed {provider} response: {field} must be a boolean"
        )
    return value


def _required_str(body: dict, field: str, provider: str) -> str:
    value = body.get(field)
    if not isinstance(value, str):
        raise ProviderFault(
            f"malformed {provider} response: {field} must be a string"
        )
    return value


def _required_nonempty_str(body: dict, field: str, provider: str) -> str:
    value = _required_str(body, field, provider)
    if not value.strip():
        raise ProviderFault(
            f"malformed {provider} response: {field} must not be empty"
        )
    return value


def _optional_str(body: dict, field: str, provider: str) -> str | None:
    value = body.get(field)
    if value is not None and not isinstance(value, str):
        raise ProviderFault(
            f"malformed {provider} response: {field} must be a string or null"
        )
    return value


def _required_string_list(body: dict, field: str, provider: str) -> list[str]:
    value = body.get(field)
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(value) != len(set(value))
    ):
        raise ProviderFault(
            f"malformed {provider} response: {field} must be unique strings"
        )
    return value


def _closed_fields(
    body: dict, *, provider: str, required: set[str], optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = required - set(body)
    unknown = set(body) - required - optional
    if missing or unknown:
        raise ProviderFault(
            f"malformed {provider} response: missing={sorted(missing)}, "
            f"unknown={sorted(unknown)}"
        )


class WorkOSClient:
    """Client for the WorkOS authorization check."""

    def __init__(self, emulator: WorkOSEmulator | None = None) -> None:
        # Explicit dependency injection always wins over ambient Docker
        # configuration. This keeps unit/integration gates deterministic even
        # when their process also has the live-matrix URL exported.
        self.url = (
            None if emulator is not None
            else os.environ.get("AGENTGYM_WORKOS_URL")
        )
        self.emulator = emulator if emulator is not None else WorkOSEmulator()
        self._fault: object = _FAULT_UNSET

    def arm_fault(self, fault: str | None) -> None:
        # Fault state belongs to this client/run. It is attached to each
        # provider request instead of mutating a process-global HTTP emulator.
        self._fault = fault

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {WORKOS_KEY}",
            "Content-Type": "application/json",
        }
        if self._fault is not _FAULT_UNSET:
            headers[FAULT_HEADER] = (
                CLEAR_FAULT if self._fault is None else str(self._fault)
            )
        return headers

    def check(self, subject: str, permission_slug: str, resource: str) -> bool:
        if (
            not isinstance(subject, str)
            or not subject.strip()
            or not isinstance(permission_slug, str)
            or not permission_slug.strip()
        ):
            raise ProviderFault(
                "malformed WorkOS request: subject and permission are required"
            )
        membership = MEMBERSHIPS.get(subject)
        if membership is None:
            return False
        if not isinstance(resource, str) or not resource.strip() or "/" not in resource:
            raise ProviderFault("malformed WorkOS request: resource must be type/id")
        resource_type, external_id = resource.split("/", 1)
        if not resource_type or not external_id:
            raise ProviderFault("malformed WorkOS request: resource must be type/id")
        payload = {
            "permission_slug": permission_slug,
            "resource_type_slug": resource_type,
            "resource_external_id": external_id,
        }
        path = f"/authorization/organization_memberships/{membership}/check"
        headers = self._headers()
        if self.url:
            body = _response_object(
                _http("POST", f"{self.url}{path}", headers, payload),
                "WorkOS",
            )
            _closed_fields(body, provider="WorkOS", required={"authorized"})
            return _required_bool(body, "authorized", "WorkOS")
        response = self.emulator.handle("POST", path, headers,
                                        json.dumps(payload).encode())
        if response.status == -1:
            raise ProviderFault("WorkOS timeout")
        if response.status != 200 or response.raw is not None:
            raise ProviderFault(f"WorkOS status {response.status}")
        body = _response_object(response.body, "WorkOS")
        _closed_fields(body, provider="WorkOS", required={"authorized"})
        return _required_bool(body, "authorized", "WorkOS")


class ArcadeClient:
    """Client for Arcade authorization + execution."""

    def __init__(self, emulator: ArcadeEmulator | None = None) -> None:
        self.url = (
            None if emulator is not None
            else os.environ.get("AGENTGYM_ARCADE_URL")
        )
        self.emulator = emulator if emulator is not None else ArcadeEmulator()
        self._fault: object = _FAULT_UNSET

    def arm_fault(self, fault: str | None) -> None:
        self._fault = fault

    def _call(self, method: str, path: str, payload: dict | None) -> dict:
        headers = {"Authorization": ARCADE_KEY, "Content-Type": "application/json"}
        if self._fault is not _FAULT_UNSET:
            headers[FAULT_HEADER] = (
                CLEAR_FAULT if self._fault is None else str(self._fault)
            )
        if self.url:
            return _response_object(
                _http(method, f"{self.url}{path}", headers, payload),
                "Arcade",
            )
        response = self.emulator.handle(
            method, path, headers,
            json.dumps(payload).encode() if payload is not None else b"",
        )
        if response.status == -1:
            raise ProviderFault("Arcade timeout")
        if response.status != 200 or response.raw is not None:
            raise ProviderFault(f"Arcade status {response.status}")
        return _response_object(response.body, "Arcade")

    def authorized(self, user: str, tool: str) -> bool:
        """True only if the exact user has a completed authorization for tool."""
        if (
            not isinstance(user, str)
            or not user.strip()
            or not isinstance(tool, str)
            or not tool.strip()
        ):
            raise ProviderFault("malformed Arcade request: user and tool are required")
        body = self._call("POST", "/v1/tools/authorize",
                           {"tool_name": tool, "user_id": user})
        _closed_fields(
            body,
            provider="Arcade authorization",
            required={"id", "status", "url", "scopes", "user_id", "provider_id"},
        )
        _required_nonempty_str(body, "id", "Arcade authorization")
        status = _required_str(body, "status", "Arcade")
        url = _optional_str(body, "url", "Arcade authorization")
        _required_string_list(body, "scopes", "Arcade authorization")
        response_user = _required_nonempty_str(body, "user_id", "Arcade")
        provider_id = _required_nonempty_str(
            body, "provider_id", "Arcade authorization",
        )
        if status not in {"not_started", "pending", "completed", "failed"}:
            raise ProviderFault(f"malformed Arcade response: unknown status {status!r}")
        if status == "completed" and url is not None:
            raise ProviderFault(
                "malformed Arcade response: completed authorization has a URL"
            )
        if status == "pending" and not url:
            raise ProviderFault(
                "malformed Arcade response: pending authorization lacks a URL"
            )
        if url is not None:
            parsed_url = urlsplit(url)
            if (
                parsed_url.scheme != "https"
                or not parsed_url.netloc
                or parsed_url.username is not None
                or parsed_url.password is not None
                or not (
                    parsed_url.hostname == "arcade.dev"
                    or (parsed_url.hostname or "").endswith(".arcade.dev")
                )
            ):
                raise ProviderFault(
                    "malformed Arcade response: authorization URL must be "
                    "absolute HTTPS on an Arcade host without userinfo"
                )
        if tool.startswith(("GoogleDrive.", "Gmail.")) and provider_id != "google":
            raise ProviderFault(
                "Arcade authorization response provider binding mismatch"
            )
        return status == "completed" and response_user == user

    def execute(self, user: str, tool: str, inputs: dict) -> bool:
        """Execute only when Arcade echoes the exact user/tool pair as success."""
        if (
            not isinstance(user, str)
            or not user.strip()
            or not isinstance(tool, str)
            or not tool.strip()
        ):
            raise ProviderFault("malformed Arcade execute request: user and tool required")
        if not isinstance(inputs, dict):
            raise ProviderFault("malformed Arcade execute request: input must be an object")
        body = self._call(
            "POST", "/v1/tools/execute",
            {"tool_name": tool, "input": inputs, "user_id": user},
        )
        _closed_fields(
            body,
            provider="Arcade execution",
            required={"id", "success", "status", "output"},
        )
        _required_nonempty_str(body, "id", "Arcade execution")
        success = _required_bool(body, "success", "Arcade")
        status = _required_str(body, "status", "Arcade")
        output = _response_object(body.get("output"), "Arcade output")
        if success:
            if status != "success":
                raise ProviderFault("malformed Arcade response: success/status mismatch")
            _closed_fields(output, provider="Arcade output", required={"value"})
            value = _response_object(output.get("value"), "Arcade output value")
            _closed_fields(
                value,
                provider="Arcade output value",
                required={"executed", "user_id"},
            )
            executed_tool = _required_nonempty_str(
                value, "executed", "Arcade output value",
            )
            executed_user = _required_nonempty_str(
                value, "user_id", "Arcade output value",
            )
            if executed_tool != tool or executed_user != user:
                raise ProviderFault("Arcade execution response binding mismatch")
            return True
        if status != "failed":
            raise ProviderFault("malformed Arcade response: failure/status mismatch")
        _closed_fields(output, provider="Arcade output", required={"error"})
        error = _response_object(output.get("error"), "Arcade execution error")
        _closed_fields(
            error,
            provider="Arcade execution error",
            required={"kind", "message", "can_retry"},
        )
        kind = _required_str(error, "kind", "Arcade")
        _required_nonempty_str(error, "message", "Arcade execution error")
        _required_bool(error, "can_retry", "Arcade execution error")
        if kind not in {"TOOL_REQUIREMENTS_NOT_MET", "UPSTREAM_RUNTIME_AUTH_ERROR"}:
            raise ProviderFault(f"malformed Arcade response: unknown error kind {kind!r}")
        return False
