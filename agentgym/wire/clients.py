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

import json
import os
import urllib.error
import urllib.request

from .arcade import API_KEY as ARCADE_KEY
from .arcade import ArcadeEmulator
from .workos import API_KEY as WORKOS_KEY
from .workos import MEMBERSHIPS, WorkOSEmulator

CLIENT_TIMEOUT = 3.0


class ProviderFault(RuntimeError):
    """A deterministic malformed, unavailable, or timed-out provider response."""


def _http(method: str, url: str, headers: dict[str, str],
          body: dict | None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=CLIENT_TIMEOUT) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise ProviderFault(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ProviderFault(f"transport error: {exc}") from exc
    except ValueError as exc:
        raise ProviderFault(f"malformed response: {exc}") from exc


class WorkOSClient:
    """Client for the WorkOS authorization check."""

    def __init__(self, emulator: WorkOSEmulator | None = None) -> None:
        self.url = os.environ.get("AGENTGYM_WORKOS_URL")
        self.emulator = emulator or WorkOSEmulator()

    def arm_fault(self, fault: str | None) -> None:
        if self.url:
            _http("POST", f"{self.url}/_agentgym/fault",
                  {"Content-Type": "application/json"}, {"fault": fault})
        else:
            self.emulator.arm_fault(fault)

    def check(self, subject: str, permission_slug: str, resource: str) -> bool:
        membership = MEMBERSHIPS.get(subject)
        if membership is None:
            return False
        resource_type, external_id = resource.split("/", 1)
        payload = {
            "permission_slug": permission_slug,
            "resource_type_slug": resource_type,
            "resource_external_id": external_id,
        }
        path = f"/authorization/organization_memberships/{membership}/check"
        headers = {"Authorization": f"Bearer {WORKOS_KEY}",
                   "Content-Type": "application/json"}
        if self.url:
            body = _http("POST", f"{self.url}{path}", headers, payload)
            return bool(body.get("authorized"))
        response = self.emulator.handle("POST", path, headers,
                                        json.dumps(payload).encode())
        if response.status == -1:
            raise ProviderFault("WorkOS timeout")
        if response.status != 200 or response.raw is not None:
            raise ProviderFault(f"WorkOS status {response.status}")
        return bool((response.body or {}).get("authorized"))


class ArcadeClient:
    """Client for Arcade authorization + execution."""

    def __init__(self, emulator: ArcadeEmulator | None = None) -> None:
        self.url = os.environ.get("AGENTGYM_ARCADE_URL")
        self.emulator = emulator or ArcadeEmulator()

    def arm_fault(self, fault: str | None) -> None:
        if self.url:
            _http("POST", f"{self.url}/_agentgym/fault",
                  {"Content-Type": "application/json"}, {"fault": fault})
        else:
            self.emulator.arm_fault(fault)

    def _call(self, method: str, path: str, payload: dict | None) -> dict:
        headers = {"Authorization": ARCADE_KEY, "Content-Type": "application/json"}
        if self.url:
            return _http(method, f"{self.url}{path}", headers, payload)
        response = self.emulator.handle(
            method, path, headers,
            json.dumps(payload).encode() if payload is not None else b"",
        )
        if response.status == -1:
            raise ProviderFault("Arcade timeout")
        if response.status != 200 or response.raw is not None:
            raise ProviderFault(f"Arcade status {response.status}")
        return response.body or {}

    def authorized(self, user: str, tool: str) -> bool:
        """True only if the exact user has a completed authorization for tool."""
        body = self._call("POST", "/v1/tools/authorize",
                           {"tool_name": tool, "user_id": user})
        return body.get("status") == "completed" and body.get("user_id") == user
