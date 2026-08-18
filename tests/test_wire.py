"""The provider emulators must speak the current wire contracts."""

from __future__ import annotations

import json

from agentgym.wire.arcade import API_KEY as ARCADE_KEY
from agentgym.wire.arcade import ArcadeEmulator
from agentgym.wire.workos import API_KEY as WORKOS_KEY
from agentgym.wire.workos import WorkOSEmulator


def _workos(emulator, path, payload, key=WORKOS_KEY):
    headers = {"Authorization": f"Bearer {key}"}
    return emulator.handle("POST", path, headers, json.dumps(payload).encode())


def test_workos_uses_current_authorization_check_path_and_shape() -> None:
    emu = WorkOSEmulator()
    path = "/authorization/organization_memberships/om_maya/check"
    response = _workos(emu, path, {
        "permission_slug": "dataset:view",
        "resource_type_slug": "dataset",
        "resource_external_id": "northstar-study",
    })
    assert response.status == 200
    assert response.body == {"authorized": True}


def test_workos_denies_sibling_resource() -> None:
    emu = WorkOSEmulator()
    path = "/authorization/organization_memberships/om_maya/check"
    response = _workos(emu, path, {
        "permission_slug": "dataset:view",
        "resource_type_slug": "dataset",
        "resource_external_id": "harbor-study",
    })
    assert response.body == {"authorized": False}


def test_workos_requires_bearer_api_key() -> None:
    emu = WorkOSEmulator()
    path = "/authorization/organization_memberships/om_maya/check"
    response = emu.handle("POST", path, {}, b"{}")
    assert response.status == 401


def test_workos_retired_fga_path_is_gone() -> None:
    emu = WorkOSEmulator()
    response = _workos(emu, "/fga/v1/check", {"op": "any_of", "checks": []})
    assert response.status == 410
    assert response.body["code"] == "fga_api_retired"


def test_workos_stale_allow_fault_survives_revocation() -> None:
    emu = WorkOSEmulator(fault="stale_allow")
    emu.revoked.add(("om_maya", "dataset:view", "dataset", "northstar-study"))
    path = "/authorization/organization_memberships/om_maya/check"
    response = _workos(emu, path, {
        "permission_slug": "dataset:view",
        "resource_type_slug": "dataset",
        "resource_external_id": "northstar-study",
    })
    assert response.body == {"authorized": True}


def _arcade(emulator, method, path, payload=None, key=ARCADE_KEY):
    headers = {"Authorization": key}
    body = json.dumps(payload).encode() if payload is not None else b""
    return emulator.handle(method, path, headers, body)


def test_arcade_authorize_returns_current_response_shape() -> None:
    emu = ArcadeEmulator()
    response = _arcade(emu, "POST", "/v1/tools/authorize", {
        "tool_name": "Gmail.SendEmail",
        "user_id": "user:maya@civic.example",
    })
    assert response.status == 200
    body = response.body
    assert body["status"] == "completed"
    assert body["user_id"] == "user:maya@civic.example"
    assert set(body) >= {"id", "status", "url", "scopes", "user_id", "provider_id"}


def test_arcade_uses_raw_key_header_not_bearer() -> None:
    emu = ArcadeEmulator()
    response = emu.handle("POST", "/v1/tools/authorize",
                          {"Authorization": f"Bearer {ARCADE_KEY}"}, b"{}")
    assert response.status == 401


def test_arcade_execute_unauthorized_returns_typed_error_kind() -> None:
    emu = ArcadeEmulator()
    response = _arcade(emu, "POST", "/v1/tools/execute", {
        "tool_name": "GoogleDrive.CreateFile",
        "user_id": "user:leo@civic.example",
        "input": {},
    })
    assert response.status == 200
    assert response.body["success"] is False
    assert response.body["output"]["error"]["kind"] == "TOOL_REQUIREMENTS_NOT_MET"


def test_arcade_authorize_pending_for_ungranted_user() -> None:
    emu = ArcadeEmulator()
    response = _arcade(emu, "POST", "/v1/tools/authorize", {
        "tool_name": "GoogleDrive.CreateFile",
        "user_id": "user:leo@civic.example",
    })
    assert response.body["status"] == "pending"
    assert response.body["url"].startswith("https://arcade.dev/oauth/")
