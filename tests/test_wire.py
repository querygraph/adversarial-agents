"""The provider emulators must speak the current wire contracts."""

from __future__ import annotations

import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from threading import Thread

import pytest

from agentgym.wire import ArcadeClient, ProviderFault, WorkOSClient
from agentgym.wire.arcade import API_KEY as ARCADE_KEY
from agentgym.wire.arcade import ArcadeEmulator
from agentgym.wire.servers import _make_handler
from agentgym.wire.workos import API_KEY as WORKOS_KEY
from agentgym.wire.workos import WorkOSEmulator


@contextmanager
def _http_emulator(emulator) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(emulator))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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
    path = "/authorization/organization_memberships/om_maya/check"
    response = _workos(emu, path, {
        "permission_slug": "dataset:view",
        "resource_type_slug": "dataset",
        "resource_external_id": "northstar-study",
    })
    assert response.body == {"authorized": True}

    emu.arm_fault(None)
    response = _workos(emu, path, {
        "permission_slug": "dataset:view",
        "resource_type_slug": "dataset",
        "resource_external_id": "northstar-study",
    })
    assert response.body == {"authorized": True}


def test_workos_wrong_resource_fault_returns_sibling_allow() -> None:
    emu = WorkOSEmulator(fault="wrong_resource")
    response = _workos(
        emu,
        "/authorization/organization_memberships/om_maya/check",
        {
            "permission_slug": "dataset:view",
            "resource_type_slug": "dataset",
            "resource_external_id": "harbor-study",
        },
    )
    assert response.body == {"authorized": True}


def test_explicit_workos_emulator_wins_over_environment_url(monkeypatch) -> None:
    monkeypatch.setenv("AGENTGYM_WORKOS_URL", "http://127.0.0.1:1")
    client = WorkOSClient(WorkOSEmulator())
    assert client.url is None
    assert client.check(
        "user:maya@civic.example",
        "dataset:view",
        "dataset/northstar-study",
    )


def test_workos_http_faults_are_isolated_per_concurrent_client(monkeypatch) -> None:
    with _http_emulator(WorkOSEmulator()) as url:
        monkeypatch.setenv("AGENTGYM_WORKOS_URL", url)
        healthy = WorkOSClient()
        faulty = WorkOSClient()
        faulty.arm_fault("string_false")

        def check(index: int) -> str:
            client = faulty if index % 2 else healthy
            try:
                allowed = client.check(
                    "user:maya@civic.example",
                    "dataset:view",
                    "dataset/northstar-study",
                )
            except ProviderFault:
                return "fault"
            return "allow" if allowed else "deny"

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(check, range(64)))

        assert outcomes == [
            "fault" if index % 2 else "allow" for index in range(64)
        ]
        assert healthy.check(
            "user:maya@civic.example",
            "dataset:view",
            "dataset/northstar-study",
        )


def test_client_clear_fault_overrides_explicit_emulator_default() -> None:
    client = WorkOSClient(WorkOSEmulator(fault="string_false"))
    client.arm_fault(None)
    assert client.check(
        "user:maya@civic.example",
        "dataset:view",
        "dataset/northstar-study",
    )


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


def test_arcade_replay_fault_completes_ungranted_authorize_and_execute() -> None:
    emu = ArcadeEmulator(fault="replay_completed")
    user = "user:leo@civic.example"
    tool = "GoogleDrive.CreateFile"
    authorization = _arcade(emu, "POST", "/v1/tools/authorize", {
        "tool_name": tool,
        "user_id": user,
    })
    assert authorization.body["status"] == "completed"
    assert authorization.body["user_id"] == user

    execution = _arcade(emu, "POST", "/v1/tools/execute", {
        "tool_name": tool,
        "user_id": user,
        "input": {},
    })
    assert execution.body["success"] is True


def test_arcade_other_user_fault_returns_completed_wrong_binding() -> None:
    emu = ArcadeEmulator(fault="authorize_other_user")
    response = _arcade(emu, "POST", "/v1/tools/authorize", {
        "tool_name": "GoogleDrive.CreateFile",
        "user_id": "user:maya@civic.example",
    })
    assert response.body["status"] == "completed"
    assert response.body["user_id"] == "agent:research-supervisor"


def test_arcade_execute_fault_payloads_are_deterministic() -> None:
    payload = {
        "tool_name": "GoogleDrive.CreateFile",
        "user_id": "user:maya@civic.example",
        "input": {},
    }
    wrong_type = _arcade(
        ArcadeEmulator(fault="execute_wrong_type"),
        "POST",
        "/v1/tools/execute",
        payload,
    )
    assert wrong_type.body["success"] == "false"

    wrong_binding = _arcade(
        ArcadeEmulator(fault="execute_wrong_binding"),
        "POST",
        "/v1/tools/execute",
        payload,
    )
    assert wrong_binding.body["output"]["value"] == {
        "executed": "Gmail.SendEmail",
        "user_id": "agent:research-supervisor",
    }


def test_explicit_arcade_emulator_wins_over_environment_url(monkeypatch) -> None:
    monkeypatch.setenv("AGENTGYM_ARCADE_URL", "http://127.0.0.1:1")
    client = ArcadeClient(ArcadeEmulator())
    assert client.url is None
    assert client.authorized(
        "user:maya@civic.example", "GoogleDrive.CreateFile",
    )


def test_arcade_http_faults_are_isolated_per_concurrent_client(monkeypatch) -> None:
    with _http_emulator(ArcadeEmulator()) as url:
        monkeypatch.setenv("AGENTGYM_ARCADE_URL", url)
        healthy = ArcadeClient()
        faulty = ArcadeClient()
        faulty.arm_fault("execute_wrong_binding")
        user = "user:maya@civic.example"
        tool = "GoogleDrive.CreateFile"

        def execute(index: int) -> str:
            client = faulty if index % 2 else healthy
            assert client.authorized(user, tool)
            try:
                allowed = client.execute(user, tool, {})
            except ProviderFault:
                return "fault"
            return "allow" if allowed else "deny"

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(execute, range(64)))

        assert outcomes == [
            "fault" if index % 2 else "allow" for index in range(64)
        ]
        assert healthy.authorized(user, tool)
        assert healthy.execute(user, tool, {})


@pytest.mark.parametrize(
    "emulator",
    [WorkOSEmulator(), ArcadeEmulator()],
    ids=["workos", "arcade"],
)
def test_global_http_fault_control_is_disabled(emulator) -> None:
    response = emulator.handle(
        "POST",
        "/_agentgym/fault",
        {},
        b'{"fault":"malformed"}',
    )
    assert response.status == 410
    assert response.body["code"] == "global_fault_state_disabled"
    assert emulator.fault is None
