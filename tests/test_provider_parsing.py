"""Policy/provider clients must reject ambiguous response types fail closed."""

from __future__ import annotations

import pytest

import agentgym.engines as engines
import agentgym.policy as policy
import agentgym.wire.clients as clients
from agentgym.adapters import ADAPTERS
from agentgym.faults import fault_cases
from agentgym.model import Decision, Principal, ToolCall
from agentgym.wire import ArcadeClient, ProviderFault, WorkOSClient


PRINCIPAL = Principal("user:maya@civic.example", "org:civic-lab")
OPA_CALL = ToolCall(
    "catalog/query",
    "read",
    "lakecat://northstar/household_energy",
)
WORKOS_ARGS = (
    PRINCIPAL.subject,
    "dataset:view",
    "dataset/northstar-study",
)
ARCADE_TOOL = "GoogleDrive.CreateFile"


def _arcade_authorization(**changes) -> dict:
    body = {
        "id": "auth_1",
        "status": "completed",
        "url": None,
        "scopes": [],
        "user_id": PRINCIPAL.subject,
        "provider_id": "google",
    }
    body.update(changes)
    return body


def _arcade_execution(**changes) -> dict:
    body = {
        "id": "exec_1",
        "success": True,
        "status": "success",
        "output": {
            "value": {
                "executed": ARCADE_TOOL,
                "user_id": PRINCIPAL.subject,
            },
        },
    }
    body.update(changes)
    return body


def _arcade_failure(**changes) -> dict:
    body = {
        "id": "exec_1",
        "success": False,
        "status": "failed",
        "output": {
            "error": {
                "kind": "TOOL_REQUIREMENTS_NOT_MET",
                "message": "authorization missing",
                "can_retry": False,
            },
        },
    }
    body.update(changes)
    return body


def test_opa_string_false_cannot_be_coerced_to_allow(monkeypatch) -> None:
    monkeypatch.setattr(
        engines,
        "_post",
        lambda *_args, **_kwargs: {"result": {"allow": "false"}},
    )
    decision = engines.OpaEngine().check(PRINCIPAL, OPA_CALL)
    assert not decision.allowed
    assert decision.invariant == "fail-closed"


@pytest.mark.parametrize("body", [[], "allowed", {"result": []}])
def test_opa_wrong_json_shapes_fail_closed(monkeypatch, body) -> None:
    monkeypatch.setattr(engines, "_post", lambda *_args, **_kwargs: body)
    assert not engines.OpaEngine().check(PRINCIPAL, OPA_CALL).allowed


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"results": {}},
        {"results": ["not-an-object"]},
        {"results": [{"actions": []}]},
        {"results": [{"actions": {"read": 1}}]},
    ],
)
def test_cerbos_wrong_json_shapes_fail_closed(monkeypatch, body) -> None:
    monkeypatch.setattr(engines, "_post", lambda *_args, **_kwargs: body)
    assert not engines.CerbosEngine().check(PRINCIPAL, OPA_CALL).allowed


def test_cerbos_volatile_call_id_is_not_canonical_evidence(monkeypatch) -> None:
    call_ids = iter(("volatile-call-1", "volatile-call-2"))

    def response(*_args, **_kwargs):
        return {
            "cerbosCallId": next(call_ids),
            "results": [{"actions": {"read": "EFFECT_ALLOW"}}],
        }

    monkeypatch.setattr(engines, "_post", response)
    first = engines.CerbosEngine().check(PRINCIPAL, OPA_CALL)
    second = engines.CerbosEngine().check(PRINCIPAL, OPA_CALL)
    assert first == second
    assert first.allowed
    assert first.proof_id is None


def test_workos_string_false_is_a_provider_fault(monkeypatch) -> None:
    client = WorkOSClient()
    client.url = "http://workos.test"
    monkeypatch.setattr(clients, "_http", lambda *_args, **_kwargs: {
        "authorized": "false",
    })
    with pytest.raises(ProviderFault, match="must be a boolean"):
        client.check(*WORKOS_ARGS)


@pytest.mark.parametrize(
    "body",
    [
        [],
        "allowed",
        {},
        {"authorized": 0},
        {"authorized": False, "debug": "smuggled"},
    ],
)
def test_workos_wrong_json_shapes_are_provider_faults(monkeypatch, body) -> None:
    client = WorkOSClient()
    client.url = "http://workos.test"
    monkeypatch.setattr(clients, "_http", lambda *_args, **_kwargs: body)
    with pytest.raises(ProviderFault):
        client.check(*WORKOS_ARGS)


@pytest.mark.parametrize(
    "body",
    [
        [],
        {},
        _arcade_authorization(id=1),
        _arcade_authorization(id=""),
        _arcade_authorization(status=True),
        _arcade_authorization(status="surprise"),
        _arcade_authorization(url=7),
        _arcade_authorization(url="https://arcade.dev/oauth/a"),
        _arcade_authorization(status="pending", url=None),
        _arcade_authorization(status="pending", url="http://arcade.dev/oauth/a"),
        _arcade_authorization(status="pending", url="https://evil.test/oauth/a"),
        _arcade_authorization(
            status="pending", url="https://user@arcade.dev/oauth/a",
        ),
        _arcade_authorization(scopes="drive.write"),
        _arcade_authorization(scopes=["drive.write", 3]),
        _arcade_authorization(scopes=["drive.write", "drive.write"]),
        _arcade_authorization(user_id=[PRINCIPAL.subject]),
        _arcade_authorization(provider_id=7),
        _arcade_authorization(provider_id=""),
        _arcade_authorization(provider_id="github"),
        _arcade_authorization(extra="smuggled"),
    ],
)
def test_arcade_authorization_schema_is_strict(monkeypatch, body) -> None:
    client = ArcadeClient()
    client.url = "http://arcade.test"
    monkeypatch.setattr(clients, "_http", lambda *_args, **_kwargs: body)
    with pytest.raises(ProviderFault):
        client.authorized(PRINCIPAL.subject, ARCADE_TOOL)


def test_arcade_authorization_accepts_only_exact_completed_user(monkeypatch) -> None:
    client = ArcadeClient()
    client.url = "http://arcade.test"
    response = _arcade_authorization()
    monkeypatch.setattr(clients, "_http", lambda *_args, **_kwargs: response)
    assert client.authorized(PRINCIPAL.subject, ARCADE_TOOL)

    response["user_id"] = "agent:research-supervisor"
    assert not client.authorized(PRINCIPAL.subject, ARCADE_TOOL)


@pytest.mark.parametrize(
    "body",
    [
        [],
        {},
        _arcade_execution(id=4),
        _arcade_execution(id=""),
        _arcade_execution(success="false"),
        _arcade_execution(status=False),
        _arcade_execution(status="failed"),
        _arcade_execution(output=[]),
        _arcade_execution(output={"value": {}, "trace": "smuggled"}),
        _arcade_execution(output={"value": []}),
        _arcade_execution(output={"value": {"executed": ARCADE_TOOL}}),
        _arcade_execution(output={"value": {
            "executed": 9, "user_id": PRINCIPAL.subject,
        }}),
        _arcade_execution(output={"value": {
            "executed": ARCADE_TOOL, "user_id": [],
        }}),
        _arcade_execution(output={"value": {
            "executed": ARCADE_TOOL,
            "user_id": PRINCIPAL.subject,
            "receipt": "smuggled",
        }}),
        _arcade_execution(output={"value": {
            "executed": "Gmail.SendEmail", "user_id": PRINCIPAL.subject,
        }}),
        _arcade_execution(output={"value": {
            "executed": ARCADE_TOOL,
            "user_id": "agent:research-supervisor",
        }}),
        _arcade_execution(extra="smuggled"),
    ],
)
def test_arcade_success_response_schema_and_binding_are_strict(
    monkeypatch, body,
) -> None:
    client = ArcadeClient()
    client.url = "http://arcade.test"
    monkeypatch.setattr(clients, "_http", lambda *_args, **_kwargs: body)
    with pytest.raises(ProviderFault):
        client.execute(PRINCIPAL.subject, ARCADE_TOOL, {})


@pytest.mark.parametrize(
    "body",
    [
        _arcade_failure(status="success"),
        _arcade_failure(output=[]),
        _arcade_failure(output={"error": {}, "trace": "smuggled"}),
        _arcade_failure(output={"error": []}),
        _arcade_failure(output={"error": {
            "kind": 1, "message": "denied", "can_retry": False,
        }}),
        _arcade_failure(output={"error": {
            "kind": "UNKNOWN", "message": "denied", "can_retry": False,
        }}),
        _arcade_failure(output={"error": {
            "kind": "TOOL_REQUIREMENTS_NOT_MET",
            "message": "",
            "can_retry": False,
        }}),
        _arcade_failure(output={"error": {
            "kind": "TOOL_REQUIREMENTS_NOT_MET",
            "message": "denied",
            "can_retry": "false",
        }}),
        _arcade_failure(output={"error": {
            "kind": "TOOL_REQUIREMENTS_NOT_MET",
            "message": "denied",
            "can_retry": False,
            "debug": "smuggled",
        }}),
    ],
)
def test_arcade_error_response_schema_is_strict(monkeypatch, body) -> None:
    client = ArcadeClient()
    client.url = "http://arcade.test"
    monkeypatch.setattr(clients, "_http", lambda *_args, **_kwargs: body)
    with pytest.raises(ProviderFault):
        client.execute(PRINCIPAL.subject, ARCADE_TOOL, {})


def test_arcade_valid_success_and_error_responses(monkeypatch) -> None:
    client = ArcadeClient()
    client.url = "http://arcade.test"
    responses = iter((_arcade_execution(), _arcade_failure()))
    monkeypatch.setattr(
        clients, "_http", lambda *_args, **_kwargs: next(responses),
    )
    assert client.execute(PRINCIPAL.subject, ARCADE_TOOL, {})
    assert not client.execute(PRINCIPAL.subject, ARCADE_TOOL, {})


@pytest.mark.parametrize(
    "fault,match",
    [
        ("execute_wrong_type", "must be a boolean"),
        ("execute_wrong_binding", "binding mismatch"),
    ],
)
def test_arcade_execute_faults_are_deterministic_and_fail_closed(
    fault: str, match: str,
) -> None:
    from agentgym.wire.arcade import ArcadeEmulator

    client = ArcadeClient(ArcadeEmulator(fault=fault))
    assert client.authorized(PRINCIPAL.subject, ARCADE_TOOL)
    with pytest.raises(ProviderFault, match=match):
        client.execute(PRINCIPAL.subject, ARCADE_TOOL, {})


class _RawResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self) -> bytes:
        return self.payload


@pytest.mark.parametrize(
    "payload",
    [
        b'{"authorized":false,"authorized":true}',
        (
            b'{"id":"exec_1","success":true,"status":"success",'
            b'"output":{"value":{"executed":"GoogleDrive.CreateFile",'
            b'"executed":"Gmail.SendEmail","user_id":'
            b'"user:maya@civic.example"}}}'
        ),
    ],
)
def test_http_json_duplicate_keys_are_rejected(monkeypatch, payload: bytes) -> None:
    monkeypatch.setattr(
        clients.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _RawResponse(payload),
    )
    with pytest.raises(ProviderFault, match="duplicate JSON field"):
        clients._http("GET", "http://provider.test", {}, None)


def test_provider_fault_applicability_matches_actual_call_paths() -> None:
    by_id = {case.id: case for case in fault_cases()}
    workos_modes = frozenset({
        "native", "workos", "opa-mediated", "cerbos-mediated", "typesec",
    })
    arcade_authorize_modes = frozenset({
        "native", "arcade", "opa-mediated", "cerbos-mediated", "typesec",
    })
    arcade_execute_modes = frozenset({
        "arcade", "opa-mediated", "cerbos-mediated", "typesec",
    })

    assert len(by_id) == 12
    for case_id in (
        "FAULT-WORKOS-TIMEOUT",
        "FAULT-WORKOS-MALFORMED",
        "FAULT-WORKOS-STRING-FALSE",
        "FAULT-WORKOS-STALE-ALLOW",
        "FAULT-WORKOS-WRONG-RESOURCE",
    ):
        assert by_id[case_id].applicable_modes == workos_modes
    for case_id in (
        "FAULT-ARCADE-TIMEOUT",
        "FAULT-ARCADE-MALFORMED",
        "FAULT-ARCADE-WRONG-TYPE",
        "FAULT-ARCADE-REPLAY-COMPLETED",
        "FAULT-ARCADE-AUTHORIZE-OTHER-USER",
    ):
        assert by_id[case_id].applicable_modes == arcade_authorize_modes
    for case_id in (
        "FAULT-ARCADE-EXECUTE-WRONG-TYPE",
        "FAULT-ARCADE-EXECUTE-WRONG-BINDING",
    ):
        assert by_id[case_id].applicable_modes == arcade_execute_modes


@pytest.mark.parametrize(
    "case_id,mode,expected_safe",
    [
        ("FAULT-WORKOS-STALE-ALLOW", "native", False),
        ("FAULT-WORKOS-STALE-ALLOW", "workos", False),
        ("FAULT-WORKOS-STALE-ALLOW", "typesec", True),
        ("FAULT-WORKOS-WRONG-RESOURCE", "native", False),
        ("FAULT-WORKOS-WRONG-RESOURCE", "workos", False),
        ("FAULT-WORKOS-WRONG-RESOURCE", "typesec", True),
        ("FAULT-ARCADE-REPLAY-COMPLETED", "native", False),
        ("FAULT-ARCADE-REPLAY-COMPLETED", "arcade", False),
        ("FAULT-ARCADE-REPLAY-COMPLETED", "typesec", True),
        ("FAULT-ARCADE-AUTHORIZE-OTHER-USER", "native", True),
        ("FAULT-ARCADE-AUTHORIZE-OTHER-USER", "arcade", True),
        ("FAULT-ARCADE-AUTHORIZE-OTHER-USER", "typesec", True),
        ("FAULT-ARCADE-EXECUTE-WRONG-TYPE", "arcade", True),
        ("FAULT-ARCADE-EXECUTE-WRONG-TYPE", "typesec", True),
        ("FAULT-ARCADE-EXECUTE-WRONG-BINDING", "arcade", True),
        ("FAULT-ARCADE-EXECUTE-WRONG-BINDING", "typesec", True),
    ],
)
def test_provider_faults_distinguish_provider_only_and_local_defenses(
    case_id: str, mode: str, expected_safe: bool,
) -> None:
    case = next(case for case in fault_cases() if case.id == case_id)
    result = ADAPTERS["langchain"].run(case, mode)
    assert result.safe is expected_safe


class _AllowEngine:
    def check(self, _principal, _call) -> Decision:
        return Decision(True, "deterministic policy allow", mechanism="test-engine")


@pytest.mark.parametrize("mode", ["opa-mediated", "cerbos-mediated"])
@pytest.mark.parametrize(
    "case_id,invariant",
    [
        ("FAULT-WORKOS-STALE-ALLOW", "lease-epoch"),
        ("FAULT-WORKOS-WRONG-RESOURCE", "exact-provider-resource"),
        ("FAULT-ARCADE-REPLAY-COMPLETED", "delegated-user-binding"),
        ("FAULT-ARCADE-AUTHORIZE-OTHER-USER", "delegated-user-binding"),
    ],
)
def test_common_mediator_defenses_are_independent_of_provider_allow(
    monkeypatch, mode: str, case_id: str, invariant: str,
) -> None:
    engine_name = mode.removesuffix("-mediated")
    monkeypatch.setitem(policy.ENGINES, engine_name, _AllowEngine())
    case = next(case for case in fault_cases() if case.id == case_id)
    result = ADAPTERS["langchain"].run(case, mode)
    assert result.safe
    assert not result.effects
    assert result.decisions[-1].invariant == invariant


@pytest.mark.parametrize("mode", ["opa-mediated", "cerbos-mediated"])
@pytest.mark.parametrize(
    "case_id",
    [
        "FAULT-ARCADE-EXECUTE-WRONG-TYPE",
        "FAULT-ARCADE-EXECUTE-WRONG-BINDING",
    ],
)
def test_mediated_arcade_execute_faults_fail_before_local_effect(
    monkeypatch, mode: str, case_id: str,
) -> None:
    engine_name = mode.removesuffix("-mediated")
    monkeypatch.setitem(policy.ENGINES, engine_name, _AllowEngine())
    case = next(case for case in fault_cases() if case.id == case_id)
    result = ADAPTERS["langchain"].run(case, mode)
    assert result.safe
    assert not result.effects
    # Authorization succeeds, but strict execute-response validation prevents
    # the boundary from consuming the permit and invoking the local tool body.
    assert result.decisions[-1].allowed
