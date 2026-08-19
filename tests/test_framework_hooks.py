"""Regression tests proving framework hooks mediate the execution boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import pytest

import agentgym.frameworks as framework_module
from agentgym.boundary import BoundaryDenied, ExecutionBoundary
from agentgym.frameworks import RUNTIMES
from agentgym.model import Decision, Principal, ToolCall
from agentgym.policy import PolicyGate
from agentgym.recorder import EffectRecorder
from agentgym.world import WORLD


PRINCIPAL = Principal("user:maya@civic.example", "org:civic-lab")
CALL = ToolCall(
    "catalog/dashboard",
    "dataset:view",
    "dataset/northstar-study",
)
DRIVE_CALL = ToolCall(
    "drive/create",
    "execute",
    "drive/create",
    delegated_user=PRINCIPAL.subject,
    runtime={"content_label": "public"},
)


@dataclass
class FakePolicyGate:
    """Exact-binding gate used to isolate framework interception behavior."""

    allowed: bool
    check_calls: list[ToolCall] = field(default_factory=list)
    verify_calls: list[ToolCall] = field(default_factory=list)

    def check(self, principal: Principal, call: ToolCall) -> Decision:
        self.check_calls.append(call)
        return Decision(
            self.allowed,
            "fake exact decision",
            mechanism="fake-policy-gate",
            invariant="exact-binding",
            request_digest=call.digest(principal),
            policy_digest=WORLD.policy_digest,
            evidence_verified=self.allowed,
        )

    def verify_execution(
        self, principal: Principal, call: ToolCall, decision: Decision,
    ) -> bool:
        self.verify_calls.append(call)
        return (
            decision.allowed
            and decision.request_digest == call.digest(principal)
            and decision.policy_digest == WORLD.policy_digest
        )


class ExplodingPolicyGate:
    def check(self, principal: Principal, call: ToolCall) -> Decision:
        del principal, call
        raise RuntimeError("authorization provider crashed")


def _fake_boundary(
    allowed: bool,
) -> tuple[ExecutionBoundary, FakePolicyGate, EffectRecorder]:
    gate = FakePolicyGate(allowed)
    recorder = EffectRecorder()
    boundary = ExecutionBoundary(PRINCIPAL, gate, recorder)  # type: ignore[arg-type]
    return boundary, gate, recorder


def _real_boundary() -> tuple[ExecutionBoundary, EffectRecorder]:
    recorder = EffectRecorder()
    boundary = ExecutionBoundary(PRINCIPAL, PolicyGate("typesec"), recorder)
    return boundary, recorder


@pytest.mark.parametrize("framework", list(RUNTIMES))
@pytest.mark.parametrize("allowed", [False, True])
def test_framework_native_gate_controls_tool_execution(
    framework: str, allowed: bool,
) -> None:
    boundary, gate, recorder = _fake_boundary(allowed)

    executed = RUNTIMES[framework].invoke(CALL, boundary)

    assert executed is allowed
    assert recorder.kinds == ({"dashboard_open"} if allowed else set())
    assert gate.check_calls == [CALL]
    assert gate.check_calls[0] is not CALL
    assert gate.verify_calls == ([CALL] if allowed else [])
    if allowed:
        assert gate.verify_calls[0] is not gate.check_calls[0]
    assert boundary.unspent_permits == 0


def test_complete_payload_round_trips_to_a_fresh_call() -> None:
    actual = framework_module._call_from_payload(
        framework_module._payload(DRIVE_CALL, PRINCIPAL), PRINCIPAL,
    )
    assert actual == DRIVE_CALL
    assert actual is not DRIVE_CALL
    assert actual.action == "execute"
    assert actual.runtime == {"content_label": "public"}


def test_payload_parser_rejects_duplicate_fields() -> None:
    payload = framework_module._payload(CALL, PRINCIPAL).replace(
        '"action":"dataset:view",',
        '"action":"dataset:view","action":"delete",',
    )
    with pytest.raises(ValueError, match="duplicate JSON field 'action'"):
        framework_module._call_from_payload(payload, PRINCIPAL)


def test_payload_parser_rejects_principal_substitution() -> None:
    payload = framework_module._payload(CALL, PRINCIPAL).replace(
        PRINCIPAL.subject, "user:attacker@example.invalid",
    )
    with pytest.raises(ValueError, match="principal binding mismatch"):
        framework_module._call_from_payload(payload, PRINCIPAL)


def test_pydantic_ai_declares_the_tool_as_approval_required(monkeypatch) -> None:
    from pydantic_ai import Agent

    declarations: list[bool] = []
    original = Agent.tool_plain

    def recording_tool_plain(self, *args, **kwargs):
        declarations.append(kwargs.get("requires_approval", False))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Agent, "tool_plain", recording_tool_plain)
    boundary, _, recorder = _fake_boundary(False)
    assert not RUNTIMES["pydantic-ai"].invoke(CALL, boundary)
    assert declarations == [True]
    assert not recorder.effects


def test_langchain_registers_middleware_on_the_agent(monkeypatch) -> None:
    import langchain.agents

    registrations: list[tuple[object, ...]] = []
    original = langchain.agents.create_agent

    def recording_create_agent(*args, **kwargs):
        registrations.append(tuple(kwargs.get("middleware", ())))
        return original(*args, **kwargs)

    monkeypatch.setattr(langchain.agents, "create_agent", recording_create_agent)
    boundary, _, recorder = _fake_boundary(False)
    assert not RUNTIMES["langchain"].invoke(CALL, boundary)
    assert len(registrations) == 1
    assert len(registrations[0]) == 1
    assert not recorder.effects


@pytest.mark.parametrize("framework", list(RUNTIMES))
def test_framework_policy_exceptions_fail_closed(framework: str) -> None:
    recorder = EffectRecorder()
    boundary = ExecutionBoundary(
        PRINCIPAL, ExplodingPolicyGate(), recorder,  # type: ignore[arg-type]
    )
    assert not RUNTIMES[framework].invoke(CALL, boundary)
    assert not boundary.decisions
    assert not recorder.effects


@pytest.mark.parametrize("framework", list(RUNTIMES))
def test_malformed_sdk_payload_fails_before_authorization(
    framework: str, monkeypatch,
) -> None:
    monkeypatch.setattr(
        framework_module,
        "_payload",
        lambda _call, _principal: '{"tool":"catalog/dashboard"}',
    )
    boundary, gate, recorder = _fake_boundary(True)
    assert not RUNTIMES[framework].invoke(CALL, boundary)
    assert not gate.check_calls
    assert not recorder.effects


@pytest.mark.parametrize("framework", list(RUNTIMES))
@pytest.mark.parametrize(
    ("original", "tampered"),
    [
        (
            CALL,
            ToolCall(
                CALL.tool,
                "delete",
                CALL.resource,
                args=CALL.args,
                runtime=CALL.runtime,
            ),
        ),
        (
            DRIVE_CALL,
            ToolCall(
                DRIVE_CALL.tool,
                DRIVE_CALL.action,
                DRIVE_CALL.resource,
                args=DRIVE_CALL.args,
                delegated_user=DRIVE_CALL.delegated_user,
                runtime={"content_label": "sensitive"},
            ),
        ),
    ],
    ids=["action", "runtime"],
)
def test_sdk_payload_tampering_is_authorized_as_the_tampered_call(
    framework: str,
    original: ToolCall,
    tampered: ToolCall,
    monkeypatch,
) -> None:
    wire_payload = framework_module._payload(tampered, PRINCIPAL)
    monkeypatch.setattr(
        framework_module, "_payload", lambda _call, _principal: wire_payload,
    )
    boundary, recorder = _real_boundary()

    assert not RUNTIMES[framework].invoke(original, boundary)
    assert len(boundary.decisions) == 1
    assert not boundary.decisions[0].allowed
    assert not recorder.effects


@pytest.mark.parametrize(
    "tampered",
    [
        ToolCall(CALL.tool, "delete", CALL.resource),
        ToolCall(
            CALL.tool,
            CALL.action,
            CALL.resource,
            runtime={"content_label": "sensitive"},
        ),
    ],
    ids=["action", "runtime"],
)
def test_boundary_rejects_post_authorization_call_swap(
    tampered: ToolCall,
) -> None:
    boundary, recorder = _real_boundary()
    assert boundary.authorize(CALL)

    with pytest.raises(BoundaryDenied, match="exact call"):
        boundary.execute(tampered)

    assert not recorder.effects
    assert boundary.unspent_permits == 1
    boundary.execute(CALL)
    assert recorder.kinds == {"dashboard_open"}


@pytest.mark.parametrize("framework", list(RUNTIMES))
@pytest.mark.parametrize(
    "tampered",
    [
        ToolCall(CALL.tool, "delete", CALL.resource),
        ToolCall(
            CALL.tool,
            CALL.action,
            CALL.resource,
            runtime={"content_label": "sensitive"},
        ),
    ],
    ids=["action", "runtime"],
)
def test_framework_rejects_call_swap_between_hook_and_tool_body(
    framework: str,
    tampered: ToolCall,
    monkeypatch,
) -> None:
    boundary, gate, recorder = _fake_boundary(True)
    decodes = 0

    def swapped_decode(
        _payload: object, _principal: Principal,
    ) -> ToolCall:
        nonlocal decodes
        decodes += 1
        return CALL if decodes == 1 else tampered

    monkeypatch.setattr(framework_module, "_call_from_payload", swapped_decode)

    assert not RUNTIMES[framework].invoke(CALL, boundary)
    assert decodes == 2
    assert gate.check_calls == [CALL]
    assert not gate.verify_calls
    assert boundary.unspent_permits == 1
    assert not recorder.effects


def test_boundary_permit_is_single_use() -> None:
    boundary, recorder = _real_boundary()
    assert boundary.authorize(CALL)
    boundary.execute(CALL)

    with pytest.raises(BoundaryDenied, match="unspent decision"):
        boundary.execute(CALL)

    assert len(recorder.effects) == 1
    assert boundary.unspent_permits == 0


def test_independent_crewai_deny_hook_is_honored() -> None:
    from crewai.hooks import before_tool_call, unregister_before_tool_call_hook

    @before_tool_call
    def deny(context):
        if context.tool_name != "agentgym_dispatch":
            return None
        return False

    boundary, gate, recorder = _fake_boundary(True)
    try:
        executed = RUNTIMES["crewai"].invoke(CALL, boundary)
    finally:
        unregister_before_tool_call_hook(deny)

    assert not executed
    assert not gate.check_calls
    assert not recorder.effects


def test_crewai_scoped_gates_do_not_cross_concurrent_invocations() -> None:
    allowed = [index % 2 == 0 for index in range(16)]

    def invoke(expected: bool) -> tuple[bool, set[str]]:
        boundary, _, recorder = _fake_boundary(expected)
        executed = RUNTIMES["crewai"].invoke(CALL, boundary)
        return executed, recorder.kinds

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(invoke, allowed))

    assert results == [
        (expected, {"dashboard_open"} if expected else set())
        for expected in allowed
    ]
