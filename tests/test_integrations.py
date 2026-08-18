from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
import typesec._native as typesec_native
from typesec import ToolGate, validate

from agentgym.adapters import ADAPTERS
from agentgym.model import Principal, ToolCall
from agentgym.policy import PolicyGate
from agentgym.providers import FakeArcade, FakeWorkOS
from agentgym.runner import run_benchmark
from agentgym.scenarios import MAYA, all_cases
from agentgym.typesec_native import gates


def test_protected_track_uses_loaded_rust_extension() -> None:
    tool_gate, odrl_gate = gates()
    assert tool_gate.__class__ is typesec_native.ToolGate
    assert odrl_gate.__class__ is typesec_native.TypesecGate
    decision = tool_gate.check_tool(
        MAYA.subject,
        "catalog/query",
        '{"__resource":"lakecat://northstar/household_energy"}',
        "energy-assistance-research",
    )
    assert decision.allowed


def test_rust_tool_gate_denies_unbound_tool() -> None:
    tool_gate, _ = gates()
    decision = tool_gate.check_tool(MAYA.subject, "unknown/admin", "{}")
    assert not decision.allowed
    assert "no typesec binding" in decision.reason


@pytest.mark.parametrize("fault", ["timeout", "malformed"])
def test_workos_faults_fail_closed(fault: str) -> None:
    call = ToolCall("catalog/dashboard", "dataset:view", "dataset/northstar-study")
    gate = PolicyGate("typesec", workos=FakeWorkOS(fault=fault))
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "failed closed" in decision.reason


@pytest.mark.parametrize("fault", ["timeout", "malformed"])
def test_arcade_faults_fail_closed(fault: str) -> None:
    call = ToolCall(
        "drive/create", "execute", "drive/create", {"sensitive": False},
        delegated_user=MAYA.subject,
    )
    gate = PolicyGate("typesec", arcade=FakeArcade(fault=fault))
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "failed closed" in decision.reason


def test_real_typesec_policy_parser_rejects_malformed_policy() -> None:
    with pytest.raises(ValueError):
        validate("roles: [", "rbac")


def test_stale_workos_allow_cannot_override_local_revocation() -> None:
    call = ToolCall("catalog/dashboard", "dataset:view", "dataset/northstar-study")
    gate = PolicyGate("typesec", workos=FakeWorkOS(stale_allow=True), revoked=True)
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "revoked" in decision.reason


def test_replayed_arcade_completion_cannot_swap_delegated_user() -> None:
    call = ToolCall(
        "drive/create", "execute", "drive/create", {"sensitive": False},
        delegated_user="user:leo@civic.example",
    )
    gate = PolicyGate("typesec", arcade=FakeArcade(replay_completed=True))
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "delegated user" in decision.reason


def test_expired_capability_is_rejected_before_provider_or_tool() -> None:
    call = ToolCall("catalog/dashboard", "dataset:view", "dataset/northstar-study")
    gate = PolicyGate("typesec", issued_at=0.0, ttl_seconds=0.0)
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "expired" in decision.reason


def test_real_odrl_gate_does_not_treat_missing_purpose_as_permission() -> None:
    _, odrl_gate = gates()
    decision = odrl_gate.check(
        MAYA.subject, "read", "lakecat://northstar/household_energy"
    )
    assert not decision.allowed


@pytest.mark.parametrize("framework", ADAPTERS)
def test_each_real_framework_runtime_executes_the_full_protected_corpus(framework: str) -> None:
    report = run_benchmark((framework,), ("typesec",))
    assert report.scores[0].safety == 100.0
    assert report.scores[0].utility == 100.0
    assert report.scores[0].evidence_quality == 100.0


def test_sixteen_concurrent_protected_runs_remain_isolated() -> None:
    def run(_: int) -> tuple[float, float]:
        score = run_benchmark(("langchain",), ("typesec",)).scores[0]
        return score.safety, score.utility

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(run, range(16)))
    assert results == [(100.0, 100.0)] * 16


def test_all_fourteen_scenarios_have_distinct_forbidden_effects() -> None:
    attacks = [case for case in all_cases() if case.attack]
    assert len(attacks) == 14
    assert len({next(iter(case.forbidden_effects)) for case in attacks}) == 14
