from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
import agentgym_native

from agentgym.adapters import ADAPTERS
from agentgym.model import Principal, ToolCall, canonical_json
from agentgym.policy import PolicyGate
from agentgym.runner import run_benchmark
from agentgym.scenarios import GOOD_QUERY, MAYA
from agentgym.typesec_native import _odrl_translation, check_rust_gate, gate
from agentgym.world import WORLD
from agentgym.wire import ArcadeClient, WorkOSClient
from agentgym.wire.arcade import ArcadeEmulator
from agentgym.wire.workos import WorkOSEmulator


def test_protected_track_uses_loaded_rust_extension() -> None:
    native_gate = gate()
    assert native_gate.__class__ is agentgym_native.AgentGymGate
    decision = check_rust_gate(MAYA, GOOD_QUERY)
    assert decision.allowed


def test_rust_tool_gate_denies_unbound_tool() -> None:
    call = ToolCall("unknown/admin", "execute", "admin/root", {"confusable": True})
    decision = gate().check(
        MAYA.subject, call.tool, call.action, call.resource, call.purpose,
        canonical_json(call.envelope(MAYA)),
        call.digest(MAYA),
    )
    assert not decision.allowed
    assert "no TypeSec binding" in decision.reason


def test_real_odrl_gate_does_not_treat_missing_purpose_as_permission() -> None:
    call = ToolCall(
        "catalog/query", "read", WORLD.approved_dataset,
        {"columns": sorted(WORLD.allowed_columns), "predicate": WORLD.row_predicate},
    )
    decision = gate().check(
        MAYA.subject, call.tool, call.action, call.resource, call.purpose,
        canonical_json(call.envelope(MAYA)), call.digest(MAYA),
    )
    assert not decision.allowed


def test_real_typesec_policy_parser_rejects_malformed_policy() -> None:
    with pytest.raises(ValueError):
        agentgym_native.AgentGymGate(
            "roles: [", _odrl_translation(), '{"catalog/query":"read"}',
            "org:civic-lab", WORLD.policy_digest,
        )


@pytest.mark.parametrize("fault", ["timeout", "malformed"])
def test_workos_faults_fail_closed(fault: str) -> None:
    call = ToolCall("catalog/dashboard", "dataset:view", "dataset/northstar-study")
    workos = WorkOSClient(WorkOSEmulator(fault=fault))
    gate = PolicyGate("typesec", workos=workos)
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "failed closed" in decision.reason


@pytest.mark.parametrize("fault", ["timeout", "malformed"])
def test_arcade_faults_fail_closed(fault: str) -> None:
    call = ToolCall("drive/create", "execute", "drive/create", {},
                    delegated_user=MAYA.subject, runtime={"content_label": "public"})
    arcade = ArcadeClient(ArcadeEmulator(fault=fault))
    gate = PolicyGate("typesec", arcade=arcade)
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "failed closed" in decision.reason


def test_stale_workos_allow_cannot_override_local_revocation() -> None:
    call = ToolCall("catalog/dashboard", "dataset:view", "dataset/northstar-study")
    gate = PolicyGate("typesec", workos=WorkOSClient(WorkOSEmulator()), revoked=True)
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "revoked" in decision.reason


def test_replayed_arcade_completion_cannot_swap_delegated_user() -> None:
    call = ToolCall("drive/create", "execute", "drive/create", {},
                    delegated_user="user:leo@civic.example",
                    runtime={"content_label": "public"})
    arcade = ArcadeClient(ArcadeEmulator(fault="replay_completed"))
    gate = PolicyGate("typesec", arcade=arcade)
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "delegated user" in decision.reason


def test_expired_capability_is_rejected_before_provider_or_tool() -> None:
    call = ToolCall("catalog/dashboard", "dataset:view", "dataset/northstar-study")
    gate = PolicyGate("typesec", issued_at=0.0, ttl_seconds=0.0)
    decision = gate.check(MAYA, call)
    assert not decision.allowed
    assert "expired" in decision.reason


@pytest.mark.parametrize("framework", list(ADAPTERS))
def test_each_real_framework_runtime_executes_the_full_protected_corpus(framework: str) -> None:
    score = run_benchmark((framework,), ("typesec",)).scores[0]
    assert score.safety == 100.0
    assert score.utility == 100.0
    assert score.evidence_quality == 100.0
    assert score.fail_closed == 100.0


def test_sixteen_concurrent_protected_runs_remain_isolated() -> None:
    def run(_: int) -> tuple[float, float]:
        score = run_benchmark(("langchain",), ("typesec",)).scores[0]
        return score.safety, score.utility

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(run, range(16)))
    assert results == [(100.0, 100.0)] * 16
