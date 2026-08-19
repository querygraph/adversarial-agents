from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from agentgym.adapters import ADAPTERS
from agentgym.cli import parser
from agentgym.model import CaseResult, Decision, Effect, thaw_json
from agentgym.runner import (
    _git_state,
    _grade,
    _score,
    run_benchmark,
    validate_provenance,
)
from agentgym.scenarios import (
    GOOD_QUERY,
    MAYA,
    approval_store_runtime,
    all_cases,
    parallel_join_runtime,
    phase1_cases,
    policy_parser_runtime,
    receipt_chain_runtime,
)
from agentgym.state import BoundaryState
from agentgym.world import WORLD, parse_odrl_policy, parse_rbac_policy

ROOT = Path(__file__).parents[1]


def test_corpus_has_benign_and_attack_case_for_each_scenario() -> None:
    cases = all_cases()
    assert {case.scenario for case in cases} == {f"BG-{n:02}" for n in range(1, 15)}
    for scenario in {case.scenario for case in cases}:
        variants = [case for case in cases if case.scenario == scenario]
        assert {case.attack for case in variants} == {False, True}


def test_every_case_has_a_story() -> None:
    assert all(case.story for case in all_cases())


def test_typesec_mode_blocks_every_attack_and_preserves_benign_utility() -> None:
    report = run_benchmark(("pydantic-ai",), ("typesec",))
    score = report.scores[0]
    assert score.safety == 100.0
    assert score.utility == 100.0
    assert score.fail_closed == 100.0
    assert score.grade == "A"
    assert all(result.passed for result in report.results)
    assert score.cases == 40
    assert sum(row.fault for row in report.results) == 12


def test_fault_trials_are_scored_separately_from_attack_safety() -> None:
    score = run_benchmark(("langchain",), ("native",)).scores[0]
    assert score.safety == 0.0
    # Seven transport/schema faults deny; three plausible stale/replayed
    # provider allows expose what a provider-only baseline cannot mediate.
    assert score.fail_closed == 70.0


def test_native_baseline_is_the_intended_weak_floor() -> None:
    report = run_benchmark(("langchain",), ("native",))
    attacks = {
        row.case_id: row for row in report.results if row.attack and not row.fault
    }
    assert set(attacks) == {f"BG-{n:02}-attack" for n in range(1, 15)}
    assert all(not row.safe for row in attacks.values())
    # This is the allow/trust-all metric golden: it retains benign utility but
    # receives no safety, binding, or evidence credit.
    assert report.scores[0].utility == 100.0
    assert report.scores[0].binding_integrity == 0.0
    assert report.scores[0].evidence_quality == 0.0
    assert report.scores[0].grade == "D"


def test_coarse_native_allows_do_not_receive_binding_credit() -> None:
    score = run_benchmark(("crewai",), ("native",)).scores[0]
    assert score.safety == 0.0
    assert score.binding_integrity == 0.0
    assert score.evidence_quality == 0.0


def test_deny_all_cannot_earn_binding_evidence_or_utility() -> None:
    benign = CaseResult(
        case_id="synthetic-good", scenario="synthetic", title="legitimate task",
        attack=False, framework="synthetic", mode="typesec", passed=False,
        safe=True, useful=False, effects=[],
        decisions=[Decision(False, "deny everything", "opaque-id",
                            mechanism="synthetic", invariant="exact-binding")],
    )
    attack = CaseResult(
        case_id="synthetic-attack", scenario="synthetic", title="attack",
        attack=True, framework="synthetic", mode="typesec", passed=True,
        safe=True, useful=True, effects=[],
        decisions=[Decision(False, "deny everything", "opaque-id",
                            mechanism="synthetic", invariant="exact-binding")],
    )
    score = _score([benign, attack])
    assert score.utility == 0.0
    assert score.binding_integrity == 0.0
    assert score.evidence_quality == 0.0
    assert score.fail_closed is None
    assert score.grade == "C"


def test_wrong_resource_or_result_details_receive_zero_utility() -> None:
    benign = CaseResult(
        case_id="BG-01-good", scenario="BG-01", title="wrong result",
        attack=False, framework="synthetic", mode="typesec", passed=True,
        safe=True, useful=True,
        effects=[Effect(
            "database_read", "user:maya@civic.example", "read",
            "lakecat://harbor/household_energy",
            {"columns": ["region"], "predicate": "TRUE"},
        )],
        decisions=[Decision(True, "allowed")],
    )
    attack = CaseResult(
        case_id="BG-01-attack", scenario="BG-01", title="blocked attack",
        attack=True, framework="synthetic", mode="typesec", passed=True,
        safe=True, useful=True, effects=[], decisions=[Decision(False, "denied")],
    )
    assert _score([benign, attack]).utility == 0.0


def test_forged_proof_receives_zero_evidence_quality_even_if_marked_verified() -> None:
    benign = CaseResult(
        case_id="BG-01-good", scenario="BG-01", title="legitimate task",
        attack=False, framework="synthetic", mode="typesec", passed=True,
        safe=True, useful=True,
        effects=[Effect(
            "database_read", MAYA.subject, GOOD_QUERY.action, GOOD_QUERY.resource,
            {
                "execution_digest": GOOD_QUERY.digest(MAYA),
                "columns": list(GOOD_QUERY.args["columns"]),
                "predicate": GOOD_QUERY.args["predicate"],
                "row_count": WORLD.approved_row_count,
                "result_digest": WORLD.approved_result_digest,
            },
        )],
        decisions=[Decision(
            True, "allowed", proof_id="opaque-call-id", mechanism="synthetic",
            invariant="exact-binding", request_digest=GOOD_QUERY.digest(MAYA),
            policy_digest=WORLD.policy_digest, evidence_verified=True,
        )],
    )
    attack = CaseResult(
        case_id="BG-01-attack", scenario="BG-01", title="blocked attack",
        attack=True, framework="synthetic", mode="typesec", passed=True,
        safe=True, useful=True, effects=[], decisions=[Decision(False, "denied")],
    )
    score = _score([benign, attack])
    assert score.utility == 100.0
    assert score.binding_integrity == 100.0
    assert score.evidence_quality == 0.0


def test_grade_a_requires_verified_evidence() -> None:
    assert _grade(100.0, 100.0, 100.0, 100.0, 0.0) == "B"
    assert _grade(100.0, 100.0, 100.0, 100.0, 100.0) == "A"


def test_non_query_utility_requires_the_exact_call_digest() -> None:
    case = next(case for case in all_cases() if case.id == "BG-07-good")
    call = case.calls[0]
    wrong = CaseResult(
        case_id=case.id, scenario=case.scenario, title="wrong delegation",
        attack=False, framework="synthetic", mode="typesec", passed=True,
        safe=True, useful=True,
        effects=[Effect(
            "delegated_run", case.principal.subject, call.action, call.resource,
            {"execution_digest": "0" * 64},
        )],
        decisions=[Decision(True, "allowed")],
    )
    assert _score([wrong]).utility == 0.0


def test_all_frameworks_use_identical_case_corpus() -> None:
    report = run_benchmark(tuple(ADAPTERS), ("native", "typesec"))
    expected = {case.id for case in all_cases()}
    for framework in ADAPTERS:
        for mode in ("native", "typesec"):
            actual = {
                row.case_id for row in report.results
                if row.framework == framework and row.mode == mode and not row.fault
            }
            assert actual == expected


def test_every_result_carries_an_explanation() -> None:
    for row in run_benchmark(("pydantic-ai",), ("typesec",)).results:
        assert row.explanation
        assert row.case_id.startswith(("BG-", "FAULT-"))
        verdict = "SAFE" if row.attack else "USEFUL"
        assert verdict in row.explanation


def test_report_is_json_serializable() -> None:
    report = run_benchmark(("crewai",), ("typesec",)).to_dict()
    json.dumps(report)
    assert report["provenance"]["schema"] == "agentgym.report/v2"
    assert report["provenance"]["policy_corpus_sha256"] == WORLD.policy_digest
    assert report["provenance"]["benchmark_version"] != "not-installed"
    assert report["provenance"]["dependencies"]["pydantic-ai"] != "not-installed"


def test_provenance_validator_rejects_missing_or_incompatible_metadata() -> None:
    report = run_benchmark(("pydantic-ai",), ("typesec",))
    provenance = report.provenance
    assert provenance["seed"] == 0
    assert provenance["run_profile"]["modes"] == ["typesec"]
    assert provenance["run_profile"]["command"] == [
        "agentgym", "--framework", "pydantic-ai", "--mode", "typesec", "--json",
    ]
    assert provenance["typesec_revision"]

    missing = deepcopy(provenance)
    missing.pop("image_ids")
    with pytest.raises(ValueError, match="missing fields"):
        validate_provenance(missing, ("pydantic-ai",), ("typesec",))

    incompatible = deepcopy(provenance)
    incompatible["schema"] = "agentgym.report/v999"
    with pytest.raises(ValueError, match="incompatible"):
        validate_provenance(incompatible, ("pydantic-ai",), ("typesec",))


def test_container_git_state_requires_an_explicit_dirty_attestation(
    monkeypatch,
) -> None:
    def unavailable(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("agentgym.runner.subprocess.run", unavailable)
    monkeypatch.setenv("AGENTGYM_GIT_COMMIT", "a" * 40)
    monkeypatch.setenv("AGENTGYM_GIT_DIRTY", "true")
    assert _git_state() == ("a" * 40, True)

    monkeypatch.setenv("AGENTGYM_GIT_DIRTY", "unknown")
    with pytest.raises(ValueError, match="must be true or false"):
        _git_state()


@pytest.mark.parametrize(
    "source",
    [
        '{"uid":"a","uid":"b","permission":{},"prohibitions":[]}',
        '{"uid":"a","permission":{},"prohibitions":[],"unknown":true}',
        '{"uid":"a","permission":{"assignee":"u","action":"read",'
        '"target":"r","constraints":{"purpose":"p","allowedColumns":[], '
        '"rowPredicate":"TRUE","credentialTtlSeconds":60}},"prohibitions":["x"]}',
        '{"uid":"a","permission":{"assignee":"u","action":"read",'
        '"target":"r","constraints":{"purpose":"p","allowedColumns":["x"],'
        '"rowPredicate":"TRUE","credentialTtlSeconds":NaN}},"prohibitions":["x"]}',
    ],
    ids=["duplicate-key", "unknown-key", "empty-columns", "nonfinite-ttl"],
)
def test_odrl_parser_rejects_ambiguous_or_open_documents(source: str) -> None:
    with pytest.raises(ValueError):
        parse_odrl_policy(source)


def test_identical_runs_are_byte_stable_within_one_environment() -> None:
    first = run_benchmark(("langchain",), ("typesec",)).to_dict()
    second = run_benchmark(("langchain",), ("typesec",)).to_dict()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_cli_parser_defaults_to_in_process_matrix() -> None:
    args = parser().parse_args([])
    assert args.framework == "all"
    assert args.mode == "default"


def test_backward_compatible_phase1_alias() -> None:
    assert phase1_cases is all_cases


def test_world_model_matches_checked_in_fixtures() -> None:
    world = json.loads((ROOT / "fixtures/world.json").read_text())
    odrl = json.loads((ROOT / "policy/odrl.json").read_text())
    rbac = (ROOT / "policy/rbac.yaml").read_text()
    assert WORLD.approved_dataset == world["datasets"]["approved"]
    assert WORLD.credential_ttl_seconds == odrl["permission"]["constraints"]["credentialTtlSeconds"]
    assert WORLD.allowed_columns == set(odrl["permission"]["constraints"]["allowedColumns"])
    assert WORLD.rbac_policy == rbac
    assert len(WORLD.rbac_grants) == 10
    assert (
        "user:maya@civic.example", "dataset:view", "dataset/northstar-study",
    ) in WORLD.rbac_grants
    assert "grants" not in world["workos"]
    assert "ttl_seconds" not in world["credential"]
    assert "query_expectation" not in world
    assert WORLD.approved_row_count == 2
    assert WORLD.approved_result_digest.startswith("sha256:")
    assert json.loads(WORLD.odrl_policy) == odrl
    assert len(WORLD.policy_digest) == 64


@pytest.mark.parametrize("source", [
    "roles: []\nroles: []\nassignments: []\n",
    "roles: []\nassignments: []\nunknown: true\n",
    """\
roles:
  - &reader {name: reader, permissions: [read], resources: [dataset/x]}
assignments:
  - {subject: user:x, roles: [reader], copied: *reader}
""",
    """\
roles:
  - {name: reader, permissions: [read, read], resources: [dataset/x]}
assignments:
  - {subject: user:x, roles: [reader]}
""",
    """\
roles:
  - {name: reader, permissions: [read], resources: [dataset/x]}
assignments:
  - {subject: user:x, roles: [missing]}
""",
])
def test_rbac_parser_rejects_ambiguous_or_unknown_syntax(source: str) -> None:
    with pytest.raises(ValueError):
        parse_rbac_policy(source)


def test_scenario_order_and_query_columns_are_deterministic() -> None:
    cases = all_cases()
    assert [case.id for case in cases] == [
        f"BG-{number:02}-{variant}"
        for number in range(1, 15)
        for variant in ("good", "attack")
    ]
    query = next(case for case in cases if case.id == "BG-01-good").calls[0]
    assert list(query.args["columns"]) == sorted(query.args["columns"])


def test_bg06_is_a_matched_request_pair() -> None:
    cases = {case.id: case for case in all_cases()}
    good = cases["BG-06-good"].calls[0]
    attack = cases["BG-06-attack"].calls[0]
    assert good.tool == attack.tool == "gmail/send"
    assert good.action == attack.action
    assert good.resource == attack.resource
    assert good.args == attack.args
    assert good.purpose == attack.purpose
    assert good.delegated_user == attack.delegated_user
    assert good.runtime["content_label"] == "public"
    assert attack.runtime["content_label"] == "sensitive"


def test_state_machine_scenarios_derive_verdicts_from_traces() -> None:
    cases = {case.id: case for case in all_cases()}

    receipt_case = cases["BG-12-good"]
    receipt = receipt_case.calls[0].runtime
    tampered = [dict(event) for event in receipt["receipt_chain"]]
    tampered[1]["previous"] = "sha256:tampered"
    receipt_state = BoundaryState.from_seed(receipt_case.trusted_state)
    assert not receipt_state.receipts.verify(
        receipt_chain_runtime(tampered)["receipt_chain"],
    ).valid

    approval_case = cases["BG-09-attack"]
    approval = approval_store_runtime(attacked=True)
    approval_state = BoundaryState.from_seed(approval_case.trusted_state)
    assert not approval_state.approvals.verify(
        "thread:maya", approval["current_call"],
    ).valid

    policy = cases["BG-13-good"].calls[0].runtime["policy_document"]
    altered_policy = thaw_json(policy)
    altered_policy["permission"]["duty"] = {"action": "obtainConsent"}
    policy_state = BoundaryState()
    assert not policy_state.policies.parse(
        policy_parser_runtime(altered_policy)["policy_document"],
    ).supported

    branch_case = cases["BG-14-good"]
    events = branch_case.calls[0].runtime["branch_events"]
    retried = [dict(event) for event in events]
    retry = dict(retried[-1])
    retry["attempt"] = 2
    retry["request_digest"] = "sha256:" + "0" * 64
    retried.append(retry)
    branch_state = BoundaryState.from_seed(branch_case.trusted_state)
    assert branch_state.branches.join(
        parallel_join_runtime(retried)["branch_events"], tenant="northstar",
    ).retry_drift
