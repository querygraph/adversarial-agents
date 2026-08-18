from __future__ import annotations

import json
from pathlib import Path

from agentgym.adapters import ADAPTERS
from agentgym.cli import parser
from agentgym.runner import run_benchmark
from agentgym.scenarios import phase1_cases


def test_corpus_has_benign_and_attack_case_for_each_scenario() -> None:
    cases = phase1_cases()
    assert {case.scenario for case in cases} == {f"BG-{number:02}" for number in range(1, 15)}
    for scenario in {case.scenario for case in cases}:
        variants = [case for case in cases if case.scenario == scenario]
        assert {case.attack for case in variants} == {False, True}


def test_typesec_mode_blocks_every_attack_and_preserves_benign_utility() -> None:
    report = run_benchmark(("pydantic-ai",), ("typesec",))
    score = report.scores[0]
    assert score.safety == 100.0
    assert score.utility == 100.0
    assert all(result.passed for result in report.results)


def test_native_mode_exposes_the_intended_boundary_failures() -> None:
    report = run_benchmark(("langchain",), ("native",))
    attack_results = {row.case_id: row for row in report.results if row.attack}
    assert set(attack_results) == {f"BG-{number:02}-attack" for number in range(1, 15)}
    assert all(not result.safe for result in attack_results.values())


def test_all_frameworks_use_identical_case_corpus() -> None:
    report = run_benchmark()
    expected = {case.id for case in phase1_cases()}
    for framework in ADAPTERS:
        for mode in ("native", "typesec"):
            actual = {
                row.case_id for row in report.results
                if row.framework == framework and row.mode == mode
            }
            assert actual == expected


def test_report_is_json_serializable() -> None:
    json.dumps(run_benchmark(("crewai",), ("typesec",)).to_dict())


def test_cli_parser_defaults_to_full_matrix() -> None:
    args = parser().parse_args([])
    assert args.framework == "all"
    assert args.mode == "all"


def test_checked_in_world_and_policy_fixtures_match_reference_model() -> None:
    root = Path(__file__).parents[1]
    world = json.loads((root / "fixtures/world.json").read_text())
    odrl = json.loads((root / "policy/odrl.json").read_text())
    assert world["datasets"]["approved"] == "lakecat://northstar/household_energy"
    assert odrl["permission"]["constraints"]["credentialTtlSeconds"] == 60
    assert set(odrl["permission"]["constraints"]["allowedColumns"]) == {
        "region", "energy_source", "monthly_energy_cost"
    }
