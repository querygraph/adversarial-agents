from __future__ import annotations

import json
from pathlib import Path

from agentgym.adapters import ADAPTERS
from agentgym.cli import parser
from agentgym.runner import run_benchmark
from agentgym.scenarios import all_cases, phase1_cases
from agentgym.world import WORLD

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
    assert score.grade == "A"
    assert all(result.passed for result in report.results)


def test_native_baseline_is_the_intended_weak_floor() -> None:
    report = run_benchmark(("langchain",), ("native",))
    attacks = {row.case_id: row for row in report.results if row.attack}
    assert set(attacks) == {f"BG-{n:02}-attack" for n in range(1, 15)}
    assert all(not row.safe for row in attacks.values())
    assert report.scores[0].grade == "D"


def test_native_binding_integrity_is_distinct_from_safety() -> None:
    # The native floor scores zero safety but nonzero binding integrity — the
    # two metrics measure different things and must not collapse together.
    score = run_benchmark(("crewai",), ("native",)).scores[0]
    assert score.safety == 0.0
    assert 0.0 < score.binding_integrity < 100.0


def test_all_frameworks_use_identical_case_corpus() -> None:
    report = run_benchmark(tuple(ADAPTERS), ("native", "typesec"))
    expected = {case.id for case in all_cases()}
    for framework in ADAPTERS:
        for mode in ("native", "typesec"):
            actual = {
                row.case_id for row in report.results
                if row.framework == framework and row.mode == mode
            }
            assert actual == expected


def test_every_result_carries_an_explanation() -> None:
    for row in run_benchmark(("pydantic-ai",), ("typesec",)).results:
        assert row.explanation
        assert row.case_id.split("-", 2)[-1] in {"good", "attack"} or "BG-" in row.explanation
        verdict = "SAFE" if row.attack else "USEFUL"
        assert verdict in row.explanation


def test_report_is_json_serializable() -> None:
    json.dumps(run_benchmark(("crewai",), ("typesec",)).to_dict())


def test_cli_parser_defaults_to_in_process_matrix() -> None:
    args = parser().parse_args([])
    assert args.framework == "all"
    assert args.mode == "default"


def test_backward_compatible_phase1_alias() -> None:
    assert phase1_cases is all_cases


def test_world_model_matches_checked_in_fixtures() -> None:
    world = json.loads((ROOT / "fixtures/world.json").read_text())
    odrl = json.loads((ROOT / "policy/odrl.json").read_text())
    assert WORLD.approved_dataset == world["datasets"]["approved"]
    assert WORLD.credential_ttl_seconds == odrl["permission"]["constraints"]["credentialTtlSeconds"]
    assert WORLD.allowed_columns == set(odrl["permission"]["constraints"]["allowedColumns"])
