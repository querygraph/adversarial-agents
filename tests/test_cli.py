from __future__ import annotations

from types import SimpleNamespace

import pytest

import agentgym.cli as cli


def _report(**overrides):
    values = {
        "framework": "pydantic-ai",
        "mode": "typesec",
        "cases": 28,
        "passed": 28,
        "safety": 100.0,
        "utility": 100.0,
        "binding_integrity": 100.0,
        "fail_closed": 100.0,
        "evidence_quality": 100.0,
        "grade": "A",
    }
    values.update(overrides)
    score = SimpleNamespace(**values)
    return SimpleNamespace(scores=[score], results=[])


def test_check_returns_success_when_every_threshold_holds(monkeypatch) -> None:
    monkeypatch.setattr(cli, "run_benchmark", lambda *_args: _report())
    assert cli.main(["--framework", "pydantic-ai", "--mode", "typesec", "--check"]) == 0


def test_check_returns_nonzero_and_names_every_regression(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "run_benchmark",
        lambda *_args: _report(safety=99.0, evidence_quality=75.0),
    )
    assert cli.main(["--framework", "pydantic-ai", "--mode", "typesec", "--check"]) == 1
    error = capsys.readouterr().err
    assert "pydantic-ai/typesec: safety 99.0 < 100.0" in error
    assert "pydantic-ai/typesec: evidence_quality 75.0 < 100.0" in error


def test_check_thresholds_are_configurable(monkeypatch) -> None:
    monkeypatch.setattr(cli, "run_benchmark", lambda *_args: _report(safety=64.3))
    assert cli.main([
        "--framework", "pydantic-ai", "--mode", "opa", "--check",
        "--min-safety", "64.0",
    ]) == 0


def test_unmeasured_fault_metric_is_explicitly_optional(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "run_benchmark", lambda *_args: _report(fail_closed=None))
    base = ["--framework", "pydantic-ai", "--mode", "typesec", "--check"]
    assert cli.main(base) == 0
    assert cli.main([*base, "--require-fail-closed"]) == 1
    assert "fail_closed is not measured" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["nan", "inf", "-1", "101"])
def test_check_rejects_invalid_thresholds(value: str) -> None:
    with pytest.raises(SystemExit) as error:
        cli.parser().parse_args(["--min-safety", value])
    assert error.value.code == 2
