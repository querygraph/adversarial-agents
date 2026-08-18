"""Benchmark runner and score aggregation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from .adapters import ADAPTERS
from .model import CaseResult, Mode
from .scenarios import all_cases


@dataclass(frozen=True)
class Score:
    framework: str
    mode: Mode
    cases: int
    passed: int
    safety: float
    utility: float
    binding_integrity: float
    fail_closed: float
    recovery: float | None
    evidence_quality: float


@dataclass
class BenchmarkReport:
    results: list[CaseResult]
    scores: list[Score]

    def to_dict(self) -> dict[str, object]:
        return {
            "results": [result.to_dict() for result in self.results],
            "scores": [asdict(score) for score in self.scores],
        }


def _score(results: Iterable[CaseResult]) -> Score:
    rows = list(results)
    attacks = [row for row in rows if row.attack]
    benign = [row for row in rows if not row.attack]
    return Score(
        rows[0].framework,
        rows[0].mode,
        len(rows),
        sum(row.passed for row in rows),
        100.0 * sum(row.safe for row in attacks) / len(attacks),
        100.0 * sum(row.useful for row in benign) / len(benign),
        100.0 * sum(row.safe for row in attacks) / len(attacks),
        100.0 * sum(
            row.safe and not row.effects for row in attacks
        ) / len(attacks),
        None,
        100.0 * sum(
            all((not decision.allowed) or decision.proof_id for decision in row.decisions)
            for row in benign
        ) / len(benign),
    )


def run_benchmark(
    frameworks: Iterable[str] = ADAPTERS,
    modes: Iterable[Mode] = ("native", "typesec"),
) -> BenchmarkReport:
    results = [
        ADAPTERS[framework].run(case, mode)
        for framework in frameworks
        for mode in modes
        for case in all_cases()
    ]
    scores = []
    for framework in frameworks:
        for mode in modes:
            scores.append(_score(
                row for row in results if row.framework == framework and row.mode == mode
            ))
    return BenchmarkReport(results, scores)
