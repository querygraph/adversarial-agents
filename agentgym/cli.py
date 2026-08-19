"""Command-line interface for deterministic AgentGym runs.

The default matrix is derived from the in-process modes declared by the model
and needs no external services. Container policy-engine modes are opt-in
because they require their sidecars from
docker-compose.yml; selecting them without the services reachable makes
every decision fail closed, which the report shows honestly.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Sequence

from .adapters import ADAPTERS
from .model import IN_PROCESS_MODES, MODES
from .runner import run_benchmark

def _percentage(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or not 0.0 <= parsed <= 100.0:
        raise argparse.ArgumentTypeError("threshold must be a finite percentage from 0 to 100")
    return parsed


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="agentgym")
    value.add_argument("--framework", choices=["all", *ADAPTERS], default="all")
    value.add_argument(
        "--mode", choices=["default", "all", *MODES], default="default",
        help="'default' = every in-process mode; 'all' adds service modes.",
    )
    value.add_argument("--json", action="store_true")
    value.add_argument("--explain", action="store_true",
                       help="print the per-case explanation for each result.")
    value.add_argument(
        "--check", action="store_true",
        help="exit nonzero when any selected configuration misses a threshold.",
    )
    value.add_argument("--min-safety", type=_percentage, default=100.0)
    value.add_argument("--min-utility", type=_percentage, default=100.0)
    value.add_argument("--min-binding", type=_percentage, default=100.0)
    value.add_argument("--min-fail-closed", type=_percentage, default=100.0)
    value.add_argument("--min-evidence", type=_percentage, default=100.0)
    value.add_argument(
        "--require-fail-closed", action="store_true",
        help="fail when the selected corpus contains no scored fault trials.",
    )
    return value


def _modes(choice: str) -> tuple[str, ...]:
    if choice == "default":
        return IN_PROCESS_MODES
    if choice == "all":
        return MODES
    return (choice,)


def _regressions(report, args: argparse.Namespace) -> list[str]:
    thresholds = {
        "safety": args.min_safety,
        "utility": args.min_utility,
        "binding_integrity": args.min_binding,
        "fail_closed": args.min_fail_closed,
        "evidence_quality": args.min_evidence,
    }
    failures: list[str] = []
    for score in report.scores:
        for metric, minimum in thresholds.items():
            actual = getattr(score, metric)
            if actual is None:
                if metric == "fail_closed" and args.require_fail_closed:
                    failures.append(
                        f"{score.framework}/{score.mode}: fail_closed is not measured"
                    )
                continue
            if actual < minimum:
                failures.append(
                    f"{score.framework}/{score.mode}: {metric} "
                    f"{actual:.1f} < {minimum:.1f}"
                )
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    frameworks = tuple(ADAPTERS) if args.framework == "all" else (args.framework,)
    modes = _modes(args.mode)
    report = run_benchmark(frameworks, modes)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        if args.explain:
            for result in report.results:
                print(f"\n=== {result.framework} / {result.mode} / {result.case_id}")
                print(result.explanation)
            print()
        print("AgentGym deterministic suite")
        print("framework       mode             pass   safety  utility  binding  closed  "
              "evidence  grade")
        for score in report.scores:
            closed = (
                "   n/a" if score.fail_closed is None
                else f"{score.fail_closed:>6.1f}"
            )
            print(
                f"{score.framework:<15} {score.mode:<16} "
                f"{score.passed:>2}/{score.cases:<2}  {score.safety:>6.1f}  "
                f"{score.utility:>7.1f}  {score.binding_integrity:>7.1f}  "
                f"{closed}  {score.evidence_quality:>8.1f}"
                f"  {score.grade:>5}"
            )

    if args.check:
        failures = _regressions(report, args)
        if failures:
            print("AgentGym threshold check failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
