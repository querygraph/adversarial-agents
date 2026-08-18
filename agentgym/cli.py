"""Command-line interface for deterministic AgentGym runs.

The default matrix is the two in-process modes — ``native`` and ``typesec``
— which need no external services. The container policy engines (``opa``,
``cerbos``) are opt-in because they require their sidecars from
docker-compose.yml; selecting them without the services reachable makes
every decision fail closed, which the report shows honestly.
"""

from __future__ import annotations

import argparse
import json

from .adapters import ADAPTERS
from .model import MODES
from .runner import run_benchmark

IN_PROCESS_MODES = ("native", "typesec")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="agentgym")
    value.add_argument("--framework", choices=["all", *ADAPTERS], default="all")
    value.add_argument(
        "--mode", choices=["default", "all", *MODES], default="default",
        help="'default' = native+typesec; 'all' adds the container engines.",
    )
    value.add_argument("--json", action="store_true")
    value.add_argument("--explain", action="store_true",
                       help="print the per-case explanation for each result.")
    return value


def _modes(choice: str) -> tuple[str, ...]:
    if choice == "default":
        return IN_PROCESS_MODES
    if choice == "all":
        return MODES
    return (choice,)


def main() -> None:
    args = parser().parse_args()
    frameworks = tuple(ADAPTERS) if args.framework == "all" else (args.framework,)
    modes = _modes(args.mode)
    report = run_benchmark(frameworks, modes)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return
    if args.explain:
        for result in report.results:
            print(f"\n=== {result.framework} / {result.mode} / {result.case_id}")
            print(result.explanation)
        print()
    print("AgentGym deterministic suite")
    print("framework       mode      pass   safety  utility  binding  closed  "
          "evidence  grade")
    for score in report.scores:
        print(
            f"{score.framework:<15} {score.mode:<8} "
            f"{score.passed:>2}/{score.cases:<2}  {score.safety:>6.1f}  "
            f"{score.utility:>7.1f}  {score.binding_integrity:>7.1f}  "
            f"{score.fail_closed:>6.1f}  {score.evidence_quality:>8.1f}"
            f"  {score.grade:>5}"
        )


if __name__ == "__main__":
    main()
