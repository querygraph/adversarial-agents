"""Command-line interface for deterministic AgentGym runs."""

from __future__ import annotations

import argparse
import json

from .adapters import ADAPTERS
from .runner import run_benchmark


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="agentgym")
    value.add_argument("--framework", choices=["all", *ADAPTERS], default="all")
    value.add_argument("--mode", choices=["all", "native", "typesec"], default="all")
    value.add_argument("--json", action="store_true")
    return value


def main() -> None:
    args = parser().parse_args()
    frameworks = ADAPTERS if args.framework == "all" else (args.framework,)
    modes = ("native", "typesec") if args.mode == "all" else (args.mode,)
    report = run_benchmark(frameworks, modes)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return
    print("AgentGym deterministic suite")
    print("framework       mode       pass   safety  utility  binding  closed  evidence")
    for score in report.scores:
        print(
            f"{score.framework:<15} {score.mode:<10} "
            f"{score.passed:>2}/{score.cases:<2}  {score.safety:>6.1f}  {score.utility:>7.1f}"
            f"  {score.binding_integrity:>7.1f}  {score.fail_closed:>6.1f}"
            f"  {score.evidence_quality:>8.1f}"
        )


if __name__ == "__main__":
    main()
