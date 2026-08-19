"""Assemble OPA's data document from the benchmark's own fixtures.

OPA evaluates ``data.world``, ``data.rbac``, and ``data.odrl``. The RBAC grant
tuples are expanded from ``policy/rbac.yaml`` by the same strict parser the
runtime uses; provider/world facts and ODRL remain direct source documents.
Run from the repo root; writes ``policy/opa/data.json``. Regenerate whenever
the corpus changes (the test suite asserts it is current).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentgym.world import parse_odrl_policy, parse_rbac_policy

ROOT = Path(__file__).resolve().parents[1]


def build() -> dict:
    world = json.loads((ROOT / "fixtures/world.json").read_text())
    odrl = parse_odrl_policy((ROOT / "policy/odrl.json").read_text())
    grants = parse_rbac_policy((ROOT / "policy/rbac.yaml").read_text())
    return {
        "world": world,
        "rbac": {"grants": [list(grant) for grant in sorted(grants)]},
        "odrl": odrl,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check", action="store_true",
        help="fail instead of writing when policy/opa/data.json is stale",
    )
    args = parser.parse_args()
    out = ROOT / "policy/opa/data.json"
    rendered = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not out.is_file() or out.read_text() != rendered:
            print(f"stale generated policy data: {out}")
            return 1
        print(f"current: {out}")
        return 0
    out.write_text(rendered)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
