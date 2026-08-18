"""Assemble OPA's data document from the benchmark's own fixtures.

OPA evaluates ``data.world`` and ``data.odrl``; both come straight from
``fixtures/world.json`` and ``policy/odrl.json`` so the Rego policy enforces
the identical constants the rest of the benchmark uses. Run from the repo
root; writes ``policy/opa/data.json``. Regenerate whenever the fixtures
change (the test suite asserts it is current).
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build() -> dict:
    world = json.loads((ROOT / "fixtures/world.json").read_text())
    odrl = json.loads((ROOT / "policy/odrl.json").read_text())
    return {"world": world, "odrl": odrl}


if __name__ == "__main__":
    out = ROOT / "policy/opa/data.json"
    out.write_text(json.dumps(build(), indent=2, sort_keys=True) + "\n")
    print(f"wrote {out}")
