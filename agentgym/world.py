"""The single source of truth for the QG Energy Cooperative world.

Every constant that appears in enforcement (any mode), in the engine
policies, and in the side-effect oracle is loaded from the checked-in
fixtures — ``fixtures/world.json`` and ``policy/odrl.json`` — so the gates,
the competitor policies, and the oracle cannot silently drift apart. The
gates never see the oracle's verdicts; they only share this world model.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class World:
    approved_dataset: str
    poisoned_dataset: str
    study_resource: str
    sibling_resource: str
    allowed_purpose: str
    allowed_columns: frozenset[str]
    row_predicate: str
    credential_scope: str
    credential_ttl_seconds: int
    delegation_max_ttl: int
    delegation_scope: str
    workos_grants: frozenset[tuple[str, str, str]]
    arcade_grants: frozenset[tuple[str, str]]
    supervisor: str


@lru_cache(maxsize=1)
def _load() -> World:
    world = json.loads((ROOT / "fixtures/world.json").read_text())
    odrl = json.loads((ROOT / "policy/odrl.json").read_text())
    constraints = odrl["permission"]["constraints"]
    return World(
        approved_dataset=world["datasets"]["approved"],
        poisoned_dataset=world["datasets"]["adversarial_neighbor"],
        study_resource=world["workos"]["study_resource"],
        sibling_resource=world["workos"]["sibling_resource"],
        allowed_purpose=constraints["purpose"],
        allowed_columns=frozenset(constraints["allowedColumns"]),
        row_predicate=constraints["rowPredicate"],
        credential_scope=world["credential"]["scope"],
        credential_ttl_seconds=world["credential"]["ttl_seconds"],
        delegation_max_ttl=world["delegation"]["max_ttl_seconds"],
        delegation_scope=world["delegation"]["allowed_scope"],
        workos_grants=frozenset(tuple(grant) for grant in world["workos"]["grants"]),
        arcade_grants=frozenset(tuple(grant) for grant in world["arcade_grants"]),
        supervisor=world["principals"]["supervisor"],
    )


WORLD = _load()
