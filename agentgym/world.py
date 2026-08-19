"""Canonical QG Energy Cooperative world and policy source documents.

Shared identities, resources, grants, RBAC, and ODRL constraints come from
the checked-in fixture/policy corpus. Engine-specific translations are
generated or drift-checked against these sources; scenario-specific attack
values remain in the scenario definitions. Gates never read oracle verdicts.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from .model import FrozenDict, canonical_json, freeze_json

ROOT = Path(__file__).resolve().parents[1]


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False,
) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ValueError("RBAC mapping keys must be strings")
        if key in mapping:
            raise ValueError(f"duplicate RBAC mapping key {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _closed_mapping(
    value: object, keys: set[str], *, path: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    missing = keys - set(value)
    unknown = set(value) - keys
    if missing or unknown:
        raise ValueError(
            f"{path} has missing={sorted(missing)}, unknown={sorted(unknown)}"
        )
    return value


def _nonempty_strings(value: object, *, path: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ValueError(f"{path} must be a non-empty list of non-empty strings")
    if len(set(value)) != len(value):
        raise ValueError(f"{path} must not contain duplicates")
    return value


def parse_rbac_policy(source: str) -> frozenset[tuple[str, str, str]]:
    """Parse and expand the canonical closed-schema RBAC policy.

    The returned tuples are the single runtime grant representation used by
    the Rust carrier, provider emulator, and generated policy translations.
    Unknown fields, aliases, duplicate YAML keys/list entries, duplicate
    role/subject declarations, and dangling role assignments fail closed.
    """
    try:
        if any(
            isinstance(event, yaml.events.AliasEvent)
            for event in yaml.parse(source, Loader=yaml.SafeLoader)
        ):
            raise ValueError("RBAC aliases are not supported")
        loaded = yaml.load(source, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid RBAC YAML: {exc}") from exc
    document = _closed_mapping(loaded, {"roles", "assignments"}, path="RBAC")
    roles = document["roles"]
    assignments = document["assignments"]
    if not isinstance(roles, list) or not roles:
        raise ValueError("RBAC.roles must be a non-empty list")
    if not isinstance(assignments, list) or not assignments:
        raise ValueError("RBAC.assignments must be a non-empty list")

    expanded_roles: dict[str, frozenset[tuple[str, str]]] = {}
    for index, raw_role in enumerate(roles):
        role = _closed_mapping(
            raw_role, {"name", "permissions", "resources"},
            path=f"RBAC.roles[{index}]",
        )
        name = role["name"]
        if not isinstance(name, str) or not name:
            raise ValueError(f"RBAC.roles[{index}].name must be a non-empty string")
        if name in expanded_roles:
            raise ValueError(f"duplicate RBAC role {name!r}")
        permissions = _nonempty_strings(
            role["permissions"], path=f"RBAC.roles[{index}].permissions",
        )
        resources = _nonempty_strings(
            role["resources"], path=f"RBAC.roles[{index}].resources",
        )
        expanded_roles[name] = frozenset(
            (permission, resource)
            for permission in permissions
            for resource in resources
        )

    grants: set[tuple[str, str, str]] = set()
    assigned_subjects: set[str] = set()
    for index, raw_assignment in enumerate(assignments):
        assignment = _closed_mapping(
            raw_assignment, {"subject", "roles"},
            path=f"RBAC.assignments[{index}]",
        )
        subject = assignment["subject"]
        if not isinstance(subject, str) or not subject:
            raise ValueError(
                f"RBAC.assignments[{index}].subject must be a non-empty string"
            )
        if subject in assigned_subjects:
            raise ValueError(f"duplicate RBAC subject assignment {subject!r}")
        assigned_subjects.add(subject)
        role_names = _nonempty_strings(
            assignment["roles"], path=f"RBAC.assignments[{index}].roles",
        )
        if len(set(role_names)) != len(role_names):
            raise ValueError(f"duplicate role in assignment for {subject!r}")
        for name in role_names:
            if name not in expanded_roles:
                raise ValueError(f"unknown RBAC role {name!r}")
            grants.update(
                (subject, permission, resource)
                for permission, resource in expanded_roles[name]
            )
    return frozenset(grants)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def parse_odrl_policy(source: str) -> dict[str, Any]:
    """Parse the canonical AgentGym ODRL profile with a closed schema."""
    try:
        loaded = json.loads(
            source,
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number {value!r}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid ODRL JSON: {exc}") from exc
    document = _closed_mapping(
        loaded, {"uid", "permission", "prohibitions"}, path="ODRL",
    )
    permission = _closed_mapping(
        document["permission"],
        {"assignee", "action", "target", "constraints"},
        path="ODRL.permission",
    )
    constraints = _closed_mapping(
        permission["constraints"],
        {"purpose", "allowedColumns", "rowPredicate", "credentialTtlSeconds"},
        path="ODRL.permission.constraints",
    )
    for path, value in (
        ("ODRL.uid", document["uid"]),
        ("ODRL.permission.assignee", permission["assignee"]),
        ("ODRL.permission.action", permission["action"]),
        ("ODRL.permission.target", permission["target"]),
        ("ODRL.permission.constraints.purpose", constraints["purpose"]),
        ("ODRL.permission.constraints.rowPredicate", constraints["rowPredicate"]),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{path} must be a non-empty string")
    _nonempty_strings(
        constraints["allowedColumns"],
        path="ODRL.permission.constraints.allowedColumns",
    )
    _nonempty_strings(document["prohibitions"], path="ODRL.prohibitions")
    ttl = constraints["credentialTtlSeconds"]
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0:
        raise ValueError(
            "ODRL.permission.constraints.credentialTtlSeconds must be "
            "a non-negative integer"
        )
    return document


def _resource_text(relative: str) -> str:
    """Read canonical data from a checkout or from an installed wheel."""
    checkout = ROOT / relative
    if checkout.is_file():
        return checkout.read_text()
    return files("agentgym").joinpath("resources", *relative.split("/")).read_text()


@dataclass(frozen=True)
class World:
    approved_dataset: str
    poisoned_dataset: str
    dataset_rows: FrozenDict
    approved_row_count: int
    approved_result_digest: str
    study_resource: str
    sibling_resource: str
    allowed_purpose: str
    allowed_columns: frozenset[str]
    row_predicate: str
    credential_scope: str
    credential_ttl_seconds: int
    delegation_max_ttl: int
    delegation_scope: str
    rbac_grants: frozenset[tuple[str, str, str]]
    arcade_grants: frozenset[tuple[str, str]]
    supervisor: str
    # The exact source documents fed to policy parsers.  Keeping these on the
    # world object prevents enforcement adapters from growing private copies
    # of the benchmark policy.
    rbac_policy: str
    odrl_policy: str
    policy_digest: str


@lru_cache(maxsize=1)
def _load() -> World:
    world = json.loads(_resource_text("fixtures/world.json"))
    rbac_policy = _resource_text("policy/rbac.yaml")
    rbac_grants = parse_rbac_policy(rbac_policy)
    odrl = parse_odrl_policy(_resource_text("policy/odrl.json"))
    odrl_policy = json.dumps(odrl, sort_keys=True, separators=(",", ":"))
    policy_digest = hashlib.sha256(
        rbac_policy.encode() + b"\0" + odrl_policy.encode()
    ).hexdigest()
    permission = odrl["permission"]
    constraints = odrl["permission"]["constraints"]
    canonical_grant = (
        permission["assignee"], permission["action"], permission["target"],
    )
    if canonical_grant not in rbac_grants:
        raise ValueError("ODRL permission has no matching canonical RBAC grant")
    if permission["target"] != world["datasets"]["approved"]:
        raise ValueError("ODRL target and approved dataset fixture disagree")
    dashboard_grant = (
        world["principals"]["analyst"], "dataset:view",
        world["workos"]["study_resource"],
    )
    if dashboard_grant not in rbac_grants:
        raise ValueError("WorkOS study resource has no matching canonical RBAC grant")

    # Independently derive the exact benign scan expectation from source rows
    # and ODRL constraints.  It is not an authored hash that can drift from the
    # fixture, nor does it call the execution service being scored.
    if constraints["rowPredicate"] != "cohort = 'approved'":
        raise ValueError("fixture executor supports only the canonical cohort predicate")
    projected = [
        {
            column: row.get(column)
            for column in sorted(constraints["allowedColumns"])
        }
        for row in world["dataset_rows"][permission["target"]]
        if row.get("cohort") == "approved"
    ]
    expected_digest = "sha256:" + hashlib.sha256(
        canonical_json(projected).encode()
    ).hexdigest()
    return World(
        approved_dataset=world["datasets"]["approved"],
        poisoned_dataset=world["datasets"]["adversarial_neighbor"],
        dataset_rows=freeze_json(world["dataset_rows"]),  # type: ignore[arg-type]
        approved_row_count=len(projected),
        approved_result_digest=expected_digest,
        study_resource=world["workos"]["study_resource"],
        sibling_resource=world["workos"]["sibling_resource"],
        allowed_purpose=constraints["purpose"],
        allowed_columns=frozenset(constraints["allowedColumns"]),
        row_predicate=constraints["rowPredicate"],
        credential_scope=world["credential"]["scope"],
        credential_ttl_seconds=constraints["credentialTtlSeconds"],
        delegation_max_ttl=world["delegation"]["max_ttl_seconds"],
        delegation_scope=world["delegation"]["allowed_scope"],
        rbac_grants=rbac_grants,
        arcade_grants=frozenset(tuple(grant) for grant in world["arcade_grants"]),
        supervisor=world["principals"]["supervisor"],
        rbac_policy=rbac_policy,
        odrl_policy=odrl_policy,
        policy_digest=policy_digest,
    )


WORLD = _load()
