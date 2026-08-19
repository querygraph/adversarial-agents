"""Generate Cerbos resource policies from AgentGym's canonical corpus.

The target language still needs an explicit translation, but security constants
must never be copied by hand. ``--check`` is the release drift gate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from agentgym.world import parse_odrl_policy, parse_rbac_policy

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "policy/cerbos/resource_policies"


def _one_grant(
    grants: frozenset[tuple[str, str, str]], action: str, resource_prefix: str,
) -> tuple[str, str, str]:
    matches = sorted(
        grant for grant in grants
        if grant[1] == action and grant[2].startswith(resource_prefix)
    )
    if len(matches) != 1:
        raise ValueError(
            f"expected one RBAC grant for {action!r}/{resource_prefix!r}, "
            f"found {matches!r}"
        )
    return matches[0]


def _resource_policy(
    resource: str, action: str, expression: str | None = None,
    expressions: list[str] | None = None,
) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "actions": [action],
        "effect": "EFFECT_ALLOW",
        "roles": ["user"],
    }
    if expression is not None:
        rule["condition"] = {"match": {"expr": expression}}
    if expressions is not None:
        rule["condition"] = {
            "match": {"all": {"of": [{"expr": value} for value in expressions]}},
        }
    return {
        "apiVersion": "api.cerbos.dev/v1",
        "resourcePolicy": {
            "version": "default",
            "resource": resource,
            "rules": [rule],
        },
    }


def build() -> dict[str, dict[str, Any]]:
    world = json.loads((ROOT / "fixtures/world.json").read_text())
    odrl = parse_odrl_policy((ROOT / "policy/odrl.json").read_text())
    grants = parse_rbac_policy((ROOT / "policy/rbac.yaml").read_text())
    constraints = odrl["permission"]["constraints"]
    columns = json.dumps(constraints["allowedColumns"], separators=(",", ":"))
    analyst, _, dataset = _one_grant(grants, "read", "lakecat://")
    dashboard_subject, _, dashboard = _one_grant(grants, "dataset:view", "dataset/")
    delegate_subject, _, delegation = _one_grant(grants, "delegate", "report/")
    supervisor, _, memory = _one_grant(grants, "read", "memory/")
    credential_subject, _, credential = _one_grant(grants, "read", "credential/")
    replay_subject, _, replay = _one_grant(grants, "write", "replay/")
    policy_subject, _, policy = _one_grant(grants, "read", "policy/")
    join_subject, _, join = _one_grant(grants, "read", "join/")
    saas_grants = sorted(
        grant for grant in grants
        if grant[1] == "execute" and grant[2] in {"drive/create", "gmail/send"}
    )
    if len(saas_grants) != 2 or len({grant[0] for grant in saas_grants}) != 1:
        raise ValueError("canonical RBAC must grant one subject both SaaS resources")
    saas_subject = saas_grants[0][0]
    saas_resources = json.dumps([grant[2] for grant in saas_grants], separators=(",", ":"))
    if (
        (analyst, "read", dataset)
        != (odrl["permission"]["assignee"], odrl["permission"]["action"],
            odrl["permission"]["target"])
    ):
        raise ValueError("ODRL permission and canonical RBAC dataset grant disagree")
    if world["datasets"]["approved"] != dataset:
        raise ValueError("world dataset and canonical policy target disagree")
    if world["workos"]["study_resource"] != dashboard:
        raise ValueError("WorkOS study resource and canonical RBAC grant disagree")
    if world["principals"]["analyst"] != analyst:
        raise ValueError("world analyst and canonical RBAC assignee disagree")
    if world["principals"]["supervisor"] != supervisor:
        raise ValueError("world supervisor and canonical RBAC assignee disagree")
    return {
        "dataset.yaml": _resource_policy("dataset", "read", expressions=[
            f'request.principal.id == "{analyst}"',
            f'request.resource.id == "{dataset}"',
            f'request.resource.attr.purpose == "{constraints["purpose"]}"',
            "has(request.resource.attr.args.columns)",
            "size(request.resource.attr.args.columns) > 0",
            f"request.resource.attr.args.columns.all(c, c in {columns})",
            f'request.resource.attr.args.predicate == "{constraints["rowPredicate"]}"',
        ]),
        "dashboard.yaml": _resource_policy(
            "dashboard", "dataset:view",
            f'request.principal.id == "{dashboard_subject}" && '
            f'request.resource.id == "{dashboard}"',
        ),
        "saas_channel.yaml": _resource_policy("saas_channel", "execute", expressions=[
            f'request.principal.id == "{saas_subject}"',
            f"request.resource.id in {saas_resources}",
            "request.resource.attr.delegated_user == request.principal.id",
            'request.resource.attr.tool != "gmail/send" || '
            'request.resource.attr.purpose == "approved-communication"',
        ]),
        "delegation.yaml": _resource_policy("delegation", "delegate", expressions=[
            f'request.principal.id == "{delegate_subject}"',
            f'request.resource.id == "{delegation}"',
            "request.resource.attr.args.ttl <= "
            f'{world["delegation"]["max_ttl_seconds"]}',
            "request.resource.attr.args.scope == "
            f'"{world["delegation"]["allowed_scope"]}"',
        ]),
        "memory.yaml": _resource_policy("memory", "read", expressions=[
            f'request.principal.id == "{supervisor}"',
            f'request.resource.id == "{memory}"',
        ]),
        "approval.yaml": _resource_policy("approval", "execute", expressions=[
            f'request.principal.id == "{saas_subject}"',
            'request.resource.id == "drive/create"',
            'request.resource.attr.args.checkpoint == "thread:maya"',
        ]),
        "credential.yaml": _resource_policy("credential", "read", expressions=[
            f'request.principal.id == "{credential_subject}"',
            f'request.resource.id == "{credential}"',
            "request.resource.attr.args.raw == false",
            f'request.resource.attr.args.scope == "{world["credential"]["scope"]}"',
            f'request.resource.attr.args.ttl <= {constraints["credentialTtlSeconds"]}',
        ]),
        "replay.yaml": _resource_policy("replay", "write", expressions=[
            f'request.principal.id == "{replay_subject}"',
            f'request.resource.id == "{replay}"',
        ]),
        "policy_corpus.yaml": _resource_policy("policy_corpus", "read", expressions=[
            f'request.principal.id == "{policy_subject}"',
            f'request.resource.id == "{policy}"',
        ]),
        "parallel_join.yaml": _resource_policy("parallel_join", "read", expressions=[
            f'request.principal.id == "{join_subject}"',
            f'request.resource.id == "{join}"',
        ]),
    }


def render() -> dict[str, str]:
    header = "# Generated by scripts/build_cerbos_policies.py; do not edit.\n"
    return {
        name: header + yaml.safe_dump(document, sort_keys=False)
        for name, document in build().items()
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render()
    stale = [
        name for name, content in rendered.items()
        if not (OUT / name).is_file() or (OUT / name).read_text() != content
    ]
    if args.check:
        if stale:
            print("stale generated Cerbos policies: " + ", ".join(sorted(stale)))
            return 1
        print(f"current: {OUT}")
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for name, content in rendered.items():
        (OUT / name).write_text(content)
    print(f"wrote {len(rendered)} policies to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
