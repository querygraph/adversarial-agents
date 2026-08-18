"""Deterministic emulator of the current WorkOS authorization API.

Implements the re-architected FGA contract (live docs, 2026-08):

- ``POST /authorization/organization_memberships/{omid}/check`` with
  ``{"permission_slug": "dataset:view", "resource_external_id": ...,
  "resource_type_slug": ...}`` → ``{"authorized": true|false}``.
- Bearer ``sk_...`` API-key auth; 401 without it.
- Role assignments and resources are seeded from the world fixture; the
  check evaluates direct assignments the way the real API documents:
  membership-centric, permission slug in ``{resource_type}:{action}``
  form, resource addressed by external ID and type slug.

The Warrant-derived ``/fga/v1/*`` API this replaces was deprecated on
2025-11-15; requests to it return 410 Gone with a pointer, so an
integration still speaking the old contract fails loudly rather than
silently.

Fault injection (armed via ``arm_fault``): ``timeout`` (no response inside
the client deadline), ``malformed`` (non-JSON body), ``stale_allow``
(authorized=true after the role assignment was revoked), ``wrong_resource``
(a correct-looking allow computed against a different resource).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..world import WORLD

API_KEY = "sk_agentgym_deterministic"

# Membership IDs the fixture publishes for each known subject.
MEMBERSHIPS = {
    "user:maya@civic.example": "om_maya",
    "user:leo@civic.example": "om_leo",
    "agent:research-supervisor": "om_supervisor",
    "agent:outsider": "om_outsider",
}


@dataclass
class Response:
    status: int
    body: dict | None
    raw: bytes | None = None

    def payload(self) -> bytes:
        if self.raw is not None:
            return self.raw
        return json.dumps(self.body or {}).encode()


@dataclass
class WorkOSEmulator:
    fault: str | None = None
    # (membership_id, permission_slug, resource_type_slug, resource_external_id)
    assignments: set[tuple[str, str, str, str]] = field(default_factory=set)
    revoked: set[tuple[str, str, str, str]] = field(default_factory=set)

    def __post_init__(self) -> None:
        for subject, permission, resource in WORLD.workos_grants:
            membership = MEMBERSHIPS[subject]
            resource_type, external_id = resource.split("/", 1)
            self.assignments.add((membership, permission, resource_type, external_id))

    def arm_fault(self, fault: str | None) -> None:
        self.fault = fault

    def handle(self, method: str, path: str, headers: dict[str, str],
               body: bytes) -> Response:
        if path.startswith("/_agentgym/fault"):
            payload = json.loads(body or b"{}")
            self.arm_fault(payload.get("fault"))
            return Response(200, {"armed": self.fault})
        if path.startswith("/fga/v1/"):
            return Response(410, {
                "message": "The Warrant-derived FGA API was deprecated on "
                           "2025-11-15; use /authorization/*.",
                "code": "fga_api_retired",
            })
        if headers.get("Authorization") != f"Bearer {API_KEY}":
            return Response(401, {"message": "Unauthorized", "code": "unauthorized"})
        if self.fault == "timeout":
            return Response(-1, None)  # transport layer sleeps past deadline
        if self.fault == "malformed":
            return Response(200, None, raw=b"<html>bad gateway</html>")
        parts = path.strip("/").split("/")
        if (
            method == "POST" and len(parts) == 4
            and parts[0] == "authorization"
            and parts[1] == "organization_memberships"
            and parts[3] == "check"
        ):
            return self._check(parts[2], json.loads(body or b"{}"))
        return Response(404, {"message": "Not found", "code": "not_found"})

    def _check(self, membership_id: str, payload: dict) -> Response:
        slug = payload.get("permission_slug")
        external_id = payload.get("resource_external_id")
        type_slug = payload.get("resource_type_slug")
        if not slug or not external_id or not type_slug:
            return Response(400, {
                "message": "permission_slug and resource identification are required",
                "code": "invalid_request",
            })
        key = (membership_id, slug, type_slug, external_id)
        if self.fault == "wrong_resource":
            # A correct-looking allow computed against a different resource:
            # the classic confused-deputy provider bug.
            key = (membership_id, slug, type_slug, "northstar-study")
        authorized = key in self.assignments
        if key in self.revoked:
            authorized = self.fault == "stale_allow"
        return Response(200, {"authorized": bool(authorized)})
