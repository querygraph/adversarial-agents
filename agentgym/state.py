"""Isolated execution-plane services for stateful adversarial scenarios.

The important trust boundary in this module is that issued approvals, receipts,
and branch capabilities are provisioned from :class:`Case` setup, never copied
from ``ToolCall.runtime``.  Runtime carries only the value presented by the
caller.  Authorization validates without spending authority; the execution
boundary atomically consumes it immediately before applying an effect.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Mapping, Sequence

from .model import ToolCall, canonical_json, thaw_json
from .world import WORLD


def object_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _is_array(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


@dataclass(frozen=True)
class ScanResult:
    rows: tuple[Mapping[str, Any], ...]
    row_count: int
    result_digest: str


class DatasetExecutor:
    """Small QueryGraph-style executor over tenant-addressed fixture records."""

    def scan(
        self, resource: str, columns: Sequence[str], predicate: str,
    ) -> ScanResult:
        source = WORLD.dataset_rows.get(resource, ())
        selected = [
            row for row in source
            if predicate == "TRUE"
            or (predicate == WORLD.row_predicate and row.get("cohort") == "approved")
        ]
        requested = tuple(columns)
        if "*" in requested:
            projected = [dict(row) for row in selected]
        else:
            projected = [
                {column: row.get(column) for column in requested}
                for row in selected
            ]
        return ScanResult(
            tuple(projected), len(projected), object_digest(projected),
        )


@dataclass(frozen=True)
class ReceiptVerification:
    valid: bool
    spliced: bool
    duplicate_event: bool
    closed_schema: bool
    terminal_digest: str
    issued: bool = False
    replayed: bool = False
    malformed: bool = False


class ReceiptLedger:
    """Verify issued hash chains and consume each terminal receipt once."""

    _fields = frozenset(
        {"event_id", "kind", "payload_hash", "previous", "schema", "digest"}
    )
    _kinds = frozenset({"authorization", "scan", "outbox"})

    def __init__(self, issued_chains: Sequence[Sequence[Mapping[str, Any]]] = ()) -> None:
        self._issued: dict[str, str] = {}
        self._spent: set[str] = set()
        self._lock = RLock()
        for chain in issued_chains:
            structural = self._verify_structure(chain)
            if not structural.valid:
                raise ValueError("trusted receipt seed must be a valid closed hash chain")
            encoded = canonical_json(chain)
            prior = self._issued.setdefault(structural.terminal_digest, encoded)
            if prior != encoded:
                raise ValueError("trusted receipt terminals must be unique")

    def _verify_structure(
        self, receipts: object,
    ) -> ReceiptVerification:
        if not _is_array(receipts):
            return ReceiptVerification(
                False, True, False, False, "invalid", malformed=True,
            )
        previous = "genesis"
        seen: set[str] = set()
        spliced = False
        duplicate = False
        closed = True
        malformed = False
        count = 0
        for raw_receipt in receipts:
            count += 1
            if not isinstance(raw_receipt, Mapping):
                malformed = True
                closed = False
                spliced = True
                previous = "invalid"
                continue
            receipt = raw_receipt
            closed = closed and set(receipt) == self._fields
            event_id = receipt.get("event_id")
            duplicate = (
                duplicate
                or not _nonempty_string(event_id)
                or event_id in seen
            )
            if isinstance(event_id, str):
                seen.add(event_id)
            closed = closed and receipt.get("schema") == "agentgym.receipt/v1"
            closed = closed and receipt.get("kind") in self._kinds
            closed = closed and _is_sha256(receipt.get("payload_hash"))
            link = receipt.get("previous")
            closed = closed and (link == "genesis" or _is_sha256(link))
            digest_value = receipt.get("digest")
            closed = closed and _is_sha256(digest_value)
            body = {
                key: thaw_json(receipt.get(key))
                for key in self._fields - {"digest"}
            }
            digest = object_digest(body)
            spliced = (
                spliced
                or link != previous
                or digest_value != digest
            )
            previous = digest_value if isinstance(digest_value, str) else "invalid"
        valid = count > 0 and closed and not spliced and not duplicate and not malformed
        return ReceiptVerification(
            valid, spliced, duplicate, closed, previous, malformed=malformed,
        )

    def verify(
        self, receipts: object, *, require_unspent: bool = True,
    ) -> ReceiptVerification:
        structural = self._verify_structure(receipts)
        if not structural.valid:
            return structural
        encoded = canonical_json(receipts)
        with self._lock:
            issued = self._issued.get(structural.terminal_digest) == encoded
            replayed = structural.terminal_digest in self._spent
        return ReceiptVerification(
            structural.valid and issued and (not require_unspent or not replayed),
            structural.spliced,
            structural.duplicate_event,
            structural.closed_schema,
            structural.terminal_digest,
            issued=issued,
            replayed=replayed,
            malformed=structural.malformed,
        )

    def consume(self, receipts: object) -> bool:
        with self._lock:
            verification = self.verify(receipts, require_unspent=True)
            if not verification.valid:
                return False
            self._spent.add(verification.terminal_digest)
            return True


@dataclass(frozen=True)
class ApprovalVerification:
    valid: bool
    approved_digest: str
    current_digest: str
    known: bool = False
    consumed: bool = False


class ApprovalStore:
    """Retrieve a trusted approval and consume its checkpoint once."""

    def __init__(self, records: Sequence[Mapping[str, Any]] = ()) -> None:
        self._records: dict[str, str] = {}
        self._spent: set[str] = set()
        self._lock = RLock()
        for record in records:
            if not isinstance(record, Mapping) or set(record) != {
                "checkpoint", "approved_call",
            }:
                raise ValueError("trusted approval seed has an invalid schema")
            checkpoint = record.get("checkpoint")
            approved_call = record.get("approved_call")
            if not _nonempty_string(checkpoint) or not isinstance(approved_call, Mapping):
                raise ValueError("trusted approval seed values are malformed")
            digest = object_digest(approved_call)
            if checkpoint in self._records:
                raise ValueError(f"duplicate trusted approval checkpoint {checkpoint!r}")
            self._records[checkpoint] = digest

    def verify(
        self,
        checkpoint: object,
        current_call: object,
        *,
        require_unspent: bool = True,
    ) -> ApprovalVerification:
        if not _nonempty_string(checkpoint) or not isinstance(current_call, Mapping):
            return ApprovalVerification(False, "missing", "invalid")
        current_digest = object_digest(current_call)
        with self._lock:
            approved_digest = self._records.get(checkpoint, "missing")
            consumed = checkpoint in self._spent
        known = approved_digest != "missing"
        return ApprovalVerification(
            known
            and approved_digest == current_digest
            and (not require_unspent or not consumed),
            approved_digest,
            current_digest,
            known=known,
            consumed=consumed,
        )

    def consume(self, checkpoint: object, current_call: object) -> bool:
        with self._lock:
            verification = self.verify(
                checkpoint, current_call, require_unspent=True,
            )
            if not verification.valid:
                return False
            assert isinstance(checkpoint, str)
            self._spent.add(checkpoint)
            return True


@dataclass(frozen=True)
class PolicyParse:
    supported: bool
    unsupported_constructs: tuple[str, ...]
    source_digest: str
    canonical_digest: str
    canonical: bool


class ClosedPolicyLoader:
    """Parse one closed ODRL profile and require the trusted corpus bytes."""

    _root = frozenset({"uid", "permission", "prohibitions"})
    _permission = frozenset({"assignee", "action", "target", "constraints"})
    _constraints = frozenset(
        {"purpose", "allowedColumns", "rowPredicate", "credentialTtlSeconds"}
    )

    def __init__(self, canonical_document: Mapping[str, Any]) -> None:
        self._canonical_json = canonical_json(canonical_document)
        self._canonical_digest = hashlib.sha256(
            self._canonical_json.encode()
        ).hexdigest()

    @staticmethod
    def _closed(
        value: object, expected: frozenset[str], path: str,
        unsupported: list[str],
    ) -> Mapping[str, Any] | None:
        if not isinstance(value, Mapping):
            unsupported.append(path)
            return None
        missing = expected - set(value)
        unknown = set(value) - expected
        unsupported.extend(f"{path}.{key}" for key in sorted(missing | unknown))
        return value

    def parse(self, document: object) -> PolicyParse:
        unsupported: list[str] = []
        root = self._closed(document, self._root, "policy", unsupported)
        permission = self._closed(
            root.get("permission") if root else None,
            self._permission,
            "policy.permission",
            unsupported,
        )
        constraints = self._closed(
            permission.get("constraints") if permission else None,
            self._constraints,
            "policy.permission.constraints",
            unsupported,
        )
        if root is not None:
            if not _nonempty_string(root.get("uid")):
                unsupported.append("policy.uid:type")
            prohibitions = root.get("prohibitions")
            if not _is_array(prohibitions) or any(
                not _nonempty_string(value) for value in prohibitions
            ):
                unsupported.append("policy.prohibitions:type")
        if permission is not None:
            for key in ("assignee", "action", "target"):
                if not _nonempty_string(permission.get(key)):
                    unsupported.append(f"policy.permission.{key}:type")
        if constraints is not None:
            for key in ("purpose", "rowPredicate"):
                if not _nonempty_string(constraints.get(key)):
                    unsupported.append(
                        f"policy.permission.constraints.{key}:type"
                    )
            columns = constraints.get("allowedColumns")
            if not _is_array(columns) or not columns or any(
                not _nonempty_string(value) for value in columns
            ):
                unsupported.append(
                    "policy.permission.constraints.allowedColumns:type"
                )
            ttl = constraints.get("credentialTtlSeconds")
            if (
                isinstance(ttl, bool)
                or not isinstance(ttl, (int, float))
                or not math.isfinite(ttl)
                or ttl < 0
            ):
                unsupported.append(
                    "policy.permission.constraints.credentialTtlSeconds:type"
                )
        try:
            encoded = canonical_json(document)
        except (TypeError, ValueError):
            encoded = "invalid"
            unsupported.append("policy:encoding")
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        values = tuple(sorted(set(unsupported)))
        canonical = not values and encoded == self._canonical_json
        return PolicyParse(
            not values,
            values,
            digest,
            self._canonical_digest,
            canonical,
        )


@dataclass(frozen=True)
class JoinVerification:
    valid: bool
    tenant_confusion: bool
    capability_reuse: bool
    retry_drift: bool
    branches: tuple[str, ...]
    unknown_capability: bool = False
    replayed: bool = False
    malformed: bool = False
    incomplete: bool = False


class BranchCapabilityRegistry:
    """Validate trusted branch grants and consume every capability atomically."""

    _event_fields = frozenset(
        {"branch_id", "tenant", "capability", "attempt", "request_digest"}
    )
    _seed_fields = frozenset(
        {"branch_id", "tenant", "capability", "request_digest"}
    )

    def __init__(self, capabilities: Sequence[Mapping[str, Any]] = ()) -> None:
        self._capabilities: dict[str, tuple[str, str, str]] = {}
        self._spent: set[str] = set()
        self._lock = RLock()
        for record in capabilities:
            if not isinstance(record, Mapping) or set(record) != self._seed_fields:
                raise ValueError("trusted branch capability seed has an invalid schema")
            capability = record.get("capability")
            branch = record.get("branch_id")
            tenant = record.get("tenant")
            request_digest = record.get("request_digest")
            if not all(_nonempty_string(value) for value in (
                capability, branch, tenant,
            )) or not _is_sha256(request_digest):
                raise ValueError("trusted branch capability seed is malformed")
            assert isinstance(capability, str)
            if capability in self._capabilities:
                raise ValueError(f"duplicate trusted capability {capability!r}")
            self._capabilities[capability] = (
                str(branch), str(tenant), str(request_digest),
            )

    def join(
        self,
        events: object,
        *,
        tenant: str,
        require_unspent: bool = True,
    ) -> JoinVerification:
        if not _is_array(events):
            return JoinVerification(
                False, True, False, False, (), malformed=True,
            )
        request_by_branch: dict[str, str] = {}
        presented: set[str] = set()
        tenant_confusion = False
        reuse = False
        drift = False
        unknown = False
        malformed = False
        replayed = False
        count = 0
        with self._lock:
            for event in events:
                count += 1
                if not isinstance(event, Mapping) or set(event) != self._event_fields:
                    malformed = True
                    continue
                branch = event.get("branch_id")
                request_digest = event.get("request_digest")
                capability = event.get("capability")
                event_tenant = event.get("tenant")
                attempt = event.get("attempt")
                if (
                    not all(_nonempty_string(value) for value in (
                        branch, capability, event_tenant,
                    ))
                    or not _is_sha256(request_digest)
                    or isinstance(attempt, bool)
                    or not isinstance(attempt, int)
                    or attempt < 1
                ):
                    malformed = True
                    continue
                assert isinstance(branch, str)
                assert isinstance(capability, str)
                assert isinstance(event_tenant, str)
                assert isinstance(request_digest, str)
                tenant_confusion = tenant_confusion or event_tenant != tenant
                if capability in presented:
                    reuse = True
                presented.add(capability)
                replayed = replayed or capability in self._spent
                expected = self._capabilities.get(capability)
                if expected is None:
                    unknown = True
                else:
                    expected_branch, expected_tenant, expected_digest = expected
                    tenant_confusion = (
                        tenant_confusion or event_tenant != expected_tenant
                    )
                    drift = drift or branch != expected_branch
                    drift = drift or request_digest != expected_digest
                if (
                    branch in request_by_branch
                    and request_by_branch[branch] != request_digest
                ):
                    drift = True
                request_by_branch.setdefault(branch, request_digest)
        expected_capabilities = {
            capability
            for capability, (_branch, expected_tenant, _digest) in self._capabilities.items()
            if expected_tenant == tenant
        }
        incomplete = presented != expected_capabilities
        valid = (
            count > 0
            and not tenant_confusion
            and not reuse
            and not drift
            and not unknown
            and not malformed
            and not incomplete
            and (not require_unspent or not replayed)
        )
        return JoinVerification(
            valid,
            tenant_confusion,
            reuse,
            drift,
            tuple(sorted(request_by_branch)),
            unknown_capability=unknown,
            replayed=replayed,
            malformed=malformed,
            incomplete=incomplete,
        )

    def consume(self, events: object, *, tenant: str) -> bool:
        with self._lock:
            verification = self.join(
                events, tenant=tenant, require_unspent=True,
            )
            if not verification.valid:
                return False
            assert _is_array(events)
            self._spent.update(str(event["capability"]) for event in events)
            return True


@dataclass
class BoundaryState:
    """All stateful services owned by one policy gate / benchmark case run."""

    approvals: ApprovalStore = field(default_factory=ApprovalStore)
    receipts: ReceiptLedger = field(default_factory=ReceiptLedger)
    branches: BranchCapabilityRegistry = field(
        default_factory=BranchCapabilityRegistry,
    )
    datasets: DatasetExecutor = field(default_factory=DatasetExecutor)
    policies: ClosedPolicyLoader = field(
        default_factory=lambda: ClosedPolicyLoader(json.loads(WORLD.odrl_policy)),
    )

    @classmethod
    def from_seed(cls, seed: Mapping[str, Any] | None = None) -> "BoundaryState":
        seed = seed or {}
        expected = {"approvals", "receipt_chains", "branch_capabilities"}
        unknown = set(seed) - expected
        if unknown:
            raise ValueError(f"unknown trusted state seed(s): {sorted(unknown)}")
        approvals = seed.get("approvals", ())
        receipt_chains = seed.get("receipt_chains", ())
        branch_capabilities = seed.get("branch_capabilities", ())
        if not all(_is_array(value) for value in (
            approvals, receipt_chains, branch_capabilities,
        )):
            raise ValueError("trusted state seed collections must be arrays")
        return cls(
            approvals=ApprovalStore(approvals),
            receipts=ReceiptLedger(receipt_chains),
            branches=BranchCapabilityRegistry(branch_capabilities),
        )

    def consume(self, call: ToolCall) -> bool:
        """Atomically spend the state authority required by ``call``."""
        if call.tool == "approval/execute":
            return self.approvals.consume(
                call.args.get("checkpoint"), call.runtime.get("current_call"),
            )
        if call.tool == "replay/import":
            return self.receipts.consume(call.runtime.get("receipt_chain"))
        if call.tool == "parallel/join":
            return self.branches.consume(
                call.runtime.get("branch_events"), tenant="northstar",
            )
        return True
