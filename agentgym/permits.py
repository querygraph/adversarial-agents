"""Authenticated, deterministic execution receipts for the benchmark boundary.

The receipt key is a public *benchmark fixture*, not a production secret.  Its
purpose is to make tampering and exact-call verification executable and
reproducible in the harness.  A deployment must inject a protected issuer key (or
use TypeSec's Ed25519 receipt issuer) instead of this fixture authority.
"""

from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Mapping

from .model import Principal, ToolCall, canonical_json

RECEIPT_VERSION = 1
BENCHMARK_ISSUER = "agentgym:test-issuer:v1"


class PermitError(ValueError):
    """An execution receipt is malformed, forged, stale, or misbound."""


_LOCAL_ISSUER = object()


class _LocalExecutionPermit:
    """Single-use boundary permit for profiles that do not ship Rust.

    Raw comparison profiles must remain runnable from the standalone base
    wheel.  They therefore use this process-local exact-call token; mediated
    profiles use the opaque Rust ``ExecutionPermit`` below.  This class is not
    evidence and never contributes to the evidence-quality score.
    """

    __slots__ = (
        "_request_digest", "_policy_digest", "_issued_at", "_expires_at",
        "_consumed",
    )

    def __init__(
        self,
        issuer: object,
        request_digest: str,
        policy_digest: str,
        issued_at: float,
        expires_at: float,
    ) -> None:
        if issuer is not _LOCAL_ISSUER:
            raise PermitError("local execution permits are boundary-issued")
        self._request_digest = request_digest
        self._policy_digest = policy_digest
        self._issued_at = issued_at
        self._expires_at = expires_at
        self._consumed = False

    def _consume(self, request_digest: str, policy_digest: str, now: float) -> None:
        if self._consumed:
            raise PermitError("execution permit was already consumed")
        if request_digest != self._request_digest or policy_digest != self._policy_digest:
            raise PermitError("execution permit call or policy binding mismatch")
        if not math.isfinite(now) or now < self._issued_at or now >= self._expires_at:
            raise PermitError("execution permit is not currently valid")
        self._consumed = True


def issue_local_execution_permit(
    *, request_digest: str, policy_digest: str, issued_at: float, expires_at: float,
) -> object:
    """Issue an unscored exact-call token for a raw comparison profile."""
    if expires_at <= issued_at:
        raise PermitError("execution permit expiry must be after issuance")
    return _LocalExecutionPermit(
        _LOCAL_ISSUER, request_digest, policy_digest, issued_at, expires_at,
    )


def consume_execution_permit(
    permit: object,
    *,
    request_digest: str,
    policy_digest: str,
    now: float,
) -> None:
    """Validate and atomically consume a supported opaque permit.

    Duck-typed objects are intentionally rejected.  This keeps a forged Python
    object from satisfying the effect boundary merely by defining ``consume``.
    """
    if isinstance(permit, _LocalExecutionPermit):
        permit._consume(request_digest, policy_digest, now)
        return
    try:
        from agentgym_native import ExecutionPermit
    except (ImportError, ModuleNotFoundError) as exc:
        raise PermitError(
            "Rust execution permit unavailable; install querygraph-agentgym-native"
        ) from exc
    if not isinstance(permit, ExecutionPermit):
        raise PermitError("effect boundary requires a recognized execution permit")
    try:
        permit.consume(request_digest, policy_digest, now)
    except (TypeError, ValueError) as exc:
        raise PermitError(f"execution permit rejected: {exc}") from exc


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise PermitError("receipt segment must be a non-empty string")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise PermitError("receipt segment is not canonical base64url") from exc


@lru_cache(maxsize=1)
def _signer() -> Any:
    try:
        from agentgym_native import ReceiptSigner
    except (ImportError, ModuleNotFoundError) as exc:
        raise PermitError(
            "Rust receipt signer unavailable; install querygraph-agentgym-native"
        ) from exc
    return ReceiptSigner()


@dataclass(frozen=True)
class ReceiptAuthority:
    """Issue and verify positive receipts through the compiled Rust signer."""

    issuer: str = BENCHMARK_ISSUER

    def _claims(
        self,
        *,
        mode: str,
        principal: Principal,
        call: ToolCall,
        policy_digest: str,
        issued_at: float,
        expires_at: float,
    ) -> dict[str, Any]:
        if expires_at <= issued_at:
            raise PermitError("receipt expiry must be after issuance")
        return {
            "v": RECEIPT_VERSION,
            "iss": self.issuer,
            "mode": mode,
            "decision": "allow",
            "subject": principal.subject,
            "organization": principal.organization,
            "tool": call.tool,
            "action": call.action,
            "resource": call.resource,
            "call": call.envelope(principal),
            "request_digest": call.digest(principal),
            "policy_digest": policy_digest,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    def issue(
        self,
        *,
        mode: str,
        principal: Principal,
        call: ToolCall,
        policy_digest: str,
        issued_at: float,
        expires_at: float,
    ) -> str:
        claims = self._claims(
            mode=mode,
            principal=principal,
            call=call,
            policy_digest=policy_digest,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return _signer().issue(canonical_json(claims))

    def execution_permit(
        self,
        *,
        token: str | None,
        mode: str,
        principal: Principal,
        call: ToolCall,
        policy_digest: str,
        issued_at: float,
        expires_at: float,
        now: float,
    ) -> Any:
        """Return a Rust-only, single-use permit for the exact effect call."""
        if token is None:
            token = self.issue(
                mode=mode,
                principal=principal,
                call=call,
                policy_digest=policy_digest,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        claims = self.verify(
            token,
            mode=mode,
            principal=principal,
            call=call,
            policy_digest=policy_digest,
            now=now,
        )
        try:
            return _signer().execution_permit(token, canonical_json(claims))
        except AttributeError as exc:
            raise PermitError(
                "installed querygraph-agentgym-native is incompatible; expected 0.3.0"
            ) from exc
        except (TypeError, ValueError) as exc:
            raise PermitError(f"Rust execution permit rejected: {exc}") from exc

    def verify(
        self,
        token: str,
        *,
        mode: str,
        principal: Principal,
        call: ToolCall,
        policy_digest: str,
        now: float,
    ) -> Mapping[str, Any]:
        if not isinstance(token, str) or token.count(".") != 1:
            raise PermitError("receipt must contain one payload/signature separator")
        payload_segment, signature_segment = token.split(".", 1)
        payload = _b64decode(payload_segment)
        _b64decode(signature_segment)
        try:
            payload_text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PermitError("receipt claims are not UTF-8") from exc
        if not _signer().verify(token, payload_text):
            raise PermitError("receipt signature is invalid")
        try:
            claims = json.loads(payload_text)
        except json.JSONDecodeError as exc:
            raise PermitError("receipt claims are not valid JSON") from exc
        if not isinstance(claims, dict):
            raise PermitError("receipt claims must be an object")
        expected = {
            "v": RECEIPT_VERSION,
            "iss": self.issuer,
            "mode": mode,
            "decision": "allow",
            "subject": principal.subject,
            "organization": principal.organization,
            "tool": call.tool,
            "action": call.action,
            "resource": call.resource,
            "call": call.envelope(principal),
            "request_digest": call.digest(principal),
            "policy_digest": policy_digest,
        }
        if set(claims) != {*expected, "issued_at", "expires_at"}:
            raise PermitError("receipt claims do not match the closed schema")
        for name, value in expected.items():
            if claims.get(name) != value:
                raise PermitError(f"receipt {name} binding mismatch")
        issued_at = claims.get("issued_at")
        expires_at = claims.get("expires_at")
        if (isinstance(issued_at, bool) or not isinstance(issued_at, (int, float))
                or isinstance(expires_at, bool) or not isinstance(expires_at, (int, float))):
            raise PermitError("receipt validity window must be numeric")
        if not math.isfinite(issued_at) or not math.isfinite(expires_at):
            raise PermitError("receipt validity window must be finite")
        if issued_at > now:
            raise PermitError("receipt is not yet valid")
        if expires_at <= now:
            raise PermitError("receipt has expired")
        return claims


DEFAULT_AUTHORITY = ReceiptAuthority()
