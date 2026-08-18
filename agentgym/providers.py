"""Deterministic WorkOS and Arcade emulators with explicit fault injection."""

from __future__ import annotations

from dataclasses import dataclass, field


class ProviderFault(RuntimeError):
    """A deterministic malformed or unavailable provider response."""


@dataclass
class FakeWorkOS:
    grants: set[tuple[str, str, str]] = field(
        default_factory=lambda: {
            ("user:maya@civic.example", "dataset:view", "dataset/northstar-study"),
        }
    )
    stale_allow: bool = False
    fault: str | None = None

    def check(self, subject: str, permission: str, resource: str) -> bool:
        if self.fault in {"timeout", "malformed"}:
            raise ProviderFault(f"WorkOS {self.fault} response")
        return self.stale_allow or (subject, permission, resource) in self.grants


@dataclass
class FakeArcade:
    grants: set[tuple[str, str]] = field(
        default_factory=lambda: {
            ("user:maya@civic.example", "GoogleDrive.CreateFile"),
            ("user:maya@civic.example", "Gmail.SendEmail"),
            ("user:leo@civic.example", "Gmail.SendEmail"),
        }
    )
    replay_completed: bool = False
    fault: str | None = None

    def authorized(self, user: str, tool: str) -> bool:
        if self.fault in {"timeout", "malformed"}:
            raise ProviderFault(f"Arcade {self.fault} response")
        return self.replay_completed or (user, tool) in self.grants
