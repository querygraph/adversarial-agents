"""Wire-faithful deterministic provider emulators.

Each emulator implements the provider's current public API contract at the
HTTP-message level — paths, headers, request and response JSON, status
enums, and error shapes — as verified against the live docs and official
SDK sources on 2026-08-17:

- WorkOS: the re-architected authorization API (``/authorization/*``).
  The Warrant-derived ``/fga/v1/*`` contract was deprecated 2025-11-15 and
  is not what a 2026 integration calls.
- Arcade: ``/v1/tools/authorize``, ``/v1/auth/status`` (long-poll), and
  ``/v1/tools/execute``, with Arcade's raw-API-key ``Authorization`` header
  (no ``Bearer`` prefix) and its typed ``output.error.kind`` enum.

One handler implements each contract; it is served in-process for fast unit
runs and over real HTTP (``workos_server`` / ``arcade_server``) inside the
Docker network. Fault injection travels as private request metadata so every
benchmark client has isolated fault state even when runs overlap.
"""

from .arcade import ArcadeEmulator
from .clients import ArcadeClient, ProviderFault, WorkOSClient
from .workos import WorkOSEmulator

__all__ = [
    "ArcadeClient",
    "ArcadeEmulator",
    "ProviderFault",
    "WorkOSClient",
    "WorkOSEmulator",
]
