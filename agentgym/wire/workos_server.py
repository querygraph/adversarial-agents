"""Entry point: serve the WorkOS emulator over HTTP for the Docker matrix."""

from __future__ import annotations

import os

from .servers import serve
from .workos import WorkOSEmulator

if __name__ == "__main__":
    serve(WorkOSEmulator(), int(os.environ.get("AGENTGYM_WORKOS_PORT", "8280")))
