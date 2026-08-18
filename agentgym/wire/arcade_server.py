"""Entry point: serve the Arcade emulator over HTTP for the Docker matrix."""

from __future__ import annotations

import os

from .arcade import ArcadeEmulator
from .servers import serve

if __name__ == "__main__":
    serve(ArcadeEmulator(), int(os.environ.get("AGENTGYM_ARCADE_PORT", "9099")))
