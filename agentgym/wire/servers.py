"""Serve the provider emulators over real HTTP for the Docker matrix.

``python -m agentgym.wire.workos_server`` and ``.arcade_server`` run these.
The handler is the same emulator object the in-process client uses, so the
compose services and the unit suite exercise identical decision logic; only
the transport differs. Fault selection is request-scoped metadata interpreted
by ``handle``; the shared server object never carries a benchmark run's fault.
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _make_handler(emulator):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            headers = {key: value for key, value in self.headers.items()}
            response = emulator.handle(method, self.path, headers, body)
            if response.status == -1:
                # Emulated timeout: hold the socket past any client deadline.
                time.sleep(10)
                return
            payload = response.payload()
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            self._dispatch("POST")

        def log_message(self, *_args) -> None:
            return

    return Handler


def serve(emulator, port: int) -> None:
    server = ThreadingHTTPServer(("0.0.0.0", port), _make_handler(emulator))
    print(json.dumps({"listening": port, "emulator": type(emulator).__name__}))
    server.serve_forever()
