"""Controlled loopback validation of the web heuristic detector.

The server only binds to 127.0.0.1 and returns deliberately constructed
responses. These tests verify expected detector behavior, not real-world
vulnerability detection accuracy.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

import pytest

from modules.webapp_scan import SQLI_PAYLOAD, XSS_PAYLOAD, run


class _ControlledHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        value = parse_qs(urlparse(self.path).query).get("id", [""])[0]
        self.send_response(200)
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "session=fixture; HttpOnly; Secure")
        self.end_headers()
        if SQLI_PAYLOAD in value:
            self.wfile.write(b"You have an error in your SQL syntax")
        elif XSS_PAYLOAD in value:
            self.wfile.write(XSS_PAYLOAD.encode("utf-8"))
        else:
            self.wfile.write(b"fixed response")

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def local_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ControlledHandler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/fixture?id=1"
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()


def test_local_ground_truth_triggers_both_reflection_heuristics(local_target):
    result = run(local_target)
    findings = {finding["id"]: finding for finding in result["findings"]}
    assert all(findings[f"header_{header}"]["passed"] is True for header in (
        "content_security_policy", "x_frame_options", "x_content_type_options",
    ))
    assert findings["header_strict_transport_security"]["status"] == "NOT_APPLICABLE"
    assert findings["https_transport"]["status"] == "FAIL"
    assert findings["reflected_sqli_heuristic"]["passed"] is False
    assert findings["reflected_xss_heuristic"]["passed"] is False
    assert result["score"] == 10
