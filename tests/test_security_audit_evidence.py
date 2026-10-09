"""Reproduce security findings on upstream bf067c5, using fake credentials only.

These are evidence probes, not assertions that the observed behavior is safe.
"""

import io
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from opencode_go_proxy.app import (
    ProxyConfig, ResponsesProxyHandler, call_upstream_responses, dashboard_payload,
)


def config():
    return ProxyConfig(
        bind="127.0.0.1", port=8787,
        chat_base_url="https://opencode.ai/zen/go/v1",
        api_key_env="AUDIT_FAKE_KEY", client_token_env="AUDIT_FAKE_CLIENT_TOKEN",
        timeout_sec=3, max_body_bytes=1000,
    )


def test_evidence_dashboard_host_controls_outbound_destination():
    urls = []

    def reject(url, **kwargs):
        urls.append(url)
        raise urllib.error.URLError("audit: no network")

    with patch.dict("os.environ", {}, clear=True), patch(
        "opencode_go_proxy.app.urllib.request.urlopen", side_effect=reject
    ):
        dashboard_payload(config(), "attacker.example:443")
    assert urls == ["http://attacker.example:443/v1/health"]


def test_evidence_authentication_is_optional():
    with patch.dict("os.environ", {}, clear=True):
        assert ResponsesProxyHandler._is_authorized(object(), config()) is True


def test_evidence_upstream_error_body_is_logged():
    error = urllib.error.HTTPError(
        "https://opencode.ai/zen/go/v1/responses", 400, "bad request", {},
        io.BytesIO(b'{"error":"fake-private-prompt-marker"}'),
    )
    with patch("opencode_go_proxy.app.resolve_api_key", return_value="fake-key"), patch(
        "opencode_go_proxy.app.urllib.request.urlopen", side_effect=error
    ), patch("opencode_go_proxy.app.trace") as log:
        try:
            call_upstream_responses({"model": "gpt-5.6-luna"}, config(), "audit")
        except Exception:
            pass
    assert any("fake-private-prompt-marker" in str(call) for call in log.call_args_list)


def test_evidence_redirect_forwards_fake_bearer_to_other_origin():
    captured = []

    class Destination(BaseHTTPRequestHandler):
        def do_GET(self):
            captured.append(self.headers.get("Authorization"))
            body = b'{"object":"response","output":[]}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Destination)

    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/landing")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    source = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    for server in (source, target):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = config()
        cfg.chat_base_url = f"http://127.0.0.1:{source.server_port}"
        with patch("opencode_go_proxy.app.resolve_api_key", return_value="audit-fake-key"):
            call_upstream_responses({"model": "gpt-5.6-luna"}, cfg, "audit")
        assert captured == ["Bearer audit-fake-key"]
    finally:
        for server in (source, target):
            server.shutdown()
            server.server_close()
