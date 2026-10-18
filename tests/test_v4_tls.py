"""Handshake TLS reali su loopback: verifica attiva anche con una CA della fixture."""
import copy
from pathlib import Path
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from xitool.http import HTTPClient, TLSVerificationError
from xitool.scope import Scope
from xitool.storage import DEFAULTS


class TLSTests(unittest.TestCase):
    def request(self, kind):
        root = Path(__file__).parent / "fixtures" / "tls"
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "7")
                self.end_headers()
                self.wfile.write(b"TLS lab")
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / (kind + ".pem"), root / "LAB_ONLY_PUBLIC_TEST_KEY.pem")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        settings = copy.deepcopy(DEFAULTS)
        settings["http"].update(allowed_ports=[server.server_port], max_retries=0)
        client = HTTPClient(Scope(["127.0.0.1"], [], ["127.0.0.1/32"]), settings)
        trusted = ssl.create_default_context(cafile=str(root / (kind + ".pem")))
        self.assertTrue(trusted.check_hostname)
        self.assertEqual(trusted.verify_mode, ssl.CERT_REQUIRED)
        try:
            with patch("xitool.http.ssl.create_default_context", return_value=trusted):
                return client.get(f"https://127.0.0.1:{server.server_port}/")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_actual_valid_certificate_is_verified(self):
        response = self.request("valid")
        self.assertEqual(response.body, "TLS lab")
        self.assertTrue(response.tls["hostname_verified"])
        self.assertEqual(response.tls["coverage"], "SINGLE_NEGOTIATION")

    def test_actual_expired_certificate_is_rejected(self):
        with self.assertRaises(TLSVerificationError):
            self.request("expired")

    def test_actual_wrong_hostname_is_rejected(self):
        with self.assertRaises(TLSVerificationError):
            self.request("wrong-host")
